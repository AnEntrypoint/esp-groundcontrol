#include "gc_app.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "driver/gpio.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "gc_config.h"
#include "gc_crypto.h"
#include "gc_ctrl_proto.h"
#include "gc_emergency.h"
#include "gc_gate.h"
#include "gc_link_monitor.h"
#include "gc_log.h"
#include "gc_modem_api.h"
#include "gc_mqtt.h"
#include "gc_nat.h"
#include "gc_netif.h"
#include "gc_ota.h"
#include "gc_pinmap.h"
#include "gc_portal.h"
#include "gc_quota.h"
#include "gc_selftest.h"
#include "gc_telemetry.h"
#include "gc_types.h"
#include "gc_watchdog.h"
#include "gc_wifi_uplink.h"

#define GC_APP_HEAP_FLOOR_BYTES 24576u
#define GC_APP_TICK_STALL_MAX_S 5u
#define GC_APP_QUOTA_PERSIST_PERIOD_S 900u
#define GC_APP_GATE_PERSIST_PERIOD_S 300u
#define GC_APP_QUOTA_PERSIST_MAX_AGE_S 3600u
#define GC_APP_LADDER_ACTION_INTERVAL_S 60u
#define GC_APP_RELAY_PULSE_S 3u
#define GC_APP_VERIFY_TIMEOUT_FALLBACK_S 30u
#define GC_APP_HEARTBEAT_FALLBACK_S 21600u
#define GC_APP_MANIFEST_CHECK_FALLBACK_S 3600u
#define GC_APP_CTRL_PAYLOAD_MAX 512u
#define GC_APP_CMD_BODY_MAX 64u
#define GC_APP_SIGNED_PAYLOAD_MAX (4u + GC_APP_CMD_BODY_MAX)
#define GC_APP_KEY_HEX_MAX ((GC_KEY_LEN * 2u) + 1u)

typedef struct {
    gc_config_t cfg;
    gc_identity_t id;
    gc_key_t no_key;

    char topic_up_tele[GC_TOPIC_MAX];
    char topic_up_event[GC_TOPIC_MAX];
    char topic_up_verify[GC_TOPIC_MAX];
    char topic_up_hello[GC_TOPIC_MAX];
    char topic_up_ota[GC_TOPIC_MAX];
    char topic_dn_verdict[GC_TOPIC_MAX];
    char topic_dn_unblock[GC_TOPIC_MAX];
    char topic_dn_ack[GC_TOPIC_MAX];
    char topic_dn_cmd[GC_TOPIC_MAX];

    uint32_t last_tick_s;
    uint32_t tick_count;
    uint32_t boot_s;
    bool clock_synced;
    int64_t clock_offset_s;

    uint64_t last_uplink_up;
    uint64_t last_uplink_down;
    uint64_t reading_uplink_baseline;
    uint64_t quota_total_kb_baseline;

    uint32_t last_telemetry_s;
    uint32_t last_heartbeat_s;
    uint32_t last_beacon_s;
    uint32_t last_reading_s;
    uint32_t last_modem_poll_s;
    uint32_t last_manifest_s;
    uint32_t last_quota_persist_s;
    uint32_t last_gate_persist_s;
    uint32_t last_ladder_action_s;
    uint32_t relay_release_s;

    gc_reading_t last_sent_reading;
    bool have_last_sent_reading;

    gc_modem_status_t modem;
    bool modem_poll_due;

    bool pending_active;
    uint32_t pending_published_s;
    gc_req_id_t pending_req;
    gc_mac_t pending_mac;
    gc_key_t pending_number_key;
    gc_key_t pending_mac_key;

    bool controller_unreachable;
    bool heartbeat_acked;
    uint32_t last_command_sequence;

    bool alarm_active;
    bool alarm_pending;
    uint32_t alarm_episode;
    bool reserve_paused;

    gc_escalation_step_t last_ladder_step;

    bool selftest_started;
    gc_app_phase_t phase;
    bool started;
} gc_app_state_t;

static gc_app_state_t app;

static uint8_t gc_app_psk[GC_PSK_LEN];
static bool gc_app_psk_ready;

static uint32_t gc_app_now_s(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

static void gc_app_sync_clock(uint32_t server_time_s)
{
    if (server_time_s == 0u) {
        return;
    }
    app.clock_offset_s = (int64_t)server_time_s - (int64_t)gc_app_uptime_s();
    app.clock_synced = true;
}

static uint32_t gc_app_controller_deadline_s(uint32_t unix_deadline_s)
{
    int64_t local_s;

    if (unix_deadline_s == 0u || !app.clock_synced) {
        return 0u;
    }
    local_s = (int64_t)unix_deadline_s - app.clock_offset_s;
    if (local_s <= 0 || local_s > (int64_t)UINT32_MAX) {
        return 0u;
    }
    return (uint32_t)local_s;
}

static uint64_t gc_app_quota_total_kb(void)
{
    return gc_quota_daily_used_kb() + gc_quota_month_used_kb();
}

static gc_app_state_t *gc_app_ctx(void)
{
    return &app;
}

static bool gc_app_tier_suppresses_events(void)
{
    return gc_quota_tier() == GC_QUOTA_TIER_HEARTBEAT;
}

static void gc_app_emit_event(const char *event,
                              const gc_key_t *number_key,
                              const gc_key_t *mac_key,
                              uint32_t strikes,
                              const char *detail)
{
    char payload[GC_APP_CTRL_PAYLOAD_MAX];

    if (gc_app_tier_suppresses_events()) {
        return;
    }
    if (gc_ctrl_encode_event(&app.id,
                             event,
                             number_key != NULL ? number_key : &app.no_key,
                             mac_key != NULL ? mac_key : &app.no_key,
                             strikes,
                             detail,
                             payload,
                             sizeof(payload)) != GC_OK) {
        return;
    }
    app.id.seq++;
    gc_mqtt_publish(app.topic_up_event, payload, strlen(payload), 0);
}

static void gc_app_account_uplink_bytes(void)
{
    uint64_t up = gc_nat_uplink_bytes_up();
    uint64_t down = gc_nat_uplink_bytes_down();
    uint64_t delta_up = up >= app.last_uplink_up ? up - app.last_uplink_up : up;
    uint64_t delta_down = down >= app.last_uplink_down ? down - app.last_uplink_down : down;
    uint64_t delta = delta_up + delta_down;

    app.last_uplink_up = up;
    app.last_uplink_down = down;

    if (delta > 0) {
        gc_quota_account_bytes(delta);
    }
}

static void gc_app_drop_strike_added_by_outage(const gc_mac_t *mac, uint32_t strikes_before)
{
    gc_client_t *client = gc_gate_find(mac);

    if (client != NULL && client->strikes > strikes_before) {
        client->strikes = strikes_before;
    }
}

static void gc_app_resolve_pending_as_controller_outage(const gc_req_id_t *req,
                                                        const gc_mac_t *mac,
                                                        const gc_key_t *number_key,
                                                        const gc_key_t *mac_key)
{
    gc_client_t *before = gc_gate_find(mac);
    uint32_t strikes_before = before != NULL ? before->strikes : 0;

    gc_gate_pending_resolve(req, false, 0, 0, GC_DENY_CONTROLLER_UNREACHABLE);
    gc_app_drop_strike_added_by_outage(mac, strikes_before);
    app.pending_active = false;
    app.controller_unreachable = true;

    gc_app_emit_event("verify_timeout",
                      number_key,
                      mac_key,
                      strikes_before,
                      gc_deny_reason_name(GC_DENY_CONTROLLER_UNREACHABLE));
}

static void gc_app_publish_verify_request(uint32_t now_s)
{
    char payload[GC_APP_CTRL_PAYLOAD_MAX];

    if (gc_ctrl_encode_verify_request(&app.id,
                                      &app.pending_req,
                                      &app.pending_number_key,
                                      &app.pending_mac_key,
                                      app.cfg.verify_mode,
                                      payload,
                                      sizeof(payload)) != GC_OK) {
        return;
    }
    app.id.seq++;
    if (gc_mqtt_publish(app.topic_up_verify, payload, strlen(payload), 1) == GC_OK) {
        app.pending_published_s = now_s;
    }
}

static void gc_app_service_verification(uint32_t now_s)
{
    gc_req_id_t req;
    gc_key_t number_key;
    gc_key_t mac_key;
    gc_mac_t mac;
    uint32_t age_s = 0;
    uint32_t timeout_s = app.cfg.verification_timeout_ms / 1000u;
    uint32_t republish_s;

    if (gc_gate_pending_peek(&req, &number_key, &mac_key, &mac, &age_s) != GC_OK) {
        app.pending_active = false;
        return;
    }
    if (timeout_s == 0) {
        timeout_s = GC_APP_VERIFY_TIMEOUT_FALLBACK_S;
    }
    republish_s = timeout_s / 2u;
    if (republish_s == 0) {
        republish_s = 1u;
    }
    if (!app.pending_active || memcmp(&req, &app.pending_req, sizeof(req)) != 0) {
        app.pending_req = req;
        app.pending_mac = mac;
        app.pending_number_key = number_key;
        app.pending_mac_key = mac_key;
        app.pending_active = true;
        app.pending_published_s = 0;
    }
    if (age_s >= timeout_s) {
        gc_app_resolve_pending_as_controller_outage(&req, &mac, &number_key, &mac_key);
        return;
    }
    if (app.pending_published_s == 0 || now_s - app.pending_published_s >= republish_s) {
        gc_app_publish_verify_request(now_s);
    }
}

static void gc_app_apply_verdict(const gc_verdict_t *verdict)
{
    gc_key_t number_key = app.pending_number_key;
    gc_key_t mac_key = app.pending_mac_key;
    gc_mac_t mac = app.pending_mac;
    bool mapped = app.pending_active &&
                  memcmp(&verdict->req_id, &app.pending_req, sizeof(verdict->req_id)) == 0;
    uint32_t allowed_until_s = gc_app_controller_deadline_s(verdict->allowed_until_s);
    uint32_t blocked_until_s = gc_app_controller_deadline_s(verdict->blocked_until_s);

    if (mapped) {
        gc_gate_apply_verdict(&mac,
                              &number_key,
                              verdict->allow,
                              allowed_until_s,
                              verdict->reason);
        gc_gate_pending_resolve(&verdict->req_id,
                                verdict->allow,
                                allowed_until_s,
                                blocked_until_s,
                                verdict->reason);
        if (!verdict->allow && blocked_until_s > 0u) {
            uint32_t up_s = gc_app_uptime_s();
            gc_gate_soft_block(&mac, blocked_until_s > up_s ? blocked_until_s - up_s : 0u);
        }
        if (verdict->permanent) {
            gc_gate_permanent_block(&number_key, &mac_key);
        }
        app.pending_active = false;
        app.controller_unreachable = false;
    } else {
        GC_LOGW("app", "verdict for unknown request ignored");
        return;
    }

    gc_app_emit_event(verdict->allow ? "verdict_allow" : "verdict_deny",
                      &number_key,
                      &mac_key,
                      verdict->strikes,
                      gc_deny_reason_name(verdict->reason));
}

static void gc_app_hex_write(const uint8_t *bytes, size_t len, char *out, size_t out_len)
{
    static const char gc_app_hex_digits[] = "0123456789abcdef";

    if (out == NULL || out_len < (len * 2u) + 1u) {
        return;
    }
    for (size_t i = 0; i < len; i++) {
        out[i * 2u] = gc_app_hex_digits[(bytes[i] >> 4) & 0x0fu];
        out[(i * 2u) + 1u] = gc_app_hex_digits[bytes[i] & 0x0fu];
    }
    out[len * 2u] = '\0';
}

static void gc_app_name_lower(const char *name, char *out, size_t out_len)
{
    if (out_len == 0u) {
        return;
    }
    for (size_t i = 0; i + 1u < out_len; i++) {
        char c = name[i];

        if (c >= 'A' && c <= 'Z') {
            c = (char)(c + ('a' - 'A'));
        }
        out[i] = c;
        if (c == '\0') {
            return;
        }
    }
    out[out_len - 1u] = '\0';
}

static size_t gc_app_command_body(const gc_command_t *cmd, char *out, size_t out_len)
{
    char name[GC_CMD_NAME_MAX + 1u];
    int written;

    if (out == NULL || out_len == 0u) {
        return 0;
    }
    gc_app_name_lower(cmd->name, name, sizeof(name));
    written = snprintf(out, out_len, "%s::%" PRIu32 ":%s",
                       name, cmd->uint_arg, cmd->bool_arg ? "1" : "0");
    if (written < 0 || (size_t)written >= out_len) {
        out[0] = '\0';
        return 0;
    }
    return (size_t)written;
}

static size_t gc_app_unblock_body(const gc_unblock_t *unblock, char *out, size_t out_len)
{
    char number_hex[GC_APP_KEY_HEX_MAX];
    int written;

    if (out == NULL || out_len == 0u) {
        return 0;
    }
    gc_app_hex_write(unblock->number_key.b, GC_KEY_LEN, number_hex, sizeof(number_hex));
    written = snprintf(out, out_len, "unblock:%s:%s:0",
                       number_hex, unblock->clear_strikes ? "1" : "0");
    if (written < 0 || (size_t)written >= out_len) {
        out[0] = '\0';
        return 0;
    }
    return (size_t)written;
}

static bool gc_app_sequence_ahead(uint32_t sequence, uint32_t last)
{
    return sequence != last && (int32_t)(sequence - last) > 0;
}

static bool gc_app_command_authorized(uint32_t sequence,
                                      const char *body,
                                      const uint8_t mac[GC_KEY_LEN])
{
    uint8_t payload[GC_APP_SIGNED_PAYLOAD_MAX];
    uint8_t expected[GC_KEY_LEN];
    size_t body_len;

    if (!gc_app_psk_ready || body == NULL || mac == NULL) {
        return false;
    }
    body_len = strlen(body);
    if (body_len == 0u || body_len > GC_APP_CMD_BODY_MAX) {
        return false;
    }
    payload[0] = (uint8_t)(sequence >> 24);
    payload[1] = (uint8_t)(sequence >> 16);
    payload[2] = (uint8_t)(sequence >> 8);
    payload[3] = (uint8_t)sequence;
    memcpy(&payload[4], body, body_len);
    if (gc_crypto_command_mac(gc_app_psk, payload, 4u + body_len, expected) != GC_OK) {
        return false;
    }
    return gc_crypto_constant_time_equal(expected, mac, GC_KEY_LEN);
}

static bool gc_app_accept_sequence(uint32_t sequence)
{
    if (gc_crypto_command_sequence_store(sequence) != GC_OK) {
        GC_LOGW("app", "sequence %" PRIu32 " not persisted, command refused", sequence);
        return false;
    }
    app.last_command_sequence = sequence;
    return true;
}

static void gc_app_dispatch_command(const gc_command_t *cmd)
{
    char body[GC_APP_CMD_BODY_MAX + 1u];

    if (gc_app_command_body(cmd, body, sizeof(body)) == 0) {
        GC_LOGW("app", "command body malformed");
        return;
    }
    if (!gc_app_sequence_ahead(cmd->sequence, app.last_command_sequence)) {
        GC_LOGW("app", "command %s sequence %" PRIu32 " not ahead of %" PRIu32,
                cmd->name, cmd->sequence, app.last_command_sequence);
        return;
    }
    if (!gc_app_command_authorized(cmd->sequence, body, cmd->mac)) {
        GC_LOGW("app", "command %s rejected, signature mismatch", cmd->name);
        return;
    }
    if (!gc_app_accept_sequence(cmd->sequence)) {
        return;
    }

    if (strcmp(cmd->name, "tunnel_up") == 0) {
        gc_app_request_tunnel(cmd->bool_arg);
    } else if (strcmp(cmd->name, "manifest_check") == 0) {
        gc_ota_check_now();
    } else if (strcmp(cmd->name, "unblock_all") == 0) {
        gc_gate_unblock_all();
    } else if (strcmp(cmd->name, "reset_counters") == 0) {
        gc_nat_reset_counters();
    } else if (strcmp(cmd->name, "trip_reserve") == 0) {
        gc_app_trip_reserve_for_bench();
    } else {
        GC_LOGW("app", "unhandled command %s", cmd->name);
    }
}

static void gc_app_apply_unblock(const gc_unblock_t *unblock)
{
    char body[GC_APP_CMD_BODY_MAX + 1u];

    if (gc_app_unblock_body(unblock, body, sizeof(body)) == 0) {
        GC_LOGW("app", "unblock body malformed");
        return;
    }
    if (!gc_app_sequence_ahead(unblock->sequence, app.last_command_sequence)) {
        GC_LOGW("app", "unblock sequence %" PRIu32 " not ahead of %" PRIu32,
                unblock->sequence, app.last_command_sequence);
        return;
    }
    if (!gc_app_command_authorized(unblock->sequence, body, unblock->mac)) {
        GC_LOGW("app", "unblock rejected, signature mismatch");
        return;
    }
    if (!gc_app_accept_sequence(unblock->sequence)) {
        return;
    }
    gc_gate_unblock(&unblock->number_key);
}

static void gc_app_on_ctrl_message(const char *topic,
                                   const char *payload,
                                   size_t len,
                                   void *ctx)
{
    gc_ctrl_msg_t msg;

    (void)ctx;
    if (gc_ctrl_decode(topic, payload, len, &msg) != GC_OK) {
        return;
    }
    switch (msg.kind) {
    case GC_CTRL_MSG_VERDICT:
        gc_app_apply_verdict(&msg.as.verdict);
        break;
    case GC_CTRL_MSG_UNBLOCK:
        gc_app_apply_unblock(&msg.as.unblock);
        break;
    case GC_CTRL_MSG_ACK:
        gc_app_sync_clock(msg.as.ack.server_time_s);
        app.heartbeat_acked = msg.as.ack.heartbeat_seen;
        app.controller_unreachable = false;
        break;
    case GC_CTRL_MSG_COMMAND:
        gc_app_dispatch_command(&msg.as.command);
        break;
    default:
        break;
    }
}

static uint8_t gc_app_telemetry_flags(void)
{
    uint8_t flags = 0;

    if (app.alarm_active) {
        flags |= GC_TELEMETRY_FLAG_ALARM;
    }
    if (gc_quota_reserve_tripped()) {
        flags |= GC_TELEMETRY_FLAG_RESERVE_TRIPPED;
    }
    if (gc_nat_forwarding_paused()) {
        flags |= GC_TELEMETRY_FLAG_FORWARDING_PAUSED;
    }
    if (gc_emergency_tunnel_is_up()) {
        flags |= GC_TELEMETRY_FLAG_TUNNEL_UP;
    }
    if (gc_ota_trial_pending()) {
        flags |= GC_TELEMETRY_FLAG_TRIAL_PENDING;
    }
    if (app.controller_unreachable) {
        flags |= GC_TELEMETRY_FLAG_CONTROLLER_UNREACHABLE;
    }
    return flags;
}

static void gc_app_service_reading(uint32_t now_s)
{
    gc_reading_t reading;
    uint64_t uplink_total = gc_nat_uplink_bytes();

    reading.rssi = (int8_t)gc_wifi_uplink_rssi();
    reading.rsrp = app.modem.rsrp;
    reading.rsrq = app.modem.rsrq;
    reading.sinr = app.modem.sinr;
    reading.clients = (uint8_t)gc_gate_client_count();
    reading.quota_delta_kb = (uplink_total - app.reading_uplink_baseline) / GC_QUOTA_KB;
    reading.uptime_delta_s = now_s - app.last_reading_s;

    if (app.have_last_sent_reading &&
        !gc_telemetry_deadband_passes(&reading, &app.last_sent_reading)) {
        return;
    }
    if (gc_telemetry_push(&reading) != GC_OK) {
        return;
    }
    app.last_sent_reading = reading;
    app.have_last_sent_reading = true;
    app.reading_uplink_baseline = uplink_total;
    app.last_reading_s = now_s;
}

static void gc_app_service_telemetry(uint32_t now_s)
{
    uint8_t frame[GC_TELEMETRY_FRAME_MAX];
    size_t written = 0;
    uint32_t period = gc_quota_batch_period_s();
    bool alarm = app.alarm_pending;

    if (period == 0) {
        period = app.cfg.telemetry_batch_period_s;
    }
    if (!alarm) {
        if (gc_telemetry_pending() == 0) {
            return;
        }
        if (now_s - app.last_telemetry_s < period) {
            return;
        }
    }
    if (gc_telemetry_encode(gc_app_telemetry_flags(),
                            &app.id,
                            app.cfg.fw_version,
                            gc_ota_running_slot(),
                            frame,
                            sizeof(frame),
                            &written) != GC_OK) {
        return;
    }
    app.id.seq++;
    if (alarm) {
        if (gc_mqtt_publish_alarm(app.topic_up_tele, frame, written) != GC_OK) {
            return;
        }
        gc_emergency_beacon_send(true);
        app.last_beacon_s = now_s;
    } else {
        if (gc_mqtt_publish(app.topic_up_tele, frame, written, 0) != GC_OK) {
            return;
        }
    }
    app.last_telemetry_s = now_s;
    app.alarm_pending = false;
}

static void gc_app_service_heartbeat(uint32_t now_s)
{
    uint8_t frame[GC_TELEMETRY_FRAME_MAX];
    size_t written = 0;
    gc_quota_tier_t tier = gc_quota_tier();
    uint32_t period = gc_quota_telemetry_keepalive_s();

    if (tier != GC_QUOTA_TIER_HEARTBEAT && tier != GC_QUOTA_TIER_RESERVE) {
        return;
    }
    if (period == 0) {
        period = app.cfg.mqtt_keepalive_s;
    }
    if (period == 0) {
        period = GC_APP_HEARTBEAT_FALLBACK_S;
    }
    if (now_s - app.last_heartbeat_s < period) {
        return;
    }
    if (gc_telemetry_encode_heartbeat(gc_app_telemetry_flags(),
                                      &app.id,
                                      app.cfg.fw_version,
                                      gc_ota_running_slot(),
                                      frame,
                                      sizeof(frame),
                                      &written) != GC_OK) {
        return;
    }
    app.id.seq++;
    if (gc_mqtt_publish(app.topic_up_tele, frame, written, 0) != GC_OK) {
        return;
    }
    app.last_heartbeat_s = now_s;
}

static void gc_app_service_alarm(void)
{
    uint32_t episode = gc_link_monitor_fault_episode();
    bool alarm_step = gc_link_monitor_step() == GC_ESCALATION_ALARM_ONLY;

    app.alarm_active = alarm_step;
    if (!alarm_step) {
        return;
    }
    if (episode != app.alarm_episode) {
        app.alarm_episode = episode;
        app.alarm_pending = true;
    }
}

static void gc_app_service_beacon(uint32_t now_s)
{
    if (now_s - app.last_beacon_s < GC_BEACON_INTERVAL_S) {
        return;
    }
    if (gc_emergency_beacon_send(false) == GC_OK) {
        app.last_beacon_s = now_s;
    }
}

static void gc_app_service_modem_poll(uint32_t now_s)
{
    uint32_t period = app.cfg.modem_poll_period_s;
    gc_modem_status_t status;

    if (!app.modem_poll_due && (period == 0 || now_s - app.last_modem_poll_s < period)) {
        return;
    }
    if (gc_modem_api_poll(&status) == GC_OK) {
        app.modem = status;
    }
    app.modem_poll_due = false;
    app.last_modem_poll_s = now_s;
}

static void gc_app_service_reserve(void)
{
    if (!gc_quota_reserve_tripped()) {
        if (app.reserve_paused) {
            gc_nat_set_forwarding_paused(false);
            app.reserve_paused = false;
        }
        return;
    }
    if (!app.reserve_paused) {
        gc_nat_set_forwarding_paused(true);
        app.reserve_paused = true;
        gc_app_emit_event("reserve_tripped",
                          &app.no_key,
                          &app.no_key,
                          0,
                          gc_quota_tier_name(gc_quota_tier()));
    }
}

static void gc_app_service_relay(uint32_t now_s)
{
    if (app.relay_release_s == 0 || now_s < app.relay_release_s) {
        return;
    }
    gpio_set_level(GC_PIN_RELAY_GPIO, GC_RELAY_ACTIVE_LEVEL == 1 ? 0 : 1);
    app.relay_release_s = 0;
}

static void gc_app_pulse_relay(uint32_t now_s)
{
    if (!gc_pinmap_relay_allowed(GC_PIN_RELAY_GPIO)) {
        GC_LOGE("app", "relay gpio %d not allowed", GC_PIN_RELAY_GPIO);
        return;
    }
    if (gc_pinmap_owner(GC_PIN_RELAY_GPIO) == NULL) {
        gc_pinmap_claim(GC_PIN_RELAY_GPIO, "app-modem-cycle");
    }
    gpio_set_level(GC_PIN_RELAY_GPIO, GC_RELAY_ACTIVE_LEVEL);
    app.relay_release_s = now_s + GC_APP_RELAY_PULSE_S;
}

static void gc_app_retry_link(uint32_t now_s)
{
    (void)now_s;
    if (!gc_wifi_uplink_connected()) {
        gc_wifi_uplink_reset_backoff();
        gc_netif_sta_start();
        gc_wifi_uplink_start(app.cfg.sta_ssid, app.cfg.sta_passphrase);
    }
    if (!gc_mqtt_connected()) {
        gc_mqtt_restart();
    }
}

static void gc_app_reresolve_dns(void)
{
    gc_mqtt_restart();
    gc_netif_sta_stop();
    gc_netif_sta_start();
}

static void gc_app_run_escalation_ladder(uint32_t now_s)
{
    gc_escalation_step_t step = gc_link_monitor_step();
    bool step_changed = step != app.last_ladder_step;
    bool granted = false;

    if (step != GC_ESCALATION_NONE && !step_changed &&
        now_s - app.last_ladder_action_s < GC_APP_LADDER_ACTION_INTERVAL_S) {
        return;
    }
    app.last_ladder_step = step;
    app.last_ladder_action_s = now_s;

    switch (step) {
    case GC_ESCALATION_RETRY_LINK:
        gc_app_retry_link(now_s);
        break;
    case GC_ESCALATION_RERESOLVE_DNS:
        gc_app_reresolve_dns();
        break;
    case GC_ESCALATION_MODEM_API_REBOOT:
        if (gc_link_monitor_claim_modem_api_reboot(now_s, &granted) == GC_OK && granted) {
            gc_modem_api_reboot();
            gc_app_emit_event("modem_api_reboot",
                              &app.no_key,
                              &app.no_key,
                              0,
                              gc_escalation_step_name(step));
        }
        break;
    case GC_ESCALATION_MODEM_POWER_CYCLE:
        if (gc_link_monitor_claim_modem_power_cycle(now_s, &granted) == GC_OK && granted) {
            gc_app_pulse_relay(now_s);
            gc_app_emit_event("modem_power_cycle",
                              &app.no_key,
                              &app.no_key,
                              0,
                              gc_escalation_step_name(step));
        }
        break;
    case GC_ESCALATION_ALARM_ONLY:
        break;
    default:
        return;
    }
}

static void gc_app_report_link_state(void)
{
    gc_link_monitor_report_internet(gc_netif_sta_has_ip() && gc_wifi_uplink_connected());
    gc_link_monitor_report_mqtt(gc_mqtt_connected());
}

static void gc_app_service_manifest(uint32_t now_s)
{
    uint32_t period = app.cfg.manifest_check_period_s;

    if (period == 0) {
        period = GC_APP_MANIFEST_CHECK_FALLBACK_S;
    }
    if (now_s - app.last_manifest_s < period) {
        return;
    }
    app.last_manifest_s = now_s;
    gc_ota_check_now();
}

static void gc_app_service_persist(uint32_t now_s)
{
    if (now_s - app.last_gate_persist_s >= GC_APP_GATE_PERSIST_PERIOD_S) {
        if (gc_gate_persist() == GC_OK) {
            app.last_gate_persist_s = now_s;
        }
    }
    if (now_s - app.last_quota_persist_s >= GC_APP_QUOTA_PERSIST_PERIOD_S) {
        if (gc_quota_persist() == GC_OK) {
            app.last_quota_persist_s = now_s;
        }
    }
}

static void gc_app_report_selftest_criteria(void)
{
    esp_netif_ip_info_t ap_ip;
    bool loopback_passed = false;

    if (gc_portal_loopback_probe(&loopback_passed) != GC_OK) {
        loopback_passed = false;
    }
    gc_selftest_report(GC_SELFTEST_CRITERION_AP_UP,
                       gc_netif_ap() != NULL && gc_netif_ap_ipv4(&ap_ip) == GC_OK);
    gc_selftest_report(GC_SELFTEST_CRITERION_STA_IP, gc_netif_sta_has_ip());
    gc_selftest_report(GC_SELFTEST_CRITERION_MODEM_SIGNAL, app.modem.valid);
    gc_selftest_report(GC_SELFTEST_CRITERION_CONTROLLER_REACHABLE,
                       gc_mqtt_connected() || gc_emergency_tunnel_is_up());
    gc_selftest_report(GC_SELFTEST_CRITERION_HEARTBEAT_ACKED, app.heartbeat_acked);
    gc_selftest_report(GC_SELFTEST_CRITERION_PORTAL_LOOPBACK, loopback_passed);
    gc_selftest_report(GC_SELFTEST_CRITERION_QUOTA_INCREMENTED,
                       gc_app_quota_total_kb() > app.quota_total_kb_baseline);
}

static void gc_app_service_trial_boot(uint32_t now_s)
{
    gc_selftest_result_t result;

    if (!gc_ota_trial_pending()) {
        app.selftest_started = false;
        return;
    }
    if (!app.selftest_started) {
        gc_selftest_start(app.cfg.selftest_deadline_s);
        app.selftest_started = true;
        app.quota_total_kb_baseline = gc_app_quota_total_kb();
    }
    gc_selftest_tick(now_s);
    gc_app_report_selftest_criteria();

    result = gc_selftest_result();
    if (result == GC_SELFTEST_PASSED) {
        gc_ota_mark_valid();
        app.selftest_started = false;
        return;
    }
    if (result == GC_SELFTEST_FAILED ||
        gc_selftest_elapsed_s() >= app.cfg.selftest_deadline_s) {
        GC_LOGE("app", "trial boot failed on %s", gc_selftest_failed_criterion());
        gc_ota_mark_invalid_and_reboot();
    }
}

static bool gc_app_check_heap(void *ctx)
{
    (void)ctx;
    return esp_get_free_heap_size() >= GC_APP_HEAP_FLOOR_BYTES;
}

static bool gc_app_check_gate_table(void *ctx)
{
    size_t clients = gc_gate_client_count();

    (void)ctx;
    return clients <= GC_MAX_CLIENTS && gc_gate_allowed_count() <= clients;
}

static bool gc_app_check_uplink_task_alive(void *ctx)
{
    gc_app_state_t *state = (gc_app_state_t *)ctx;

    return state != NULL && (gc_app_now_s() - state->last_tick_s) <= GC_APP_TICK_STALL_MAX_S;
}

static bool gc_app_check_quota_persisted(void *ctx)
{
    gc_app_state_t *state = (gc_app_state_t *)ctx;
    uint32_t now_s = gc_app_now_s();

    if (state == NULL || state->last_quota_persist_s == 0) {
        return false;
    }
    return now_s - state->last_quota_persist_s <= GC_APP_QUOTA_PERSIST_MAX_AGE_S;
}

static bool gc_app_notice_pending_visitor(const gc_client_t *client, void *ctx)
{
    bool *pending = (bool *)ctx;

    if (client != NULL && !client->notice_served) {
        *pending = true;
    }
    return true;
}

static bool gc_app_notice_pending(void)
{
    bool pending = false;

    gc_gate_foreach(gc_app_notice_pending_visitor, &pending);

    return pending;
}

static void gc_app_register_watchdog_checks(void)
{
    gc_watchdog_register("heap", gc_app_check_heap, NULL);
    gc_watchdog_register("gate", gc_app_check_gate_table, NULL);
    gc_watchdog_register("uplink", gc_app_check_uplink_task_alive, gc_app_ctx());
    gc_watchdog_register("quota", gc_app_check_quota_persisted, gc_app_ctx());
}

static void gc_app_update_phase(void)
{
    if (gc_ota_trial_pending()) {
        app.phase = GC_APP_PHASE_TRIAL_BOOT;
    } else if (gc_quota_reserve_tripped()) {
        app.phase = GC_APP_PHASE_DEGRADED;
    } else if (gc_mqtt_connected()) {
        app.phase = GC_APP_PHASE_ONLINE;
    } else if (gc_wifi_uplink_connected() || gc_netif_sta_has_ip()) {
        app.phase = GC_APP_PHASE_NO_UPLINK;
    } else if (gc_netif_ap() != NULL) {
        app.phase = GC_APP_PHASE_PORTAL_ONLY;
    } else {
        app.phase = GC_APP_PHASE_BOOT;
    }
}

gc_err_t gc_app_init(void)
{
    memset(&app, 0, sizeof(app));
    app.phase = GC_APP_PHASE_BOOT;
    app.modem_poll_due = true;
    app.last_ladder_step = GC_ESCALATION_NONE;

    gc_config_defaults(&app.cfg);
    if (gc_config_load(&app.cfg) != GC_OK) {
        GC_LOGW("app", "config load failed, running on defaults");
    }
    app.id.site_id = app.cfg.site_id;
    app.id.device_id = app.cfg.device_id;
    app.id.boot_id = 0;
    app.id.seq = 0;

    if (gc_crypto_load_psk(gc_app_psk) != GC_OK) {
        gc_app_psk_ready = false;
        GC_LOGW("app", "psk unavailable, every signed command will be refused");
    } else {
        gc_app_psk_ready = true;
    }
    if (gc_crypto_command_sequence_load(&app.last_command_sequence) != GC_OK) {
        app.last_command_sequence = 0;
        GC_LOGW("app", "command sequence unreadable, starting at 0");
    }

    gc_ctrl_topics_for_identity(app.id.site_id,
                                app.id.device_id,
                                app.topic_up_tele,
                                sizeof(app.topic_up_tele),
                                app.topic_up_event,
                                sizeof(app.topic_up_event),
                                app.topic_up_verify,
                                sizeof(app.topic_up_verify),
                                app.topic_up_hello,
                                sizeof(app.topic_up_hello),
                                app.topic_up_ota,
                                sizeof(app.topic_up_ota),
                                app.topic_dn_verdict,
                                sizeof(app.topic_dn_verdict),
                                app.topic_dn_unblock,
                                sizeof(app.topic_dn_unblock),
                                app.topic_dn_ack,
                                sizeof(app.topic_dn_ack),
                                app.topic_dn_cmd,
                                sizeof(app.topic_dn_cmd));

    if (gc_mqtt_init(gc_app_on_ctrl_message, NULL) != GC_OK) {
        GC_LOGE("app", "mqtt init failed");
    }
    gpio_reset_pin(GC_PIN_RELAY_GPIO);
    gpio_set_direction(GC_PIN_RELAY_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(GC_PIN_RELAY_GPIO, GC_RELAY_ACTIVE_LEVEL == 1 ? 0 : 1);

    return GC_OK;
}

gc_err_t gc_app_start(void)
{
    char payload[GC_APP_CTRL_PAYLOAD_MAX];

    app.boot_s = gc_app_now_s();
    app.last_telemetry_s = app.boot_s;
    app.last_heartbeat_s = app.boot_s;
    app.last_beacon_s = app.boot_s;
    app.last_reading_s = app.boot_s;
    app.last_modem_poll_s = app.boot_s;
    app.last_manifest_s = app.boot_s;
    app.last_quota_persist_s = app.boot_s;
    app.last_gate_persist_s = app.boot_s;
    app.last_ladder_action_s = app.boot_s;
    app.reading_uplink_baseline = gc_nat_uplink_bytes();
    app.last_uplink_up = gc_nat_uplink_bytes_up();
    app.last_uplink_down = gc_nat_uplink_bytes_down();
    app.quota_total_kb_baseline = gc_app_quota_total_kb();

    gc_mqtt_subscribe(app.topic_dn_verdict, 1);
    gc_mqtt_subscribe(app.topic_dn_unblock, 1);
    gc_mqtt_subscribe(app.topic_dn_ack, 1);
    gc_mqtt_subscribe(app.topic_dn_cmd, 1);

    gc_app_register_watchdog_checks();

    if (gc_ctrl_encode_hello(&app.id,
                             app.cfg.fw_version,
                             gc_ota_running_slot(),
                             gc_ota_trial_pending(),
                             gc_app_notice_pending(),
                             payload,
                             sizeof(payload)) == GC_OK) {
        app.id.seq++;
        gc_mqtt_publish(app.topic_up_hello, payload, strlen(payload), 1);
    }
    app.started = true;

    return GC_OK;
}

void gc_app_tick_once(uint32_t now_s)
{
    app.last_tick_s = now_s;
    app.tick_count++;

    gc_app_account_uplink_bytes();
    gc_gate_tick(now_s);
    gc_quota_tick(now_s);
    gc_emergency_tick(now_s);
    gc_emergency_poll_reply();
    gc_ota_tick(now_s);

    gc_app_report_link_state();
    gc_link_monitor_tick(now_s);
    gc_app_run_escalation_ladder(now_s);
    gc_app_service_alarm();

    gc_app_service_verification(now_s);
    gc_app_service_reserve();
    gc_app_service_modem_poll(now_s);
    gc_app_service_reading(now_s);
    gc_app_service_telemetry(now_s);
    gc_app_service_heartbeat(now_s);
    gc_app_service_beacon(now_s);
    gc_app_service_manifest(now_s);
    gc_app_service_persist(now_s);
    gc_app_service_relay(now_s);
    gc_app_service_trial_boot(now_s);

    gc_watchdog_tick();
    gc_app_update_phase();
}

gc_app_phase_t gc_app_phase(void)
{
    return app.phase;
}

const char *gc_app_phase_name(gc_app_phase_t phase)
{
    switch (phase) {
    case GC_APP_PHASE_BOOT:
        return "BOOT";
    case GC_APP_PHASE_NO_UPLINK:
        return "NO_UPLINK";
    case GC_APP_PHASE_PORTAL_ONLY:
        return "PORTAL_ONLY";
    case GC_APP_PHASE_ONLINE:
        return "ONLINE";
    case GC_APP_PHASE_TRIAL_BOOT:
        return "TRIAL_BOOT";
    case GC_APP_PHASE_DEGRADED:
        return "DEGRADED";
    default:
        return "UNKNOWN";
    }
}

gc_err_t gc_app_status(char *out, size_t len)
{
    if (out == NULL || len == 0) {
        return GC_ERR_INVALID_ARG;
    }
    snprintf(out,
             len,
             "phase=%s up=%" PRIu32 "s clients=%u/%u allowed=%u quota=%" PRIu64 "/%" PRIu64
             "kb tier=%s mqtt=%d sta=%d inet=%d tun=%d alarm=%d trial=%d wd=%" PRIu32 "/%" PRIu32
             " fw=%u slot=%d boot=%u",
             gc_app_phase_name(app.phase),
             gc_app_uptime_s(),
             (unsigned)gc_gate_client_count(),
             (unsigned)GC_MAX_CLIENTS,
             (unsigned)gc_gate_allowed_count(),
             gc_quota_daily_used_kb(),
             gc_quota_daily_budget_kb(),
             gc_quota_tier_name(gc_quota_tier()),
             gc_mqtt_connected() ? 1 : 0,
             gc_wifi_uplink_connected() ? 1 : 0,
             gc_link_monitor_internet_up() ? 1 : 0,
             gc_emergency_tunnel_is_up() ? 1 : 0,
             app.alarm_active ? 1 : 0,
             gc_ota_trial_pending() ? 1 : 0,
             gc_watchdog_kick_count(),
             gc_watchdog_stall_count(),
             (unsigned)app.cfg.fw_version,
             (int)gc_ota_running_slot(),
             (unsigned)app.id.boot_id);

    return GC_OK;
}

gc_err_t gc_app_request_tunnel(bool up)
{
    gc_err_t err = up ? gc_emergency_tunnel_up() : gc_emergency_tunnel_down();

    gc_app_emit_event(up ? "tunnel_up" : "tunnel_down",
                      &app.no_key,
                      &app.no_key,
                      0,
                      gc_err_name(err));

    return err;
}

gc_err_t gc_app_force_manifest_check(void)
{
    return gc_ota_check_now();
}

gc_err_t gc_app_trip_reserve_for_bench(void)
{
    uint64_t reserve_bytes = (uint64_t)gc_quota_month_reserve_kb() * GC_QUOTA_KB;
    gc_err_t err = gc_quota_account_bytes(reserve_bytes > 0 ? reserve_bytes : GC_QUOTA_KB);

    gc_quota_tick(gc_app_uptime_s());
    if (gc_quota_reserve_tripped()) {
        gc_nat_set_forwarding_paused(true);
        app.reserve_paused = true;
    }
    gc_app_emit_event("bench_reserve_trip", &app.no_key, &app.no_key, 0, gc_err_name(err));

    return err;
}

void gc_app_set_boot_id(uint16_t boot_id)
{
    app.id.boot_id = boot_id;
}

uint32_t gc_app_uptime_s(void)
{
    return gc_app_now_s() - app.boot_s;
}
