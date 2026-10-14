#include "gc_ctrl_proto.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "gc_log.h"

#define GC_CTRL_TAG "gc_ctrl"

#define GC_CTRL_HEX_BUF_MAX (((GC_KEY_LEN > GC_REQ_ID_LEN) ? GC_KEY_LEN : GC_REQ_ID_LEN) * 2u + 1u)
#define GC_CTRL_REASON_BUF_MAX (GC_VERDICT_REASON_MAX + 1u)
#define GC_CTRL_TOPIC_PREFIX "gc/v1"

static const char gc_ctrl_direction_up[] = "up";
static const char gc_ctrl_direction_dn[] = "dn";

static const char gc_ctrl_channel_tele[] = "tele";
static const char gc_ctrl_channel_event[] = "event";
static const char gc_ctrl_channel_verify[] = "verify";
static const char gc_ctrl_channel_hello[] = "hello";
static const char gc_ctrl_channel_ota[] = "ota";
static const char gc_ctrl_channel_verdict[] = "verdict";
static const char gc_ctrl_channel_unblock[] = "unblock";
static const char gc_ctrl_channel_ack[] = "ack";
static const char gc_ctrl_channel_cmd[] = "cmd";

static const char gc_ctrl_mode_contact[] = "contact";
static const char gc_ctrl_mode_challenge[] = "challenge";

static const char gc_ctrl_slot_factory[] = "factory";
static const char gc_ctrl_slot_ota_0[] = "ota_0";
static const char gc_ctrl_slot_ota_1[] = "ota_1";

static void gc_ctrl_hex_write(const uint8_t *bytes, size_t len, char *out, size_t out_len)
{
    static const char gc_ctrl_hex_digits[] = "0123456789abcdef";

    if (out == NULL || out_len < (len * 2u) + 1u) {
        return;
    }
    for (size_t i = 0; i < len; i++) {
        out[(i * 2u)] = gc_ctrl_hex_digits[(bytes[i] >> 4) & 0x0fu];
        out[(i * 2u) + 1u] = gc_ctrl_hex_digits[bytes[i] & 0x0fu];
    }
    out[len * 2u] = '\0';
}

static int gc_ctrl_hex_digit(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return (c - 'a') + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return (c - 'A') + 10;
    }
    return -1;
}

static bool gc_ctrl_hex_read(const char *hex, uint8_t *out, size_t out_len)
{
    if (hex == NULL || out == NULL) {
        return false;
    }
    if (strlen(hex) != out_len * 2u) {
        return false;
    }
    for (size_t i = 0; i < out_len; i++) {
        int high = gc_ctrl_hex_digit(hex[i * 2u]);
        int low = gc_ctrl_hex_digit(hex[(i * 2u) + 1u]);
        if (high < 0 || low < 0) {
            return false;
        }
        out[i] = (uint8_t)((high << 4) | low);
    }
    return true;
}

static gc_err_t gc_ctrl_emit(cJSON *root, char *out, size_t out_len)
{
    if (root == NULL) {
        return GC_ERR_NO_MEM;
    }
    if (out == NULL || out_len == 0u) {
        cJSON_Delete(root);
        return GC_ERR_INVALID_ARG;
    }

    size_t limit = (out_len > (size_t)INT_MAX) ? (size_t)INT_MAX : out_len;
    cJSON_bool printed = cJSON_PrintPreallocated(root, out, (int)limit, false);
    cJSON_Delete(root);

    out[out_len - 1u] = '\0';
    if (!printed) {
        out[0] = '\0';
        return GC_ERR_FULL;
    }
    return GC_OK;
}

static bool gc_ctrl_read_bool(cJSON *root, const char *key, bool *out)
{
    cJSON *item = cJSON_GetObjectItem(root, key);

    if (item == NULL) {
        *out = false;
        return true;
    }
    if (cJSON_IsBool(item)) {
        *out = cJSON_IsTrue(item);
        return true;
    }
    if (cJSON_IsNumber(item)) {
        *out = (item->valuedouble != 0.0);
        return true;
    }
    return false;
}

static bool gc_ctrl_read_u32(cJSON *root, const char *key, uint32_t *out)
{
    cJSON *item = cJSON_GetObjectItem(root, key);

    if (item == NULL) {
        *out = 0u;
        return true;
    }
    if (!cJSON_IsNumber(item)) {
        return false;
    }
    if (item->valuedouble < 0.0 || item->valuedouble > 4294967295.0) {
        return false;
    }
    *out = (uint32_t)item->valuedouble;
    return true;
}

static bool gc_ctrl_read_text(cJSON *root, const char *key, char *out, size_t out_len)
{
    cJSON *item = cJSON_GetObjectItem(root, key);

    if (item == NULL) {
        out[0] = '\0';
        return true;
    }
    if (!cJSON_IsString(item) || item->valuestring == NULL) {
        return false;
    }
    size_t len = strlen(item->valuestring);
    if (len >= out_len) {
        len = out_len - 1u;
    }
    memcpy(out, item->valuestring, len);
    out[len] = '\0';
    return true;
}

static gc_deny_reason_t gc_ctrl_reason_from_text(const char *text)
{
    if (strcmp(text, "not_verified") == 0) {
        return GC_DENY_NOT_VERIFIED;
    }
    if (strcmp(text, "strike_limit") == 0) {
        return GC_DENY_STRIKE_LIMIT;
    }
    if (strcmp(text, "controller_unreachable") == 0) {
        return GC_DENY_CONTROLLER_UNREACHABLE;
    }
    if (strcmp(text, "quota_reserve") == 0) {
        return GC_DENY_QUOTA_RESERVE;
    }
    if (strcmp(text, "expired") == 0) {
        return GC_DENY_EXPIRED;
    }
    if (strcmp(text, "pending") == 0) {
        return GC_DENY_PENDING;
    }
    return GC_DENY_NONE;
}

void gc_ctrl_topic_build(char *out,
                         size_t out_len,
                         const char *direction,
                         const char *channel,
                         uint16_t site_id,
                         uint16_t device_id)
{
    if (out == NULL || out_len == 0u) {
        return;
    }
    if (direction == NULL || channel == NULL) {
        out[0] = '\0';
        return;
    }

    int written = snprintf(out, out_len, "%s/%u/%u/%s/%s",
                           GC_CTRL_TOPIC_PREFIX,
                           (unsigned)site_id,
                           (unsigned)device_id,
                           direction,
                           channel);
    if (written < 0 || (size_t)written >= out_len) {
        out[out_len - 1u] = '\0';
        GC_LOGW(GC_CTRL_TAG, "topic truncated to %u bytes", (unsigned)out_len);
    }
}

void gc_ctrl_topics_for_identity(uint16_t site_id,
                                 uint16_t device_id,
                                 char *up_tele,
                                 size_t up_tele_len,
                                 char *up_event,
                                 size_t up_event_len,
                                 char *up_verify,
                                 size_t up_verify_len,
                                 char *up_hello,
                                 size_t up_hello_len,
                                 char *up_ota,
                                 size_t up_ota_len,
                                 char *dn_verdict,
                                 size_t dn_verdict_len,
                                 char *dn_unblock,
                                 size_t dn_unblock_len,
                                 char *dn_ack,
                                 size_t dn_ack_len,
                                 char *dn_cmd,
                                 size_t dn_cmd_len)
{
    gc_ctrl_topic_build(up_tele, up_tele_len, gc_ctrl_direction_up, gc_ctrl_channel_tele, site_id, device_id);
    gc_ctrl_topic_build(up_event, up_event_len, gc_ctrl_direction_up, gc_ctrl_channel_event, site_id, device_id);
    gc_ctrl_topic_build(up_verify, up_verify_len, gc_ctrl_direction_up, gc_ctrl_channel_verify, site_id, device_id);
    gc_ctrl_topic_build(up_hello, up_hello_len, gc_ctrl_direction_up, gc_ctrl_channel_hello, site_id, device_id);
    gc_ctrl_topic_build(up_ota, up_ota_len, gc_ctrl_direction_up, gc_ctrl_channel_ota, site_id, device_id);
    gc_ctrl_topic_build(dn_verdict, dn_verdict_len, gc_ctrl_direction_dn, gc_ctrl_channel_verdict, site_id, device_id);
    gc_ctrl_topic_build(dn_unblock, dn_unblock_len, gc_ctrl_direction_dn, gc_ctrl_channel_unblock, site_id, device_id);
    gc_ctrl_topic_build(dn_ack, dn_ack_len, gc_ctrl_direction_dn, gc_ctrl_channel_ack, site_id, device_id);
    gc_ctrl_topic_build(dn_cmd, dn_cmd_len, gc_ctrl_direction_dn, gc_ctrl_channel_cmd, site_id, device_id);
}

const char *gc_ctrl_channel_for_topic(const char *topic)
{
    if (topic == NULL) {
        return NULL;
    }
    const char *last = strrchr(topic, '/');
    if (last == NULL || last[1] == '\0') {
        return NULL;
    }
    return last + 1;
}

gc_err_t gc_ctrl_encode_verify_request(const gc_identity_t *id,
                                       const gc_req_id_t *req,
                                       const gc_key_t *number_key,
                                       const gc_key_t *mac_key,
                                       gc_verify_mode_t mode,
                                       char *out,
                                       size_t out_len)
{
    if (id == NULL || req == NULL || number_key == NULL || mac_key == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    if (out == NULL || out_len == 0u) {
        return GC_ERR_INVALID_ARG;
    }

    char req_hex[GC_CTRL_HEX_BUF_MAX];
    char num_hex[GC_CTRL_HEX_BUF_MAX];
    char mac_hex[GC_CTRL_HEX_BUF_MAX];

    gc_ctrl_hex_write(req->b, GC_REQ_ID_LEN, req_hex, sizeof(req_hex));
    gc_ctrl_hex_write(number_key->b, GC_KEY_LEN, num_hex, sizeof(num_hex));
    gc_ctrl_hex_write(mac_key->b, GC_KEY_LEN, mac_hex, sizeof(mac_hex));

    const char *mode_text = (mode == GC_VERIFY_MODE_CHALLENGE) ? gc_ctrl_mode_challenge : gc_ctrl_mode_contact;

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return GC_ERR_NO_MEM;
    }

    bool ok = true;
    ok = ok && (cJSON_AddNumberToObject(root, "v", (double)GC_FRAME_VERSION) != NULL);
    ok = ok && (cJSON_AddStringToObject(root, "req", req_hex) != NULL);
    ok = ok && (cJSON_AddStringToObject(root, "num", num_hex) != NULL);
    ok = ok && (cJSON_AddStringToObject(root, "mac", mac_hex) != NULL);
    ok = ok && (cJSON_AddStringToObject(root, "mode", mode_text) != NULL);
    ok = ok && (cJSON_AddNumberToObject(root, "ts", (double)time(NULL)) != NULL);

    if (!ok) {
        cJSON_Delete(root);
        return GC_ERR_NO_MEM;
    }
    return gc_ctrl_emit(root, out, out_len);
}

gc_err_t gc_ctrl_encode_event(const gc_identity_t *id,
                              const char *event,
                              const gc_key_t *number_key,
                              const gc_key_t *mac_key,
                              uint32_t strikes,
                              const char *detail,
                              char *out,
                              size_t out_len)
{
    if (id == NULL || event == NULL || number_key == NULL || mac_key == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    if (out == NULL || out_len == 0u) {
        return GC_ERR_INVALID_ARG;
    }

    char num_hex[GC_CTRL_HEX_BUF_MAX];
    char mac_hex[GC_CTRL_HEX_BUF_MAX];

    gc_ctrl_hex_write(number_key->b, GC_KEY_LEN, num_hex, sizeof(num_hex));
    gc_ctrl_hex_write(mac_key->b, GC_KEY_LEN, mac_hex, sizeof(mac_hex));

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return GC_ERR_NO_MEM;
    }

    bool ok = true;
    ok = ok && (cJSON_AddNumberToObject(root, "v", (double)GC_FRAME_VERSION) != NULL);
    ok = ok && (cJSON_AddStringToObject(root, "ev", event) != NULL);
    ok = ok && (cJSON_AddStringToObject(root, "num", num_hex) != NULL);
    ok = ok && (cJSON_AddStringToObject(root, "mac", mac_hex) != NULL);
    ok = ok && (cJSON_AddNumberToObject(root, "strikes", (double)strikes) != NULL);
    ok = ok && (cJSON_AddStringToObject(root, "detail", (detail != NULL) ? detail : "") != NULL);

    if (!ok) {
        cJSON_Delete(root);
        return GC_ERR_NO_MEM;
    }
    return gc_ctrl_emit(root, out, out_len);
}

gc_err_t gc_ctrl_encode_hello(const gc_identity_t *id,
                              uint8_t fw_version,
                              gc_slot_t slot,
                              bool trial_pending,
                              bool notice_pending,
                              char *out,
                              size_t out_len)
{
    if (id == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    if (out == NULL || out_len == 0u) {
        return GC_ERR_INVALID_ARG;
    }

    const char *slot_text;
    switch (slot) {
    case GC_SLOT_FACTORY:
        slot_text = gc_ctrl_slot_factory;
        break;
    case GC_SLOT_OTA_0:
        slot_text = gc_ctrl_slot_ota_0;
        break;
    case GC_SLOT_OTA_1:
        slot_text = gc_ctrl_slot_ota_1;
        break;
    default:
        return GC_ERR_INVALID_ARG;
    }

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return GC_ERR_NO_MEM;
    }

    bool ok = true;
    ok = ok && (cJSON_AddNumberToObject(root, "v", (double)GC_FRAME_VERSION) != NULL);
    ok = ok && (cJSON_AddNumberToObject(root, "fw", (double)fw_version) != NULL);
    ok = ok && (cJSON_AddStringToObject(root, "slot", slot_text) != NULL);
    ok = ok && (cJSON_AddBoolToObject(root, "trial", trial_pending) != NULL);
    ok = ok && (cJSON_AddBoolToObject(root, "notice", notice_pending) != NULL);

    if (!ok) {
        cJSON_Delete(root);
        return GC_ERR_NO_MEM;
    }
    return gc_ctrl_emit(root, out, out_len);
}

static gc_err_t gc_ctrl_decode_verdict(cJSON *root, gc_verdict_t *out)
{
    cJSON *req = cJSON_GetObjectItem(root, "req");
    if (!cJSON_IsString(req) || !gc_ctrl_hex_read(req->valuestring, out->req_id.b, GC_REQ_ID_LEN)) {
        return GC_ERR_INVALID_ARG;
    }

    char reason[GC_CTRL_REASON_BUF_MAX];
    if (!gc_ctrl_read_bool(root, "allow", &out->allow) ||
        !gc_ctrl_read_u32(root, "until", &out->allowed_until_s) ||
        !gc_ctrl_read_u32(root, "blocked_until", &out->blocked_until_s) ||
        !gc_ctrl_read_u32(root, "strikes", &out->strikes) ||
        !gc_ctrl_read_bool(root, "permanent", &out->permanent) ||
        !gc_ctrl_read_text(root, "reason", reason, sizeof(reason)) ||
        !gc_ctrl_read_text(root, "hint", out->challenge_hint, sizeof(out->challenge_hint))) {
        return GC_ERR_INVALID_ARG;
    }

    out->reason = gc_ctrl_reason_from_text(reason);
    return GC_OK;
}

static gc_err_t gc_ctrl_decode_unblock(cJSON *root, gc_unblock_t *out)
{
    cJSON *num = cJSON_GetObjectItem(root, "num");
    cJSON *mac = cJSON_GetObjectItem(root, "mac");
    cJSON *sig = cJSON_GetObjectItem(root, "sig");

    if (!cJSON_IsString(num) || !gc_ctrl_hex_read(num->valuestring, out->number_key.b, GC_KEY_LEN)) {
        return GC_ERR_INVALID_ARG;
    }
    if (!cJSON_IsString(mac) || !gc_ctrl_hex_read(mac->valuestring, out->mac_key.b, GC_KEY_LEN)) {
        return GC_ERR_INVALID_ARG;
    }
    if (!cJSON_IsString(sig) || !gc_ctrl_hex_read(sig->valuestring, out->mac, GC_KEY_LEN)) {
        return GC_ERR_INVALID_ARG;
    }
    if (!gc_ctrl_read_u32(root, "seq", &out->sequence) ||
        !gc_ctrl_read_bool(root, "clear_strikes", &out->clear_strikes)) {
        return GC_ERR_INVALID_ARG;
    }
    return GC_OK;
}

static gc_err_t gc_ctrl_decode_ack(cJSON *root, gc_ack_t *out)
{
    if (!gc_ctrl_read_u32(root, "seq", &out->sequence) ||
        !gc_ctrl_read_u32(root, "time", &out->server_time_s)) {
        return GC_ERR_INVALID_ARG;
    }
    out->heartbeat_seen = true;
    return GC_OK;
}

static gc_err_t gc_ctrl_decode_command(cJSON *root, gc_command_t *out)
{
    cJSON *sig = cJSON_GetObjectItem(root, "sig");

    if (!gc_ctrl_read_text(root, "cmd", out->name, sizeof(out->name)) || out->name[0] == '\0') {
        return GC_ERR_INVALID_ARG;
    }
    if (!cJSON_IsString(sig) || !gc_ctrl_hex_read(sig->valuestring, out->mac, GC_KEY_LEN)) {
        return GC_ERR_INVALID_ARG;
    }
    if (!gc_ctrl_read_u32(root, "seq", &out->sequence) ||
        !gc_ctrl_read_u32(root, "arg", &out->uint_arg) ||
        !gc_ctrl_read_bool(root, "flag", &out->bool_arg)) {
        return GC_ERR_INVALID_ARG;
    }
    return GC_OK;
}

gc_err_t gc_ctrl_decode(const char *topic,
                        const char *json,
                        size_t json_len,
                        gc_ctrl_msg_t *out)
{
    if (topic == NULL || json == NULL || json_len == 0u || out == NULL) {
        return GC_ERR_INVALID_ARG;
    }

    memset(out, 0, sizeof(*out));

    const char *channel = gc_ctrl_channel_for_topic(topic);
    if (channel == NULL) {
        return GC_ERR_INVALID_ARG;
    }

    gc_ctrl_msg_kind_t kind;
    if (strcmp(channel, gc_ctrl_channel_verdict) == 0) {
        kind = GC_CTRL_MSG_VERDICT;
    } else if (strcmp(channel, gc_ctrl_channel_unblock) == 0) {
        kind = GC_CTRL_MSG_UNBLOCK;
    } else if (strcmp(channel, gc_ctrl_channel_ack) == 0) {
        kind = GC_CTRL_MSG_ACK;
    } else if (strcmp(channel, gc_ctrl_channel_cmd) == 0) {
        kind = GC_CTRL_MSG_COMMAND;
    } else {
        GC_LOGW(GC_CTRL_TAG, "topic channel %s is not a control channel", channel);
        return GC_ERR_UNSUPPORTED;
    }

    cJSON *root = cJSON_ParseWithLength(json, json_len);
    if (root == NULL) {
        GC_LOGW(GC_CTRL_TAG, "malformed json on %s", topic);
        return GC_ERR_INVALID_ARG;
    }

    gc_err_t err;
    switch (kind) {
    case GC_CTRL_MSG_VERDICT:
        err = gc_ctrl_decode_verdict(root, &out->as.verdict);
        break;
    case GC_CTRL_MSG_UNBLOCK:
        err = gc_ctrl_decode_unblock(root, &out->as.unblock);
        break;
    case GC_CTRL_MSG_ACK:
        err = gc_ctrl_decode_ack(root, &out->as.ack);
        break;
    default:
        err = gc_ctrl_decode_command(root, &out->as.command);
        break;
    }
    cJSON_Delete(root);

    if (err != GC_OK) {
        memset(out, 0, sizeof(*out));
        GC_LOGW(GC_CTRL_TAG, "rejected %s message on %s", gc_ctrl_kind_name(kind), topic);
        return err;
    }

    out->kind = kind;
    return GC_OK;
}

const char *gc_ctrl_kind_name(gc_ctrl_msg_kind_t kind)
{
    switch (kind) {
    case GC_CTRL_MSG_VERDICT:
        return gc_ctrl_channel_verdict;
    case GC_CTRL_MSG_UNBLOCK:
        return gc_ctrl_channel_unblock;
    case GC_CTRL_MSG_ACK:
        return gc_ctrl_channel_ack;
    case GC_CTRL_MSG_COMMAND:
        return "command";
    default:
        return "unknown";
    }
}
