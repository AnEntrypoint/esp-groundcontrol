#include "gc_config.h"

#include <stdio.h>
#include <string.h>

#include "gc_log.h"
#include "gc_nvs.h"
#include "sdkconfig.h"

#define GC_CONFIG_TAG "config"

#define GC_CONFIG_KEY_SITE_ID "site"
#define GC_CONFIG_KEY_DEVICE_ID "dev"
#define GC_CONFIG_KEY_AP_SSID "apssid"
#define GC_CONFIG_KEY_AP_PASSPHRASE "appass"
#define GC_CONFIG_KEY_STA_SSID "stassid"
#define GC_CONFIG_KEY_STA_PASSPHRASE "stapass"
#define GC_CONFIG_KEY_MODEM_IP "mdmip"
#define GC_CONFIG_KEY_MODEM_USER "mdmusr"
#define GC_CONFIG_KEY_MODEM_PASS "mdmpass"
#define GC_CONFIG_KEY_BROKER_URL "brkurl"
#define GC_CONFIG_KEY_BROKER_USER "brkusr"
#define GC_CONFIG_KEY_BROKER_PASS "brkpass"
#define GC_CONFIG_KEY_MANIFEST_URL "manurl"
#define GC_CONFIG_KEY_BEACON_HOST "bcnhost"
#define GC_CONFIG_KEY_BEACON_PORT "bcnport"
#define GC_CONFIG_KEY_NOTICE "notice"
#define GC_CONFIG_KEY_VERIFY_MODE "vmode"
#define GC_CONFIG_KEY_VERIFY_TIMEOUT "vto"
#define GC_CONFIG_KEY_ALLOW_GRACE "grace"
#define GC_CONFIG_KEY_SOFT_BLOCK "sftblk"
#define GC_CONFIG_KEY_STRIKE_LIMIT "strike"
#define GC_CONFIG_KEY_DAILY_BUDGET "dbudget"
#define GC_CONFIG_KEY_MONTHLY_RESERVE "mrsrv"
#define GC_CONFIG_KEY_CLIENT_RATE "crate"
#define GC_CONFIG_KEY_TELEMETRY_BATCH "tbatch"
#define GC_CONFIG_KEY_MQTT_KEEPALIVE "kalive"
#define GC_CONFIG_KEY_MODEM_POLL "mdpoll"
#define GC_CONFIG_KEY_MANIFEST_PERIOD "manper"
#define GC_CONFIG_KEY_SELFTEST_DEADLINE "selfdl"
#define GC_CONFIG_KEY_MODEM_API_REBOOT "mdmrbt"
#define GC_CONFIG_KEY_MODEM_POWER_CYCLE "mdmpwr"
#define GC_CONFIG_KEY_OTA_WINDOW_START "otaws"
#define GC_CONFIG_KEY_OTA_WINDOW_END "otawe"
#define GC_CONFIG_KEY_OTA_MIN_RSRP "otarsrp"
#define GC_CONFIG_KEY_FW_VERSION "fwver"

#define GC_CONFIG_DEFAULT_NOTICE \
    "This network is public and shared. To connect you must enter your phone " \
    "number. The number is used only to check whether it has sent a message to " \
    "the WhatsApp bot for this network, and it is stored hashed, never in the " \
    "clear. Traffic is metered and may be paused when the data budget runs low. " \
    "A number that has not contacted the bot is blocked for 24 hours, and is " \
    "blocked permanently after three strikes."

typedef struct {
    const char *key;
    char *out;
    size_t size;
    const char *fallback;
} gc_config_str_field_t;

typedef struct {
    const char *key;
    const char *value;
} gc_config_str_value_t;

typedef struct {
    const char *key;
    uint32_t *out;
    uint32_t fallback;
} gc_config_u32_field_t;

typedef struct {
    const char *key;
    uint32_t value;
} gc_config_u32_value_t;

static void gc_config_copy_string(char *dst, size_t dst_size, const char *src)
{
    if (dst == NULL || dst_size == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    if (dst == src) {
        return;
    }
    snprintf(dst, dst_size, "%s", src);
}

static void gc_config_load_strings(const gc_config_str_field_t *fields, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        size_t len = fields[i].size;
        if (gc_nvs_get_str(fields[i].key, fields[i].out, &len) == GC_OK) {
            fields[i].out[fields[i].size - 1] = '\0';
            continue;
        }
        gc_config_copy_string(fields[i].out, fields[i].size, fields[i].fallback);
    }
}

static gc_err_t gc_config_save_strings(const gc_config_str_value_t *fields, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        gc_err_t err = gc_nvs_set_str(fields[i].key, fields[i].value == NULL ? "" : fields[i].value);
        if (err != GC_OK) {
            return err;
        }
    }
    return GC_OK;
}

static void gc_config_load_u32s(const gc_config_u32_field_t *fields, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        uint32_t value = 0;
        if (gc_nvs_get_u32(fields[i].key, &value) == GC_OK) {
            *fields[i].out = value;
            continue;
        }
        *fields[i].out = fields[i].fallback;
    }
}

static gc_err_t gc_config_save_u32s(const gc_config_u32_value_t *fields, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        gc_err_t err = gc_nvs_set_u32(fields[i].key, fields[i].value);
        if (err != GC_OK) {
            return err;
        }
    }
    return GC_OK;
}

static void gc_config_load_u16(const char *key, uint16_t *out, uint16_t fallback)
{
    uint32_t value = fallback;
    gc_config_load_u32s(&(gc_config_u32_field_t){key, &value, fallback}, 1);
    *out = (uint16_t)(value > 0xFFFFu ? 0xFFFFu : value);
}

static void gc_config_load_i8(const char *key, int8_t *out, int8_t fallback)
{
    uint32_t raw = (uint32_t)(int32_t)fallback;
    uint32_t value = raw;
    gc_config_load_u32s(&(gc_config_u32_field_t){key, &value, raw}, 1);
    int32_t signed_value = (int32_t)value;
    if (signed_value > 127) {
        signed_value = 127;
    }
    if (signed_value < -128) {
        signed_value = -128;
    }
    *out = (int8_t)signed_value;
}

void gc_config_defaults(gc_config_t *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));

    out->site_id = (uint16_t)CONFIG_GC_SITE_ID;
    out->device_id = (uint16_t)CONFIG_GC_DEVICE_ID;
    out->beacon_port = (uint16_t)CONFIG_GC_BEACON_PORT;
    out->ota_window_start_minute = 0;
    out->ota_window_end_minute = 1440;
    out->ota_min_rsrp = -110;
    out->fw_version = (uint8_t)CONFIG_GC_FW_VERSION;

    gc_config_copy_string(out->ap_ssid, sizeof(out->ap_ssid), CONFIG_GC_AP_SSID);
    gc_config_copy_string(out->ap_passphrase, sizeof(out->ap_passphrase), CONFIG_GC_AP_PASSPHRASE);
    gc_config_copy_string(out->sta_ssid, sizeof(out->sta_ssid), CONFIG_GC_STA_SSID);
    gc_config_copy_string(out->sta_passphrase, sizeof(out->sta_passphrase), CONFIG_GC_STA_PASSPHRASE);
    gc_config_copy_string(out->modem_ip, sizeof(out->modem_ip), "192.168.8.1");
    gc_config_copy_string(out->modem_user, sizeof(out->modem_user), "admin");
    gc_config_copy_string(out->broker_url, sizeof(out->broker_url), CONFIG_GC_BROKER_URI);
    gc_config_copy_string(out->manifest_url, sizeof(out->manifest_url), CONFIG_GC_MANIFEST_URL);
    gc_config_copy_string(out->beacon_host, sizeof(out->beacon_host), CONFIG_GC_BEACON_HOST);
    gc_config_copy_string(out->notice, sizeof(out->notice), GC_CONFIG_DEFAULT_NOTICE);

#ifdef CONFIG_GC_VERIFY_MODE_CHALLENGE
    out->verify_mode = GC_VERIFY_MODE_CHALLENGE;
#else
    out->verify_mode = GC_VERIFY_MODE_CONTACT;
#endif

    out->verification_timeout_ms = 15000;
    out->allow_grace_s = (uint32_t)CONFIG_GC_ALLOW_GRACE_S;
    out->soft_block_s = (uint32_t)CONFIG_GC_SOFT_BLOCK_S;
    out->strike_limit = (uint32_t)CONFIG_GC_STRIKE_LIMIT;
    out->daily_budget_kb = (uint32_t)CONFIG_GC_DAILY_BUDGET_KB;
    out->monthly_reserve_kb = (uint32_t)CONFIG_GC_MONTHLY_RESERVE_KB;
    out->client_rate_kbyte_s = (uint32_t)CONFIG_GC_CLIENT_RATE_KBYTE_S;
    out->telemetry_batch_period_s = (uint32_t)CONFIG_GC_TELEMETRY_BATCH_S;
    out->mqtt_keepalive_s = (uint32_t)CONFIG_GC_MQTT_KEEPALIVE_S;
    out->modem_poll_period_s = (uint32_t)CONFIG_GC_MODEM_POLL_S;
    out->manifest_check_period_s = 21600;
    out->selftest_deadline_s = (uint32_t)CONFIG_GC_SELFTEST_DEADLINE_S;
    out->modem_api_reboot_min_interval_s = 21600;
    out->modem_power_cycle_min_interval_s = 86400;
}

static void gc_config_read(gc_config_t *out)
{
    gc_config_t cfg;
    gc_config_defaults(&cfg);

    const gc_config_str_field_t strings[] = {
        {GC_CONFIG_KEY_AP_SSID, cfg.ap_ssid, sizeof(cfg.ap_ssid), cfg.ap_ssid},
        {GC_CONFIG_KEY_AP_PASSPHRASE, cfg.ap_passphrase, sizeof(cfg.ap_passphrase), cfg.ap_passphrase},
        {GC_CONFIG_KEY_STA_SSID, cfg.sta_ssid, sizeof(cfg.sta_ssid), cfg.sta_ssid},
        {GC_CONFIG_KEY_STA_PASSPHRASE, cfg.sta_passphrase, sizeof(cfg.sta_passphrase), cfg.sta_passphrase},
        {GC_CONFIG_KEY_MODEM_IP, cfg.modem_ip, sizeof(cfg.modem_ip), cfg.modem_ip},
        {GC_CONFIG_KEY_MODEM_USER, cfg.modem_user, sizeof(cfg.modem_user), cfg.modem_user},
        {GC_CONFIG_KEY_MODEM_PASS, cfg.modem_pass, sizeof(cfg.modem_pass), cfg.modem_pass},
        {GC_CONFIG_KEY_BROKER_URL, cfg.broker_url, sizeof(cfg.broker_url), cfg.broker_url},
        {GC_CONFIG_KEY_BROKER_USER, cfg.broker_user, sizeof(cfg.broker_user), cfg.broker_user},
        {GC_CONFIG_KEY_BROKER_PASS, cfg.broker_pass, sizeof(cfg.broker_pass), cfg.broker_pass},
        {GC_CONFIG_KEY_MANIFEST_URL, cfg.manifest_url, sizeof(cfg.manifest_url), cfg.manifest_url},
        {GC_CONFIG_KEY_BEACON_HOST, cfg.beacon_host, sizeof(cfg.beacon_host), cfg.beacon_host},
        {GC_CONFIG_KEY_NOTICE, cfg.notice, sizeof(cfg.notice), cfg.notice},
    };
    gc_config_load_strings(strings, sizeof(strings) / sizeof(strings[0]));

    uint32_t verify_mode = (uint32_t)cfg.verify_mode;
    uint32_t fw_version = cfg.fw_version;

    const gc_config_u32_field_t values[] = {
        {GC_CONFIG_KEY_VERIFY_MODE, &verify_mode, verify_mode},
        {GC_CONFIG_KEY_VERIFY_TIMEOUT, &cfg.verification_timeout_ms, cfg.verification_timeout_ms},
        {GC_CONFIG_KEY_ALLOW_GRACE, &cfg.allow_grace_s, cfg.allow_grace_s},
        {GC_CONFIG_KEY_SOFT_BLOCK, &cfg.soft_block_s, cfg.soft_block_s},
        {GC_CONFIG_KEY_STRIKE_LIMIT, &cfg.strike_limit, cfg.strike_limit},
        {GC_CONFIG_KEY_DAILY_BUDGET, &cfg.daily_budget_kb, cfg.daily_budget_kb},
        {GC_CONFIG_KEY_MONTHLY_RESERVE, &cfg.monthly_reserve_kb, cfg.monthly_reserve_kb},
        {GC_CONFIG_KEY_CLIENT_RATE, &cfg.client_rate_kbyte_s, cfg.client_rate_kbyte_s},
        {GC_CONFIG_KEY_TELEMETRY_BATCH, &cfg.telemetry_batch_period_s, cfg.telemetry_batch_period_s},
        {GC_CONFIG_KEY_MQTT_KEEPALIVE, &cfg.mqtt_keepalive_s, cfg.mqtt_keepalive_s},
        {GC_CONFIG_KEY_MODEM_POLL, &cfg.modem_poll_period_s, cfg.modem_poll_period_s},
        {GC_CONFIG_KEY_MANIFEST_PERIOD, &cfg.manifest_check_period_s, cfg.manifest_check_period_s},
        {GC_CONFIG_KEY_SELFTEST_DEADLINE, &cfg.selftest_deadline_s, cfg.selftest_deadline_s},
        {GC_CONFIG_KEY_MODEM_API_REBOOT, &cfg.modem_api_reboot_min_interval_s, cfg.modem_api_reboot_min_interval_s},
        {GC_CONFIG_KEY_MODEM_POWER_CYCLE, &cfg.modem_power_cycle_min_interval_s, cfg.modem_power_cycle_min_interval_s},
    };
    gc_config_load_u32s(values, sizeof(values) / sizeof(values[0]));

    gc_config_load_u16(GC_CONFIG_KEY_SITE_ID, &cfg.site_id, cfg.site_id);
    gc_config_load_u16(GC_CONFIG_KEY_DEVICE_ID, &cfg.device_id, cfg.device_id);
    gc_config_load_u16(GC_CONFIG_KEY_BEACON_PORT, &cfg.beacon_port, cfg.beacon_port);
    gc_config_load_u16(GC_CONFIG_KEY_OTA_WINDOW_START, &cfg.ota_window_start_minute,
                       cfg.ota_window_start_minute);
    gc_config_load_u16(GC_CONFIG_KEY_OTA_WINDOW_END, &cfg.ota_window_end_minute,
                       cfg.ota_window_end_minute);
    gc_config_load_i8(GC_CONFIG_KEY_OTA_MIN_RSRP, &cfg.ota_min_rsrp, cfg.ota_min_rsrp);

    cfg.verify_mode = (verify_mode == (uint32_t)GC_VERIFY_MODE_CHALLENGE)
                          ? GC_VERIFY_MODE_CHALLENGE
                          : GC_VERIFY_MODE_CONTACT;

    gc_config_load_u32s(&(gc_config_u32_field_t){GC_CONFIG_KEY_FW_VERSION, &fw_version, fw_version}, 1);
    cfg.fw_version = (uint8_t)(fw_version > 0xFFu ? 0xFFu : fw_version);
    *out = cfg;
}

gc_err_t gc_config_load(gc_config_t *out)
{
    if (out == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    gc_config_t cfg;
    gc_config_read(&cfg);

    const char *failed_field = NULL;
    if (!gc_config_validate(&cfg, &failed_field)) {
        GC_LOGE(GC_CONFIG_TAG, "rejected, field %s",
                failed_field == NULL ? "unknown" : failed_field);
        return GC_ERR_INVALID_ARG;
    }
    *out = cfg;
    return GC_OK;
}

gc_err_t gc_config_save(const gc_config_t *cfg)
{
    if (cfg == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    const gc_config_str_value_t strings[] = {
        {GC_CONFIG_KEY_AP_SSID, cfg->ap_ssid},
        {GC_CONFIG_KEY_AP_PASSPHRASE, cfg->ap_passphrase},
        {GC_CONFIG_KEY_STA_SSID, cfg->sta_ssid},
        {GC_CONFIG_KEY_STA_PASSPHRASE, cfg->sta_passphrase},
        {GC_CONFIG_KEY_MODEM_IP, cfg->modem_ip},
        {GC_CONFIG_KEY_MODEM_USER, cfg->modem_user},
        {GC_CONFIG_KEY_MODEM_PASS, cfg->modem_pass},
        {GC_CONFIG_KEY_BROKER_URL, cfg->broker_url},
        {GC_CONFIG_KEY_BROKER_USER, cfg->broker_user},
        {GC_CONFIG_KEY_BROKER_PASS, cfg->broker_pass},
        {GC_CONFIG_KEY_MANIFEST_URL, cfg->manifest_url},
        {GC_CONFIG_KEY_BEACON_HOST, cfg->beacon_host},
        {GC_CONFIG_KEY_NOTICE, cfg->notice},
    };
    gc_err_t err = gc_config_save_strings(strings, sizeof(strings) / sizeof(strings[0]));
    if (err != GC_OK) {
        return err;
    }

    const gc_config_u32_value_t values[] = {
        {GC_CONFIG_KEY_VERIFY_MODE, (uint32_t)cfg->verify_mode},
        {GC_CONFIG_KEY_VERIFY_TIMEOUT, cfg->verification_timeout_ms},
        {GC_CONFIG_KEY_ALLOW_GRACE, cfg->allow_grace_s},
        {GC_CONFIG_KEY_SOFT_BLOCK, cfg->soft_block_s},
        {GC_CONFIG_KEY_STRIKE_LIMIT, cfg->strike_limit},
        {GC_CONFIG_KEY_DAILY_BUDGET, cfg->daily_budget_kb},
        {GC_CONFIG_KEY_MONTHLY_RESERVE, cfg->monthly_reserve_kb},
        {GC_CONFIG_KEY_CLIENT_RATE, cfg->client_rate_kbyte_s},
        {GC_CONFIG_KEY_TELEMETRY_BATCH, cfg->telemetry_batch_period_s},
        {GC_CONFIG_KEY_MQTT_KEEPALIVE, cfg->mqtt_keepalive_s},
        {GC_CONFIG_KEY_MODEM_POLL, cfg->modem_poll_period_s},
        {GC_CONFIG_KEY_MANIFEST_PERIOD, cfg->manifest_check_period_s},
        {GC_CONFIG_KEY_SELFTEST_DEADLINE, cfg->selftest_deadline_s},
        {GC_CONFIG_KEY_MODEM_API_REBOOT, cfg->modem_api_reboot_min_interval_s},
        {GC_CONFIG_KEY_MODEM_POWER_CYCLE, cfg->modem_power_cycle_min_interval_s},
        {GC_CONFIG_KEY_SITE_ID, cfg->site_id},
        {GC_CONFIG_KEY_DEVICE_ID, cfg->device_id},
        {GC_CONFIG_KEY_BEACON_PORT, cfg->beacon_port},
        {GC_CONFIG_KEY_OTA_WINDOW_START, cfg->ota_window_start_minute},
        {GC_CONFIG_KEY_OTA_WINDOW_END, cfg->ota_window_end_minute},
        {GC_CONFIG_KEY_OTA_MIN_RSRP, (uint32_t)(int32_t)cfg->ota_min_rsrp},
        {GC_CONFIG_KEY_FW_VERSION, cfg->fw_version},
    };
    err = gc_config_save_u32s(values, sizeof(values) / sizeof(values[0]));
    if (err != GC_OK) {
        return err;
    }
    return gc_nvs_commit();
}

gc_err_t gc_config_set_site(uint16_t site_id, uint16_t device_id)
{
    gc_config_t cfg;
    gc_config_read(&cfg);
    cfg.site_id = site_id;
    cfg.device_id = device_id;
    return gc_config_save(&cfg);
}

gc_err_t gc_config_set_string(const char *key, const char *value)
{
    if (key == NULL || value == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    gc_config_t cfg;
    gc_config_read(&cfg);

    if (strcmp(key, "ap_ssid") == 0) {
        gc_config_copy_string(cfg.ap_ssid, sizeof(cfg.ap_ssid), value);
    } else if (strcmp(key, "ap_passphrase") == 0) {
        gc_config_copy_string(cfg.ap_passphrase, sizeof(cfg.ap_passphrase), value);
    } else if (strcmp(key, "sta_ssid") == 0) {
        gc_config_copy_string(cfg.sta_ssid, sizeof(cfg.sta_ssid), value);
    } else if (strcmp(key, "sta_passphrase") == 0) {
        gc_config_copy_string(cfg.sta_passphrase, sizeof(cfg.sta_passphrase), value);
    } else if (strcmp(key, "modem_ip") == 0) {
        gc_config_copy_string(cfg.modem_ip, sizeof(cfg.modem_ip), value);
    } else if (strcmp(key, "modem_user") == 0) {
        gc_config_copy_string(cfg.modem_user, sizeof(cfg.modem_user), value);
    } else if (strcmp(key, "modem_pass") == 0) {
        gc_config_copy_string(cfg.modem_pass, sizeof(cfg.modem_pass), value);
    } else if (strcmp(key, "broker_url") == 0) {
        gc_config_copy_string(cfg.broker_url, sizeof(cfg.broker_url), value);
    } else if (strcmp(key, "broker_user") == 0) {
        gc_config_copy_string(cfg.broker_user, sizeof(cfg.broker_user), value);
    } else if (strcmp(key, "broker_pass") == 0) {
        gc_config_copy_string(cfg.broker_pass, sizeof(cfg.broker_pass), value);
    } else if (strcmp(key, "manifest_url") == 0) {
        gc_config_copy_string(cfg.manifest_url, sizeof(cfg.manifest_url), value);
    } else if (strcmp(key, "beacon_host") == 0) {
        gc_config_copy_string(cfg.beacon_host, sizeof(cfg.beacon_host), value);
    } else if (strcmp(key, "notice") == 0) {
        gc_config_copy_string(cfg.notice, sizeof(cfg.notice), value);
    } else {
        GC_LOGE(GC_CONFIG_TAG, "unknown config key %s", key);
        return GC_ERR_INVALID_ARG;
    }
    return gc_config_save(&cfg);
}

bool gc_config_validate(const gc_config_t *cfg, const char **failed_field)
{
    if (cfg == NULL) {
        if (failed_field != NULL) {
            *failed_field = "cfg";
        }
        return false;
    }
    if (cfg->ap_ssid[0] == '\0') {
        if (failed_field != NULL) {
            *failed_field = "ap_ssid";
        }
        return false;
    }
    if (cfg->sta_ssid[0] == '\0') {
        if (failed_field != NULL) {
            *failed_field = "sta_ssid";
        }
        return false;
    }
    if (cfg->broker_url[0] == '\0') {
        if (failed_field != NULL) {
            *failed_field = "broker_url";
        }
        return false;
    }
    if (cfg->daily_budget_kb < cfg->monthly_reserve_kb) {
        if (failed_field != NULL) {
            *failed_field = "daily_budget_kb";
        }
        return false;
    }
    if (cfg->strike_limit == 0) {
        if (failed_field != NULL) {
            *failed_field = "strike_limit";
        }
        return false;
    }
    if (cfg->soft_block_s == 0) {
        if (failed_field != NULL) {
            *failed_field = "soft_block_s";
        }
        return false;
    }
    if (failed_field != NULL) {
        *failed_field = NULL;
    }
    return true;
}
