#pragma once

#include <stdint.h>
#include <stddef.h>
#include "gc_types.h"

#define GC_SSID_MAX 32
#define GC_PASSPHRASE_MAX 64
#define GC_URL_MAX 160
#define GC_USER_MAX 64
#define GC_THRESHOLD_RSSI_GOOD (-60)

typedef enum {
    GC_VERIFY_MODE_CONTACT = 0,
    GC_VERIFY_MODE_CHALLENGE,
} gc_verify_mode_t;

typedef struct {
    uint16_t site_id;
    uint16_t device_id;
    char ap_ssid[GC_SSID_MAX + 1];
    char ap_passphrase[GC_PASSPHRASE_MAX + 1];
    char sta_ssid[GC_SSID_MAX + 1];
    char sta_passphrase[GC_PASSPHRASE_MAX + 1];
    char modem_ip[GC_HOST_MAX];
    char modem_user[GC_USER_MAX];
    char modem_pass[GC_USER_MAX];
    char broker_url[GC_URL_MAX];
    char broker_user[GC_USER_MAX];
    char broker_pass[GC_USER_MAX];
    char manifest_url[GC_URL_MAX];
    char beacon_host[GC_HOST_MAX];
    uint16_t beacon_port;
    char notice[GC_NOTICE_MAX + 1];
    gc_verify_mode_t verify_mode;
    uint32_t verification_timeout_ms;
    uint32_t allow_grace_s;
    uint32_t soft_block_s;
    uint32_t strike_limit;
    uint32_t daily_budget_kb;
    uint32_t monthly_reserve_kb;
    uint32_t client_rate_kbyte_s;
    uint32_t telemetry_batch_period_s;
    uint32_t mqtt_keepalive_s;
    uint32_t modem_poll_period_s;
    uint32_t manifest_check_period_s;
    uint32_t selftest_deadline_s;
    uint32_t modem_api_reboot_min_interval_s;
    uint32_t modem_power_cycle_min_interval_s;
    uint16_t ota_window_start_minute;
    uint16_t ota_window_end_minute;
    int8_t ota_min_rsrp;
    uint8_t fw_version;
} gc_config_t;

gc_err_t gc_config_load(gc_config_t *out);
gc_err_t gc_config_save(const gc_config_t *cfg);
gc_err_t gc_config_set_site(uint16_t site_id, uint16_t device_id);
gc_err_t gc_config_set_string(const char *key, const char *value);
void gc_config_defaults(gc_config_t *out);
bool gc_config_validate(const gc_config_t *cfg, const char **failed_field);
