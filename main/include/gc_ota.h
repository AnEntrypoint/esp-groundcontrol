#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "gc_types.h"

#define GC_OTA_MANIFEST_MAX 512
#define GC_OTA_VERSION_MAX 16
#define GC_OTA_SHA256_HEX 65

typedef enum {
    GC_OTA_IDLE = 0,
    GC_OTA_CHECKING,
    GC_OTA_PREFLIGHT,
    GC_OTA_DOWNLOADING,
    GC_OTA_VERIFYING,
    GC_OTA_TRIAL,
    GC_OTA_ROLLING_BACK,
    GC_OTA_FAILED,
} gc_ota_state_t;

typedef struct {
    uint32_t version;
    uint32_t size;
    uint32_t min_security_version;
    char sha256[GC_OTA_SHA256_HEX];
    char url[GC_URL_MAX];
    bool delta;
    uint32_t delta_base_version;
} gc_ota_manifest_t;

gc_err_t gc_ota_init(const char *manifest_url, uint32_t window_start_minute,
                     uint32_t window_end_minute, int8_t min_rsrp);
gc_ota_state_t gc_ota_state(void);
const char *gc_ota_state_name(gc_ota_state_t state);

gc_err_t gc_ota_tick(uint32_t now_s);
gc_err_t gc_ota_check_now(void);
gc_err_t gc_ota_abort(void);

gc_slot_t gc_ota_running_slot(void);
bool gc_ota_trial_pending(void);
gc_err_t gc_ota_mark_valid(void);
gc_err_t gc_ota_mark_invalid_and_reboot(void);

gc_err_t gc_ota_block_version(uint32_t version);
bool gc_ota_version_blocked(uint32_t version);
uint32_t gc_ota_running_version(void);
uint32_t gc_ota_downloaded_bytes(void);
uint32_t gc_ota_last_failure_version(void);
