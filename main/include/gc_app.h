#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "gc_types.h"
#include "gc_config.h"

#define GC_APP_TICK_PERIOD_MS 1000
#define GC_APP_STATUS_MAX 512

typedef enum {
    GC_APP_PHASE_BOOT = 0,
    GC_APP_PHASE_NO_UPLINK,
    GC_APP_PHASE_PORTAL_ONLY,
    GC_APP_PHASE_ONLINE,
    GC_APP_PHASE_TRIAL_BOOT,
    GC_APP_PHASE_DEGRADED,
} gc_app_phase_t;

gc_err_t gc_app_init(void);
gc_err_t gc_app_start(void);
void gc_app_tick_once(uint32_t now_s);

gc_app_phase_t gc_app_phase(void);
const char *gc_app_phase_name(gc_app_phase_t phase);
gc_err_t gc_app_status(char *out, size_t len);

gc_err_t gc_app_request_tunnel(bool up);
gc_err_t gc_app_force_manifest_check(void);
gc_err_t gc_app_trip_reserve_for_bench(void);
uint32_t gc_app_uptime_s(void);

void gc_app_set_boot_id(uint16_t boot_id);
