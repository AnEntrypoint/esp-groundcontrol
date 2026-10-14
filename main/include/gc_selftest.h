#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "gc_types.h"

#define GC_SELFTEST_CRITERION_MAX 32
#define GC_SELFTEST_CRITERIA 7

typedef enum {
    GC_SELFTEST_NOT_RUN = 0,
    GC_SELFTEST_RUNNING,
    GC_SELFTEST_PASSED,
    GC_SELFTEST_FAILED,
} gc_selftest_result_t;

typedef enum {
    GC_SELFTEST_CRITERION_AP_UP = 0,
    GC_SELFTEST_CRITERION_STA_IP,
    GC_SELFTEST_CRITERION_MODEM_SIGNAL,
    GC_SELFTEST_CRITERION_CONTROLLER_REACHABLE,
    GC_SELFTEST_CRITERION_HEARTBEAT_ACKED,
    GC_SELFTEST_CRITERION_PORTAL_LOOPBACK,
    GC_SELFTEST_CRITERION_QUOTA_INCREMENTED,
} gc_selftest_criterion_t;

gc_err_t gc_selftest_start(uint32_t deadline_s);
gc_err_t gc_selftest_tick(uint32_t now_s);
gc_selftest_result_t gc_selftest_result(void);
const char *gc_selftest_failed_criterion(void);
bool gc_selftest_criterion_met(gc_selftest_criterion_t criterion);
const char *gc_selftest_criterion_name(gc_selftest_criterion_t criterion);
gc_err_t gc_selftest_report(gc_selftest_criterion_t criterion, bool ok);
uint32_t gc_selftest_elapsed_s(void);
