#include "gc_selftest.h"

#include "gc_log.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define GC_SELFTEST_TAG "gc_selftest"
#define GC_SELFTEST_NONE_NAME "none"
#define GC_SELFTEST_UNKNOWN_NAME "unknown"

static const char *const s_criterion_names[GC_SELFTEST_CRITERIA] = {
    "AP_UP",
    "STA_IP",
    "MODEM_SIGNAL",
    "CONTROLLER_REACHABLE",
    "HEARTBEAT_ACKED",
    "PORTAL_LOOPBACK",
    "QUOTA_INCREMENTED",
};

static bool s_met[GC_SELFTEST_CRITERIA];
static gc_selftest_result_t s_result = GC_SELFTEST_NOT_RUN;
static gc_selftest_criterion_t s_first_unmet = GC_SELFTEST_CRITERION_AP_UP;
static uint32_t s_deadline_s;
static uint32_t s_start_s;
static uint32_t s_now_s;
static bool s_started;
static bool s_time_valid;
static bool s_first_unmet_valid;

static bool gc_selftest_criterion_valid(gc_selftest_criterion_t criterion)
{
    return (int)criterion >= 0 && (size_t)criterion < GC_SELFTEST_CRITERIA;
}

static bool gc_selftest_all_met(void)
{
    for (size_t i = 0; i < GC_SELFTEST_CRITERIA; i++) {
        if (!s_met[i]) {
            return false;
        }
    }
    return true;
}

static void gc_selftest_record_first_unmet(void)
{
    for (size_t i = 0; i < GC_SELFTEST_CRITERIA; i++) {
        if (!s_met[i]) {
            s_first_unmet = (gc_selftest_criterion_t)i;
            s_first_unmet_valid = true;
            return;
        }
    }
    s_first_unmet_valid = false;
}

gc_err_t gc_selftest_start(uint32_t deadline_s)
{
    for (size_t i = 0; i < GC_SELFTEST_CRITERIA; i++) {
        s_met[i] = false;
    }
    s_deadline_s = deadline_s;
    s_start_s = 0u;
    s_now_s = 0u;
    s_result = GC_SELFTEST_RUNNING;
    s_first_unmet = GC_SELFTEST_CRITERION_AP_UP;
    s_started = true;
    s_time_valid = false;
    s_first_unmet_valid = false;
    GC_LOGI(GC_SELFTEST_TAG, "start deadline=%us", deadline_s);
    return GC_OK;
}

gc_err_t gc_selftest_tick(uint32_t now_s)
{
    uint32_t elapsed_s;

    if (!s_started) {
        return GC_ERR_BUSY;
    }
    if (s_result != GC_SELFTEST_RUNNING) {
        return GC_OK;
    }
    if (!s_time_valid) {
        s_start_s = now_s;
        s_time_valid = true;
    }
    s_now_s = now_s;
    elapsed_s = now_s - s_start_s;

    if (gc_selftest_all_met()) {
        s_result = GC_SELFTEST_PASSED;
        s_first_unmet_valid = false;
        GC_LOGI(GC_SELFTEST_TAG, "passed elapsed=%us", elapsed_s);
        return GC_OK;
    }
    if (elapsed_s > s_deadline_s) {
        gc_selftest_record_first_unmet();
        s_result = GC_SELFTEST_FAILED;
        GC_LOGE(GC_SELFTEST_TAG, "failed elapsed=%us on %s", elapsed_s,
                gc_selftest_failed_criterion());
    }
    return GC_OK;
}

gc_err_t gc_selftest_report(gc_selftest_criterion_t criterion, bool ok)
{
    if (!gc_selftest_criterion_valid(criterion)) {
        return GC_ERR_INVALID_ARG;
    }
    if (!s_started) {
        return GC_ERR_BUSY;
    }
    if (!ok || s_met[criterion]) {
        return GC_OK;
    }
    s_met[criterion] = true;
    GC_LOGD(GC_SELFTEST_TAG, "criterion %s met", gc_selftest_criterion_name(criterion));
    return GC_OK;
}

gc_selftest_result_t gc_selftest_result(void)
{
    return s_result;
}

const char *gc_selftest_failed_criterion(void)
{
    if (!s_started || !s_first_unmet_valid) {
        return GC_SELFTEST_NONE_NAME;
    }
    return gc_selftest_criterion_name(s_first_unmet);
}

bool gc_selftest_criterion_met(gc_selftest_criterion_t criterion)
{
    if (!gc_selftest_criterion_valid(criterion)) {
        return false;
    }
    return s_met[criterion];
}

const char *gc_selftest_criterion_name(gc_selftest_criterion_t criterion)
{
    if (!gc_selftest_criterion_valid(criterion)) {
        return GC_SELFTEST_UNKNOWN_NAME;
    }
    return s_criterion_names[criterion];
}

uint32_t gc_selftest_elapsed_s(void)
{
    if (!s_started || !s_time_valid) {
        return 0u;
    }
    return s_now_s - s_start_s;
}
