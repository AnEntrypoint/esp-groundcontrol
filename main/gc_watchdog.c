#include "gc_watchdog.h"

#include "gc_log.h"
#include "gc_pinmap.h"

#include "driver/gpio.h"
#include "esp_timer.h"

#include <stdio.h>
#include <string.h>

#define GC_WATCHDOG_TAG "gc_watchdog"
#define GC_WATCHDOG_OWNER "watchdog"
#define GC_WATCHDOG_NONE_NAME "none"
#define GC_WATCHDOG_STATUS_MAX 96

typedef struct {
    char name[GC_WATCHDOG_NAME_MAX];
    gc_watchdog_check_fn check;
    void *ctx;
    int64_t failing_since_us;
    uint32_t fail_count;
    bool failing;
} gc_watchdog_entry_t;

static gc_watchdog_entry_t s_checks[GC_WATCHDOG_MAX_CHECKS];
static size_t s_check_count;
static uint32_t s_kick_count;
static uint32_t s_stall_count;
static int64_t s_failing_since_us;
static char s_failing_name[GC_WATCHDOG_NAME_MAX];
static bool s_failing_valid;
static bool s_pin_owned;
static bool s_pin_warned;
static bool s_started;
static bool s_timeout_logged;

static gc_watchdog_entry_t *gc_watchdog_find(const char *name)
{
    for (size_t i = 0; i < s_check_count; i++) {
        if (strncmp(s_checks[i].name, name, GC_WATCHDOG_NAME_MAX) == 0) {
            return &s_checks[i];
        }
    }
    return NULL;
}

static void gc_watchdog_record_failure(gc_watchdog_entry_t *entry, int64_t now_us)
{
    entry->fail_count++;
    if (!entry->failing) {
        entry->failing = true;
        entry->failing_since_us = now_us;
    }
}

static void gc_watchdog_pulse_line(void)
{
    gpio_set_level(GC_PIN_WATCHDOG_KICK_GPIO, 1);
    int64_t pulse_start_us = esp_timer_get_time();
    while (esp_timer_get_time() - pulse_start_us < GC_WATCHDOG_KICK_PULSE_US) {
    }
    gpio_set_level(GC_PIN_WATCHDOG_KICK_GPIO, 0);
}

static bool gc_watchdog_kick_line(void)
{
    if (!s_pin_owned) {
        if (!s_pin_warned) {
            GC_LOGE(GC_WATCHDOG_TAG, "kick gpio %d not owned, no kick",
                    GC_PIN_WATCHDOG_KICK_GPIO);
            s_pin_warned = true;
        }
        return false;
    }

    gc_watchdog_pulse_line();
    return true;
}

gc_err_t gc_watchdog_init(void)
{
    memset(s_checks, 0, sizeof(s_checks));
    s_check_count = 0;
    s_kick_count = 0;
    s_stall_count = 0;
    s_failing_since_us = 0;
    s_failing_name[0] = '\0';
    s_failing_valid = false;
    s_started = false;
    s_timeout_logged = false;
    s_pin_warned = false;

    if (!gc_pinmap_claim(GC_PIN_WATCHDOG_KICK_GPIO, GC_WATCHDOG_OWNER)) {
        const char *owner = gc_pinmap_owner(GC_PIN_WATCHDOG_KICK_GPIO);
        GC_LOGE(GC_WATCHDOG_TAG, "kick gpio %d unavailable owner=%s",
                GC_PIN_WATCHDOG_KICK_GPIO, owner != NULL ? owner : GC_WATCHDOG_NONE_NAME);
        s_pin_owned = false;
        s_pin_warned = true;
        return GC_OK;
    }

    s_pin_owned = true;
    gpio_reset_pin(GC_PIN_WATCHDOG_KICK_GPIO);
    gpio_set_direction(GC_PIN_WATCHDOG_KICK_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(GC_PIN_WATCHDOG_KICK_GPIO, 0);
    return GC_OK;
}

gc_err_t gc_watchdog_start(void)
{
    int64_t now_us = esp_timer_get_time();
    for (size_t i = 0; i < s_check_count; i++) {
        s_checks[i].failing = false;
        s_checks[i].failing_since_us = now_us;
    }
    s_failing_valid = false;
    s_failing_name[0] = '\0';
    s_timeout_logged = false;
    s_started = true;
    GC_LOGI(GC_WATCHDOG_TAG, "started checks=%u", (unsigned)s_check_count);
    return GC_OK;
}

gc_err_t gc_watchdog_register(const char *name, gc_watchdog_check_fn check, void *ctx)
{
    if (name == NULL || name[0] == '\0' || check == NULL) {
        return GC_ERR_INVALID_ARG;
    }

    gc_watchdog_entry_t *existing = gc_watchdog_find(name);
    if (existing != NULL) {
        existing->check = check;
        existing->ctx = ctx;
        return GC_OK;
    }

    if (s_check_count >= GC_WATCHDOG_MAX_CHECKS) {
        GC_LOGE(GC_WATCHDOG_TAG, "check registry full max=%d", GC_WATCHDOG_MAX_CHECKS);
        return GC_ERR_FULL;
    }

    gc_watchdog_entry_t *slot = &s_checks[s_check_count];
    snprintf(slot->name, sizeof(slot->name), "%s", name);
    slot->check = check;
    slot->ctx = ctx;
    slot->failing = false;
    slot->failing_since_us = esp_timer_get_time();
    slot->fail_count = 0;
    s_check_count++;
    return GC_OK;
}

gc_err_t gc_watchdog_unregister(const char *name)
{
    if (name == NULL) {
        return GC_ERR_INVALID_ARG;
    }

    for (size_t i = 0; i < s_check_count; i++) {
        if (strncmp(s_checks[i].name, name, GC_WATCHDOG_NAME_MAX) != 0) {
            continue;
        }

        bool dropped_was_failing = s_failing_valid &&
                                   strncmp(s_failing_name, name, GC_WATCHDOG_NAME_MAX) == 0;
        for (size_t j = i + 1; j < s_check_count; j++) {
            s_checks[j - 1] = s_checks[j];
        }
        s_check_count--;
        memset(&s_checks[s_check_count], 0, sizeof(s_checks[0]));

        if (dropped_was_failing) {
            s_failing_valid = false;
            s_failing_name[0] = '\0';
            s_failing_since_us = 0;
            s_timeout_logged = false;
        }
        return GC_OK;
    }

    return GC_ERR_NOT_FOUND;
}

gc_err_t gc_watchdog_tick(void)
{
    int64_t now_us = esp_timer_get_time();
    const char *oldest_name = NULL;
    int64_t oldest_since_us = 0;
    bool all_pass = true;

    for (size_t i = 0; i < s_check_count; i++) {
        gc_watchdog_entry_t *entry = &s_checks[i];
        if (entry->check(entry->ctx)) {
            entry->failing = false;
            entry->failing_since_us = 0;
            continue;
        }

        all_pass = false;
        gc_watchdog_record_failure(entry, now_us);
        if (oldest_name == NULL || entry->failing_since_us < oldest_since_us) {
            oldest_name = entry->name;
            oldest_since_us = entry->failing_since_us;
        }
    }

    s_failing_valid = oldest_name != NULL;
    if (s_failing_valid) {
        snprintf(s_failing_name, sizeof(s_failing_name), "%s", oldest_name);
        s_failing_since_us = oldest_since_us;
    } else {
        s_failing_name[0] = '\0';
        s_failing_since_us = now_us;
    }

    if (s_failing_valid && s_started) {
        int64_t failing_ms = (now_us - s_failing_since_us) / 1000;
        if (failing_ms >= GC_WATCHDOG_TIMEOUT_MS && !s_timeout_logged) {
            GC_LOGE(GC_WATCHDOG_TAG, "check %s failing for %dms beyond %dms",
                    s_failing_name, (int)failing_ms, GC_WATCHDOG_TIMEOUT_MS);
            s_timeout_logged = true;
        }
    } else if (!s_failing_valid) {
        s_timeout_logged = false;
    }

    if (!all_pass) {
        s_stall_count++;
        return GC_ERR_BUSY;
    }

    if (!gc_watchdog_kick_line()) {
        s_stall_count++;
        return GC_ERR_IO;
    }

    s_kick_count++;
    return GC_OK;
}

bool gc_watchdog_all_checks_pass(void)
{
    if (s_check_count == 0) {
        return false;
    }

    for (size_t i = 0; i < s_check_count; i++) {
        if (!s_checks[i].check(s_checks[i].ctx)) {
            return false;
        }
    }
    return true;
}

uint32_t gc_watchdog_kick_count(void)
{
    return s_kick_count;
}

uint32_t gc_watchdog_stall_count(void)
{
    return s_stall_count;
}

const char *gc_watchdog_failing_check(void)
{
    return s_failing_valid ? s_failing_name : GC_WATCHDOG_NONE_NAME;
}

gc_err_t gc_watchdog_status(char *out, size_t len)
{
    if (out == NULL || len == 0) {
        return GC_ERR_INVALID_ARG;
    }

    int64_t failing_ms = s_failing_valid ? (esp_timer_get_time() - s_failing_since_us) / 1000 : 0;
    int written = snprintf(out, len, "wdog kicks=%u stalls=%u checks=%u failing=%s for=%dms",
                           (unsigned)s_kick_count,
                           (unsigned)s_stall_count,
                           (unsigned)s_check_count,
                           s_failing_valid ? s_failing_name : GC_WATCHDOG_NONE_NAME,
                           (int)failing_ms);

    if (written < 0) {
        return GC_ERR_IO;
    }
    if ((size_t)written >= len) {
        out[len - 1] = '\0';
        return GC_ERR_NO_MEM;
    }
    return GC_OK;
}
