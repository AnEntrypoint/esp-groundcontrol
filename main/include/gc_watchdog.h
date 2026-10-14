#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "gc_types.h"

#define GC_WATCHDOG_MAX_CHECKS 12
#define GC_WATCHDOG_NAME_MAX 16
#define GC_WATCHDOG_TIMEOUT_MS 30000

typedef bool (*gc_watchdog_check_fn)(void *ctx);

gc_err_t gc_watchdog_init(void);
gc_err_t gc_watchdog_start(void);
gc_err_t gc_watchdog_register(const char *name, gc_watchdog_check_fn check, void *ctx);
gc_err_t gc_watchdog_unregister(const char *name);

gc_err_t gc_watchdog_tick(void);
bool gc_watchdog_all_checks_pass(void);
uint32_t gc_watchdog_kick_count(void);
uint32_t gc_watchdog_stall_count(void);
const char *gc_watchdog_failing_check(void);
gc_err_t gc_watchdog_status(char *out, size_t len);
