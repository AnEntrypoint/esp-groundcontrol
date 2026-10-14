#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "gc_types.h"

#define GC_QUOTA_KB 1024u

gc_err_t gc_quota_init(uint32_t daily_budget_kb, uint32_t monthly_reserve_kb);

gc_err_t gc_quota_account_up(uint64_t bytes);
gc_err_t gc_quota_account_down(uint64_t bytes);
gc_err_t gc_quota_account_bytes(uint64_t bytes);

uint64_t gc_quota_daily_used_kb(void);
uint64_t gc_quota_month_used_kb(void);
uint64_t gc_quota_daily_budget_kb(void);
uint64_t gc_quota_month_reserve_kb(void);

gc_quota_tier_t gc_quota_tier(void);
bool gc_quota_reserve_tripped(void);
bool gc_quota_forwarding_paused(void);
uint32_t gc_quota_batch_period_s(void);
uint32_t gc_quota_telemetry_keepalive_s(void);
uint32_t gc_quota_seconds_to_rollover(void);

gc_err_t gc_quota_tick(uint32_t now_s);
gc_err_t gc_quota_force_rollover(void);
gc_err_t gc_quota_persist(void);
gc_err_t gc_quota_restore(void);
gc_err_t gc_quota_set_budget(uint32_t daily_budget_kb, uint32_t monthly_reserve_kb);
