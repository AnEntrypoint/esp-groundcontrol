#include "gc_quota.h"

#include <inttypes.h>
#include <time.h>

#include "gc_config.h"
#include "gc_log.h"
#include "gc_nvs.h"

#define GC_QUOTA_TAG "quota"

#define GC_QUOTA_SECONDS_PER_DAY 86400u
#define GC_QUOTA_KB_SHIFT 10u
#define GC_QUOTA_PERCENT_SCALE 100u

#define GC_QUOTA_KEY_DAY_INDEX "qday"
#define GC_QUOTA_KEY_DAY_USED "qused"
#define GC_QUOTA_KEY_MONTH_USED "qmon"

#define GC_QUOTA_FALLBACK_BATCH_S 3600u
#define GC_QUOTA_FALLBACK_KEEPALIVE_S 60u
#define GC_QUOTA_HEARTBEAT_PERIOD_S 21600u

#define GC_QUOTA_REDUCED_PERCENT 70u
#define GC_QUOTA_HEARTBEAT_PERCENT 90u

typedef struct {
    uint64_t daily_used_kb;
    uint64_t month_used_kb;
    uint64_t carry_bytes;
    uint32_t daily_budget_kb;
    uint32_t monthly_reserve_kb;
    uint32_t day_index;
    uint32_t month_index;
    uint32_t now_s;
    uint32_t batch_period_s;
    uint32_t keepalive_s;
    gc_quota_tier_t tier;
    bool reserve_tripped;
    bool forwarding_paused;
} gc_quota_state_t;

static gc_quota_state_t s_quota;

static uint32_t day_index_of(uint32_t now_s)
{
    return now_s / GC_QUOTA_SECONDS_PER_DAY;
}

static uint32_t month_index_of(uint32_t now_s)
{
    time_t when = (time_t)now_s;
    struct tm utc;
    if (gmtime_r(&when, &utc) == NULL) {
        return 0u;
    }
    return (uint32_t)(((utc.tm_year + 1900) * 12) + utc.tm_mon);
}

static uint32_t usage_percent(uint64_t used_kb, uint32_t budget_kb)
{
    if (budget_kb == 0u) {
        return 0u;
    }
    if (used_kb >= (uint64_t)budget_kb) {
        return GC_QUOTA_PERCENT_SCALE;
    }
    if (used_kb > (UINT64_MAX / GC_QUOTA_PERCENT_SCALE)) {
        return GC_QUOTA_PERCENT_SCALE;
    }
    return (uint32_t)((used_kb * GC_QUOTA_PERCENT_SCALE) / budget_kb);
}

static void tier_refresh(void)
{
    bool reserve_reached = (s_quota.monthly_reserve_kb != 0u) &&
                           (s_quota.month_used_kb >= (uint64_t)s_quota.monthly_reserve_kb);
    gc_quota_tier_t tier = GC_QUOTA_TIER_NORMAL;

    if (reserve_reached) {
        tier = GC_QUOTA_TIER_RESERVE;
    } else {
        uint32_t percent = usage_percent(s_quota.daily_used_kb, s_quota.daily_budget_kb);
        if (percent >= GC_QUOTA_HEARTBEAT_PERCENT) {
            tier = GC_QUOTA_TIER_HEARTBEAT;
        } else if (percent >= GC_QUOTA_REDUCED_PERCENT) {
            tier = GC_QUOTA_TIER_REDUCED;
        }
    }

    s_quota.reserve_tripped = reserve_reached;
    s_quota.forwarding_paused = reserve_reached;

    s_quota.reserve_tripped = reserve_reached;
    s_quota.forwarding_paused = reserve_reached;

    if (tier != s_quota.tier) {
        GC_LOGI(GC_QUOTA_TAG, "tier %s daily %" PRIu64 " of %" PRIu32 " kb month %" PRIu64 " of %" PRIu32 " kb",
                gc_quota_tier_name(tier), s_quota.daily_used_kb, s_quota.daily_budget_kb,
                s_quota.month_used_kb, s_quota.monthly_reserve_kb);
    }
    s_quota.tier = tier;
}

static uint64_t kb_add(uint64_t total, uint64_t kb)
{
    return (total > (UINT64_MAX - kb)) ? UINT64_MAX : (total + kb);
}

static void account_kb(uint64_t kb)
{
    s_quota.daily_used_kb = kb_add(s_quota.daily_used_kb, kb);
    s_quota.month_used_kb = kb_add(s_quota.month_used_kb, kb);
    tier_refresh();
}

gc_err_t gc_quota_init(uint32_t daily_budget_kb, uint32_t monthly_reserve_kb)
{
    s_quota.daily_budget_kb = daily_budget_kb;
    s_quota.monthly_reserve_kb = monthly_reserve_kb;
    s_quota.batch_period_s = GC_QUOTA_FALLBACK_BATCH_S;
    s_quota.keepalive_s = GC_QUOTA_FALLBACK_KEEPALIVE_S;

    gc_config_t cfg;
    gc_config_defaults(&cfg);
    if (gc_config_load(&cfg) == GC_OK) {
        if (cfg.telemetry_batch_period_s != 0u) {
            s_quota.batch_period_s = cfg.telemetry_batch_period_s;
        }
        if (cfg.mqtt_keepalive_s != 0u) {
            s_quota.keepalive_s = cfg.mqtt_keepalive_s;
        }
    }

    tier_refresh();
    return GC_OK;
}

gc_err_t gc_quota_account_bytes(uint64_t bytes)
{
    uint64_t total = s_quota.carry_bytes + bytes;
    s_quota.carry_bytes = total & (uint64_t)(GC_QUOTA_KB - 1u);
    account_kb(total >> GC_QUOTA_KB_SHIFT);
    return GC_OK;
}

gc_err_t gc_quota_account_up(uint64_t bytes)
{
    return gc_quota_account_bytes(bytes);
}

gc_err_t gc_quota_account_down(uint64_t bytes)
{
    return gc_quota_account_bytes(bytes);
}

uint64_t gc_quota_daily_used_kb(void)
{
    return s_quota.daily_used_kb;
}

uint64_t gc_quota_month_used_kb(void)
{
    return s_quota.month_used_kb;
}

uint64_t gc_quota_daily_budget_kb(void)
{
    return (uint64_t)s_quota.daily_budget_kb;
}

uint64_t gc_quota_month_reserve_kb(void)
{
    return (uint64_t)s_quota.monthly_reserve_kb;
}

gc_quota_tier_t gc_quota_tier(void)
{
    return s_quota.tier;
}

bool gc_quota_reserve_tripped(void)
{
    return s_quota.reserve_tripped;
}

bool gc_quota_forwarding_paused(void)
{
    return s_quota.forwarding_paused;
}

uint32_t gc_quota_batch_period_s(void)
{
    uint32_t base = (s_quota.batch_period_s != 0u) ? s_quota.batch_period_s : GC_QUOTA_FALLBACK_BATCH_S;

    switch (s_quota.tier) {
    case GC_QUOTA_TIER_REDUCED:
        return (base > (UINT32_MAX / 2u)) ? UINT32_MAX : (base * 2u);
    case GC_QUOTA_TIER_HEARTBEAT:
    case GC_QUOTA_TIER_RESERVE:
        return GC_QUOTA_HEARTBEAT_PERIOD_S;
    case GC_QUOTA_TIER_NORMAL:
    default:
        return base;
    }
}

uint32_t gc_quota_telemetry_keepalive_s(void)
{
    return (s_quota.keepalive_s != 0u) ? s_quota.keepalive_s : GC_QUOTA_FALLBACK_KEEPALIVE_S;
}

uint32_t gc_quota_seconds_to_rollover(void)
{
    return GC_QUOTA_SECONDS_PER_DAY - (s_quota.now_s % GC_QUOTA_SECONDS_PER_DAY);
}

gc_err_t gc_quota_tick(uint32_t now_s)
{
    s_quota.now_s = now_s;

    bool rolled = false;
    uint32_t day = day_index_of(now_s);
    if (s_quota.day_index == 0u) {
        s_quota.day_index = day;
    } else if (day != s_quota.day_index) {
        s_quota.day_index = day;
        s_quota.daily_used_kb = 0u;
        s_quota.carry_bytes = 0u;
        rolled = true;
    }

    uint32_t month = month_index_of(now_s);
    if (month != 0u) {
        if (s_quota.month_index == 0u) {
            s_quota.month_index = month;
        } else if (month != s_quota.month_index) {
            s_quota.month_index = month;
            s_quota.month_used_kb = 0u;
            rolled = true;
        }
    }

    tier_refresh();

    if (rolled) {
        return gc_quota_persist();
    }
    return GC_OK;
}

gc_err_t gc_quota_force_rollover(void)
{
    s_quota.daily_used_kb = 0u;
    s_quota.carry_bytes = 0u;
    if (s_quota.now_s != 0u) {
        s_quota.day_index = day_index_of(s_quota.now_s);
    }
    tier_refresh();
    return gc_quota_persist();
}

gc_err_t gc_quota_persist(void)
{
    gc_err_t err = gc_nvs_set_u32(GC_QUOTA_KEY_DAY_INDEX, s_quota.day_index);
    if (err != GC_OK) {
        return err;
    }
    err = gc_nvs_set_u64(GC_QUOTA_KEY_DAY_USED, s_quota.daily_used_kb);
    if (err != GC_OK) {
        return err;
    }
    err = gc_nvs_set_u64(GC_QUOTA_KEY_MONTH_USED, s_quota.month_used_kb);
    if (err != GC_OK) {
        return err;
    }
    return gc_nvs_commit();
}

gc_err_t gc_quota_restore(void)
{
    uint32_t day = 0u;
    uint64_t day_used = 0u;
    uint64_t month_used = 0u;

    gc_err_t err = gc_nvs_get_u32(GC_QUOTA_KEY_DAY_INDEX, &day);
    if (err != GC_OK) {
        return err;
    }
    if (gc_nvs_get_u64(GC_QUOTA_KEY_DAY_USED, &day_used) != GC_OK) {
        day_used = 0u;
    }
    if (gc_nvs_get_u64(GC_QUOTA_KEY_MONTH_USED, &month_used) != GC_OK) {
        month_used = 0u;
    }

    s_quota.day_index = day;
    s_quota.daily_used_kb = day_used;
    s_quota.month_used_kb = month_used;
    s_quota.carry_bytes = 0u;

    if (s_quota.now_s != 0u) {
        uint32_t today = day_index_of(s_quota.now_s);
        if (day != today) {
            s_quota.day_index = today;
            s_quota.daily_used_kb = 0u;
        }
        uint32_t month = month_index_of(s_quota.now_s);
        if (month != 0u) {
            s_quota.month_index = month;
        }
    }

    tier_refresh();
    return GC_OK;
}

gc_err_t gc_quota_set_budget(uint32_t daily_budget_kb, uint32_t monthly_reserve_kb)
{
    s_quota.daily_budget_kb = daily_budget_kb;
    s_quota.monthly_reserve_kb = monthly_reserve_kb;
    tier_refresh();
    return GC_OK;
}
