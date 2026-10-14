#include "gc_types.h"

const char *gc_client_state_name(gc_client_state_t state)
{
    static const char *const names[] = {
        "NEW",
        "PENDING",
        "ALLOWED",
        "SOFT_BLOCKED",
        "PERMANENTLY_BLOCKED",
    };

    if ((size_t)state >= (sizeof(names) / sizeof(names[0]))) {
        return "UNKNOWN";
    }
    return names[state];
}

const char *gc_deny_reason_name(gc_deny_reason_t reason)
{
    static const char *const names[] = {
        "NONE",
        "PENDING",
        "NOT_VERIFIED",
        "STRIKE_LIMIT",
        "CONTROLLER_UNREACHABLE",
        "QUOTA_RESERVE",
        "EXPIRED",
    };

    if ((size_t)reason >= (sizeof(names) / sizeof(names[0]))) {
        return "UNKNOWN";
    }
    return names[reason];
}

const char *gc_quota_tier_name(gc_quota_tier_t tier)
{
    static const char *const names[] = {
        "NORMAL",
        "REDUCED",
        "HEARTBEAT",
        "RESERVE",
    };

    if ((size_t)tier >= (sizeof(names) / sizeof(names[0]))) {
        return "UNKNOWN";
    }
    return names[tier];
}

const char *gc_escalation_step_name(gc_escalation_step_t step)
{
    static const char *const names[] = {
        "NONE",
        "RETRY_LINK",
        "RERESOLVE_DNS",
        "MODEM_API_REBOOT",
        "MODEM_POWER_CYCLE",
        "ALARM_ONLY",
    };

    if ((size_t)step >= (sizeof(names) / sizeof(names[0]))) {
        return "UNKNOWN";
    }
    return names[step];
}

const char *gc_err_name(gc_err_t err)
{
    static const char *const names[] = {
        "OK",
        "INVALID_ARG",
        "NO_MEM",
        "NOT_FOUND",
        "FULL",
        "TIMEOUT",
        "IO",
        "AUTH",
        "BUSY",
        "UNSUPPORTED",
    };

    if ((size_t)err >= (sizeof(names) / sizeof(names[0]))) {
        return "UNKNOWN";
    }
    return names[err];
}
