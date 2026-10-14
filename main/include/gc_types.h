#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define GC_FRAME_VERSION 1u

#define GC_KEY_LEN 8u
#define GC_MAC_LEN 6u
#define GC_REQ_ID_LEN 8u
#define GC_MAX_CLIENTS 24u
#define GC_MAX_PENDING_VERIFY 8u
#define GC_NOTICE_MAX 512u
#define GC_HOST_MAX 64u

typedef enum {
    GC_OK = 0,
    GC_ERR_INVALID_ARG,
    GC_ERR_NO_MEM,
    GC_ERR_NOT_FOUND,
    GC_ERR_FULL,
    GC_ERR_TIMEOUT,
    GC_ERR_IO,
    GC_ERR_AUTH,
    GC_ERR_BUSY,
    GC_ERR_UNSUPPORTED,
} gc_err_t;

typedef enum {
    GC_CLIENT_NEW = 0,
    GC_CLIENT_PENDING,
    GC_CLIENT_ALLOWED,
    GC_CLIENT_SOFT_BLOCKED,
    GC_CLIENT_PERMANENTLY_BLOCKED,
} gc_client_state_t;

typedef enum {
    GC_DENY_NONE = 0,
    GC_DENY_PENDING,
    GC_DENY_NOT_VERIFIED,
    GC_DENY_STRIKE_LIMIT,
    GC_DENY_CONTROLLER_UNREACHABLE,
    GC_DENY_QUOTA_RESERVE,
    GC_DENY_EXPIRED,
} gc_deny_reason_t;

typedef enum {
    GC_QUOTA_TIER_NORMAL = 0,
    GC_QUOTA_TIER_REDUCED,
    GC_QUOTA_TIER_HEARTBEAT,
    GC_QUOTA_TIER_RESERVE,
} gc_quota_tier_t;

typedef enum {
    GC_SLOT_UNKNOWN = 0,
    GC_SLOT_FACTORY,
    GC_SLOT_OTA_0,
    GC_SLOT_OTA_1,
} gc_slot_t;

typedef enum {
    GC_ESCALATION_NONE = 0,
    GC_ESCALATION_RETRY_LINK,
    GC_ESCALATION_RERESOLVE_DNS,
    GC_ESCALATION_MODEM_API_REBOOT,
    GC_ESCALATION_MODEM_POWER_CYCLE,
    GC_ESCALATION_ALARM_ONLY,
} gc_escalation_step_t;

typedef struct {
    uint8_t b[GC_KEY_LEN];
} gc_key_t;

typedef struct {
    uint8_t b[GC_MAC_LEN];
} gc_mac_t;

typedef struct {
    uint8_t b[GC_REQ_ID_LEN];
} gc_req_id_t;

typedef struct {
    uint16_t site_id;
    uint16_t device_id;
    uint16_t boot_id;
    uint16_t seq;
} gc_identity_t;

typedef struct {
    gc_mac_t mac;
    gc_client_state_t state;
    gc_deny_reason_t last_deny;
    gc_key_t number_key;
    gc_key_t mac_key;
    uint32_t allowed_until_s;
    uint32_t blocked_until_s;
    uint32_t strikes;
    uint64_t bytes_up;
    uint64_t bytes_down;
    uint32_t rate_tokens_byte;
    uint32_t rate_last_ms;
    bool notice_served;
    bool permanent;
} gc_client_t;

typedef struct {
    int8_t rssi;
    int8_t rsrp;
    int8_t rsrq;
    int8_t sinr;
    uint8_t clients;
    uint64_t quota_delta_kb;
    uint32_t uptime_delta_s;
} gc_reading_t;

typedef struct {
    bool forwarding_paused;
    bool reserve_tripped;
    bool tunnel_up;
    bool trial_boot_pending;
    bool alarm_active;
} gc_flags_t;

static inline bool gc_key_equal(const gc_key_t *a, const gc_key_t *b)
{
    if (a == NULL || b == NULL) {
        return false;
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < GC_KEY_LEN; i++) {
        diff |= (uint8_t)(a->b[i] ^ b->b[i]);
    }
    return diff == 0;
}

static inline bool gc_mac_equal(const gc_mac_t *a, const gc_mac_t *b)
{
    if (a == NULL || b == NULL) {
        return false;
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < GC_MAC_LEN; i++) {
        diff |= (uint8_t)(a->b[i] ^ b->b[i]);
    }
    return diff == 0;
}

static inline bool gc_mac_is_zero(const gc_mac_t *m)
{
    if (m == NULL) {
        return true;
    }
    uint8_t acc = 0;
    for (size_t i = 0; i < GC_MAC_LEN; i++) {
        acc |= m->b[i];
    }
    return acc == 0;
}

const char *gc_client_state_name(gc_client_state_t state);
const char *gc_deny_reason_name(gc_deny_reason_t reason);
const char *gc_quota_tier_name(gc_quota_tier_t tier);
const char *gc_escalation_step_name(gc_escalation_step_t step);
const char *gc_err_name(gc_err_t err);
