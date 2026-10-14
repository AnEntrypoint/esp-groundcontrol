#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "gc_types.h"
#include "gc_config.h"

#define GC_PORTAL_HTTP_PORT 80
#define GC_PORTAL_DNS_PORT 53
#define GC_PORTAL_CAPTIVE_HOSTS 6

typedef enum {
    GC_PORTAL_NUMBER_INVALID = 0,
    GC_PORTAL_NUMBER_OK,
    GC_PORTAL_NUMBER_BLOCKED,
    GC_PORTAL_NUMBER_PENDING,
} gc_portal_number_status_t;

gc_err_t gc_portal_init(uint16_t http_port);
gc_err_t gc_portal_start(const gc_config_t *cfg);
gc_err_t gc_portal_stop(void);

gc_err_t gc_portal_dns_start(uint32_t ap_ip);
gc_err_t gc_portal_dns_stop(void);

bool gc_portal_running(void);
bool gc_portal_dns_running(void);

gc_err_t gc_portal_set_notice(const char *notice);
gc_err_t gc_portal_normalize_number(const char *raw, char *e164, size_t e164_len);

gc_portal_number_status_t gc_portal_number_status(const char *e164, uint32_t *blocked_remaining_s);

gc_err_t gc_portal_loopback_probe(bool *passed);
uint32_t gc_portal_login_attempts(void);
uint32_t gc_portal_served_notices(void);
