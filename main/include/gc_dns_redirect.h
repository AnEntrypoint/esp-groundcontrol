#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "gc_types.h"

#define GC_DNS_PORT 53
#define GC_DNS_REDIRECT_TTL_S 5

gc_err_t gc_dns_redirect_start(uint32_t ap_ip);
gc_err_t gc_dns_redirect_stop(void);
bool gc_dns_redirect_running(void);

bool gc_dns_redirect_is_captive_probe(const char *host);
void gc_dns_redirect_set_allow_forwarding(bool allow);
uint32_t gc_dns_redirect_queries(void);
uint32_t gc_dns_redirect_redirected(void);
