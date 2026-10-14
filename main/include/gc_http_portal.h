#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "gc_types.h"
#include "gc_config.h"

#define GC_HTTP_MAX_CLIENTS 4
#define GC_HTTP_FIELD_MAX 32
#define GC_HTTP_BODY_MAX 256

gc_err_t gc_http_portal_start(const gc_config_t *cfg);
gc_err_t gc_http_portal_stop(void);
bool gc_http_portal_running(void);

gc_err_t gc_http_portal_set_port(uint16_t port);
gc_err_t gc_http_portal_set_notice(const char *notice);
gc_err_t gc_http_portal_reply_pending(gc_req_id_t req, uint32_t wait_ms);

gc_err_t gc_http_portal_probe_login(const char *e164, gc_mac_t *test_mac, bool *passed);
uint32_t gc_http_portal_requests(void);
uint32_t gc_http_portal_logins(void);
uint32_t gc_http_portal_notices_served(void);
