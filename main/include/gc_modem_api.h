#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "gc_types.h"

#define GC_MODEM_TOKEN_MAX 64
#define GC_MODEM_PLMN_MAX 8

typedef struct {
    bool valid;
    int8_t rsrp;
    int8_t rsrq;
    int8_t sinr;
    int rssi;
    uint32_t age_s;
    char plmn[GC_MODEM_PLMN_MAX + 1];
} gc_modem_status_t;

gc_err_t gc_modem_api_init(const char *host, const char *user, const char *pass);
void gc_modem_api_deinit(void);

gc_err_t gc_modem_api_poll(gc_modem_status_t *out);
gc_err_t gc_modem_api_reboot(void);

bool gc_modem_api_reachable(void);
uint32_t gc_modem_api_last_latency_ms(void);
uint32_t gc_modem_api_failures(void);
uint32_t gc_modem_api_token_age_s(void);
gc_err_t gc_modem_api_invalidate_token(void);
