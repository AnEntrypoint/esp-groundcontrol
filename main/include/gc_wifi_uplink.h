#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "gc_types.h"

#define GC_UPLINK_BACKOFF_MIN_S 2
#define GC_UPLINK_BACKOFF_MAX_S 300
#define GC_UPLINK_RSSI_UNKNOWN 127

gc_err_t gc_wifi_uplink_init(void);
gc_err_t gc_wifi_uplink_start(const char *ssid, const char *passphrase);
gc_err_t gc_wifi_uplink_stop(void);

bool gc_wifi_uplink_connected(void);
bool gc_wifi_uplink_has_ip(void);
int gc_wifi_uplink_rssi(void);
uint32_t gc_wifi_uplink_backoff_s(void);
uint32_t gc_wifi_uplink_connect_attempts(void);
gc_err_t gc_wifi_uplink_reset_backoff(void);
gc_err_t gc_wifi_uplink_forget_and_retry(void);
