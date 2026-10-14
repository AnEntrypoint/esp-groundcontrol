#pragma once

#include <stdint.h>
#include <stddef.h>
#include "gc_types.h"
#include "esp_netif.h"

gc_err_t gc_netif_init(void);

esp_netif_t *gc_netif_sta(void);
esp_netif_t *gc_netif_ap(void);

gc_err_t gc_netif_sta_start(void);
gc_err_t gc_netif_sta_stop(void);
gc_err_t gc_netif_ap_start(const char *ssid, const char *passphrase, uint8_t max_clients);
gc_err_t gc_netif_ap_stop(void);

bool gc_netif_sta_has_ip(void);
bool gc_netif_sta_link_up(void);
gc_err_t gc_netif_sta_ipv4(esp_netif_ip_info_t *out);
gc_err_t gc_netif_sta_gateway_ipv4(uint32_t *out);
gc_err_t gc_netif_ap_ipv4(esp_netif_ip_info_t *out);

gc_err_t gc_netif_install_counters(void);
bool gc_netif_rx_counter_wrapped(void);

void gc_netif_account_sta_tx(size_t bytes);
void gc_netif_account_sta_rx(size_t bytes);
void gc_netif_account_ap_tx(const uint8_t *dst_mac, size_t bytes);
void gc_netif_account_ap_rx(const uint8_t *src_mac, size_t bytes);

uint64_t gc_netif_sta_tx_bytes(void);
uint64_t gc_netif_sta_rx_bytes(void);
uint64_t gc_netif_uplink_bytes(void);
