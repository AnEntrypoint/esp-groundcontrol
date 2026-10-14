#include "gc_netif.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "lwip/err.h"
#include "lwip/ip4_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"

#include "gc_gate.h"
#include "gc_log.h"
#include "gc_types.h"

#define GC_NETIF_L2_HEADER_LEN (2u * GC_MAC_LEN)
#define GC_NETIF_AP_CLIENTS_MAX GC_MAX_CLIENTS
#define GC_NETIF_IMPL_NAME_LEN (NETIF_NAMESIZE + 2u)

static const char *gc_netif_tag = "gc_netif";

typedef struct {
    struct netif *impl;
    netif_linkoutput_fn linkoutput_original;
    netif_input_fn input_original;
    bool linkoutput_wrapped;
    bool input_wrapped;
} gc_netif_hook_t;

static esp_netif_t *gc_netif_sta_handle;
static esp_netif_t *gc_netif_ap_handle;
static bool gc_netif_ready;
static bool gc_netif_sta_running;
static bool gc_netif_ap_running;
static bool gc_netif_wifi_started;
static bool gc_netif_counters_installed;
static bool gc_netif_rx_wrap_verified;
static bool gc_netif_rx_wrap_fired;
static portMUX_TYPE gc_netif_counter_lock = portMUX_INITIALIZER_UNLOCKED;
static uint64_t gc_netif_sta_tx_total;
static uint64_t gc_netif_sta_rx_total;
static gc_netif_hook_t gc_netif_sta_hook;
static gc_netif_hook_t gc_netif_ap_hook;

static void gc_netif_counter_add(uint64_t *counter, size_t bytes)
{
    portENTER_CRITICAL(&gc_netif_counter_lock);
    *counter += (uint64_t)bytes;
    portEXIT_CRITICAL(&gc_netif_counter_lock);
}

static uint64_t gc_netif_counter_read(const uint64_t *counter)
{
    uint64_t value;
    portENTER_CRITICAL(&gc_netif_counter_lock);
    value = *counter;
    portEXIT_CRITICAL(&gc_netif_counter_lock);
    return value;
}

static void gc_netif_mark_rx_wrap_fired(void)
{
    portENTER_CRITICAL(&gc_netif_counter_lock);
    gc_netif_rx_wrap_fired = true;
    portEXIT_CRITICAL(&gc_netif_counter_lock);
}

static bool gc_netif_read_l2_addresses(struct pbuf *p,
                                       uint8_t dst_mac[GC_MAC_LEN],
                                       uint8_t src_mac[GC_MAC_LEN])
{
    uint8_t header[GC_NETIF_L2_HEADER_LEN];

    if (p == NULL || p->tot_len < GC_NETIF_L2_HEADER_LEN) {
        return false;
    }
    if (pbuf_copy_partial(p, header, (u16_t)sizeof(header), 0) != (u16_t)sizeof(header)) {
        return false;
    }
    memcpy(dst_mac, &header[0], GC_MAC_LEN);
    memcpy(src_mac, &header[GC_MAC_LEN], GC_MAC_LEN);
    return true;
}

static void gc_netif_account_client(const uint8_t *mac, size_t bytes, bool uplink)
{
    gc_mac_t client_mac;

    if (mac == NULL || bytes == 0u) {
        return;
    }
    memcpy(client_mac.b, mac, GC_MAC_LEN);
    gc_gate_account_bytes(&client_mac, uplink, bytes);
}

void gc_netif_account_sta_tx(size_t bytes)
{
    gc_netif_counter_add(&gc_netif_sta_tx_total, bytes);
}

void gc_netif_account_sta_rx(size_t bytes)
{
    gc_netif_counter_add(&gc_netif_sta_rx_total, bytes);
}

void gc_netif_account_ap_tx(const uint8_t *dst_mac, size_t bytes)
{
    gc_netif_account_client(dst_mac, bytes, false);
}

void gc_netif_account_ap_rx(const uint8_t *src_mac, size_t bytes)
{
    gc_netif_account_client(src_mac, bytes, true);
}

static err_t gc_netif_sta_linkoutput_hook(struct netif *netif, struct pbuf *p)
{
    if (p != NULL) {
        gc_netif_account_sta_tx(p->tot_len);
    }
    if (gc_netif_sta_hook.linkoutput_original == NULL) {
        return ERR_IF;
    }
    return gc_netif_sta_hook.linkoutput_original(netif, p);
}

static err_t gc_netif_sta_input_hook(struct pbuf *p, struct netif *inp)
{
    gc_netif_mark_rx_wrap_fired();
    if (p != NULL) {
        gc_netif_account_sta_rx(p->tot_len);
    }
    if (gc_netif_sta_hook.input_original == NULL) {
        if (p != NULL) {
            pbuf_free(p);
        }
        return ERR_OK;
    }
    return gc_netif_sta_hook.input_original(p, inp);
}

static err_t gc_netif_ap_linkoutput_hook(struct netif *netif, struct pbuf *p)
{
    uint8_t dst_mac[GC_MAC_LEN];
    uint8_t src_mac[GC_MAC_LEN];

    if (gc_netif_read_l2_addresses(p, dst_mac, src_mac)) {
        gc_netif_account_ap_tx(dst_mac, p->tot_len);
    }
    if (gc_netif_ap_hook.linkoutput_original == NULL) {
        return ERR_IF;
    }
    return gc_netif_ap_hook.linkoutput_original(netif, p);
}

static err_t gc_netif_ap_input_hook(struct pbuf *p, struct netif *inp)
{
    uint8_t dst_mac[GC_MAC_LEN];
    uint8_t src_mac[GC_MAC_LEN];

    gc_netif_mark_rx_wrap_fired();
    if (gc_netif_read_l2_addresses(p, dst_mac, src_mac)) {
        gc_netif_account_ap_rx(src_mac, p->tot_len);
    }
    if (gc_netif_ap_hook.input_original == NULL) {
        if (p != NULL) {
            pbuf_free(p);
        }
        return ERR_OK;
    }
    return gc_netif_ap_hook.input_original(p, inp);
}

static bool gc_netif_impl_has_ipv4(const struct netif *candidate, uint32_t wanted_addr)
{
    const ip4_addr_t *candidate_addr;

    if (candidate == NULL || wanted_addr == 0u) {
        return false;
    }
    candidate_addr = netif_ip4_addr(candidate);
    return candidate_addr->addr == wanted_addr;
}

static struct netif *gc_netif_find_impl_by_ipv4(esp_netif_t *netif)
{
    esp_netif_ip_info_t ip_info;
    struct netif *candidate;

    if (netif == NULL) {
        return NULL;
    }
    if (esp_netif_get_ip_info(netif, &ip_info) != ESP_OK) {
        return NULL;
    }
    for (candidate = netif_list; candidate != NULL; candidate = candidate->next) {
        if (gc_netif_impl_has_ipv4(candidate, ip_info.ip.addr)) {
            return candidate;
        }
    }
    return NULL;
}

static struct netif *gc_netif_find_impl_by_name(esp_netif_t *netif)
{
    char name[GC_NETIF_IMPL_NAME_LEN];

    if (netif == NULL) {
        return NULL;
    }
    memset(name, 0, sizeof(name));
    if (esp_netif_get_netif_impl_name(netif, name) != ESP_OK) {
        return NULL;
    }
    return netif_find(name);
}

static struct netif *gc_netif_find_impl(esp_netif_t *netif)
{
    struct netif *impl;

    impl = gc_netif_find_impl_by_ipv4(netif);
    if (impl != NULL) {
        return impl;
    }
    return gc_netif_find_impl_by_name(netif);
}

static gc_err_t gc_netif_hook_install(gc_netif_hook_t *hook,
                                      esp_netif_t *netif,
                                      netif_linkoutput_fn linkoutput_hook,
                                      netif_input_fn input_hook)
{
    const char *ifkey;
    struct netif *impl;

    if (hook == NULL || netif == NULL) {
        return GC_ERR_INVALID_ARG;
    }

    impl = gc_netif_find_impl(netif);
    if (impl == NULL) {
        ifkey = esp_netif_get_ifkey(netif);
        GC_LOGW(gc_netif_tag, "lwip netif not resolvable for %s",
                ifkey != NULL ? ifkey : "unknown");
        return GC_ERR_NOT_FOUND;
    }
    hook->impl = impl;

    if (hook->impl->linkoutput != NULL && !hook->linkoutput_wrapped) {
        hook->linkoutput_original = hook->impl->linkoutput;
        hook->impl->linkoutput = linkoutput_hook;
        hook->linkoutput_wrapped = hook->impl->linkoutput != hook->linkoutput_original;
    }

    if (hook->impl->input != NULL && !hook->input_wrapped) {
        hook->input_original = hook->impl->input;
        hook->impl->input = input_hook;
        hook->input_wrapped = hook->impl->input != hook->input_original;
        if (hook->input_wrapped) {
            gc_netif_rx_wrap_verified = true;
        }
    }

    return GC_OK;
}

gc_err_t gc_netif_init(void)
{
    esp_err_t err;

    if (gc_netif_ready) {
        return GC_OK;
    }

    err = esp_netif_init();
    if (err != ESP_OK) {
        GC_LOGE(gc_netif_tag, "esp_netif_init failed: %s", esp_err_to_name(err));
        return GC_ERR_IO;
    }

    err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        GC_LOGE(gc_netif_tag, "event loop create failed: %s", esp_err_to_name(err));
        return GC_ERR_IO;
    }

    gc_netif_sta_handle = esp_netif_create_default_wifi_sta();
    gc_netif_ap_handle = esp_netif_create_default_wifi_ap();

    if (gc_netif_sta_handle == NULL || gc_netif_ap_handle == NULL) {
        GC_LOGE(gc_netif_tag, "default wifi interfaces unavailable");
        return GC_ERR_NO_MEM;
    }

    gc_netif_ready = true;
    return GC_OK;
}

esp_netif_t *gc_netif_sta(void)
{
    return gc_netif_sta_handle;
}

esp_netif_t *gc_netif_ap(void)
{
    return gc_netif_ap_handle;
}

static gc_err_t gc_netif_wifi_start_once(void)
{
    esp_err_t err;

    if (gc_netif_wifi_started) {
        return GC_OK;
    }
    err = esp_wifi_start();
    if (err != ESP_OK) {
        GC_LOGE(gc_netif_tag, "esp_wifi_start failed: %s", esp_err_to_name(err));
        return GC_ERR_IO;
    }
    gc_netif_wifi_started = true;
    return GC_OK;
}

gc_err_t gc_netif_sta_start(void)
{
    wifi_mode_t mode;
    esp_err_t err;
    gc_err_t status;

    if (!gc_netif_ready || gc_netif_sta_handle == NULL) {
        return GC_ERR_NOT_FOUND;
    }

    mode = gc_netif_ap_running ? WIFI_MODE_APSTA : WIFI_MODE_STA;
    err = esp_wifi_set_mode(mode);
    if (err != ESP_OK) {
        GC_LOGE(gc_netif_tag, "station mode %d rejected: %s", (int)mode, esp_err_to_name(err));
        return GC_ERR_IO;
    }

    status = gc_netif_wifi_start_once();
    if (status != GC_OK) {
        return status;
    }

    gc_netif_sta_running = true;
    return GC_OK;
}

gc_err_t gc_netif_sta_stop(void)
{
    wifi_mode_t mode;
    esp_err_t err;

    if (!gc_netif_ready) {
        return GC_ERR_NOT_FOUND;
    }

    esp_wifi_disconnect();
    mode = gc_netif_ap_running ? WIFI_MODE_AP : WIFI_MODE_NULL;
    err = esp_wifi_set_mode(mode);
    if (err != ESP_OK) {
        GC_LOGE(gc_netif_tag, "station stop mode %d rejected: %s", (int)mode, esp_err_to_name(err));
        return GC_ERR_IO;
    }

    gc_netif_sta_running = false;
    return GC_OK;
}

gc_err_t gc_netif_ap_start(const char *ssid, const char *passphrase, uint8_t max_clients)
{
    wifi_config_t wifi_config;
    wifi_mode_t mode;
    esp_err_t err;
    gc_err_t status;
    size_t ssid_len;
    size_t ssid_copy;
    size_t pass_len;
    size_t pass_copy;

    if (!gc_netif_ready || gc_netif_ap_handle == NULL) {
        return GC_ERR_NOT_FOUND;
    }
    if (ssid == NULL || ssid[0] == '\0' || passphrase == NULL || max_clients == 0u) {
        return GC_ERR_INVALID_ARG;
    }

    mode = gc_netif_sta_running ? WIFI_MODE_APSTA : WIFI_MODE_AP;
    err = esp_wifi_set_mode(mode);
    if (err != ESP_OK) {
        GC_LOGE(gc_netif_tag, "soft-ap mode %d rejected: %s", (int)mode, esp_err_to_name(err));
        return GC_ERR_IO;
    }

    memset(&wifi_config, 0, sizeof(wifi_config));
    ssid_len = strlen(ssid);
    ssid_copy = ssid_len < sizeof(wifi_config.ap.ssid) ? ssid_len : sizeof(wifi_config.ap.ssid) - 1u;
    memcpy(wifi_config.ap.ssid, ssid, ssid_copy);
    wifi_config.ap.ssid[ssid_copy] = '\0';
    wifi_config.ap.ssid_len = (uint8_t)ssid_copy;

    if (passphrase[0] != '\0') {
        wifi_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
        pass_len = strlen(passphrase);
        pass_copy = pass_len < sizeof(wifi_config.ap.password) ? pass_len : sizeof(wifi_config.ap.password) - 1u;
        memcpy(wifi_config.ap.password, passphrase, pass_copy);
        wifi_config.ap.password[pass_copy] = '\0';
    } else {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    wifi_config.ap.max_connection = max_clients > (uint8_t)GC_NETIF_AP_CLIENTS_MAX
                                         ? (uint8_t)GC_NETIF_AP_CLIENTS_MAX
                                         : max_clients;

    err = esp_wifi_set_config(WIFI_IF_AP, &wifi_config);
    if (err != ESP_OK) {
        GC_LOGE(gc_netif_tag, "soft-ap config rejected: %s", esp_err_to_name(err));
        return GC_ERR_IO;
    }

    status = gc_netif_wifi_start_once();
    if (status != GC_OK) {
        return status;
    }

    gc_netif_ap_running = true;
    return GC_OK;
}

gc_err_t gc_netif_ap_stop(void)
{
    wifi_mode_t mode;
    esp_err_t err;

    if (!gc_netif_ready) {
        return GC_ERR_NOT_FOUND;
    }

    mode = gc_netif_sta_running ? WIFI_MODE_STA : WIFI_MODE_NULL;
    err = esp_wifi_set_mode(mode);
    if (err != ESP_OK) {
        GC_LOGE(gc_netif_tag, "soft-ap stop mode %d rejected: %s", (int)mode, esp_err_to_name(err));
        return GC_ERR_IO;
    }

    gc_netif_ap_running = false;
    return GC_OK;
}

bool gc_netif_sta_has_ip(void)
{
    esp_netif_ip_info_t ip_info;

    if (gc_netif_sta_handle == NULL) {
        return false;
    }
    if (esp_netif_get_ip_info(gc_netif_sta_handle, &ip_info) != ESP_OK) {
        return false;
    }
    return ip_info.ip.addr != 0u;
}

bool gc_netif_sta_link_up(void)
{
    struct netif *impl;

    if (gc_netif_sta_handle == NULL) {
        return false;
    }
    if (!esp_netif_is_netif_up(gc_netif_sta_handle)) {
        return false;
    }
    impl = gc_netif_find_impl(gc_netif_sta_handle);
    if (impl == NULL) {
        return false;
    }
    return netif_is_link_up(impl) != 0u;
}

gc_err_t gc_netif_sta_ipv4(esp_netif_ip_info_t *out)
{
    if (out == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    if (gc_netif_sta_handle == NULL) {
        return GC_ERR_NOT_FOUND;
    }
    if (esp_netif_get_ip_info(gc_netif_sta_handle, out) != ESP_OK) {
        return GC_ERR_IO;
    }
    return GC_OK;
}

gc_err_t gc_netif_sta_gateway_ipv4(uint32_t *out)
{
    esp_netif_ip_info_t ip_info;
    gc_err_t status;

    if (out == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    status = gc_netif_sta_ipv4(&ip_info);
    if (status != GC_OK) {
        return status;
    }
    *out = ip_info.gw.addr;
    return GC_OK;
}

gc_err_t gc_netif_ap_ipv4(esp_netif_ip_info_t *out)
{
    if (out == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    if (gc_netif_ap_handle == NULL) {
        return GC_ERR_NOT_FOUND;
    }
    if (esp_netif_get_ip_info(gc_netif_ap_handle, out) != ESP_OK) {
        return GC_ERR_IO;
    }
    return GC_OK;
}

gc_err_t gc_netif_install_counters(void)
{
    gc_err_t sta_status;
    gc_err_t ap_status;

    if (gc_netif_counters_installed) {
        return GC_OK;
    }
    if (gc_netif_sta_handle == NULL || gc_netif_ap_handle == NULL) {
        return GC_ERR_NOT_FOUND;
    }

    sta_status = gc_netif_hook_install(&gc_netif_sta_hook, gc_netif_sta_handle,
                                       gc_netif_sta_linkoutput_hook, gc_netif_sta_input_hook);
    if (sta_status != GC_OK) {
        GC_LOGE(gc_netif_tag, "station counter install failed");
    }

    ap_status = gc_netif_hook_install(&gc_netif_ap_hook, gc_netif_ap_handle,
                                      gc_netif_ap_linkoutput_hook, gc_netif_ap_input_hook);
    if (ap_status != GC_OK) {
        GC_LOGE(gc_netif_tag, "soft-ap counter install failed");
    }

    if (sta_status != GC_OK) {
        return sta_status;
    }
    if (ap_status != GC_OK) {
        return ap_status;
    }

    gc_netif_counters_installed = true;
    GC_LOGI(gc_netif_tag, "counters installed sta_rx=%d ap_rx=%d",
            (int)gc_netif_sta_hook.input_wrapped, (int)gc_netif_ap_hook.input_wrapped);
    return GC_OK;
}

bool gc_netif_rx_counter_wrapped(void)
{
    bool wrapped;

    portENTER_CRITICAL(&gc_netif_counter_lock);
    wrapped = gc_netif_rx_wrap_verified || gc_netif_rx_wrap_fired;
    portEXIT_CRITICAL(&gc_netif_counter_lock);
    return wrapped;
}

uint64_t gc_netif_sta_tx_bytes(void)
{
    return gc_netif_counter_read(&gc_netif_sta_tx_total);
}

uint64_t gc_netif_sta_rx_bytes(void)
{
    return gc_netif_counter_read(&gc_netif_sta_rx_total);
}

uint64_t gc_netif_uplink_bytes(void)
{
    uint64_t total;

    portENTER_CRITICAL(&gc_netif_counter_lock);
    total = gc_netif_sta_tx_total + gc_netif_sta_rx_total;
    portEXIT_CRITICAL(&gc_netif_counter_lock);
    return total;
}
