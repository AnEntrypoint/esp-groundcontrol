#include "gc_portal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "esp_netif.h"
#include "esp_timer.h"

#include "gc_crypto.h"
#include "gc_dns_redirect.h"
#include "gc_gate.h"
#include "gc_http_portal.h"
#include "gc_log.h"
#include "gc_netif.h"
#include "gc_types.h"

#define GC_PORTAL_TAG "gc_portal"

#define GC_PORTAL_DIGITS_MAX 15u
#define GC_PORTAL_DIGITS_MIN 10u
#define GC_PORTAL_E164_PREFIX_LEN 1u
#define GC_PORTAL_LOOPBACK_NUMBER "+10000000000"

static const uint8_t k_loopback_test_mac[GC_MAC_LEN] = { 0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u };

static uint16_t s_http_port = GC_PORTAL_HTTP_PORT;
static bool s_initialised;

typedef struct {
    uint8_t pepper[GC_PEPPER_LEN];
    gc_key_t wanted;
    const gc_client_t *match;
} gc_portal_number_lookup_t;

static bool gc_portal_number_visitor(const gc_client_t *client, void *ctx)
{
    gc_portal_number_lookup_t *lookup = (gc_portal_number_lookup_t *)ctx;

    if (client == NULL) {
        return true;
    }

    if (gc_key_equal(&client->number_key, &lookup->wanted)) {
        lookup->match = client;
    }

    return true;
}

gc_err_t gc_portal_init(uint16_t http_port)
{
    s_http_port = (http_port == 0u) ? (uint16_t)GC_PORTAL_HTTP_PORT : http_port;
    s_initialised = true;

    GC_LOGI(GC_PORTAL_TAG, "initialised for http port %u", (unsigned)s_http_port);

    return GC_OK;
}

gc_err_t gc_portal_set_notice(const char *notice)
{
    return gc_http_portal_set_notice(notice);
}

gc_err_t gc_portal_dns_start(uint32_t ap_ip)
{
    gc_err_t err = gc_dns_redirect_start(ap_ip);
    if (err != GC_OK) {
        GC_LOGW(GC_PORTAL_TAG, "dns redirect start failed: %s", gc_err_name(err));
    }

    return err;
}

gc_err_t gc_portal_dns_stop(void)
{
    gc_dns_redirect_stop();

    return GC_OK;
}

gc_err_t gc_portal_start(const gc_config_t *cfg)
{
    if (cfg == NULL) {
        return GC_ERR_INVALID_ARG;
    }

    if (!s_initialised) {
        s_http_port = GC_PORTAL_HTTP_PORT;
    }

    (void)gc_http_portal_set_port(s_http_port);

    gc_err_t notice_err = gc_portal_set_notice(cfg->notice);
    if (notice_err != GC_OK) {
        GC_LOGW(GC_PORTAL_TAG, "notice rejected: %s", gc_err_name(notice_err));
    }

    esp_netif_ip_info_t ap_info;
    uint32_t ap_ip_network_order = 0u;
    if (gc_netif_ap_ipv4(&ap_info) == GC_OK) {
        ap_ip_network_order = ap_info.ip.addr;
    }

    if (ap_ip_network_order != 0u) {
        (void)gc_portal_dns_start(ap_ip_network_order);
    } else {
        GC_LOGW(GC_PORTAL_TAG, "ap address unknown, dns redirect not started");
    }

    return gc_http_portal_start(cfg);
}

gc_err_t gc_portal_stop(void)
{
    gc_http_portal_stop();
    gc_portal_dns_stop();

    return GC_OK;
}

bool gc_portal_running(void)
{
    return gc_http_portal_running();
}

bool gc_portal_dns_running(void)
{
    return gc_dns_redirect_running();
}

gc_err_t gc_portal_normalize_number(const char *raw, char *e164, size_t e164_len)
{
    if ((raw == NULL) || (e164 == NULL) || (e164_len == 0u)) {
        return GC_ERR_INVALID_ARG;
    }

    size_t pos = 0u;
    bool has_plus = false;

    while ((raw[pos] == ' ') || (raw[pos] == '\t')) {
        pos++;
    }

    if (raw[pos] == '+') {
        has_plus = true;
        pos++;
    } else if ((raw[pos] == '0') && (raw[pos + 1u] == '0')) {
        has_plus = true;
        pos += 2u;
    }

    char digits[GC_PORTAL_DIGITS_MAX + 1u];
    size_t digit_count = 0u;

    for (size_t i = pos; raw[i] != '\0'; i++) {
        char c = raw[i];
        if ((c < '0') || (c > '9')) {
            continue;
        }
        if (digit_count >= GC_PORTAL_DIGITS_MAX) {
            return GC_ERR_INVALID_ARG;
        }
        digits[digit_count] = c;
        digit_count++;
    }

    digits[digit_count] = '\0';

    if ((digit_count < GC_PORTAL_DIGITS_MIN) || (digit_count > GC_PORTAL_DIGITS_MAX)) {
        return GC_ERR_INVALID_ARG;
    }

    if (e164_len < (digit_count + GC_PORTAL_E164_PREFIX_LEN + 1u)) {
        return GC_ERR_INVALID_ARG;
    }

    e164[0] = '+';
    memcpy(&e164[1], digits, digit_count + 1u);

    if (!has_plus) {
        GC_LOGD(GC_PORTAL_TAG, "number normalised without country prefix");
    }

    return GC_OK;
}

static bool gc_portal_number_key(const char *e164, gc_key_t *out)
{
    uint8_t pepper[GC_PEPPER_LEN];

    if (gc_crypto_load_pepper(pepper) != GC_OK) {
        GC_LOGW(GC_PORTAL_TAG, "pepper unavailable");
        return false;
    }

    if (gc_crypto_number_key(pepper, e164, out) != GC_OK) {
        GC_LOGW(GC_PORTAL_TAG, "number key derivation failed");
        return false;
    }

    return true;
}

gc_portal_number_status_t gc_portal_number_status(const char *e164, uint32_t *blocked_remaining_s)
{
    if (blocked_remaining_s != NULL) {
        *blocked_remaining_s = 0u;
    }

    if (e164 == NULL) {
        return GC_PORTAL_NUMBER_INVALID;
    }

    gc_portal_number_lookup_t lookup;
    memset(&lookup, 0, sizeof(lookup));
    lookup.match = NULL;

    if (!gc_portal_number_key(e164, &lookup.wanted)) {
        return GC_PORTAL_NUMBER_INVALID;
    }

    (void)gc_gate_foreach(gc_portal_number_visitor, &lookup);

    const gc_client_t *client = lookup.match;

    if (client == NULL) {
        if (gc_gate_permanently_blocked_key(&lookup.wanted)) {
            return GC_PORTAL_NUMBER_BLOCKED;
        }
        return GC_PORTAL_NUMBER_INVALID;
    }

    uint32_t now_s = (uint32_t)(esp_timer_get_time() / 1000000ULL);

    if (client->permanent || (client->state == GC_CLIENT_PERMANENTLY_BLOCKED)) {
        return GC_PORTAL_NUMBER_BLOCKED;
    }

    if (client->blocked_until_s > now_s) {
        if (blocked_remaining_s != NULL) {
            *blocked_remaining_s = client->blocked_until_s - now_s;
        }
        return GC_PORTAL_NUMBER_BLOCKED;
    }

    if (client->state == GC_CLIENT_SOFT_BLOCKED) {
        return GC_PORTAL_NUMBER_BLOCKED;
    }

    if (client->state == GC_CLIENT_ALLOWED) {
        return GC_PORTAL_NUMBER_OK;
    }

    return GC_PORTAL_NUMBER_PENDING;
}

gc_err_t gc_portal_loopback_probe(bool *passed)
{
    if (passed == NULL) {
        return GC_ERR_INVALID_ARG;
    }

    *passed = false;

    gc_mac_t test_mac;
    memcpy(test_mac.b, k_loopback_test_mac, GC_MAC_LEN);

    return gc_http_portal_probe_login(GC_PORTAL_LOOPBACK_NUMBER, &test_mac, passed);
}

uint32_t gc_portal_login_attempts(void)
{
    return gc_http_portal_logins();
}

uint32_t gc_portal_served_notices(void)
{
    return gc_http_portal_notices_served();
}
