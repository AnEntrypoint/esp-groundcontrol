#include "gc_http_portal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/prot/ethernet.h"
#include "lwip/sockets.h"

#include "gc_gate.h"
#include "gc_log.h"
#include "gc_netif.h"
#include "gc_portal.h"
#include "gc_types.h"

#define GC_HTTP_TAG "gc_http"

#define GC_HTTP_ESCAPED_NOTICE_MAX ((GC_NOTICE_MAX * 6u) + 1u)
#define GC_HTTP_PAGE_MAX (GC_HTTP_ESCAPED_NOTICE_MAX + 2048u)
#define GC_HTTP_LINE_MAX 192u
#define GC_HTTP_QUERY_MAX 128u
#define GC_HTTP_STATUS_MAX 128u
#define GC_HTTP_PROBE_RESP_MAX 256u
#define GC_HTTP_DISCARD_CHUNK 64u
#define GC_HTTP_DEFAULT_WAIT_MS 15000u
#define GC_HTTP_MIN_REFRESH_S 2u
#define GC_HTTP_PROBE_TIMEOUT_S 2
#define GC_HTTP_LOOPBACK_ADDR 0x7F000001u
#define GC_HTTP_E164_MAX 17u
#define GC_HTTP_MAC_HEX_MAX ((GC_MAC_LEN * 2u) + 1u)
#define GC_HTTP_LAST_DIGITS_MAX 3u

static const char k_login_page[] =
    "<!DOCTYPE html>\n"
    "<html lang=\"en\">\n"
    "<head>\n"
    "<meta charset=\"utf-8\">\n"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
    "<title>Usage notice</title>\n"
    "</head>\n"
    "<body>\n"
    "<h1>Usage notice</h1>\n"
    "<p id=\"notice\">%s</p>\n"
    "%s\n"
    "<form id=\"login\" method=\"post\" action=\"/login\">\n"
    "<label for=\"number\">Phone number</label>\n"
    "<input id=\"number\" name=\"number\" type=\"tel\" inputmode=\"tel\" autocomplete=\"tel\""
    " placeholder=\"+27123456789\" required>\n"
    "<button type=\"submit\">Continue</button>\n"
    "</form>\n"
    "</body>\n"
    "</html>\n";

static const char k_notice_page[] =
    "<!DOCTYPE html>\n"
    "<html lang=\"en\">\n"
    "<head>\n"
    "<meta charset=\"utf-8\">\n"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
    "<title>Usage notice</title>\n"
    "</head>\n"
    "<body>\n"
    "<h1>Usage notice</h1>\n"
    "<p id=\"notice\">%s</p>\n"
    "<p><a href=\"/\">Continue</a></p>\n"
    "</body>\n"
    "</html>\n";

static const char k_waiting_page[] =
    "<!DOCTYPE html>\n"
    "<html lang=\"en\">\n"
    "<head>\n"
    "<meta charset=\"utf-8\">\n"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
    "<meta http-equiv=\"refresh\" content=\"%u\">\n"
    "<title>Waiting</title>\n"
    "</head>\n"
    "<body>\n"
    "<h1>Waiting for confirmation</h1>\n"
    "<p>The number ending in %s was sent for confirmation.</p>\n"
    "<p>This page reloads until the controller answers.</p>\n"
    "</body>\n"
    "</html>\n";

static const char k_blocked_page[] =
    "<!DOCTYPE html>\n"
    "<html lang=\"en\">\n"
    "<head>\n"
    "<meta charset=\"utf-8\">\n"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
    "<title>Blocked</title>\n"
    "</head>\n"
    "<body>\n"
    "<h1>Access blocked</h1>\n"
    "<p id=\"block\">%s</p>\n"
    "<p><a href=\"/\">Back</a></p>\n"
    "</body>\n"
    "</html>\n";

static const char k_allowed_page[] =
    "<!DOCTYPE html>\n"
    "<html lang=\"en\">\n"
    "<head>\n"
    "<meta charset=\"utf-8\">\n"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
    "<title>Connected</title>\n"
    "</head>\n"
    "<body>\n"
    "<h1>Access granted</h1>\n"
    "<p>This device may use the network.</p>\n"
    "</body>\n"
    "</html>\n";

typedef struct {
    bool blocked;
    bool permanent;
    uint32_t remaining_s;
} http_block_state_t;

typedef struct {
    bool in_use;
    gc_mac_t mac;
    gc_req_id_t req;
    uint64_t deadline_us;
} http_pending_reply_t;

static httpd_handle_t s_server;
static bool s_running;
static uint16_t s_port = GC_PORTAL_HTTP_PORT;
static uint32_t s_wait_ms = GC_HTTP_DEFAULT_WAIT_MS;
static char s_notice[GC_NOTICE_MAX + 1u];
static uint32_t s_requests;
static uint32_t s_logins;
static uint32_t s_notices_served;
static http_pending_reply_t s_pending[GC_MAX_PENDING_VERIFY];
static SemaphoreHandle_t s_pending_lock;

static uint32_t http_now_s(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

static void http_pending_lock(void)
{
    if (s_pending_lock != NULL) {
        (void)xSemaphoreTake(s_pending_lock, portMAX_DELAY);
    }
}

static void http_pending_unlock(void)
{
    if (s_pending_lock != NULL) {
        (void)xSemaphoreGive(s_pending_lock);
    }
}

static gc_err_t http_pending_add(const gc_mac_t *mac, const gc_req_id_t *req, uint32_t wait_ms)
{
    http_pending_lock();

    gc_err_t err = GC_ERR_FULL;
    for (size_t i = 0u; i < GC_MAX_PENDING_VERIFY; i++) {
        if (!s_pending[i].in_use) {
            s_pending[i].in_use = true;
            s_pending[i].req = *req;
            if (mac != NULL) {
                s_pending[i].mac = *mac;
            } else {
                memset(&s_pending[i].mac, 0, sizeof(s_pending[i].mac));
            }
            s_pending[i].deadline_us = esp_timer_get_time() + ((uint64_t)wait_ms * 1000ULL);
            err = GC_OK;
            break;
        }
    }

    http_pending_unlock();
    return err;
}

static bool http_req_id_equal(const gc_req_id_t *a, const gc_req_id_t *b)
{
    uint8_t diff = 0u;

    for (size_t i = 0u; i < GC_REQ_ID_LEN; i++) {
        diff |= (uint8_t)(a->b[i] ^ b->b[i]);
    }

    return diff == 0u;
}

static void http_pending_set_mac(const gc_req_id_t *req, const gc_mac_t *mac)
{
    http_pending_lock();

    for (size_t i = 0u; i < GC_MAX_PENDING_VERIFY; i++) {
        if (s_pending[i].in_use && http_req_id_equal(&s_pending[i].req, req)) {
            s_pending[i].mac = *mac;
            break;
        }
    }

    http_pending_unlock();
}

static void http_pending_release(const gc_mac_t *mac)
{
    http_pending_lock();

    for (size_t i = 0u; i < GC_MAX_PENDING_VERIFY; i++) {
        if (s_pending[i].in_use && gc_mac_equal(&s_pending[i].mac, mac)) {
            s_pending[i].in_use = false;
        }
    }

    http_pending_unlock();
}

static bool http_pending_active(const gc_mac_t *mac, uint32_t *remaining_ms)
{
    bool active = false;
    uint64_t now_us = esp_timer_get_time();

    http_pending_lock();

    for (size_t i = 0u; i < GC_MAX_PENDING_VERIFY; i++) {
        if (!s_pending[i].in_use || !gc_mac_equal(&s_pending[i].mac, mac)) {
            continue;
        }
        if (s_pending[i].deadline_us > now_us) {
            active = true;
            if (remaining_ms != NULL) {
                *remaining_ms = (uint32_t)((s_pending[i].deadline_us - now_us) / 1000ULL);
            }
            break;
        }
        s_pending[i].in_use = false;
    }

    http_pending_unlock();
    return active;
}

static int http_hex_value(char c)
{
    if ((c >= '0') && (c <= '9')) {
        return (int)(c - '0');
    }
    if ((c >= 'a') && (c <= 'f')) {
        return (int)(c - 'a') + 10;
    }
    if ((c >= 'A') && (c <= 'F')) {
        return (int)(c - 'A') + 10;
    }
    return -1;
}

static bool http_parse_mac_hex(const char *hex, gc_mac_t *out)
{
    if (strlen(hex) < (GC_MAC_LEN * 2u)) {
        return false;
    }

    for (size_t i = 0u; i < GC_MAC_LEN; i++) {
        int hi = http_hex_value(hex[(2u * i)]);
        int lo = http_hex_value(hex[(2u * i) + 1u]);
        if ((hi < 0) || (lo < 0)) {
            return false;
        }
        out->b[i] = (uint8_t)((hi << 4) | lo);
    }

    return true;
}

static void http_mac_hex(const gc_mac_t *mac, char *out, size_t out_len)
{
    if (out_len < (GC_MAC_LEN * 2u) + 1u) {
        return;
    }

    for (size_t i = 0u; i < GC_MAC_LEN; i++) {
        out[(2u * i)] = "0123456789abcdef"[(mac->b[i] >> 4) & 0x0Fu];
        out[(2u * i) + 1u] = "0123456789abcdef"[mac->b[i] & 0x0Fu];
    }
    out[GC_MAC_LEN * 2u] = '\0';
}

static size_t http_html_escape(const char *in, char *out, size_t out_len)
{
    size_t n = 0u;

    if (out_len == 0u) {
        return 0u;
    }

    for (size_t i = 0u; (in[i] != '\0') && ((n + 1u) < out_len); i++) {
        char c = in[i];
        const char *replacement = NULL;

        switch (c) {
        case '&':
            replacement = "&amp;";
            break;
        case '<':
            replacement = "&lt;";
            break;
        case '>':
            replacement = "&gt;";
            break;
        case '"':
            replacement = "&quot;";
            break;
        case '\'':
            replacement = "&#39;";
            break;
        default:
            break;
        }

        if (replacement == NULL) {
            out[n] = c;
            n++;
            continue;
        }

        size_t rlen = strlen(replacement);
        if ((n + rlen) >= out_len) {
            break;
        }
        memcpy(&out[n], replacement, rlen);
        n += rlen;
    }

    out[n] = '\0';
    return n;
}

static bool http_url_decode(const char *in, size_t in_len, char *out, size_t out_len)
{
    size_t n = 0u;

    if (out_len == 0u) {
        return false;
    }

    for (size_t i = 0u; (i < in_len) && ((n + 1u) < out_len); i++) {
        char c = in[i];

        if (c == '+') {
            out[n] = ' ';
            n++;
        } else if (c == '%') {
            if ((i + 2u) >= in_len) {
                return false;
            }
            int hi = http_hex_value(in[i + 1u]);
            int lo = http_hex_value(in[i + 2u]);
            if ((hi < 0) || (lo < 0)) {
                return false;
            }
            out[n] = (char)((hi << 4) | lo);
            n++;
            i += 2u;
        } else if ((c == '&') || (c == ';')) {
            break;
        } else {
            out[n] = c;
            n++;
        }
    }

    out[n] = '\0';
    return n > 0u;
}

static bool http_form_field(const char *body, size_t body_len, const char *key, char *out, size_t out_len)
{
    size_t key_len = strlen(key);

    if ((key_len == 0u) || (body_len < (key_len + 1u))) {
        return false;
    }

    for (size_t pos = 0u; (pos + key_len + 1u) <= body_len; pos++) {
        bool at_boundary = (pos == 0u) || (body[pos - 1u] == '&');
        if (!at_boundary) {
            continue;
        }
        if (memcmp(&body[pos], key, key_len) != 0) {
            continue;
        }
        if (body[pos + key_len] != '=') {
            continue;
        }

        size_t start = pos + key_len + 1u;
        size_t end = start;
        while ((end < body_len) && (body[end] != '&') && (body[end] != ';')) {
            end++;
        }

        return http_url_decode(&body[start], end - start, out, out_len);
    }

    return false;
}

static gc_err_t http_read_body(httpd_req_t *req, char *buf, size_t buf_len)
{
    size_t total = 0u;

    while (total < req->content_len) {
        if (total < buf_len) {
            int got = httpd_req_recv(req, &buf[total], buf_len - total);
            if (got <= 0) {
                return GC_ERR_IO;
            }
            total += (size_t)got;
            continue;
        }

        char discard[GC_HTTP_DISCARD_CHUNK];
        size_t want = req->content_len - total;
        if (want > sizeof(discard)) {
            want = sizeof(discard);
        }
        int got = httpd_req_recv(req, discard, want);
        if (got <= 0) {
            return GC_ERR_IO;
        }
        total += (size_t)got;
    }

    size_t terminator = (total < buf_len) ? total : (buf_len - 1u);
    buf[terminator] = '\0';

    return GC_OK;
}

static bool http_client_ip(httpd_req_t *req, uint32_t *ip_net)
{
    int fd = httpd_req_to_sockfd(req);
    if (fd < 0) {
        return false;
    }

    struct sockaddr_storage peer;
    socklen_t peer_len = (socklen_t)sizeof(peer);
    if (getpeername(fd, (struct sockaddr *)&peer, &peer_len) != 0) {
        return false;
    }

    if (peer.ss_family != AF_INET) {
        return false;
    }

    const struct sockaddr_in *peer_in = (const struct sockaddr_in *)&peer;
    *ip_net = peer_in->sin_addr.s_addr;

    return true;
}

static bool http_client_mac(httpd_req_t *req, gc_mac_t *out)
{
    uint32_t ip_net = 0u;
    if (!http_client_ip(req, &ip_net)) {
        return false;
    }

    struct netif *ap_netif = (struct netif *)esp_netif_get_netif_impl(gc_netif_ap());
    if (ap_netif == NULL) {
        return false;
    }

    ip4_addr_t target;
    target.addr = ip_net;

    struct eth_addr *eth = NULL;
    const ip4_addr_t *resolved = NULL;

    if (etharp_find_addr(ap_netif, &target, &eth, &resolved) < 0) {
        return false;
    }
    if (eth == NULL) {
        return false;
    }

    memcpy(out->b, eth->addr, GC_MAC_LEN);
    return true;
}

static http_block_state_t http_block_state(const gc_client_t *client)
{
    http_block_state_t state;
    state.blocked = false;
    state.permanent = false;
    state.remaining_s = 0u;

    if (client == NULL) {
        return state;
    }

    uint32_t now = http_now_s();

    if (client->permanent || (client->state == GC_CLIENT_PERMANENTLY_BLOCKED)) {
        state.blocked = true;
        state.permanent = true;
        return state;
    }

    if (client->blocked_until_s > now) {
        state.blocked = true;
        state.remaining_s = client->blocked_until_s - now;
        return state;
    }

    if (client->state == GC_CLIENT_SOFT_BLOCKED) {
        state.blocked = true;
    }

    return state;
}

static void http_block_line(const http_block_state_t *state, char *out, size_t out_len)
{
    if ((state == NULL) || !state->blocked) {
        out[0] = '\0';
        return;
    }

    if (state->permanent) {
        (void)snprintf(out, out_len, "<p class=\"block\">This number is permanently blocked.</p>");
        return;
    }

    if (state->remaining_s == 0u) {
        (void)snprintf(out, out_len, "<p class=\"block\">Access is blocked.</p>");
        return;
    }

    (void)snprintf(out, out_len, "<p class=\"block\">Blocked. Try again in %lu s.</p>",
                   (unsigned long)state->remaining_s);
}

static char *http_alloc_page(void)
{
    char *page = (char *)heap_caps_malloc(GC_HTTP_PAGE_MAX, MALLOC_CAP_SPIRAM);
    if (page == NULL) {
        page = (char *)heap_caps_malloc(GC_HTTP_PAGE_MAX, MALLOC_CAP_8BIT);
    }
    return page;
}

static esp_err_t http_send_html(httpd_req_t *req, const char *html)
{
    (void)httpd_resp_set_type(req, "text/html");
    (void)httpd_resp_set_hdr(req, "Cache-Control", "no-store, no-cache, must-revalidate");
    return httpd_resp_send(req, html, (ssize_t)strlen(html));
}

static esp_err_t http_serve_login(httpd_req_t *req, const http_block_state_t *block)
{
    char *page = http_alloc_page();
    if (page == NULL) {
        GC_LOGW(GC_HTTP_TAG, "page buffer unavailable");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR);
    }

    char escaped[GC_HTTP_ESCAPED_NOTICE_MAX];
    char line[GC_HTTP_LINE_MAX];

    (void)http_html_escape(s_notice, escaped, sizeof(escaped));
    http_block_line(block, line, sizeof(line));

    (void)snprintf(page, GC_HTTP_PAGE_MAX, k_login_page, escaped, line);

    esp_err_t err = http_send_html(req, page);
    heap_caps_free(page);

    return err;
}

static esp_err_t http_serve_blocked(httpd_req_t *req, const http_block_state_t *block)
{
    char *page = http_alloc_page();
    if (page == NULL) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR);
    }

    char line[GC_HTTP_LINE_MAX];
    http_block_line(block, line, sizeof(line));

    (void)snprintf(page, GC_HTTP_PAGE_MAX, k_blocked_page, line);

    esp_err_t err = http_send_html(req, page);
    heap_caps_free(page);

    return err;
}

static esp_err_t http_serve_notice(httpd_req_t *req)
{
    char *page = http_alloc_page();
    if (page == NULL) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR);
    }

    char escaped[GC_HTTP_ESCAPED_NOTICE_MAX];
    (void)http_html_escape(s_notice, escaped, sizeof(escaped));
    (void)snprintf(page, GC_HTTP_PAGE_MAX, k_notice_page, escaped);

    s_notices_served++;

    esp_err_t err = http_send_html(req, page);
    heap_caps_free(page);

    return err;
}

static void http_last_digits(const char *e164, char *out)
{
    size_t len = strlen(e164);

    if (len < 2u) {
        out[0] = '\0';
        return;
    }

    out[0] = e164[len - 2u];
    out[1] = e164[len - 1u];
    out[2] = '\0';
}

static esp_err_t http_get_root(httpd_req_t *req)
{
    s_requests++;

    gc_mac_t mac;
    if (!http_client_mac(req, &mac)) {
        GC_LOGW(GC_HTTP_TAG, "client mac unresolved");
        return http_serve_login(req, NULL);
    }

    gc_client_t *client = gc_gate_find(&mac);
    if (client == NULL) {
        (void)gc_gate_upsert(&mac, &client);
    }

    if (client != NULL) {
        if (!gc_gate_notice_served(&mac)) {
            (void)gc_gate_mark_notice_served(&mac);
            s_notices_served++;
        }

        if (client->state == GC_CLIENT_ALLOWED) {
            http_pending_release(&mac);
            return http_send_html(req, k_allowed_page);
        }

        http_block_state_t block = http_block_state(client);
        if (block.blocked) {
            http_pending_release(&mac);
            return http_serve_login(req, &block);
        }
    }

    uint32_t remaining_ms = 0u;
    if (http_pending_active(&mac, &remaining_ms)) {
        GC_LOGD(GC_HTTP_TAG, "refresh while pending");
    }

    return http_serve_login(req, NULL);
}

static esp_err_t http_get_notice(httpd_req_t *req)
{
    s_requests++;

    gc_mac_t mac;
    if (http_client_mac(req, &mac)) {
        gc_client_t *client = gc_gate_find(&mac);
        if (client == NULL) {
            (void)gc_gate_upsert(&mac, &client);
        }
        if (!gc_gate_notice_served(&mac)) {
            (void)gc_gate_mark_notice_served(&mac);
        }
    }

    return http_serve_notice(req);
}

static const char *http_state_name(gc_client_state_t state)
{
    switch (state) {
    case GC_CLIENT_NEW:
        return "new";
    case GC_CLIENT_PENDING:
        return "pending";
    case GC_CLIENT_ALLOWED:
        return "allowed";
    case GC_CLIENT_SOFT_BLOCKED:
    case GC_CLIENT_PERMANENTLY_BLOCKED:
        return "blocked";
    default:
        return "unknown";
    }
}

static esp_err_t http_get_status(httpd_req_t *req)
{
    s_requests++;

    const char *state = "unknown";
    unsigned long remaining = 0ul;
    const char *notice_served = "false";

    gc_mac_t mac;
    if (http_client_mac(req, &mac)) {
        const gc_client_t *client = gc_gate_find(&mac);
        if (client != NULL) {
            state = http_state_name(client->state);
            http_block_state_t block = http_block_state(client);
            remaining = (unsigned long)block.remaining_s;
            notice_served = gc_gate_notice_served(&mac) ? "true" : "false";
        }
    }

    char body[GC_HTTP_STATUS_MAX];
    int len = snprintf(body, sizeof(body),
                       "{\"state\":\"%s\",\"blocked_remaining_s\":%lu,\"notice_served\":%s}",
                       state, remaining, notice_served);
    if (len <= 0) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR);
    }

    (void)httpd_resp_set_type(req, "application/json");
    (void)httpd_resp_set_hdr(req, "Cache-Control", "no-store");

    return httpd_resp_send(req, body, (ssize_t)len);
}

static esp_err_t http_get_probe(httpd_req_t *req)
{
    s_requests++;

    const char *state = "none";

    char query[GC_HTTP_QUERY_MAX];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        char mac_hex[GC_HTTP_MAC_HEX_MAX];
        if (httpd_query_key_value(query, "mac", mac_hex, sizeof(mac_hex)) == ESP_OK) {
            gc_mac_t mac;
            if (http_parse_mac_hex(mac_hex, &mac)) {
                const gc_client_t *client = gc_gate_find(&mac);
                if (client != NULL) {
                    state = http_state_name(client->state);
                } else {
                    state = "new";
                }
            }
        }
    }

    char body[GC_HTTP_STATUS_MAX];
    int len = snprintf(body, sizeof(body), "OK state=%s\n", state);
    if (len <= 0) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR);
    }

    (void)httpd_resp_set_type(req, "text/plain");
    (void)httpd_resp_set_hdr(req, "Cache-Control", "no-store");

    return httpd_resp_send(req, body, (ssize_t)len);
}

static esp_err_t http_post_login(httpd_req_t *req)
{
    s_requests++;

    char body[GC_HTTP_BODY_MAX + 1u];
    if (http_read_body(req, body, sizeof(body)) != GC_OK) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST);
    }

    char raw[GC_HTTP_FIELD_MAX + 1u];
    if (!http_form_field(body, strlen(body), "number", raw, sizeof(raw))) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST);
    }

    s_logins++;

    gc_mac_t mac;
    if (!http_client_mac(req, &mac)) {
        GC_LOGW(GC_HTTP_TAG, "login without client mac");
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR);
    }

    char e164[GC_HTTP_E164_MAX];
    if (gc_portal_normalize_number(raw, e164, sizeof(e164)) != GC_OK) {
        GC_LOGW(GC_HTTP_TAG, "number rejected by normaliser");
        return http_serve_login(req, NULL);
    }

    gc_client_t *client = NULL;
    (void)gc_gate_upsert(&mac, &client);
    if (client != NULL && !gc_gate_notice_served(&mac)) {
        (void)gc_gate_mark_notice_served(&mac);
    }

    gc_req_id_t submitted;
    memset(&submitted, 0, sizeof(submitted));
    gc_err_t submitted_err = gc_gate_submit_number(&mac, e164, &submitted);
    if (submitted_err != GC_OK) {
        GC_LOGW(GC_HTTP_TAG, "submit failed: %s", gc_err_name(submitted_err));
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR);
    }

    http_block_state_t block = http_block_state(gc_gate_find(&mac));
    if (block.blocked) {
        http_pending_release(&mac);
        return http_serve_blocked(req, &block);
    }

    (void)gc_http_portal_reply_pending(submitted, s_wait_ms);
    http_pending_set_mac(&submitted, &mac);

    char *page = http_alloc_page();
    if (page == NULL) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR);
    }

    char last_digits[GC_HTTP_LAST_DIGITS_MAX];
    http_last_digits(e164, last_digits);

    uint32_t refresh_s = s_wait_ms / 1000u;
    if (refresh_s < GC_HTTP_MIN_REFRESH_S) {
        refresh_s = GC_HTTP_MIN_REFRESH_S;
    }

    (void)snprintf(page, GC_HTTP_PAGE_MAX, k_waiting_page, (unsigned)refresh_s, last_digits);

    esp_err_t err = http_send_html(req, page);
    heap_caps_free(page);

    return err;
}

static const httpd_uri_t k_handlers[] = {
    { .uri = "/", .method = HTTP_GET, .handler = http_get_root, .user_ctx = NULL },
    { .uri = "/notice", .method = HTTP_GET, .handler = http_get_notice, .user_ctx = NULL },
    { .uri = "/status", .method = HTTP_GET, .handler = http_get_status, .user_ctx = NULL },
    { .uri = "/probe", .method = HTTP_GET, .handler = http_get_probe, .user_ctx = NULL },
    { .uri = "/login", .method = HTTP_POST, .handler = http_post_login, .user_ctx = NULL },
    { .uri = "*", .method = HTTP_GET, .handler = http_get_root, .user_ctx = NULL },
};

gc_err_t gc_http_portal_set_port(uint16_t port)
{
    if (s_running) {
        return GC_ERR_BUSY;
    }

    s_port = (port == 0u) ? (uint16_t)GC_PORTAL_HTTP_PORT : port;
    return GC_OK;
}

gc_err_t gc_http_portal_set_notice(const char *notice)
{
    if (notice == NULL) {
        return GC_ERR_INVALID_ARG;
    }

    size_t len = strlen(notice);
    if (len > GC_NOTICE_MAX) {
        return GC_ERR_INVALID_ARG;
    }

    memcpy(s_notice, notice, len + 1u);
    return GC_OK;
}

gc_err_t gc_http_portal_reply_pending(gc_req_id_t req, uint32_t wait_ms)
{
    return http_pending_add(NULL, &req, wait_ms);
}

gc_err_t gc_http_portal_start(const gc_config_t *cfg)
{
    if (s_running) {
        return GC_ERR_BUSY;
    }

    if (cfg != NULL) {
        if (gc_http_portal_set_notice(cfg->notice) != GC_OK) {
            GC_LOGW(GC_HTTP_TAG, "notice too long, keeping previous notice");
        }
        s_wait_ms = (cfg->verification_timeout_ms == 0u) ? GC_HTTP_DEFAULT_WAIT_MS
                                                        : cfg->verification_timeout_ms;
    }

    if (s_pending_lock == NULL) {
        s_pending_lock = xSemaphoreCreateMutex();
        if (s_pending_lock == NULL) {
            GC_LOGE(GC_HTTP_TAG, "pending lock unavailable");
            return GC_ERR_NO_MEM;
        }
    }

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = s_port;
    config.max_open_sockets = GC_HTTP_MAX_CLIENTS;
    config.max_uri_handlers = (sizeof(k_handlers) / sizeof(k_handlers[0])) + 4u;
    config.uri_match_fn = httpd_uri_match_wildcard;
    config.lru_purge_enable = true;

    if (httpd_start(&s_server, &config) != ESP_OK) {
        GC_LOGE(GC_HTTP_TAG, "server start failed on port %u", (unsigned)s_port);
        return GC_ERR_IO;
    }

    for (size_t i = 0u; i < (sizeof(k_handlers) / sizeof(k_handlers[0])); i++) {
        esp_err_t err = httpd_register_uri_handler(s_server, &k_handlers[i]);
        if (err != ESP_OK) {
            GC_LOGE(GC_HTTP_TAG, "handler registration failed for %s", k_handlers[i].uri);
        }
    }

    s_running = true;
    GC_LOGI(GC_HTTP_TAG, "serving portal on port %u", (unsigned)s_port);

    return GC_OK;
}

void gc_http_portal_stop(void)
{
    if (!s_running) {
        return;
    }

    (void)httpd_stop(s_server);
    s_server = NULL;
    s_running = false;

    http_pending_lock();
    memset(s_pending, 0, sizeof(s_pending));
    http_pending_unlock();

    GC_LOGI(GC_HTTP_TAG, "stopped");
}

bool gc_http_portal_running(void)
{
    return s_running;
}

static bool http_status_is_ok(const char *response)
{
    const char *version = strstr(response, "HTTP/1.");
    if (version == NULL) {
        return false;
    }

    const char *space = strchr(version, ' ');
    if (space == NULL) {
        return false;
    }

    long code = strtol(space + 1, NULL, 10);
    return code == 200L;
}

static bool http_loopback_get(uint32_t ip_net, uint16_t port, const char *path)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        return false;
    }

    struct timeval timeout;
    timeout.tv_sec = GC_HTTP_PROBE_TIMEOUT_S;
    timeout.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_len = sizeof(addr);
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = ip_net;

    bool answered = false;

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        const uint8_t *octets = (const uint8_t *)&ip_net;
        char request[192];
        int len = snprintf(request, sizeof(request),
                           "GET %s HTTP/1.1\r\nHost: %u.%u.%u.%u\r\nConnection: close\r\n\r\n",
                           path, (unsigned)octets[0], (unsigned)octets[1],
                           (unsigned)octets[2], (unsigned)octets[3]);
        if ((len > 0) && (send(fd, request, (size_t)len, 0) > 0)) {
            char response[GC_HTTP_PROBE_RESP_MAX];
            int got = recv(fd, response, sizeof(response) - 1u, 0);
            if (got > 0) {
                response[got] = '\0';
                answered = http_status_is_ok(response);
            }
        }
    }

    closesocket(fd);
    return answered;
}

gc_err_t gc_http_portal_probe_login(const char *e164, gc_mac_t *test_mac, bool *passed)
{
    if (passed == NULL) {
        return GC_ERR_INVALID_ARG;
    }

    *passed = false;

    static const uint8_t k_default_test_mac[GC_MAC_LEN] = { 0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u };

    gc_mac_t mac;
    if ((test_mac != NULL) && !gc_mac_is_zero(test_mac)) {
        mac = *test_mac;
    } else {
        memcpy(mac.b, k_default_test_mac, GC_MAC_LEN);
        if (test_mac != NULL) {
            *test_mac = mac;
        }
    }

    char mac_hex[GC_HTTP_MAC_HEX_MAX];
    http_mac_hex(&mac, mac_hex, sizeof(mac_hex));

    char last_digits[GC_HTTP_LAST_DIGITS_MAX];
    if (e164 != NULL) {
        http_last_digits(e164, last_digits);
    } else {
        last_digits[0] = '\0';
    }

    char path[160];
    (void)snprintf(path, sizeof(path), "/probe?mac=%s&n=%s", mac_hex, last_digits);

    uint32_t targets[2];
    size_t target_count = 0u;
    targets[target_count++] = htonl(GC_HTTP_LOOPBACK_ADDR);

    esp_netif_ip_info_t ap_info;
    if (gc_netif_ap_ipv4(&ap_info) == GC_OK) {
        targets[target_count++] = ap_info.ip.addr;
    }

    for (size_t i = 0u; i < target_count; i++) {
        if (targets[i] == 0u) {
            continue;
        }
        if (http_loopback_get(targets[i], s_port, path)) {
            *passed = true;
            break;
        }
    }

    GC_LOGI(GC_HTTP_TAG, "loopback probe %s", *passed ? "passed" : "failed");

    return GC_OK;
}

uint32_t gc_http_portal_requests(void)
{
    return s_requests;
}

uint32_t gc_http_portal_logins(void)
{
    return s_logins;
}

uint32_t gc_http_portal_notices_served(void)
{
    return s_notices_served;
}
