#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "esp_http_client.h"
#include "esp_timer.h"

#include "gc_log.h"
#include "gc_modem_api.h"
#include "gc_types.h"

#define GC_MODEM_TAG "modem_api"

#define GC_MODEM_DEFAULT_HOST "http://192.168.8.1"
#define GC_MODEM_PATH_LOGIN "/api/user/login"
#define GC_MODEM_PATH_STATUS "/api/monitoring/status"
#define GC_MODEM_PATH_SIGNAL "/api/device/signal"
#define GC_MODEM_PATH_CONTROL "/api/device/control"

#define GC_MODEM_CRED_MAX 64
#define GC_MODEM_URL_MAX 160
#define GC_MODEM_BODY_MAX 3072
#define GC_MODEM_COOKIE_MAX 160
#define GC_MODEM_SESSION_NAME_MAX 32
#define GC_MODEM_LOGIN_BODY_MAX 256
#define GC_MODEM_HTTP_TIMEOUT_MS 5000

typedef struct {
    char body[GC_MODEM_BODY_MAX];
    size_t body_len;
    bool body_truncated;
    char cookie[GC_MODEM_COOKIE_MAX + 1];
    int status;
    bool answered;
} gc_modem_response_t;

typedef struct {
    char host[GC_MODEM_URL_MAX];
    char user[GC_MODEM_CRED_MAX];
    char pass[GC_MODEM_CRED_MAX];
    char session_name[GC_MODEM_SESSION_NAME_MAX + 1];
    char session_value[GC_MODEM_TOKEN_MAX + 1];
    uint32_t session_acquired_s;
    uint32_t last_latency_ms;
    uint32_t failures;
    uint32_t last_ok_s;
    gc_modem_status_t last_status;
    bool ready;
    bool reachable;
    bool logging_in;
    gc_modem_response_t response;
} gc_modem_ctx_t;

static gc_modem_ctx_t s_modem;

static uint32_t modem_now_s(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

static bool modem_copy_bounded(char *dst, size_t cap, const char *src)
{
    if (dst == NULL || cap == 0) {
        return false;
    }
    dst[0] = '\0';
    if (src == NULL) {
        return true;
    }
    size_t i = 0;
    while (src[i] != '\0') {
        if (i + 1 >= cap) {
            dst[0] = '\0';
            return false;
        }
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return true;
}

static bool modem_eq_ci(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca + 32);
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb + 32);
        }
        if (ca != cb) {
            return false;
        }
    }
    return true;
}

static const char *modem_find_ci(const char *hay, size_t hay_len, const char *needle)
{
    size_t n = strlen(needle);
    if (n == 0 || hay == NULL || hay_len < n) {
        return NULL;
    }
    for (size_t i = 0; i + n <= hay_len; i++) {
        if (modem_eq_ci(hay + i, needle, n)) {
            return hay + i;
        }
    }
    return NULL;
}

static bool modem_body_has(const char *body, size_t len, const char *marker)
{
    return modem_find_ci(body, len, marker) != NULL;
}

static bool modem_is_value_separator(char c)
{
    return c == ':' || c == '"' || c == '\'' || c == '>' || c == '=' ||
           c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static bool modem_parse_int_after(const char *at, size_t remain, int32_t *out)
{
    size_t i = 0;
    while (i < remain && modem_is_value_separator(at[i])) {
        i++;
    }
    bool negative = false;
    if (i < remain && (at[i] == '-' || at[i] == '+')) {
        negative = at[i] == '-';
        i++;
    }
    if (i >= remain || at[i] < '0' || at[i] > '9') {
        return false;
    }
    int32_t value = 0;
    while (i < remain && at[i] >= '0' && at[i] <= '9') {
        int32_t digit = at[i] - '0';
        if (value > (INT32_MAX - digit) / 10) {
            value = INT32_MAX;
            break;
        }
        value = value * 10 + digit;
        i++;
    }
    *out = negative ? -value : value;
    return true;
}

static bool modem_is_text_char(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           c == '.' || c == '-' || c == '_';
}

static bool modem_parse_text_after(const char *at, size_t remain, char *out, size_t out_cap)
{
    size_t i = 0;
    while (i < remain && modem_is_value_separator(at[i])) {
        i++;
    }
    if (out == NULL || out_cap == 0) {
        return false;
    }
    out[0] = '\0';
    size_t w = 0;
    while (i < remain && modem_is_text_char(at[i]) && w + 1 < out_cap) {
        out[w] = at[i];
        w++;
        i++;
    }
    out[w] = '\0';
    return w > 0;
}

static bool modem_body_scan_int(const char *body, size_t len, const char *key, int32_t *out)
{
    const char *at = modem_find_ci(body, len, key);
    if (at == NULL) {
        return false;
    }
    size_t consumed = (size_t)(at - body) + strlen(key);
    return modem_parse_int_after(body + consumed, len - consumed, out);
}

static bool modem_body_scan_text(const char *body, size_t len, const char *key, char *out, size_t out_cap)
{
    const char *at = modem_find_ci(body, len, key);
    if (at == NULL) {
        return false;
    }
    size_t consumed = (size_t)(at - body) + strlen(key);
    return modem_parse_text_after(body + consumed, len - consumed, out, out_cap);
}

static int8_t modem_clamp_i8(int32_t v)
{
    if (v < -128) {
        return -128;
    }
    if (v > 127) {
        return 127;
    }
    return (int8_t)v;
}

static bool modem_cookie_name_is_session(const char *name)
{
    static const char *session_names[] = {
        "SessionID", "session_id", "Session", "session",
        "SessionToken", "sessiontoken", "Token", "token",
        "SID", "sid",
    };
    size_t name_len = strlen(name);
    for (size_t i = 0; i < sizeof(session_names) / sizeof(session_names[0]); i++) {
        size_t candidate_len = strlen(session_names[i]);
        if (name_len == candidate_len && modem_eq_ci(name, session_names[i], candidate_len)) {
            return true;
        }
    }
    return false;
}

static bool modem_split_cookie(const char *header_value,
                               char *name, size_t name_cap,
                               char *value, size_t value_cap)
{
    if (header_value == NULL || name == NULL || value == NULL) {
        return false;
    }
    name[0] = '\0';
    value[0] = '\0';
    size_t i = 0;
    while (header_value[i] != '\0' && header_value[i] != '=' && header_value[i] != ';' && i + 1 < name_cap) {
        name[i] = header_value[i];
        i++;
    }
    name[i] = '\0';
    if (header_value[i] != '=') {
        return false;
    }
    i++;
    size_t w = 0;
    while (header_value[i] != '\0' && header_value[i] != ';' && w + 1 < value_cap) {
        value[w] = header_value[i];
        w++;
        i++;
    }
    value[w] = '\0';
    return name[0] != '\0' && value[0] != '\0';
}

static void modem_store_cookie(gc_modem_response_t *resp, const char *header_value)
{
    if (resp == NULL || header_value == NULL) {
        return;
    }
    char chosen[GC_MODEM_SESSION_NAME_MAX + GC_MODEM_TOKEN_MAX + 2];
    char candidate[GC_MODEM_SESSION_NAME_MAX + GC_MODEM_TOKEN_MAX + 2];
    char name[GC_MODEM_SESSION_NAME_MAX + 1];
    char value[GC_MODEM_TOKEN_MAX + 1];
    bool chosen_is_session = false;

    chosen[0] = '\0';
    const char *cursor = header_value;
    while (*cursor != '\0') {
        while (*cursor == ' ' || *cursor == '\t') {
            cursor++;
        }
        const char *end = strchr(cursor, ';');
        size_t len = end != NULL ? (size_t)(end - cursor) : strlen(cursor);
        bool usable = false;
        if (len > 0 && len < sizeof(candidate)) {
            memcpy(candidate, cursor, len);
            candidate[len] = '\0';
            usable = modem_split_cookie(candidate, name, sizeof(name), value, sizeof(value));
        }
        if (usable) {
            if (modem_cookie_name_is_session(name)) {
                modem_copy_bounded(chosen, sizeof(chosen), candidate);
                chosen_is_session = true;
                break;
            }
            if (chosen[0] == '\0') {
                modem_copy_bounded(chosen, sizeof(chosen), candidate);
            }
        }
        if (end == NULL) {
            break;
        }
        cursor = end + 1;
    }
    if (chosen[0] == '\0') {
        return;
    }
    if (resp->cookie[0] != '\0' && !chosen_is_session) {
        return;
    }
    modem_copy_bounded(resp->cookie, sizeof(resp->cookie), chosen);
}

static esp_err_t modem_http_event(esp_http_client_event_t *evt)
{
    gc_modem_response_t *resp = (gc_modem_response_t *)evt->user_data;
    if (resp == NULL) {
        return ESP_OK;
    }
    switch (evt->event_id) {
    case HTTP_EVENT_ON_HEADER:
        if (evt->header_key != NULL && evt->header_value != NULL &&
            strncasecmp(evt->header_key, "Set-Cookie", 10) == 0) {
            modem_store_cookie(resp, evt->header_value);
        }
        break;
    case HTTP_EVENT_ON_DATA: {
        if (evt->data == NULL || evt->data_len == 0) {
            break;
        }
        size_t room = (sizeof(resp->body) - 1) - resp->body_len;
        size_t take = evt->data_len;
        if (take > room) {
            take = room;
            resp->body_truncated = true;
        }
        if (take > 0) {
            memcpy(resp->body + resp->body_len, evt->data, take);
            resp->body_len += take;
            resp->body[resp->body_len] = '\0';
        }
        break;
    }
    default:
        break;
    }
    return ESP_OK;
}

static void modem_attach_session(esp_http_client_handle_t client)
{
    if (client == NULL) {
        return;
    }
    if (s_modem.session_name[0] != '\0') {
        char cookie[GC_MODEM_SESSION_NAME_MAX + GC_MODEM_TOKEN_MAX + 4];
        int written = snprintf(cookie, sizeof(cookie), "%s=%s", s_modem.session_name, s_modem.session_value);
        if (written > 0 && (size_t)written < sizeof(cookie)) {
            esp_http_client_set_header(client, "Cookie", cookie);
        }
        return;
    }
    if (s_modem.session_value[0] != '\0') {
        esp_http_client_set_header(client, "__RequestVerificationToken", s_modem.session_value);
    }
}

static gc_err_t modem_call_once(esp_http_client_method_t method,
                                const char *path,
                                const char *content_type,
                                const char *payload,
                                gc_modem_response_t *resp)
{
    if (path == NULL || resp == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    memset(resp, 0, sizeof(*resp));

    char url[GC_MODEM_URL_MAX];
    int written = snprintf(url, sizeof(url), "%s%s", s_modem.host, path);
    if (written < 0 || (size_t)written >= sizeof(url)) {
        return GC_ERR_INVALID_ARG;
    }

    esp_http_client_config_t config = {
        .url = url,
        .method = method,
        .event_handler = modem_http_event,
        .user_data = resp,
        .timeout_ms = GC_MODEM_HTTP_TIMEOUT_MS,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        s_modem.failures++;
        return GC_ERR_NO_MEM;
    }

    if (payload != NULL) {
        if (content_type != NULL) {
            esp_http_client_set_header(client, "Content-Type", content_type);
        }
        if (esp_http_client_set_post_field(client, payload, (int)strlen(payload)) != ESP_OK) {
            esp_http_client_cleanup(client);
            s_modem.failures++;
            return GC_ERR_IO;
        }
    }
    modem_attach_session(client);

    uint64_t started_us = esp_timer_get_time();
    esp_err_t perform = esp_http_client_perform(client);
    uint64_t finished_us = esp_timer_get_time();
    s_modem.last_latency_ms = (uint32_t)((finished_us - started_us) / 1000ULL);
    int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (perform != ESP_OK) {
        s_modem.reachable = false;
        if (s_modem.failures < UINT32_MAX) {
            s_modem.failures++;
        }
        return GC_ERR_IO;
    }
    resp->status = status;
    resp->answered = true;
    s_modem.reachable = true;
    return GC_OK;
}

static bool modem_response_is_session_error(const gc_modem_response_t *resp)
{
    if (resp == NULL) {
        return false;
    }
    if (resp->status == 401 || resp->status == 403) {
        return true;
    }
    static const char *session_markers[] = {
        "sessionerror", "session error", "session_error", "invalid_session",
        "session expired", "sessionexpired", "notlogin", "125002",
    };
    for (size_t i = 0; i < sizeof(session_markers) / sizeof(session_markers[0]); i++) {
        if (modem_body_has(resp->body, resp->body_len, session_markers[i])) {
            return true;
        }
    }
    return false;
}

static gc_err_t modem_login(void);

static gc_err_t modem_call(esp_http_client_method_t method,
                           const char *path,
                           const char *content_type,
                           const char *payload,
                           gc_modem_response_t *resp)
{
    gc_err_t err = modem_call_once(method, path, content_type, payload, resp);
    if (err != GC_OK) {
        return err;
    }
    if (!modem_response_is_session_error(resp)) {
        return GC_OK;
    }
    if (s_modem.logging_in) {
        return GC_ERR_AUTH;
    }
    gc_modem_api_invalidate_token();
    s_modem.logging_in = true;
    gc_err_t login_err = modem_login();
    s_modem.logging_in = false;
    if (login_err != GC_OK) {
        GC_LOGW(GC_MODEM_TAG, "relogin failed err %d", (int)login_err);
        return GC_ERR_AUTH;
    }
    return modem_call_once(method, path, content_type, payload, resp);
}

static void modem_apply_login_response(const gc_modem_response_t *resp)
{
    char name[GC_MODEM_SESSION_NAME_MAX + 1];
    char value[GC_MODEM_TOKEN_MAX + 1];
    if (resp->cookie[0] != '\0' &&
        modem_split_cookie(resp->cookie, name, sizeof(name), value, sizeof(value))) {
        modem_copy_bounded(s_modem.session_name, sizeof(s_modem.session_name), name);
        modem_copy_bounded(s_modem.session_value, sizeof(s_modem.session_value), value);
    }
    if (s_modem.session_value[0] == '\0') {
        static const struct {
            const char *key;
            bool as_cookie;
        } session_body_keys[] = {
            {"SessionID", true},
            {"session_id", true},
            {"SessionToken", false},
            {"Token", false},
        };
        for (size_t i = 0; i < sizeof(session_body_keys) / sizeof(session_body_keys[0]); i++) {
            if (modem_body_scan_text(resp->body, resp->body_len, session_body_keys[i].key,
                                     value, sizeof(value))) {
                modem_copy_bounded(s_modem.session_value, sizeof(s_modem.session_value), value);
                modem_copy_bounded(s_modem.session_name, sizeof(s_modem.session_name),
                                   session_body_keys[i].as_cookie ? "SessionID" : "");
                break;
            }
        }
    }
    if (s_modem.session_value[0] != '\0') {
        s_modem.session_acquired_s = modem_now_s();
    }
}

static gc_err_t modem_login(void)
{
    char body[GC_MODEM_LOGIN_BODY_MAX];
    int written = snprintf(body, sizeof(body), "{\"Username\":\"%s\",\"Password\":\"%s\"}",
                           s_modem.user, s_modem.pass);
    if (written < 0 || (size_t)written >= sizeof(body)) {
        return GC_ERR_INVALID_ARG;
    }
    gc_err_t err = modem_call(HTTP_METHOD_POST, GC_MODEM_PATH_LOGIN, "application/json", body,
                              &s_modem.response);
    if (err != GC_OK) {
        GC_LOGW(GC_MODEM_TAG, "login transport err %d", (int)err);
        return err;
    }
    if (s_modem.response.status < 200 || s_modem.response.status >= 300) {
        GC_LOGW(GC_MODEM_TAG, "login rejected status %d", s_modem.response.status);
        return GC_ERR_AUTH;
    }
    modem_apply_login_response(&s_modem.response);
    if (s_modem.session_value[0] == '\0') {
        GC_LOGW(GC_MODEM_TAG, "login without session identifier");
    }
    return GC_OK;
}

static void modem_note_success(const gc_modem_status_t *status)
{
    s_modem.failures = 0;
    s_modem.last_ok_s = modem_now_s();
    if (status != NULL) {
        s_modem.last_status = *status;
    }
}

static void modem_note_failure(void)
{
    if (s_modem.failures < UINT32_MAX) {
        s_modem.failures++;
    }
}

static gc_err_t modem_parse_status(const gc_modem_response_t *resp, gc_modem_status_t *out)
{
    int32_t value = 0;
    uint32_t previous_ok_s = s_modem.last_ok_s;

    memset(out, 0, sizeof(*out));
    bool have_rsrp = modem_body_scan_int(resp->body, resp->body_len, "rsrp", &value);
    if (have_rsrp) {
        out->rsrp = modem_clamp_i8(value);
        out->valid = true;
    }
    if (modem_body_scan_int(resp->body, resp->body_len, "rsrq", &value)) {
        out->rsrq = modem_clamp_i8(value);
    }
    if (modem_body_scan_int(resp->body, resp->body_len, "sinr", &value)) {
        out->sinr = modem_clamp_i8(value);
    }
    if (modem_body_scan_int(resp->body, resp->body_len, "rssi", &value)) {
        out->rssi = value;
    }
    modem_body_scan_text(resp->body, resp->body_len, "plmn", out->plmn, sizeof(out->plmn));
    out->age_s = (previous_ok_s == 0) ? 0 : (modem_now_s() - previous_ok_s);

    if (!have_rsrp) {
        GC_LOGW(GC_MODEM_TAG, "no rsrp in %u byte body", (unsigned)resp->body_len);
        return GC_ERR_NOT_FOUND;
    }
    return GC_OK;
}

static gc_err_t modem_fetch_status(const char *path, gc_modem_status_t *out)
{
    gc_err_t err = modem_call(HTTP_METHOD_GET, path, NULL, NULL, &s_modem.response);
    if (err != GC_OK) {
        modem_note_failure();
        return err;
    }
    if (s_modem.response.status < 200 || s_modem.response.status >= 300) {
        GC_LOGW(GC_MODEM_TAG, "%s status %d", path, s_modem.response.status);
        modem_note_failure();
        return GC_ERR_IO;
    }
    if (s_modem.response.body_truncated) {
        GC_LOGD(GC_MODEM_TAG, "body truncated at %u bytes", (unsigned)s_modem.response.body_len);
    }
    gc_err_t parse_err = modem_parse_status(&s_modem.response, out);
    if (parse_err != GC_OK) {
        modem_note_failure();
        return parse_err;
    }
    modem_note_success(out);
    return GC_OK;
}

gc_err_t gc_modem_api_init(const char *host, const char *user, const char *pass)
{
    memset(&s_modem, 0, sizeof(s_modem));

    const char *chosen_host = (host != NULL && host[0] != '\0') ? host : GC_MODEM_DEFAULT_HOST;
    if (!modem_copy_bounded(s_modem.host, sizeof(s_modem.host), chosen_host)) {
        return GC_ERR_INVALID_ARG;
    }
    size_t host_len = strlen(s_modem.host);
    while (host_len > 0 && s_modem.host[host_len - 1] == '/') {
        s_modem.host[host_len - 1] = '\0';
        host_len--;
    }
    if (user == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    if (!modem_copy_bounded(s_modem.user, sizeof(s_modem.user), user)) {
        return GC_ERR_INVALID_ARG;
    }
    if (!modem_copy_bounded(s_modem.pass, sizeof(s_modem.pass), pass != NULL ? pass : "")) {
        return GC_ERR_INVALID_ARG;
    }
    s_modem.ready = true;
    return GC_OK;
}

void gc_modem_api_deinit(void)
{
    memset(&s_modem, 0, sizeof(s_modem));
}

gc_err_t gc_modem_api_poll(gc_modem_status_t *out)
{
    if (out == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    if (!s_modem.ready) {
        return GC_ERR_IO;
    }
    gc_err_t primary = modem_fetch_status(GC_MODEM_PATH_STATUS, out);
    if (primary == GC_OK) {
        return GC_OK;
    }
    gc_err_t variant = modem_fetch_status(GC_MODEM_PATH_SIGNAL, out);
    if (variant == GC_OK) {
        return GC_OK;
    }
    return primary;
}

gc_err_t gc_modem_api_reboot(void)
{
    if (!s_modem.ready) {
        return GC_ERR_IO;
    }
    static const char reboot_body[] = "{\"Control\":1}";
    gc_err_t err = modem_call(HTTP_METHOD_POST, GC_MODEM_PATH_CONTROL, "application/json",
                              reboot_body, &s_modem.response);
    if (err != GC_OK) {
        GC_LOGW(GC_MODEM_TAG, "reboot transport err %d", (int)err);
        modem_note_failure();
        return err;
    }
    if (s_modem.response.status < 200 || s_modem.response.status >= 300) {
        GC_LOGW(GC_MODEM_TAG, "reboot rejected status %d", s_modem.response.status);
        modem_note_failure();
        return GC_ERR_IO;
    }
    modem_note_success(NULL);
    GC_LOGW(GC_MODEM_TAG, "modem reboot accepted latency %u ms", (unsigned)s_modem.last_latency_ms);
    return GC_OK;
}

bool gc_modem_api_reachable(void)
{
    return s_modem.reachable;
}

uint32_t gc_modem_api_last_latency_ms(void)
{
    return s_modem.last_latency_ms;
}

uint32_t gc_modem_api_failures(void)
{
    return s_modem.failures;
}

uint32_t gc_modem_api_token_age_s(void)
{
    if (s_modem.session_value[0] == '\0') {
        return 0;
    }
    return modem_now_s() - s_modem.session_acquired_s;
}

gc_err_t gc_modem_api_invalidate_token(void)
{
    memset(s_modem.session_name, 0, sizeof(s_modem.session_name));
    memset(s_modem.session_value, 0, sizeof(s_modem.session_value));
    s_modem.session_acquired_s = 0;
    return GC_OK;
}
