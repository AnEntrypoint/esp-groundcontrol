#include "gc_config.h"
#include "gc_ota.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "esp_app_format.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/version.h"
#include "sdkconfig.h"

#include "gc_crypto.h"
#include "gc_link_monitor.h"
#include "gc_log.h"
#include "gc_modem_api.h"
#include "gc_nvs.h"
#include "gc_selftest.h"

#define GC_OTA_TAG "ota"

#define GC_OTA_BLOCKED_MAX 8u
#define GC_OTA_CHECK_PERIOD_S 3600u
#define GC_OTA_RETRY_LIMIT 3u
#define GC_OTA_RETRY_PAUSE_S 60u
#define GC_OTA_FAILED_PAUSE_S 3600u
#define GC_OTA_PREFLIGHT_RETRIES 12u
#define GC_OTA_PREFLIGHT_PAUSE_S 300u
#define GC_OTA_TRIAL_POLL_S 5u
#define GC_OTA_TRIAL_START_TIMEOUT_S 120u
#define GC_OTA_BACKOFF_S 86400u
#define GC_OTA_MIN_FREE_HEAP 60000u
#define GC_OTA_MANIFEST_TIMEOUT_MS 10000
#define GC_OTA_IMAGE_TIMEOUT_MS 15000
#define GC_OTA_CHUNK_SIZE 4096u
#define GC_OTA_TICK_BYTES 32768u
#define GC_OTA_PERSIST_INTERVAL 65536u
#define GC_OTA_READBACK_BLOCKS_PER_TICK 16u
#define GC_OTA_SIGNATURE_HEX_MAX 513u
#define GC_OTA_SIGNATURE_BYTES_MAX 256u
#define GC_OTA_PUBKEY_MAX 1024u
#define GC_OTA_DIGEST_LEN 32u
#define GC_OTA_EPOCH_FLOOR 1600000000u
#define GC_OTA_SECTOR_SIZE 4096u
#define GC_OTA_IMAGE_HEADER_MAGIC 0xE9u
#define GC_OTA_MINUTES_PER_DAY 1440u

#define GC_OTA_NVS_BLOCKED "blkver"
#define GC_OTA_NVS_LAST_FAIL_VERSION "otalfver"
#define GC_OTA_NVS_LAST_FAIL_AT "otalfats"
#define GC_OTA_NVS_PARTIAL_VERSION "otapartv"
#define GC_OTA_NVS_PARTIAL_RECEIVED "otapartr"
#define GC_OTA_NVS_PARTIAL_SHA "otaparts"
#define GC_OTA_NVS_PUBKEY "otakey"

#if MBEDTLS_VERSION_MAJOR >= 3
#define gc_sha256_start(ctx) mbedtls_sha256_starts((ctx), 0)
#define gc_sha256_update(ctx, in, len) mbedtls_sha256_update((ctx), (in), (len))
#define gc_sha256_finish(ctx, out) mbedtls_sha256_finish((ctx), (out))
#else
#define gc_sha256_start(ctx) mbedtls_sha256_starts_ret((ctx), 0)
#define gc_sha256_update(ctx, in, len) mbedtls_sha256_update_ret((ctx), (in), (len))
#define gc_sha256_finish(ctx, out) mbedtls_sha256_finish_ret((ctx), (out))
#endif

typedef enum {
    GC_OTA_VERIFY_DIGEST = 0,
    GC_OTA_VERIFY_SIGNATURE,
    GC_OTA_VERIFY_READBACK,
    GC_OTA_VERIFY_COMMIT,
} gc_ota_verify_step_t;

static gc_ota_state_t s_state = GC_OTA_IDLE;
static gc_ota_verify_step_t s_verify_step = GC_OTA_VERIFY_DIGEST;
static bool s_initialised;
static bool s_enabled;

static char s_manifest_url[GC_URL_MAX];
static uint32_t s_window_start_minute;
static uint32_t s_window_end_minute;
static int8_t s_min_rsrp;

static char s_manifest_body[GC_OTA_MANIFEST_MAX + 1];
static gc_ota_manifest_t s_manifest;
static bool s_manifest_valid;
static bool s_manifest_signed;
static char s_signature_hex[GC_OTA_SIGNATURE_HEX_MAX];

static uint32_t s_blocked[GC_OTA_BLOCKED_MAX];
static size_t s_blocked_count;

static uint32_t s_last_failure_version;
static uint32_t s_last_failure_at;

static uint32_t s_partial_version;
static uint32_t s_partial_received;
static char s_partial_sha[GC_OTA_SHA256_HEX];

static uint32_t s_running_version;
static uint32_t s_received;
static uint32_t s_downloaded_bytes;
static uint32_t s_expected_digest[GC_OTA_DIGEST_LEN / sizeof(uint32_t)];
static uint32_t s_verify_offset;
static uint32_t s_trial_entered_s;
static uint32_t s_next_action_s;
static uint32_t s_last_check_s;
static uint8_t s_retries;
static uint8_t s_preflight_retries;
static bool s_alarm_active;

static const esp_partition_t *s_target_partition;
static esp_ota_handle_t s_ota_handle;
static bool s_ota_open;
static esp_http_client_handle_t s_client;
static uint8_t *s_chunk;
static mbedtls_sha256_context s_image_sha;
static bool s_image_sha_started;
static mbedtls_sha256_context s_readback_sha;
static bool s_readback_sha_started;
static uint32_t s_persist_mark;

static uint32_t align_down_sector(uint32_t value)
{
    return value & ~(GC_OTA_SECTOR_SIZE - 1u);
}

static uint32_t align_up_sector(uint32_t value)
{
    return (value + GC_OTA_SECTOR_SIZE - 1u) & ~(GC_OTA_SECTOR_SIZE - 1u);
}

static uint32_t wall_clock_s(void)
{
    time_t now = time(NULL);
    if (now < (time_t)GC_OTA_EPOCH_FLOOR) {
        return 0u;
    }
    return (uint32_t)now;
}

static void transition(gc_ota_state_t state)
{
    if (state == s_state) {
        return;
    }
    GC_LOGD(GC_OTA_TAG, "state %s -> %s", gc_ota_state_name(s_state), gc_ota_state_name(state));
    s_state = state;
    s_next_action_s = 0u;
}

static void deferred(uint32_t now_s, uint32_t delay_s)
{
    s_next_action_s = now_s + delay_s;
}

static bool gate_open(uint32_t now_s)
{
    return (int32_t)(now_s - s_next_action_s) >= 0;
}

const char *gc_ota_state_name(gc_ota_state_t state)
{
    switch (state) {
        case GC_OTA_IDLE:
            return "IDLE";
        case GC_OTA_CHECKING:
            return "CHECKING";
        case GC_OTA_PREFLIGHT:
            return "PREFLIGHT";
        case GC_OTA_DOWNLOADING:
            return "DOWNLOADING";
        case GC_OTA_VERIFYING:
            return "VERIFYING";
        case GC_OTA_TRIAL:
            return "TRIAL";
        case GC_OTA_ROLLING_BACK:
            return "ROLLING_BACK";
        case GC_OTA_FAILED:
            return "FAILED";
        default:
            return "UNKNOWN";
    }
}

gc_ota_state_t gc_ota_state(void)
{
    return s_state;
}

static void blocked_load(void)
{
    uint32_t versions[GC_OTA_BLOCKED_MAX];
    size_t len = sizeof(versions);

    s_blocked_count = 0u;
    memset(s_blocked, 0, sizeof(s_blocked));
    if (gc_nvs_get_blob(GC_OTA_NVS_BLOCKED, versions, &len) != GC_OK || len != sizeof(versions)) {
        return;
    }
    for (size_t i = 0; i < GC_OTA_BLOCKED_MAX; i++) {
        if (versions[i] != 0u) {
            s_blocked[s_blocked_count++] = versions[i];
        }
    }
}

static void failure_load(void)
{
    uint32_t version = 0u;
    uint32_t at = 0u;

    if (gc_nvs_get_u32(GC_OTA_NVS_LAST_FAIL_VERSION, &version) == GC_OK) {
        s_last_failure_version = version;
    }
    if (gc_nvs_get_u32(GC_OTA_NVS_LAST_FAIL_AT, &at) == GC_OK) {
        s_last_failure_at = at;
    }
}

static void partial_load(void)
{
    uint32_t version = 0u;
    uint32_t received = 0u;
    size_t len = sizeof(s_partial_sha);

    s_partial_version = 0u;
    s_partial_received = 0u;
    s_partial_sha[0] = '\0';

    if (gc_nvs_get_u32(GC_OTA_NVS_PARTIAL_VERSION, &version) == GC_OK) {
        s_partial_version = version;
    }
    if (gc_nvs_get_u32(GC_OTA_NVS_PARTIAL_RECEIVED, &received) == GC_OK) {
        s_partial_received = received;
    }
    if (gc_nvs_get_str(GC_OTA_NVS_PARTIAL_SHA, s_partial_sha, &len) != GC_OK) {
        s_partial_sha[0] = '\0';
    }
}

static void partial_store(void)
{
    s_persist_mark = s_received;
    s_partial_version = s_manifest.version;
    s_partial_received = s_received;
    memcpy(s_partial_sha, s_manifest.sha256, GC_OTA_SHA256_HEX);

    (void)gc_nvs_set_u32(GC_OTA_NVS_PARTIAL_VERSION, s_partial_version);
    (void)gc_nvs_set_u32(GC_OTA_NVS_PARTIAL_RECEIVED, s_partial_received);
    (void)gc_nvs_set_str(GC_OTA_NVS_PARTIAL_SHA, s_partial_sha);
}

static void partial_clear(void)
{
    s_partial_version = 0u;
    s_partial_received = 0u;
    s_persist_mark = 0u;
    s_partial_sha[0] = '\0';

    (void)gc_nvs_erase_key(GC_OTA_NVS_PARTIAL_VERSION);
    (void)gc_nvs_erase_key(GC_OTA_NVS_PARTIAL_RECEIVED);
    (void)gc_nvs_erase_key(GC_OTA_NVS_PARTIAL_SHA);
}

static void failure_record(uint32_t version)
{
    s_last_failure_version = version;
    s_last_failure_at = wall_clock_s();
    (void)gc_nvs_set_u32(GC_OTA_NVS_LAST_FAIL_VERSION, s_last_failure_version);
    (void)gc_nvs_set_u32(GC_OTA_NVS_LAST_FAIL_AT, s_last_failure_at);
}

static uint32_t running_version_probe(void)
{
    const esp_app_desc_t *desc = esp_app_get_description();
    uint32_t parsed = 0u;

    if (desc != NULL) {
        parsed = (uint32_t)strtoul(desc->version, NULL, 10);
    }
    if (parsed == 0u) {
        parsed = (uint32_t)CONFIG_GC_FW_VERSION;
    }
    return parsed;
}

gc_err_t gc_ota_init(const char *manifest_url, uint32_t window_start_minute,
                     uint32_t window_end_minute, int8_t min_rsrp)
{
    size_t url_len;

    if (manifest_url == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    url_len = strlen(manifest_url);
    if (url_len >= GC_URL_MAX) {
        return GC_ERR_INVALID_ARG;
    }
    if (window_start_minute > GC_OTA_MINUTES_PER_DAY || window_end_minute > GC_OTA_MINUTES_PER_DAY) {
        return GC_ERR_INVALID_ARG;
    }

    memcpy(s_manifest_url, manifest_url, url_len + 1u);
    s_window_start_minute = window_start_minute;
    s_window_end_minute = window_end_minute;
    s_min_rsrp = min_rsrp;
    s_enabled = url_len > 0u;
    s_state = GC_OTA_IDLE;
    s_manifest_valid = false;

    blocked_load();
    failure_load();
    partial_load();
    s_running_version = running_version_probe();

    s_initialised = true;

    if (!s_enabled) {
        GC_LOGW(GC_OTA_TAG, "no manifest url configured, updates disabled");
        return GC_OK;
    }
    if (gc_ota_trial_pending()) {
        s_trial_entered_s = 0u;
        transition(GC_OTA_TRIAL);
        GC_LOGI(GC_OTA_TAG, "trial boot pending for version %lu", (unsigned long)s_running_version);
    }
    return GC_OK;
}

gc_slot_t gc_ota_running_slot(void)
{
    const esp_partition_t *running = esp_ota_get_running_partition();

    if (running == NULL) {
        return GC_SLOT_UNKNOWN;
    }
    switch (running->subtype) {
        case ESP_PARTITION_SUBTYPE_APP_FACTORY:
            return GC_SLOT_FACTORY;
        case ESP_PARTITION_SUBTYPE_APP_OTA_0:
            return GC_SLOT_OTA_0;
        case ESP_PARTITION_SUBTYPE_APP_OTA_1:
            return GC_SLOT_OTA_1;
        default:
            return GC_SLOT_UNKNOWN;
    }
}

bool gc_ota_trial_pending(void)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t ota_state = ESP_OTA_IMG_UNDEFINED;

    if (running == NULL) {
        return false;
    }
    if (esp_ota_get_state_partition(running, &ota_state) != ESP_OK) {
        return false;
    }
    return ota_state == ESP_OTA_IMG_PENDING_VERIFY;
}

uint32_t gc_ota_running_version(void)
{
    return s_running_version;
}

uint32_t gc_ota_downloaded_bytes(void)
{
    return s_downloaded_bytes;
}

uint32_t gc_ota_last_failure_version(void)
{
    return s_last_failure_version;
}

gc_err_t gc_ota_block_version(uint32_t version)
{
    if (version == 0u) {
        return GC_ERR_INVALID_ARG;
    }
    if (gc_ota_version_blocked(version)) {
        return GC_OK;
    }
    if (s_blocked_count < GC_OTA_BLOCKED_MAX) {
        s_blocked[s_blocked_count++] = version;
    } else {
        memmove(s_blocked, &s_blocked[1], sizeof(s_blocked[0]) * (GC_OTA_BLOCKED_MAX - 1u));
        s_blocked[GC_OTA_BLOCKED_MAX - 1u] = version;
    }
    GC_LOGW(GC_OTA_TAG, "version %lu blocked", (unsigned long)version);
    return gc_nvs_set_blob(GC_OTA_NVS_BLOCKED, s_blocked, sizeof(s_blocked));
}

bool gc_ota_version_blocked(uint32_t version)
{
    if (version == 0u) {
        return false;
    }
    for (size_t i = 0; i < s_blocked_count; i++) {
        if (s_blocked[i] == version) {
            return true;
        }
    }
    return false;
}

void gc_ota_set_alarm_active(bool active)
{
    s_alarm_active = active;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static bool hex_is_string(const char *hex, size_t len)
{
    if (hex == NULL) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        if (hex_nibble(hex[i]) < 0) {
            return false;
        }
    }
    return true;
}

static bool hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    if (!hex_is_string(hex, out_len * 2u)) {
        return false;
    }
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[2u * i]);
        int lo = hex_nibble(hex[2u * i + 1u]);
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static void digest_to_hex(const uint8_t *digest, char *out, size_t out_len)
{
    static const char digits[] = "0123456789abcdef";

    for (size_t i = 0; i < GC_OTA_DIGEST_LEN && (2u * i + 1u) < out_len; i++) {
        out[2u * i] = digits[(digest[i] >> 4) & 0x0Fu];
        out[2u * i + 1u] = digits[digest[i] & 0x0Fu];
    }
    out[GC_OTA_DIGEST_LEN * 2u] = '\0';
}

static gc_err_t manifest_fetch(void)
{
    esp_http_client_config_t config = {
        .url = s_manifest_url,
        .method = HTTP_METHOD_GET,
        .timeout_ms = GC_OTA_MANIFEST_TIMEOUT_MS,
        .buffer_size = GC_OTA_MANIFEST_MAX + 64,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    gc_err_t result = GC_ERR_IO;
    size_t total = 0u;

    if (client == NULL) {
        return GC_ERR_NO_MEM;
    }
    if (esp_http_client_open(client, 0) != ESP_OK) {
        goto out;
    }
    (void)esp_http_client_fetch_headers(client);
    if (esp_http_client_get_status_code(client) != 200) {
        GC_LOGW(GC_OTA_TAG, "manifest http status %d", esp_http_client_get_status_code(client));
        goto out;
    }
    while (total < GC_OTA_MANIFEST_MAX) {
        int read = esp_http_client_read(client, &s_manifest_body[total],
                                        (int)(GC_OTA_MANIFEST_MAX - total));
        if (read < 0) {
            goto out;
        }
        if (read == 0) {
            break;
        }
        total += (size_t)read;
    }
    s_manifest_body[total] = '\0';
    if (total == 0u || total >= GC_OTA_MANIFEST_MAX) {
        result = GC_ERR_FULL;
        goto out;
    }
    result = GC_OK;

out:
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return result;
}

static gc_err_t manifest_parse(void)
{
    cJSON *root = cJSON_Parse(s_manifest_body);
    gc_ota_manifest_t parsed;
    char signature_hex[GC_OTA_SIGNATURE_HEX_MAX];
    gc_err_t result = GC_ERR_IO;
    const cJSON *item;

    if (root == NULL) {
        return GC_ERR_IO;
    }
    memset(&parsed, 0, sizeof(parsed));
    signature_hex[0] = '\0';

    item = cJSON_GetObjectItemCaseSensitive(root, "version");
    if (!cJSON_IsNumber(item)) {
        goto out;
    }
    parsed.version = (uint32_t)item->valuedouble;

    item = cJSON_GetObjectItemCaseSensitive(root, "size");
    if (!cJSON_IsNumber(item)) {
        goto out;
    }
    parsed.size = (uint32_t)item->valuedouble;

    item = cJSON_GetObjectItemCaseSensitive(root, "sha256");
    if (!cJSON_IsString(item) || item->valuestring == NULL) {
        goto out;
    }
    if (strlen(item->valuestring) != GC_OTA_SHA256_HEX - 1u) {
        goto out;
    }
    if (!hex_is_string(item->valuestring, GC_OTA_SHA256_HEX - 1u)) {
        goto out;
    }
    memcpy(parsed.sha256, item->valuestring, GC_OTA_SHA256_HEX);

    item = cJSON_GetObjectItemCaseSensitive(root, "url");
    if (!cJSON_IsString(item) || item->valuestring == NULL) {
        goto out;
    }
    if (strlen(item->valuestring) == 0u || strlen(item->valuestring) >= GC_URL_MAX) {
        goto out;
    }
    snprintf(parsed.url, GC_URL_MAX, "%s", item->valuestring);

    item = cJSON_GetObjectItemCaseSensitive(root, "min_security_version");
    if (cJSON_IsNumber(item)) {
        parsed.min_security_version = (uint32_t)item->valuedouble;
    }

    item = cJSON_GetObjectItemCaseSensitive(root, "delta");
    if (cJSON_IsBool(item)) {
        parsed.delta = cJSON_IsTrue(item) ? true : false;
    }

    item = cJSON_GetObjectItemCaseSensitive(root, "delta_base_version");
    if (cJSON_IsNumber(item)) {
        parsed.delta_base_version = (uint32_t)item->valuedouble;
    }

    item = cJSON_GetObjectItemCaseSensitive(root, "signature");
    if (cJSON_IsString(item) && item->valuestring != NULL && strlen(item->valuestring) > 0u) {
        if (strlen(item->valuestring) >= GC_OTA_SIGNATURE_HEX_MAX) {
            goto out;
        }
        memcpy(signature_hex, item->valuestring, strlen(item->valuestring) + 1u);
    }

    s_manifest = parsed;
    s_manifest_valid = true;
    s_manifest_signed = signature_hex[0] != '\0';
    if (s_manifest_signed) {
        memcpy(s_signature_hex, signature_hex, sizeof(s_signature_hex));
    } else {
        s_signature_hex[0] = '\0';
    }
    result = GC_OK;

out:
    cJSON_Delete(root);
    return result;
}

static bool manifest_applicable(void)
{
    if (s_manifest.version == 0u || s_manifest.size == 0u) {
        GC_LOGW(GC_OTA_TAG, "manifest carries no usable version or size, skipped");
        return false;
    }
    if (gc_ota_version_blocked(s_manifest.version)) {
        GC_LOGI(GC_OTA_TAG, "version %lu is blocked, skipped", (unsigned long)s_manifest.version);
        return false;
    }
    if (s_manifest.version == s_running_version) {
        GC_LOGD(GC_OTA_TAG, "version %lu already running, skipped", (unsigned long)s_manifest.version);
        return false;
    }
    if (s_manifest.delta) {
        GC_LOGW(GC_OTA_TAG, "delta image version %lu base %lu not applicable, skipped",
                (unsigned long)s_manifest.version, (unsigned long)s_manifest.delta_base_version);
        return false;
    }
    return true;
}

static bool gate_free_heap(void)
{
    return esp_get_free_heap_size() >= (uint32_t)GC_OTA_MIN_FREE_HEAP;
}

static bool gate_slot(uint32_t size)
{
    const esp_partition_t *next = esp_ota_get_next_update_partition(NULL);
    const esp_partition_t *running = esp_ota_get_running_partition();

    if (next == NULL) {
        GC_LOGW(GC_OTA_TAG, "no inactive ota slot found");
        return false;
    }
    if (size == 0u || size > next->size) {
        GC_LOGW(GC_OTA_TAG, "image %lu does not fit slot %s (%lu)",
                (unsigned long)size, next->label, (unsigned long)next->size);
        return false;
    }
    if (running != NULL && next->address == running->address) {
        GC_LOGW(GC_OTA_TAG, "inactive slot resolves to the running slot");
        return false;
    }
    s_target_partition = next;
    return true;
}

static bool gate_signal(void)
{
    gc_modem_status_t status;

    memset(&status, 0, sizeof(status));
    if (gc_modem_api_poll(&status) != GC_OK || !status.valid) {
        GC_LOGW(GC_OTA_TAG, "no valid modem signal reading");
        return false;
    }
    if (status.rsrp < s_min_rsrp) {
        GC_LOGW(GC_OTA_TAG, "rsrp %d below %d", status.rsrp, s_min_rsrp);
        return false;
    }
    return true;
}

static bool gate_window(void)
{
    uint32_t epoch = wall_clock_s();
    time_t stamp;
    struct tm parts;
    uint32_t minute;

    if (epoch == 0u) {
        GC_LOGW(GC_OTA_TAG, "wall clock not set, update window unknown");
        return false;
    }
    memset(&parts, 0, sizeof(parts));
    stamp = (time_t)epoch;
    if (localtime_r(&stamp, &parts) == NULL) {
        return false;
    }
    minute = (uint32_t)parts.tm_hour * 60u + (uint32_t)parts.tm_min;
    if (s_window_start_minute == s_window_end_minute) {
        return true;
    }
    if (s_window_start_minute < s_window_end_minute) {
        return minute >= s_window_start_minute && minute < s_window_end_minute;
    }
    return minute >= s_window_start_minute || minute < s_window_end_minute;
}

static bool gate_no_alarm(void)
{
    if (s_alarm_active) {
        GC_LOGW(GC_OTA_TAG, "alarm active, update held");
        return false;
    }
    if (gc_link_monitor_fault_episode() != 0u) {
        GC_LOGW(GC_OTA_TAG, "link fault episode open, update held");
        return false;
    }
    return true;
}

static bool gate_backoff_clear(uint32_t version)
{
    uint32_t epoch = wall_clock_s();

    if (s_last_failure_version != version || s_last_failure_at == 0u) {
        return true;
    }
    if (epoch == 0u || epoch < s_last_failure_at) {
        GC_LOGW(GC_OTA_TAG, "wall clock unusable, backoff for version %lu held",
                (unsigned long)version);
        return false;
    }
    if (epoch - s_last_failure_at < GC_OTA_BACKOFF_S) {
        GC_LOGW(GC_OTA_TAG, "version %lu failed %lu s ago, backoff %lu s",
                (unsigned long)version, (unsigned long)(epoch - s_last_failure_at),
                (unsigned long)GC_OTA_BACKOFF_S);
        return false;
    }
    return true;
}

static bool gate_security_version(uint32_t required)
{
    const esp_app_desc_t *desc = esp_app_get_description();
    uint32_t running_secure = 0u;

    if (required == 0u) {
        return true;
    }
    if (desc != NULL) {
        running_secure = desc->secure_version;
    }
    if (running_secure < required) {
        GC_LOGW(GC_OTA_TAG, "running security version %lu below required %lu",
                (unsigned long)running_secure, (unsigned long)required);
        return false;
    }
    return true;
}

static void preflight_defer(uint32_t now_s, const char *reason)
{
    s_preflight_retries++;
    GC_LOGW(GC_OTA_TAG, "preflight held by %s for version %lu (%u/%u)", reason,
            (unsigned long)s_manifest.version, (unsigned)s_preflight_retries,
            (unsigned)GC_OTA_PREFLIGHT_RETRIES);

    if (s_preflight_retries >= GC_OTA_PREFLIGHT_RETRIES) {
        s_preflight_retries = 0u;
        s_last_check_s = now_s;
        transition(GC_OTA_IDLE);
        deferred(now_s, GC_OTA_CHECK_PERIOD_S);
        return;
    }
    deferred(now_s, GC_OTA_PREFLIGHT_PAUSE_S);
}

static gc_err_t retry_or_fail(uint32_t now_s, gc_ota_state_t retry_state, gc_err_t err,
                               const char *stage)
{
    s_retries++;
    if (s_retries < GC_OTA_RETRY_LIMIT) {
        GC_LOGW(GC_OTA_TAG, "%s failed err=%d, attempt %u of %u", stage, (int)err,
                (unsigned)s_retries, (unsigned)GC_OTA_RETRY_LIMIT);
        transition(retry_state);
        deferred(now_s, GC_OTA_RETRY_PAUSE_S);
        return err;
    }
    GC_LOGE(GC_OTA_TAG, "%s failed err=%d after %u attempts", stage, (int)err,
            (unsigned)s_retries);
    transition(GC_OTA_FAILED);
    deferred(now_s, GC_OTA_FAILED_PAUSE_S);
    return err;
}

static void http_close(void)
{
    if (s_client == NULL) {
        return;
    }
    esp_http_client_close(s_client);
    esp_http_client_cleanup(s_client);
    s_client = NULL;
}

static void chunk_release(void)
{
    if (s_chunk == NULL) {
        return;
    }
    heap_caps_free(s_chunk);
    s_chunk = NULL;
}

static void download_release(void)
{
    http_close();
    chunk_release();
    if (s_ota_open) {
        esp_ota_abort(s_ota_handle);
        s_ota_open = false;
    }
}

static bool sha_start(mbedtls_sha256_context *ctx, bool *started)
{
    mbedtls_sha256_init(ctx);
    if (gc_sha256_start(ctx) != 0) {
        return false;
    }
    *started = true;
    return true;
}

static void sha_release(mbedtls_sha256_context *ctx, bool *started)
{
    if (*started) {
        mbedtls_sha256_free(ctx);
        *started = false;
    }
}

static gc_err_t sha_prefix_from_flash(uint32_t length)
{
    uint32_t offset = 0u;

    while (offset < length) {
        uint32_t want = length - offset;
        int read_status;

        if (want > GC_OTA_CHUNK_SIZE) {
            want = GC_OTA_CHUNK_SIZE;
        }
        if (esp_partition_read(s_target_partition, offset, s_chunk, want) != ESP_OK) {
            return GC_ERR_IO;
        }
        read_status = gc_sha256_update(&s_image_sha, s_chunk, want);
        if (read_status != 0) {
            return GC_ERR_IO;
        }
        offset += want;
    }
    return GC_OK;
}

static bool partition_prefix_intact(uint32_t length)
{
    uint8_t magic = 0u;
    uint8_t tail = 0u;

    if (length == 0u) {
        return false;
    }
    if (esp_partition_read(s_target_partition, 0, &magic, 1u) != ESP_OK) {
        return false;
    }
    if (magic != GC_OTA_IMAGE_HEADER_MAGIC) {
        return false;
    }
    if (esp_partition_read(s_target_partition, length - 1u, &tail, 1u) != ESP_OK) {
        return false;
    }
    return tail != 0xFFu;
}

static gc_err_t download_prepare(void)
{
    uint32_t resume_at = 0u;
    uint32_t erase_from = 0u;
    uint32_t erase_size = 0u;
    esp_err_t err;

    if (s_manifest.size == 0u || s_manifest.size > s_target_partition->size) {
        return GC_ERR_INVALID_ARG;
    }

    err = esp_ota_begin(s_target_partition, OTA_WITH_SEQUENTIAL_WRITES, &s_ota_handle);
    if (err != ESP_OK) {
        GC_LOGE(GC_OTA_TAG, "esp_ota_begin failed %d", (int)err);
        return GC_ERR_IO;
    }
    s_ota_open = true;

    if (s_partial_version == s_manifest.version && s_partial_received > 0u &&
        s_partial_received < s_manifest.size &&
        strncmp(s_partial_sha, s_manifest.sha256, GC_OTA_SHA256_HEX) == 0) {
        resume_at = align_down_sector(s_partial_received);
        if (resume_at > 0u && !partition_prefix_intact(resume_at)) {
            GC_LOGW(GC_OTA_TAG, "partial image lost, restarting download");
            resume_at = 0u;
        }
    }

    erase_from = resume_at;
    erase_size = align_up_sector(s_manifest.size) - erase_from;
    if (erase_size > s_target_partition->size - erase_from) {
        erase_size = align_down_sector(s_target_partition->size - erase_from);
    }
    if (erase_size > 0u &&
        esp_partition_erase_range(s_target_partition, erase_from, erase_size) != ESP_OK) {
        GC_LOGE(GC_OTA_TAG, "slot erase from %lu size %lu failed", (unsigned long)erase_from,
                (unsigned long)erase_size);
        return GC_ERR_IO;
    }

    s_chunk = heap_caps_malloc(GC_OTA_CHUNK_SIZE, MALLOC_CAP_8BIT);
    if (s_chunk == NULL) {
        return GC_ERR_NO_MEM;
    }
    if (!sha_start(&s_image_sha, &s_image_sha_started)) {
        return GC_ERR_NO_MEM;
    }

    if (resume_at > 0u) {
        if (sha_prefix_from_flash(resume_at) != GC_OK) {
            GC_LOGW(GC_OTA_TAG, "partial image unreadable, restarting download");
            sha_release(&s_image_sha, &s_image_sha_started);
            if (!sha_start(&s_image_sha, &s_image_sha_started)) {
                return GC_ERR_NO_MEM;
            }
            if (esp_partition_erase_range(s_target_partition, 0u,
                                          align_up_sector(s_manifest.size)) != ESP_OK) {
                return GC_ERR_IO;
            }
            resume_at = 0u;
        }
    }

    s_received = resume_at;
    s_persist_mark = resume_at;
    if (resume_at > 0u) {
        GC_LOGI(GC_OTA_TAG, "resuming version %lu at %lu of %lu",
                (unsigned long)s_manifest.version, (unsigned long)resume_at,
                (unsigned long)s_manifest.size);
    }
    return GC_OK;
}

static gc_err_t download_open(void)
{
    esp_http_client_config_t config = {
        .url = s_manifest.url,
        .method = HTTP_METHOD_GET,
        .timeout_ms = GC_OTA_IMAGE_TIMEOUT_MS,
        .buffer_size = GC_OTA_CHUNK_SIZE,
    };
    char range[32];
    int status;

    if (s_received > 0u) {
        snprintf(range, sizeof(range), "bytes=%lu-", (unsigned long)s_received);
    } else {
        range[0] = '\0';
    }
    s_client = esp_http_client_init(&config);
    if (s_client == NULL) {
        return GC_ERR_NO_MEM;
    }
    if (range[0] != '\0' && esp_http_client_set_header(s_client, "Range", range) != ESP_OK) {
        http_close();
        return GC_ERR_IO;
    }
    if (esp_http_client_open(s_client, 0) != ESP_OK) {
        http_close();
        return GC_ERR_IO;
    }
    (void)esp_http_client_fetch_headers(s_client);
    status = esp_http_client_get_status_code(s_client);
    if (status == 200 && s_received > 0u) {
        GC_LOGW(GC_OTA_TAG, "server ignored range, restarting download");
        http_close();
        download_release();
        return download_prepare();
    }
    if (status != 200 && status != 206) {
        GC_LOGW(GC_OTA_TAG, "image http status %d", status);
        http_close();
        return GC_ERR_IO;
    }
    return GC_OK;
}

static gc_err_t image_write(size_t length)
{
    size_t padded = (length + 3u) & ~(size_t)3u;

    if (padded > length) {
        memset(s_chunk + length, 0xFF, padded - length);
    }
    if (esp_ota_write_with_offset(s_ota_handle, s_chunk, padded, s_received) != ESP_OK) {
        return GC_ERR_IO;
    }
    return GC_OK;
}

static gc_err_t signature_verify(const uint8_t *digest)
{
    uint8_t pem[GC_OTA_PUBKEY_MAX];
    uint8_t signature[GC_OTA_SIGNATURE_BYTES_MAX];
    size_t pem_len = sizeof(pem);
    size_t signature_len = 0u;
    mbedtls_pk_context key;
    int rc;

    if (!hex_to_bytes(s_signature_hex, signature, GC_OTA_SIGNATURE_BYTES_MAX)) {
        size_t hex_len = strlen(s_signature_hex);
        if ((hex_len % 2u) != 0u) {
            return GC_ERR_AUTH;
        }
        signature_len = hex_len / 2u;
        if (signature_len > GC_OTA_SIGNATURE_BYTES_MAX ||
            !hex_to_bytes(s_signature_hex, signature, signature_len)) {
            return GC_ERR_AUTH;
        }
    } else {
        signature_len = GC_OTA_SIGNATURE_BYTES_MAX;
    }

    memset(pem, 0, sizeof(pem));
    if (gc_nvs_get_blob(GC_OTA_NVS_PUBKEY, pem, &pem_len) != GC_OK || pem_len == 0u) {
        GC_LOGE(GC_OTA_TAG, "signed manifest but no public key provisioned");
        return GC_ERR_NOT_FOUND;
    }
    if (pem_len >= sizeof(pem)) {
        pem_len = sizeof(pem) - 1u;
    }
    pem[pem_len] = '\0';

    mbedtls_pk_init(&key);
    rc = mbedtls_pk_parse_public_key(&key, pem, pem_len + 1u);
    if (rc != 0) {
        mbedtls_pk_free(&key);
        GC_LOGE(GC_OTA_TAG, "provisioned public key unparsable %d", rc);
        return GC_ERR_AUTH;
    }
    rc = mbedtls_pk_verify(&key, MBEDTLS_MD_SHA256, digest, GC_OTA_DIGEST_LEN, signature,
                           signature_len);
    mbedtls_pk_free(&key);
    if (rc != 0) {
        GC_LOGE(GC_OTA_TAG, "manifest signature verification failed %d", rc);
        return GC_ERR_AUTH;
    }
    return GC_OK;
}

static void discard_and_block(uint32_t now_s, uint32_t version, const char *reason)
{
    download_release();
    sha_release(&s_image_sha, &s_image_sha_started);
    sha_release(&s_readback_sha, &s_readback_sha_started);
    partial_clear();
    (void)gc_ota_block_version(version);
    failure_record(version);
    s_manifest_valid = false;
    GC_LOGE(GC_OTA_TAG, "version %lu discarded: %s", (unsigned long)version, reason);
    transition(GC_OTA_FAILED);
    deferred(now_s, GC_OTA_FAILED_PAUSE_S);
}

static gc_err_t verify_readback(uint32_t now_s)
{
    uint16_t blocks = GC_OTA_READBACK_BLOCKS_PER_TICK;
    char hex[GC_OTA_SHA256_HEX];
    uint8_t digest[GC_OTA_DIGEST_LEN];

    if (!s_readback_sha_started) {
        if (!sha_start(&s_readback_sha, &s_readback_sha_started)) {
            discard_and_block(now_s, s_manifest.version, "readback hash unavailable");
            return GC_ERR_NO_MEM;
        }
    }

    while (blocks > 0u && s_verify_offset < s_manifest.size) {
        uint32_t want = s_manifest.size - s_verify_offset;

        if (want > GC_OTA_CHUNK_SIZE) {
            want = GC_OTA_CHUNK_SIZE;
        }
        if (esp_partition_read(s_target_partition, s_verify_offset, s_chunk, want) != ESP_OK) {
            discard_and_block(now_s, s_manifest.version, "readback failed");
            return GC_ERR_IO;
        }
        if (gc_sha256_update(&s_readback_sha, s_chunk, want) != 0) {
            discard_and_block(now_s, s_manifest.version, "readback hash failed");
            return GC_ERR_IO;
        }
        s_verify_offset += want;
        blocks--;
    }

    if (s_verify_offset < s_manifest.size) {
        return GC_OK;
    }

    if (gc_sha256_finish(&s_readback_sha, digest) != 0) {
        discard_and_block(now_s, s_manifest.version, "readback hash failed");
        return GC_ERR_IO;
    }
    sha_release(&s_readback_sha, &s_readback_sha_started);
    digest_to_hex(digest, hex, sizeof(hex));
    if (!gc_crypto_constant_time_equal(hex, s_manifest.sha256, GC_OTA_SHA256_HEX - 1u)) {
        discard_and_block(now_s, s_manifest.version, "readback hash mismatch");
        return GC_ERR_AUTH;
    }

    GC_LOGI(GC_OTA_TAG, "version %lu verified in slot %s", (unsigned long)s_manifest.version,
            s_target_partition->label);
    s_verify_step = GC_OTA_VERIFY_COMMIT;
    return GC_OK;
}

static gc_err_t verify_commit(uint32_t now_s)
{
    esp_err_t err;

    err = esp_ota_end(s_ota_handle);
    s_ota_open = false;
    if (err != ESP_OK) {
        discard_and_block(now_s, s_manifest.version, "image rejected by esp_ota_end");
        return GC_ERR_AUTH;
    }
    err = esp_ota_set_boot_partition(s_target_partition);
    if (err != ESP_OK) {
        GC_LOGE(GC_OTA_TAG, "esp_ota_set_boot_partition failed %d", (int)err);
        discard_and_block(now_s, s_manifest.version, "boot partition not set");
        return GC_ERR_IO;
    }

    chunk_release();
    sha_release(&s_image_sha, &s_image_sha_started);
    partial_clear();
    s_manifest_valid = false;
    GC_LOGI(GC_OTA_TAG, "rebooting into trial of version %lu", (unsigned long)s_manifest.version);
    esp_restart();
    return GC_OK;
}

static gc_err_t tick_idle(uint32_t now_s)
{
    if (gc_ota_trial_pending()) {
        s_trial_entered_s = now_s;
        transition(GC_OTA_TRIAL);
        return GC_OK;
    }
    if (s_last_check_s == 0u) {
        s_last_check_s = now_s;
        deferred(now_s, GC_OTA_CHECK_PERIOD_S);
        return GC_OK;
    }
    if ((uint32_t)(now_s - s_last_check_s) < GC_OTA_CHECK_PERIOD_S) {
        deferred(now_s, s_last_check_s + GC_OTA_CHECK_PERIOD_S - now_s);
        return GC_OK;
    }
    s_last_check_s = now_s;
    s_retries = 0u;
    transition(GC_OTA_CHECKING);
    return GC_OK;
}

static gc_err_t tick_checking(uint32_t now_s)
{
    gc_err_t err = manifest_fetch();

    if (err != GC_OK) {
        return retry_or_fail(now_s, GC_OTA_CHECKING, err, "manifest fetch");
    }
    err = manifest_parse();
    if (err != GC_OK) {
        return retry_or_fail(now_s, GC_OTA_CHECKING, err, "manifest parse");
    }
    if (!manifest_applicable()) {
        s_manifest_valid = false;
        s_last_check_s = now_s;
        transition(GC_OTA_IDLE);
        deferred(now_s, GC_OTA_CHECK_PERIOD_S);
        return GC_OK;
    }
    GC_LOGI(GC_OTA_TAG, "candidate version %lu size %lu", (unsigned long)s_manifest.version,
            (unsigned long)s_manifest.size);
    s_preflight_retries = 0u;
    transition(GC_OTA_PREFLIGHT);
    return GC_OK;
}

static gc_err_t tick_preflight(uint32_t now_s)
{
    if (!s_manifest_valid) {
        s_last_check_s = now_s;
        transition(GC_OTA_IDLE);
        deferred(now_s, GC_OTA_CHECK_PERIOD_S);
        return GC_ERR_BUSY;
    }
    if (!gate_free_heap()) {
        preflight_defer(now_s, "free heap");
        return GC_OK;
    }
    if (!gate_slot(s_manifest.size)) {
        preflight_defer(now_s, "slot size");
        return GC_OK;
    }
    if (!gate_signal()) {
        preflight_defer(now_s, "modem signal");
        return GC_OK;
    }
    if (!gate_window()) {
        preflight_defer(now_s, "time window");
        return GC_OK;
    }
    if (!gate_no_alarm()) {
        preflight_defer(now_s, "active alarm");
        return GC_OK;
    }
    if (!gate_backoff_clear(s_manifest.version)) {
        preflight_defer(now_s, "failure backoff");
        return GC_OK;
    }
    if (!gate_security_version(s_manifest.min_security_version)) {
        preflight_defer(now_s, "security version");
        return GC_OK;
    }

    s_received = 0u;
    s_downloaded_bytes = 0u;
    if (download_prepare() != GC_OK) {
        return retry_or_fail(now_s, GC_OTA_PREFLIGHT, GC_ERR_IO, "download prepare");
    }
    transition(GC_OTA_DOWNLOADING);
    return GC_OK;
}

static gc_err_t tick_downloading(uint32_t now_s)
{
    uint32_t budget = GC_OTA_TICK_BYTES;

    if (!s_manifest_valid || s_target_partition == NULL || !s_ota_open || s_chunk == NULL) {
        transition(GC_OTA_FAILED);
        deferred(now_s, GC_OTA_FAILED_PAUSE_S);
        return GC_ERR_BUSY;
    }
    if (s_client == NULL) {
        gc_err_t err = download_open();
        if (err != GC_OK) {
            return retry_or_fail(now_s, GC_OTA_DOWNLOADING, err, "image open");
        }
    }

    while (budget > 0u && s_received < s_manifest.size) {
        uint32_t remaining = s_manifest.size - s_received;
        int want = (int)GC_OTA_CHUNK_SIZE;
        int read;

        if ((uint32_t)want > budget) {
            want = (int)budget;
        }
        if ((uint32_t)want > remaining) {
            want = (int)remaining;
        }
        read = esp_http_client_read(s_client, (char *)s_chunk, want);
        if (read < 0) {
            http_close();
            return retry_or_fail(now_s, GC_OTA_DOWNLOADING, GC_ERR_IO, "image read");
        }
        if (read == 0) {
            break;
        }
        if (gc_sha256_update(&s_image_sha, s_chunk, (size_t)read) != 0) {
            http_close();
            return retry_or_fail(now_s, GC_OTA_DOWNLOADING, GC_ERR_IO, "image hash");
        }
        if (image_write((size_t)read) != GC_OK) {
            http_close();
            return retry_or_fail(now_s, GC_OTA_DOWNLOADING, GC_ERR_IO, "image write");
        }
        s_received += (uint32_t)read;
        s_downloaded_bytes += (uint32_t)read;
        budget -= (uint32_t)read;
        if (s_received - s_persist_mark >= GC_OTA_PERSIST_INTERVAL) {
            partial_store();
        }
    }

    if (s_received < s_manifest.size) {
        http_close();
        partial_store();
        return retry_or_fail(now_s, GC_OTA_DOWNLOADING, GC_ERR_TIMEOUT, "image incomplete");
    }

    http_close();
    partial_store();
    s_verify_step = GC_OTA_VERIFY_DIGEST;
    transition(GC_OTA_VERIFYING);
    return GC_OK;
}

static gc_err_t tick_verifying(uint32_t now_s)
{
    uint8_t digest[GC_OTA_DIGEST_LEN];
    char hex[GC_OTA_SHA256_HEX];

    switch (s_verify_step) {
        case GC_OTA_VERIFY_DIGEST:
            if (gc_sha256_finish(&s_image_sha, digest) != 0) {
                discard_and_block(now_s, s_manifest.version, "image hash failed");
                return GC_ERR_IO;
            }
            sha_release(&s_image_sha, &s_image_sha_started);
            memcpy(s_expected_digest, digest, sizeof(s_expected_digest));
            digest_to_hex(digest, hex, sizeof(hex));
            if (!gc_crypto_constant_time_equal(hex, s_manifest.sha256, GC_OTA_SHA256_HEX - 1u)) {
                discard_and_block(now_s, s_manifest.version, "image hash mismatch");
                return GC_ERR_AUTH;
            }
            s_verify_step = s_manifest_signed ? GC_OTA_VERIFY_SIGNATURE : GC_OTA_VERIFY_READBACK;
            s_verify_offset = 0u;
            return GC_OK;

        case GC_OTA_VERIFY_SIGNATURE: {
            gc_err_t err = signature_verify((const uint8_t *)s_expected_digest);
            if (err == GC_ERR_NOT_FOUND) {
                download_release();
                sha_release(&s_readback_sha, &s_readback_sha_started);
                partial_clear();
                s_manifest_valid = false;
                transition(GC_OTA_FAILED);
                deferred(now_s, GC_OTA_FAILED_PAUSE_S);
                return err;
            }
            if (err != GC_OK) {
                discard_and_block(now_s, s_manifest.version, "signature mismatch");
                return err;
            }
            s_verify_step = GC_OTA_VERIFY_READBACK;
            s_verify_offset = 0u;
            return GC_OK;
        }

        case GC_OTA_VERIFY_READBACK:
            return verify_readback(now_s);

        case GC_OTA_VERIFY_COMMIT:
            return verify_commit(now_s);

        default:
            discard_and_block(now_s, s_manifest.version, "verify step unknown");
            return GC_ERR_BUSY;
    }
}

static gc_err_t tick_trial(uint32_t now_s)
{
    gc_selftest_result_t result = gc_selftest_result();

    if (s_trial_entered_s == 0u) {
        s_trial_entered_s = now_s;
    }
    if (result == GC_SELFTEST_PASSED) {
        GC_LOGI(GC_OTA_TAG, "trial self-test passed");
        return gc_ota_mark_valid();
    }
    if (result == GC_SELFTEST_FAILED) {
        const char *failed = gc_selftest_failed_criterion();
        GC_LOGE(GC_OTA_TAG, "trial self-test failed on %s", failed != NULL ? failed : "unknown");
        (void)gc_ota_block_version(s_running_version);
        failure_record(s_running_version);
        transition(GC_OTA_ROLLING_BACK);
        return GC_OK;
    }
    if (result == GC_SELFTEST_NOT_RUN && now_s - s_trial_entered_s > GC_OTA_TRIAL_START_TIMEOUT_S) {
        GC_LOGE(GC_OTA_TAG, "trial self-test never started, rolling back");
        (void)gc_ota_block_version(s_running_version);
        failure_record(s_running_version);
        transition(GC_OTA_ROLLING_BACK);
        return GC_OK;
    }
    deferred(now_s, GC_OTA_TRIAL_POLL_S);
    return GC_OK;
}

static gc_err_t tick_rolling_back(uint32_t now_s)
{
    esp_err_t err = esp_ota_mark_app_invalid_rollback_and_reboot();

    if (err == ESP_OK) {
        return GC_OK;
    }
    GC_LOGE(GC_OTA_TAG, "rollback failed %d", (int)err);
    transition(GC_OTA_FAILED);
    deferred(now_s, GC_OTA_FAILED_PAUSE_S);
    return GC_ERR_IO;
}

static gc_err_t tick_failed(uint32_t now_s)
{
    s_retries = 0u;
    s_preflight_retries = 0u;
    s_manifest_valid = false;
    s_last_check_s = now_s;
    transition(GC_OTA_IDLE);
    deferred(now_s, GC_OTA_CHECK_PERIOD_S);
    return GC_OK;
}

gc_err_t gc_ota_tick(uint32_t now_s)
{
    if (!s_initialised) {
        return GC_ERR_BUSY;
    }
    if (!s_enabled) {
        return GC_OK;
    }
    if (!gate_open(now_s)) {
        return GC_OK;
    }
    switch (s_state) {
        case GC_OTA_IDLE:
            return tick_idle(now_s);
        case GC_OTA_CHECKING:
            return tick_checking(now_s);
        case GC_OTA_PREFLIGHT:
            return tick_preflight(now_s);
        case GC_OTA_DOWNLOADING:
            return tick_downloading(now_s);
        case GC_OTA_VERIFYING:
            return tick_verifying(now_s);
        case GC_OTA_TRIAL:
            return tick_trial(now_s);
        case GC_OTA_ROLLING_BACK:
            return tick_rolling_back(now_s);
        case GC_OTA_FAILED:
            return tick_failed(now_s);
        default:
            transition(GC_OTA_IDLE);
            return GC_ERR_BUSY;
    }
}

gc_err_t gc_ota_check_now(void)
{
    if (!s_initialised || !s_enabled) {
        return GC_ERR_BUSY;
    }
    if (s_state != GC_OTA_IDLE && s_state != GC_OTA_FAILED) {
        return GC_ERR_BUSY;
    }
    s_retries = 0u;
    s_preflight_retries = 0u;
    s_manifest_valid = false;
    s_alarm_active = false;
    s_last_check_s = 0u;
    transition(GC_OTA_CHECKING);
    return GC_OK;
}

gc_err_t gc_ota_abort(void)
{
    if (!s_initialised) {
        return GC_ERR_BUSY;
    }
    if (s_state == GC_OTA_IDLE || s_state == GC_OTA_TRIAL || s_state == GC_OTA_ROLLING_BACK) {
        return GC_ERR_BUSY;
    }
    if (s_ota_open && s_received > 0u) {
        partial_store();
    }
    download_release();
    sha_release(&s_image_sha, &s_image_sha_started);
    sha_release(&s_readback_sha, &s_readback_sha_started);
    s_manifest_valid = false;
    s_alarm_active = true;
    s_retries = 0u;
    s_preflight_retries = 0u;
    s_last_check_s = 0u;
    transition(GC_OTA_IDLE);
    deferred(0u, GC_OTA_CHECK_PERIOD_S);
    return GC_OK;
}

gc_err_t gc_ota_mark_valid(void)
{
    if (esp_ota_mark_app_valid_cancel_rollback() != ESP_OK) {
        return GC_ERR_IO;
    }
    partial_clear();
    s_manifest_valid = false;
    s_last_check_s = 0u;
    transition(GC_OTA_IDLE);
    return GC_OK;
}

gc_err_t gc_ota_mark_invalid_and_reboot(void)
{
    uint32_t version = gc_ota_running_version();

    (void)gc_ota_block_version(version);
    failure_record(version);
    if (esp_ota_mark_app_invalid_rollback_and_reboot() != ESP_OK) {
        return GC_ERR_IO;
    }
    return GC_OK;
}
