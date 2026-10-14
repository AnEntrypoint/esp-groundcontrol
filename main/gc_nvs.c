#include "gc_nvs.h"

#include <assert.h>
#include <string.h>

#include "esp_err.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "gc_log.h"
#include "gc_types.h"

#define GC_NVS_TAG "gc_nvs"

static nvs_handle_t s_handle;
static bool s_ready;

static gc_err_t gc_nvs_translate(esp_err_t err)
{
    switch (err) {
        case ESP_OK:
            return GC_OK;
        case ESP_ERR_NVS_NOT_FOUND:
            return GC_ERR_NOT_FOUND;
        case ESP_ERR_INVALID_ARG:
        case ESP_ERR_NVS_INVALID_NAME:
        case ESP_ERR_NVS_KEY_TOO_LONG:
        case ESP_ERR_NVS_INVALID_LENGTH:
        case ESP_ERR_NVS_TYPE_MISMATCH:
            return GC_ERR_INVALID_ARG;
        case ESP_ERR_NVS_NOT_ENOUGH_SPACE:
        case ESP_ERR_NVS_VALUE_TOO_LONG:
        case ESP_ERR_NVS_PAGE_FULL:
            return GC_ERR_FULL;
        case ESP_ERR_NO_MEM:
            return GC_ERR_NO_MEM;
        default:
            return GC_ERR_IO;
    }
}

static void gc_nvs_assert_key(const char *key)
{
    assert(key != NULL);
    assert(strlen(key) <= GC_NVS_KEY_MAX);
}

static gc_err_t gc_nvs_ensure(void)
{
    if (s_ready) {
        return GC_OK;
    }

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        GC_LOGW(GC_NVS_TAG, "nvs partition unusable (%s), erasing", esp_err_to_name(err));
        err = nvs_flash_erase();
        if (err != ESP_OK) {
            GC_LOGE(GC_NVS_TAG, "nvs_flash_erase failed: %s", esp_err_to_name(err));
            return GC_ERR_IO;
        }
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        GC_LOGE(GC_NVS_TAG, "nvs_flash_init failed: %s", esp_err_to_name(err));
        return GC_ERR_IO;
    }

    err = nvs_open(GC_NVS_NAMESPACE, NVS_READWRITE, &s_handle);
    if (err != ESP_OK) {
        GC_LOGE(GC_NVS_TAG, "nvs_open %s failed: %s", GC_NVS_NAMESPACE, esp_err_to_name(err));
        return GC_ERR_IO;
    }

    s_ready = true;
    return GC_OK;
}

gc_err_t gc_nvs_init(void)
{
    return gc_nvs_ensure();
}

gc_err_t gc_nvs_commit(void)
{
    if (!s_ready) {
        return GC_OK;
    }
    esp_err_t err = nvs_commit(s_handle);
    if (err != ESP_OK) {
        GC_LOGE(GC_NVS_TAG, "nvs_commit failed: %s", esp_err_to_name(err));
    }
    return gc_nvs_translate(err);
}

gc_err_t gc_nvs_get_u32(const char *key, uint32_t *out)
{
    gc_nvs_assert_key(key);
    if (out == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    gc_err_t ready = gc_nvs_ensure();
    if (ready != GC_OK) {
        return ready;
    }
    return gc_nvs_translate(nvs_get_u32(s_handle, key, out));
}

gc_err_t gc_nvs_set_u32(const char *key, uint32_t value)
{
    gc_nvs_assert_key(key);
    gc_err_t ready = gc_nvs_ensure();
    if (ready != GC_OK) {
        return ready;
    }
    return gc_nvs_translate(nvs_set_u32(s_handle, key, value));
}

gc_err_t gc_nvs_get_u64(const char *key, uint64_t *out)
{
    gc_nvs_assert_key(key);
    if (out == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    gc_err_t ready = gc_nvs_ensure();
    if (ready != GC_OK) {
        return ready;
    }
    return gc_nvs_translate(nvs_get_u64(s_handle, key, out));
}

gc_err_t gc_nvs_set_u64(const char *key, uint64_t value)
{
    gc_nvs_assert_key(key);
    gc_err_t ready = gc_nvs_ensure();
    if (ready != GC_OK) {
        return ready;
    }
    return gc_nvs_translate(nvs_set_u64(s_handle, key, value));
}

gc_err_t gc_nvs_get_str(const char *key, char *out, size_t *len)
{
    gc_nvs_assert_key(key);
    if (len == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    gc_err_t ready = gc_nvs_ensure();
    if (ready != GC_OK) {
        return ready;
    }
    return gc_nvs_translate(nvs_get_str(s_handle, key, out, len));
}

gc_err_t gc_nvs_set_str(const char *key, const char *value)
{
    gc_nvs_assert_key(key);
    if (value == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    gc_err_t ready = gc_nvs_ensure();
    if (ready != GC_OK) {
        return ready;
    }
    return gc_nvs_translate(nvs_set_str(s_handle, key, value));
}

gc_err_t gc_nvs_get_blob(const char *key, void *out, size_t *len)
{
    gc_nvs_assert_key(key);
    if (len == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    gc_err_t ready = gc_nvs_ensure();
    if (ready != GC_OK) {
        return ready;
    }
    return gc_nvs_translate(nvs_get_blob(s_handle, key, out, len));
}

gc_err_t gc_nvs_set_blob(const char *key, const void *value, size_t len)
{
    gc_nvs_assert_key(key);
    if (value == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    gc_err_t ready = gc_nvs_ensure();
    if (ready != GC_OK) {
        return ready;
    }
    return gc_nvs_translate(nvs_set_blob(s_handle, key, value, len));
}

gc_err_t gc_nvs_erase_key(const char *key)
{
    gc_nvs_assert_key(key);
    gc_err_t ready = gc_nvs_ensure();
    if (ready != GC_OK) {
        return ready;
    }
    return gc_nvs_translate(nvs_erase_key(s_handle, key));
}

bool gc_nvs_has_key(const char *key)
{
    gc_nvs_assert_key(key);
    if (gc_nvs_ensure() != GC_OK) {
        return false;
    }
    return nvs_find_key(s_handle, key, NULL) == ESP_OK;
}
