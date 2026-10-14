#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "gc_types.h"

#define GC_NVS_NAMESPACE "gc"
#define GC_NVS_KEY_MAX 15

gc_err_t gc_nvs_init(void);
gc_err_t gc_nvs_commit(void);

gc_err_t gc_nvs_get_u32(const char *key, uint32_t *out);
gc_err_t gc_nvs_set_u32(const char *key, uint32_t value);

gc_err_t gc_nvs_get_u64(const char *key, uint64_t *out);
gc_err_t gc_nvs_set_u64(const char *key, uint64_t value);

gc_err_t gc_nvs_get_str(const char *key, char *out, size_t *len);
gc_err_t gc_nvs_set_str(const char *key, const char *value);

gc_err_t gc_nvs_get_blob(const char *key, void *out, size_t *len);
gc_err_t gc_nvs_set_blob(const char *key, const void *value, size_t len);

gc_err_t gc_nvs_erase_key(const char *key);
bool gc_nvs_has_key(const char *key);
