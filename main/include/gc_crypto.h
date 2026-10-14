#pragma once

#include <stdint.h>
#include <stddef.h>
#include "gc_types.h"

#define GC_PSK_LEN 32
#define GC_PEPPER_LEN 32

gc_err_t gc_crypto_init(void);

gc_err_t gc_crypto_load_psk(uint8_t out[GC_PSK_LEN]);
gc_err_t gc_crypto_load_pepper(uint8_t out[GC_PEPPER_LEN]);
gc_err_t gc_crypto_store_psk(const uint8_t in[GC_PSK_LEN]);
gc_err_t gc_crypto_store_pepper(const uint8_t in[GC_PEPPER_LEN]);

gc_err_t gc_crypto_number_key(const uint8_t pepper[GC_PEPPER_LEN],
                              const char *e164_number,
                              gc_key_t *out);

gc_err_t gc_crypto_mac_key(const uint8_t pepper[GC_PEPPER_LEN],
                           const gc_mac_t *mac,
                           gc_key_t *out);

gc_err_t gc_crypto_beacon_mac(const uint8_t psk[GC_PSK_LEN],
                              const uint8_t *payload,
                              size_t payload_len,
                              uint8_t out[GC_KEY_LEN]);

gc_err_t gc_crypto_command_mac(const uint8_t psk[GC_PSK_LEN],
                               const uint8_t *payload,
                               size_t payload_len,
                               uint8_t out[GC_KEY_LEN]);

bool gc_crypto_constant_time_equal(const void *a, const void *b, size_t len);

gc_err_t gc_crypto_random(void *buf, size_t len);

gc_err_t gc_crypto_sha256_hex(const uint8_t *data, size_t len, char out[65]);

gc_err_t gc_crypto_beacon_counter_load(uint32_t *out);
gc_err_t gc_crypto_beacon_counter_store(uint32_t value);
gc_err_t gc_crypto_command_sequence_load(uint32_t *out);
gc_err_t gc_crypto_command_sequence_store(uint32_t value);
