#include "gc_crypto.h"

#include <string.h>

#include "gc_log.h"
#include "gc_nvs.h"

#include "esp_random.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

#define GC_CRYPTO_TAG "crypto"

#define GC_CRYPTO_NVS_PSK "psk"
#define GC_CRYPTO_NVS_PEPPER "pep"
#define GC_CRYPTO_NVS_BEACON_COUNTER "bcnt"
#define GC_CRYPTO_NVS_COMMAND_SEQUENCE "cseq"

#define GC_CRYPTO_SHA256_LEN 32
#define GC_CRYPTO_E164_MAX 32
#define GC_CRYPTO_E164_DIGITS_MIN 7
#define GC_CRYPTO_E164_DIGITS_MAX 15

#define GC_CRYPTO_DOMAIN_NUMBER 0x6Eu
#define GC_CRYPTO_DOMAIN_MAC 0x6Du
#define GC_CRYPTO_DOMAIN_BEACON "beacon"
#define GC_CRYPTO_DOMAIN_COMMAND "cmd"

static const mbedtls_md_info_t *gc_crypto_sha256_info(void)
{
    return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
}

static gc_err_t gc_crypto_hmac(const uint8_t *key,
                               size_t key_len,
                               const uint8_t *msg,
                               size_t msg_len,
                               uint8_t digest[GC_CRYPTO_SHA256_LEN])
{
    const mbedtls_md_info_t *info = gc_crypto_sha256_info();
    if (info == NULL) {
        return GC_ERR_UNSUPPORTED;
    }
    if (mbedtls_md_hmac(info, key, key_len, msg, msg_len, digest) != 0) {
        return GC_ERR_IO;
    }
    return GC_OK;
}

static gc_err_t gc_crypto_hmac_domain(const uint8_t *key,
                                      size_t key_len,
                                      const void *domain,
                                      size_t domain_len,
                                      const uint8_t *payload,
                                      size_t payload_len,
                                      uint8_t digest[GC_CRYPTO_SHA256_LEN])
{
    const mbedtls_md_info_t *info = gc_crypto_sha256_info();
    if (info == NULL) {
        return GC_ERR_UNSUPPORTED;
    }
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    int rc = mbedtls_md_setup(&ctx, info, 1);
    if (rc == 0) {
        rc = mbedtls_md_hmac_starts(&ctx, key, key_len);
    }
    if (rc == 0) {
        rc = mbedtls_md_hmac_update(&ctx, (const unsigned char *)domain, domain_len);
    }
    if (rc == 0 && payload != NULL && payload_len > 0) {
        rc = mbedtls_md_hmac_update(&ctx, payload, payload_len);
    }
    if (rc == 0) {
        rc = mbedtls_md_hmac_finish(&ctx, digest);
    }
    mbedtls_md_free(&ctx);
    return rc == 0 ? GC_OK : GC_ERR_IO;
}

static void gc_crypto_truncate(gc_key_t *out, const uint8_t digest[GC_CRYPTO_SHA256_LEN])
{
    memcpy(out->b, digest, GC_KEY_LEN);
}

static gc_err_t gc_crypto_secret_load(const char *key, uint8_t *out, size_t len)
{
    size_t got = len;
    gc_err_t err = gc_nvs_get_blob(key, out, &got);
    if (err != GC_OK) {
        return err;
    }
    if (got != len) {
        return GC_ERR_IO;
    }
    return GC_OK;
}

static gc_err_t gc_crypto_secret_store(const char *key, const uint8_t *in, size_t len)
{
    gc_err_t err = gc_nvs_set_blob(key, in, len);
    if (err != GC_OK) {
        return err;
    }
    return gc_nvs_commit();
}

gc_err_t gc_crypto_init(void)
{
    if (gc_crypto_sha256_info() == NULL) {
        GC_LOGE(GC_CRYPTO_TAG, "sha256 digest unavailable");
        return GC_ERR_UNSUPPORTED;
    }
    uint8_t psk[GC_PSK_LEN];
    gc_err_t err = gc_crypto_secret_load(GC_CRYPTO_NVS_PSK, psk, GC_PSK_LEN);
    if (err != GC_OK) {
        GC_LOGE(GC_CRYPTO_TAG, "psk not provisioned");
        return err;
    }
    uint8_t pepper[GC_PEPPER_LEN];
    err = gc_crypto_secret_load(GC_CRYPTO_NVS_PEPPER, pepper, GC_PEPPER_LEN);
    if (err != GC_OK) {
        GC_LOGE(GC_CRYPTO_TAG, "pepper not provisioned");
        return err;
    }
    return GC_OK;
}

gc_err_t gc_crypto_load_psk(uint8_t out[GC_PSK_LEN])
{
    if (out == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    return gc_crypto_secret_load(GC_CRYPTO_NVS_PSK, out, GC_PSK_LEN);
}

gc_err_t gc_crypto_load_pepper(uint8_t out[GC_PEPPER_LEN])
{
    if (out == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    return gc_crypto_secret_load(GC_CRYPTO_NVS_PEPPER, out, GC_PEPPER_LEN);
}

gc_err_t gc_crypto_store_psk(const uint8_t in[GC_PSK_LEN])
{
    if (in == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    return gc_crypto_secret_store(GC_CRYPTO_NVS_PSK, in, GC_PSK_LEN);
}

gc_err_t gc_crypto_store_pepper(const uint8_t in[GC_PEPPER_LEN])
{
    if (in == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    return gc_crypto_secret_store(GC_CRYPTO_NVS_PEPPER, in, GC_PEPPER_LEN);
}

gc_err_t gc_crypto_number_key(const uint8_t pepper[GC_PEPPER_LEN],
                              const char *e164_number,
                              gc_key_t *out)
{
    if (pepper == NULL || e164_number == NULL || out == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    uint8_t msg[1 + GC_CRYPTO_E164_MAX];
    size_t digits_len = 0;
    for (size_t i = 0; e164_number[i] != '\0'; i++) {
        const char c = e164_number[i];
        if (c < '0' || c > '9') {
            continue;
        }
        if (digits_len >= GC_CRYPTO_E164_DIGITS_MAX) {
            return GC_ERR_INVALID_ARG;
        }
        msg[1 + digits_len] = (uint8_t)c;
        digits_len++;
    }
    if (digits_len < GC_CRYPTO_E164_DIGITS_MIN) {
        return GC_ERR_INVALID_ARG;
    }
    msg[0] = (uint8_t)GC_CRYPTO_DOMAIN_NUMBER;
    uint8_t digest[GC_CRYPTO_SHA256_LEN];
    gc_err_t err = gc_crypto_hmac(pepper, GC_PEPPER_LEN, msg, 1 + digits_len, digest);
    if (err != GC_OK) {
        return err;
    }
    gc_crypto_truncate(out, digest);
    return GC_OK;
}

gc_err_t gc_crypto_mac_key(const uint8_t pepper[GC_PEPPER_LEN],
                           const gc_mac_t *mac,
                           gc_key_t *out)
{
    if (pepper == NULL || mac == NULL || out == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    uint8_t msg[1 + GC_MAC_LEN];
    msg[0] = (uint8_t)GC_CRYPTO_DOMAIN_MAC;
    memcpy(&msg[1], mac->b, GC_MAC_LEN);
    uint8_t digest[GC_CRYPTO_SHA256_LEN];
    gc_err_t err = gc_crypto_hmac(pepper, GC_PEPPER_LEN, msg, sizeof(msg), digest);
    if (err != GC_OK) {
        return err;
    }
    gc_crypto_truncate(out, digest);
    return GC_OK;
}

gc_err_t gc_crypto_beacon_mac(const uint8_t psk[GC_PSK_LEN],
                              const uint8_t *payload,
                              size_t payload_len,
                              uint8_t out[GC_KEY_LEN])
{
    if (psk == NULL || out == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    uint8_t digest[GC_CRYPTO_SHA256_LEN];
    gc_err_t err = gc_crypto_hmac_domain(psk,
                                         GC_PSK_LEN,
                                         GC_CRYPTO_DOMAIN_BEACON,
                                         strlen(GC_CRYPTO_DOMAIN_BEACON),
                                         payload,
                                         payload_len,
                                         digest);
    if (err != GC_OK) {
        return err;
    }
    memcpy(out, digest, GC_KEY_LEN);
    return GC_OK;
}

gc_err_t gc_crypto_command_mac(const uint8_t psk[GC_PSK_LEN],
                               const uint8_t *payload,
                               size_t payload_len,
                               uint8_t out[GC_KEY_LEN])
{
    if (psk == NULL || out == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    uint8_t digest[GC_CRYPTO_SHA256_LEN];
    gc_err_t err = gc_crypto_hmac_domain(psk,
                                         GC_PSK_LEN,
                                         GC_CRYPTO_DOMAIN_COMMAND,
                                         strlen(GC_CRYPTO_DOMAIN_COMMAND),
                                         payload,
                                         payload_len,
                                         digest);
    if (err != GC_OK) {
        return err;
    }
    memcpy(out, digest, GC_KEY_LEN);
    return GC_OK;
}

bool gc_crypto_constant_time_equal(const void *a, const void *b, size_t len)
{
    if (a == NULL || b == NULL) {
        return false;
    }
    const uint8_t *lhs = (const uint8_t *)a;
    const uint8_t *rhs = (const uint8_t *)b;
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc |= (uint8_t)(lhs[i] ^ rhs[i]);
    }
    return acc == 0;
}

gc_err_t gc_crypto_random(void *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return GC_ERR_INVALID_ARG;
    }
    esp_fill_random(buf, len);
    return GC_OK;
}

gc_err_t gc_crypto_sha256_hex(const uint8_t *data, size_t len, char out[65])
{
    if (out == NULL || (len > 0 && data == NULL)) {
        return GC_ERR_INVALID_ARG;
    }
    uint8_t digest[GC_CRYPTO_SHA256_LEN];
    if (mbedtls_sha256(data, len, digest, 0) != 0) {
        return GC_ERR_IO;
    }
    static const char gc_crypto_hex_digits[] = "0123456789abcdef";
    for (size_t i = 0; i < GC_CRYPTO_SHA256_LEN; i++) {
        out[2 * i] = gc_crypto_hex_digits[digest[i] >> 4];
        out[2 * i + 1] = gc_crypto_hex_digits[digest[i] & 0x0Fu];
    }
    out[64] = '\0';
    return GC_OK;
}

gc_err_t gc_crypto_beacon_counter_load(uint32_t *out)
{
    if (out == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    gc_err_t err = gc_nvs_get_u32(GC_CRYPTO_NVS_BEACON_COUNTER, out);
    if (err == GC_ERR_NOT_FOUND) {
        *out = 0;
        return GC_OK;
    }
    return err;
}

gc_err_t gc_crypto_beacon_counter_store(uint32_t value)
{
    gc_err_t err = gc_nvs_set_u32(GC_CRYPTO_NVS_BEACON_COUNTER, value);
    if (err != GC_OK) {
        return err;
    }
    return gc_nvs_commit();
}

gc_err_t gc_crypto_command_sequence_load(uint32_t *out)
{
    if (out == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    gc_err_t err = gc_nvs_get_u32(GC_CRYPTO_NVS_COMMAND_SEQUENCE, out);
    if (err == GC_ERR_NOT_FOUND) {
        *out = 0;
        return GC_OK;
    }
    return err;
}

gc_err_t gc_crypto_command_sequence_store(uint32_t value)
{
    gc_err_t err = gc_nvs_set_u32(GC_CRYPTO_NVS_COMMAND_SEQUENCE, value);
    if (err != GC_OK) {
        return err;
    }
    return gc_nvs_commit();
}
