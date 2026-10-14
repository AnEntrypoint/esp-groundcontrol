#include "gc_gate.h"

#include "gc_config.h"
#include "gc_crypto.h"
#include "gc_log.h"
#include "gc_nvs.h"

#include "esp_heap_caps.h"
#include "esp_random.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include <string.h>

#define GC_GATE_BLOCK_MAX 64u
#define GC_GATE_BLOCKS_KEY "blocks"
#define GC_GATE_BLOCK_VERSION 1u
#define GC_GATE_BLOCK_HEADER_SIZE 8u
#define GC_GATE_BLOCK_RECORD_SIZE 28u
#define GC_GATE_E164_DIGITS_MAX 15u
#define GC_GATE_STRIKE_LIMIT_DEFAULT 3u
#define GC_GATE_SOFT_BLOCK_S_DEFAULT 86400u
#define GC_GATE_ALLOW_GRACE_S_DEFAULT 3600u

static const uint8_t GC_GATE_BLOCK_MAGIC[4] = { 'G', 'C', 'B', '1' };

typedef struct {
    gc_key_t number_key;
    gc_key_t mac_key;
    uint32_t strikes;
    uint32_t blocked_until_s;
    uint8_t permanent;
    uint8_t reserved[3];
} gc_block_record_t;

typedef struct {
    gc_block_record_t rec;
    uint32_t updated_ms;
    bool used;
} gc_block_entry_t;

typedef char gc_gate_block_record_size_check[
    (sizeof(gc_block_record_t) == GC_GATE_BLOCK_RECORD_SIZE) ? 1 : -1];

typedef struct {
    gc_client_t client;
    uint32_t last_activity_ms;
    bool used;
} gc_client_slot_t;

typedef struct {
    gc_req_id_t req;
    gc_key_t number_key;
    gc_key_t mac_key;
    gc_mac_t mac;
    uint32_t queued_ms;
    bool used;
} gc_pending_t;

static SemaphoreHandle_t s_lock;
static gc_client_slot_t *s_clients;
static size_t s_client_cap;
static gc_pending_t s_pending[GC_MAX_PENDING_VERIFY];
static size_t s_pending_count;
static gc_block_entry_t s_blocks[GC_GATE_BLOCK_MAX];
static gc_config_t s_cfg;
static uint32_t s_rate_byte_s;
static int64_t s_clock_offset_s;

static void *gate_alloc(size_t bytes)
{
    void *p = heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM);
    if (p == NULL) {
        p = heap_caps_malloc(bytes, MALLOC_CAP_8BIT);
    }
    return p;
}

static uint32_t gate_now_s(void)
{
    int64_t uptime_s = (int64_t)(esp_timer_get_time() / 1000000ULL);
    int64_t now_s = uptime_s + s_clock_offset_s;
    if (now_s < 0) {
        return 0u;
    }
    if (now_s > (int64_t)UINT32_MAX) {
        return UINT32_MAX;
    }
    return (uint32_t)now_s;
}

static uint32_t gate_now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000ULL);
}

static bool gate_lock(void)
{
    if (s_lock == NULL) {
        return false;
    }
    return xSemaphoreTakeRecursive(s_lock, portMAX_DELAY) == pdTRUE;
}

static void gate_unlock(void)
{
    if (s_lock != NULL) {
        xSemaphoreGiveRecursive(s_lock);
    }
}

static uint32_t strike_limit(void)
{
    return s_cfg.strike_limit != 0u ? s_cfg.strike_limit : GC_GATE_STRIKE_LIMIT_DEFAULT;
}

static uint32_t soft_block_s(void)
{
    return s_cfg.soft_block_s != 0u ? s_cfg.soft_block_s : GC_GATE_SOFT_BLOCK_S_DEFAULT;
}

static uint32_t allow_grace_s(void)
{
    return s_cfg.allow_grace_s != 0u ? s_cfg.allow_grace_s : GC_GATE_ALLOW_GRACE_S_DEFAULT;
}

static bool key_is_zero(const gc_key_t *k)
{
    if (k == NULL) {
        return true;
    }
    uint8_t acc = 0;
    for (size_t i = 0; i < GC_KEY_LEN; i++) {
        acc |= k->b[i];
    }
    return acc == 0;
}

static uint32_t add_saturating_u32(uint32_t value, uint32_t addend)
{
    uint32_t sum = value + addend;
    if (sum < value) {
        return UINT32_MAX;
    }
    return sum;
}

static void put_u16(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value & 0xFFu);
    out[1] = (uint8_t)((value >> 8) & 0xFFu);
}

static void put_u32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value & 0xFFu);
    out[1] = (uint8_t)((value >> 8) & 0xFFu);
    out[2] = (uint8_t)((value >> 16) & 0xFFu);
    out[3] = (uint8_t)((value >> 24) & 0xFFu);
}

static uint16_t get_u16(const uint8_t *in)
{
    return (uint16_t)((uint16_t)in[0] | ((uint16_t)in[1] << 8));
}

static uint32_t get_u32(const uint8_t *in)
{
    return (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

static void block_record_write(uint8_t *out, const gc_block_record_t *rec)
{
    memcpy(out, rec->number_key.b, GC_KEY_LEN);
    memcpy(out + GC_KEY_LEN, rec->mac_key.b, GC_KEY_LEN);
    put_u32(out + (2u * GC_KEY_LEN), rec->strikes);
    put_u32(out + (2u * GC_KEY_LEN) + 4u, rec->blocked_until_s);
    out[(2u * GC_KEY_LEN) + 8u] = rec->permanent;
    memset(out + (2u * GC_KEY_LEN) + 9u, 0, 3);
}

static void block_record_read(const uint8_t *in, gc_block_record_t *rec)
{
    memcpy(rec->number_key.b, in, GC_KEY_LEN);
    memcpy(rec->mac_key.b, in + GC_KEY_LEN, GC_KEY_LEN);
    rec->strikes = get_u32(in + (2u * GC_KEY_LEN));
    rec->blocked_until_s = get_u32(in + (2u * GC_KEY_LEN) + 4u);
    rec->permanent = in[(2u * GC_KEY_LEN) + 8u];
    memset(rec->reserved, 0, sizeof(rec->reserved));
}

static gc_block_entry_t *block_find(const gc_key_t *number_key)
{
    if (number_key == NULL || key_is_zero(number_key)) {
        return NULL;
    }
    for (size_t i = 0; i < GC_GATE_BLOCK_MAX; i++) {
        if (s_blocks[i].used && gc_key_equal(&s_blocks[i].rec.number_key, number_key)) {
            return &s_blocks[i];
        }
    }
    return NULL;
}

static gc_block_entry_t *block_find_mac(const gc_key_t *mac_key)
{
    if (mac_key == NULL || key_is_zero(mac_key)) {
        return NULL;
    }
    for (size_t i = 0; i < GC_GATE_BLOCK_MAX; i++) {
        if (s_blocks[i].used && gc_key_equal(&s_blocks[i].rec.mac_key, mac_key)) {
            return &s_blocks[i];
        }
    }
    return NULL;
}

static gc_block_entry_t *block_acquire(const gc_key_t *number_key, const gc_key_t *mac_key)
{
    gc_block_entry_t *found = block_find(number_key);
    if (found != NULL) {
        if (mac_key != NULL && !key_is_zero(mac_key) && key_is_zero(&found->rec.mac_key)) {
            found->rec.mac_key = *mac_key;
        }
        return found;
    }
    if (number_key == NULL || key_is_zero(number_key)) {
        return NULL;
    }

    for (size_t i = 0; i < GC_GATE_BLOCK_MAX; i++) {
        if (!s_blocks[i].used) {
            memset(&s_blocks[i], 0, sizeof(s_blocks[i]));
            s_blocks[i].rec.number_key = *number_key;
            if (mac_key != NULL) {
                s_blocks[i].rec.mac_key = *mac_key;
            }
            s_blocks[i].used = true;
            s_blocks[i].updated_ms = gate_now_ms();
            return &s_blocks[i];
        }
    }

    gc_block_entry_t *victim = NULL;
    for (size_t i = 0; i < GC_GATE_BLOCK_MAX; i++) {
        gc_block_entry_t *candidate = &s_blocks[i];
        if (candidate->rec.permanent != 0u || candidate->rec.strikes != 0u) {
            continue;
        }
        if (victim == NULL || candidate->updated_ms < victim->updated_ms) {
            victim = candidate;
        }
    }
    if (victim == NULL) {
        for (size_t i = 0; i < GC_GATE_BLOCK_MAX; i++) {
            gc_block_entry_t *candidate = &s_blocks[i];
            if (candidate->rec.permanent != 0u) {
                continue;
            }
            if (victim == NULL || candidate->updated_ms < victim->updated_ms) {
                victim = candidate;
            }
        }
    }
    if (victim == NULL) {
        GC_LOGW("gate", "block ledger full, strike not recorded");
        return NULL;
    }

    memset(&victim->rec, 0, sizeof(victim->rec));
    victim->rec.number_key = *number_key;
    if (mac_key != NULL) {
        victim->rec.mac_key = *mac_key;
    }
    victim->updated_ms = gate_now_ms();
    return victim;
}

static gc_client_slot_t *slot_find(const gc_mac_t *mac)
{
    if (mac == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < s_client_cap; i++) {
        if (s_clients[i].used && gc_mac_equal(&s_clients[i].client.mac, mac)) {
            return &s_clients[i];
        }
    }
    return NULL;
}

static void slot_touch(gc_client_slot_t *slot)
{
    slot->last_activity_ms = gate_now_ms();
}

static gc_client_slot_t *slot_create(const gc_mac_t *mac)
{
    for (size_t i = 0; i < s_client_cap; i++) {
        if (!s_clients[i].used) {
            memset(&s_clients[i], 0, sizeof(s_clients[i]));
            s_clients[i].client.mac = *mac;
            s_clients[i].client.state = GC_CLIENT_NEW;
            s_clients[i].client.last_deny = GC_DENY_NONE;
            s_clients[i].client.rate_tokens_byte = s_rate_byte_s;
            s_clients[i].client.rate_last_ms = gate_now_ms();
            s_clients[i].last_activity_ms = s_clients[i].client.rate_last_ms;
            s_clients[i].used = true;
            return &s_clients[i];
        }
    }

    gc_client_slot_t *victim = NULL;
    for (size_t i = 0; i < s_client_cap; i++) {
        gc_client_slot_t *candidate = &s_clients[i];
        if (candidate->client.state == GC_CLIENT_ALLOWED || candidate->client.permanent) {
            continue;
        }
        if (victim == NULL || candidate->last_activity_ms < victim->last_activity_ms) {
            victim = candidate;
        }
    }
    if (victim == NULL) {
        return NULL;
    }

    memset(&victim->client, 0, sizeof(victim->client));
    victim->client.mac = *mac;
    victim->client.state = GC_CLIENT_NEW;
    victim->client.last_deny = GC_DENY_NONE;
    victim->client.rate_tokens_byte = s_rate_byte_s;
    victim->client.rate_last_ms = gate_now_ms();
    victim->last_activity_ms = victim->client.rate_last_ms;
    return victim;
}

static void client_sync_block(gc_client_t *client)
{
    gc_block_entry_t *block = block_find(&client->number_key);
    if (block == NULL) {
        block = block_find_mac(&client->mac_key);
    }
    if (block == NULL) {
        return;
    }
    uint32_t now_s = gate_now_s();
    client->strikes = block->rec.strikes;
    client->permanent = block->rec.permanent != 0u;
    if (client->permanent) {
        client->state = GC_CLIENT_PERMANENTLY_BLOCKED;
        client->last_deny = GC_DENY_STRIKE_LIMIT;
        client->allowed_until_s = 0u;
        client->blocked_until_s = 0u;
        return;
    }
    if (block->rec.blocked_until_s > now_s) {
        client->blocked_until_s = block->rec.blocked_until_s;
        if (client->state == GC_CLIENT_NEW) {
            client->state = GC_CLIENT_SOFT_BLOCKED;
            client->last_deny = GC_DENY_NOT_VERIFIED;
        }
    } else {
        client->blocked_until_s = 0u;
        if (client->state == GC_CLIENT_SOFT_BLOCKED) {
            client->state = GC_CLIENT_NEW;
            client->last_deny = GC_DENY_NONE;
        }
    }
}

static gc_err_t block_strike(const gc_key_t *number_key,
                             const gc_key_t *mac_key,
                             uint32_t blocked_until_s,
                             uint32_t *strikes_out)
{
    gc_block_entry_t *block = block_acquire(number_key, mac_key);
    if (block == NULL) {
        return GC_ERR_NO_MEM;
    }
    if (block->rec.permanent != 0u) {
        if (strikes_out != NULL) {
            *strikes_out = block->rec.strikes;
        }
        return GC_OK;
    }
    if (block->rec.blocked_until_s > gate_now_s()) {
        if (blocked_until_s != 0u) {
            block->rec.blocked_until_s = blocked_until_s;
            block->updated_ms = gate_now_ms();
        }
        if (strikes_out != NULL) {
            *strikes_out = block->rec.strikes;
        }
        return GC_OK;
    }
    uint32_t strikes = add_saturating_u32(block->rec.strikes, 1u);
    block->rec.strikes = strikes;
    block->updated_ms = gate_now_ms();
    if (strikes >= strike_limit()) {
        block->rec.permanent = 1u;
        block->rec.blocked_until_s = 0u;
    } else {
        block->rec.blocked_until_s = blocked_until_s;
    }
    if (strikes_out != NULL) {
        *strikes_out = strikes;
    }
    return GC_OK;
}

static void client_apply_deny(gc_client_t *client,
                             uint32_t strikes,
                             uint32_t blocked_until_s,
                             gc_deny_reason_t reason)
{
    client->strikes = strikes;
    client->allowed_until_s = 0u;
    client->permanent = strikes >= strike_limit();
    if (client->permanent) {
        client->state = GC_CLIENT_PERMANENTLY_BLOCKED;
        client->last_deny = GC_DENY_STRIKE_LIMIT;
        client->blocked_until_s = 0u;
        return;
    }
    client->state = GC_CLIENT_SOFT_BLOCKED;
    client->blocked_until_s = blocked_until_s;
    client->last_deny = (reason == GC_DENY_NONE) ? GC_DENY_NOT_VERIFIED : reason;
}

static gc_err_t client_register_deny(gc_client_slot_t *slot,
                                     uint32_t blocked_until_s,
                                     gc_deny_reason_t reason)
{
    gc_client_t *client = &slot->client;
    uint32_t blocked = (blocked_until_s != 0u) ? blocked_until_s : gate_now_s() + soft_block_s();
    uint32_t strikes = add_saturating_u32(client->strikes, 1u);

    if (!key_is_zero(&client->number_key)) {
        uint32_t recorded = 0u;
        if (block_strike(&client->number_key, &client->mac_key, blocked, &recorded) == GC_OK) {
            strikes = recorded;
        }
    }

    client_apply_deny(client, strikes, blocked, reason);
    slot_touch(slot);
    return gc_gate_persist();
}

static gc_err_t client_register_allow(gc_client_t *client, uint32_t allowed_until_s)
{
    if (client->permanent) {
        return GC_ERR_AUTH;
    }
    gc_block_entry_t *block = block_find(&client->number_key);
    if (block != NULL && block->rec.permanent != 0u) {
        client->permanent = true;
        client->state = GC_CLIENT_PERMANENTLY_BLOCKED;
        client->last_deny = GC_DENY_STRIKE_LIMIT;
        return GC_ERR_AUTH;
    }
    uint32_t until_s = (allowed_until_s != 0u) ? allowed_until_s : gate_now_s() + allow_grace_s();
    client->state = GC_CLIENT_ALLOWED;
    client->allowed_until_s = until_s;
    client->blocked_until_s = 0u;
    client->last_deny = GC_DENY_NONE;
    client->notice_served = true;
    return GC_OK;
}

static gc_err_t normalise_e164(const char *in, char *out, size_t out_len)
{
    if (in == NULL || out == NULL || out_len < 2u) {
        return GC_ERR_INVALID_ARG;
    }
    size_t n = 0u;
    out[n++] = '+';
    for (const char *p = in; *p != '\0'; p++) {
        char ch = *p;
        if (ch >= '0' && ch <= '9') {
            if (n + 1u >= out_len) {
                return GC_ERR_INVALID_ARG;
            }
            out[n++] = ch;
            continue;
        }
        if (ch == '+' || ch == ' ' || ch == '-' || ch == '.' || ch == '(' || ch == ')') {
            continue;
        }
        return GC_ERR_INVALID_ARG;
    }
    out[n] = '\0';
    if (n < 2u || (n - 1u) > GC_GATE_E164_DIGITS_MAX) {
        return GC_ERR_INVALID_ARG;
    }
    return GC_OK;
}

static gc_err_t pending_push(const gc_req_id_t *req,
                             const gc_key_t *number_key,
                             const gc_key_t *mac_key,
                             const gc_mac_t *mac)
{
    if (s_pending_count == GC_MAX_PENDING_VERIFY) {
        memmove(&s_pending[0], &s_pending[1], (GC_MAX_PENDING_VERIFY - 1u) * sizeof(s_pending[0]));
        s_pending_count--;
        GC_LOGW("gate", "pending verify queue full, oldest request dropped");
    }
    gc_pending_t *entry = &s_pending[s_pending_count];
    memset(entry, 0, sizeof(*entry));
    entry->req = *req;
    entry->number_key = *number_key;
    entry->mac_key = *mac_key;
    entry->mac = *mac;
    entry->queued_ms = gate_now_ms();
    entry->used = true;
    s_pending_count++;
    return GC_OK;
}

static gc_pending_t *pending_find(const gc_req_id_t *req)
{
    if (req == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < s_pending_count; i++) {
        if (memcmp(&s_pending[i].req, req, GC_REQ_ID_LEN) == 0) {
            return &s_pending[i];
        }
    }
    return NULL;
}

static void pending_drop(const gc_pending_t *entry)
{
    size_t index = (size_t)(entry - &s_pending[0]);
    if (index >= s_pending_count) {
        return;
    }
    memmove(&s_pending[index],
            &s_pending[index + 1u],
            (s_pending_count - index - 1u) * sizeof(s_pending[0]));
    s_pending_count--;
    memset(&s_pending[s_pending_count], 0, sizeof(s_pending[0]));
}

gc_err_t gc_gate_init(size_t max_clients, uint32_t client_rate_kbyte_s)
{
    if (max_clients == 0u) {
        return GC_ERR_INVALID_ARG;
    }
    if (max_clients > GC_MAX_CLIENTS) {
        max_clients = GC_MAX_CLIENTS;
    }

    if (gc_config_load(&s_cfg) != GC_OK) {
        gc_config_defaults(&s_cfg);
        GC_LOGW("gate", "config load failed, using defaults for gate timing");
    }
    if (client_rate_kbyte_s == 0u) {
        client_rate_kbyte_s = s_cfg.client_rate_kbyte_s;
    }
    if (client_rate_kbyte_s == 0u) {
        client_rate_kbyte_s = 1u;
    }

    gc_client_slot_t *clients = gate_alloc(max_clients * sizeof(*clients));
    if (clients == NULL) {
        return GC_ERR_NO_MEM;
    }
    memset(clients, 0, max_clients * sizeof(*clients));

    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateRecursiveMutex();
        if (s_lock == NULL) {
            heap_caps_free(clients);
            return GC_ERR_NO_MEM;
        }
    }

    if (s_clients != NULL) {
        heap_caps_free(s_clients);
    }
    s_clients = clients;
    s_client_cap = max_clients;
    s_rate_byte_s = client_rate_kbyte_s * 1024u;
    s_clock_offset_s = 0;
    s_pending_count = 0u;
    memset(s_pending, 0, sizeof(s_pending));
    memset(s_blocks, 0, sizeof(s_blocks));

    GC_LOGI("gate", "clients=%u rate=%u B/s strikes=%u soft_block=%us",
            (unsigned)s_client_cap, (unsigned)s_rate_byte_s,
            (unsigned)strike_limit(), (unsigned)soft_block_s());
    return GC_OK;
}

void gc_gate_deinit(void)
{
    if (!gate_lock()) {
        return;
    }
    if (s_clients != NULL) {
        heap_caps_free(s_clients);
        s_clients = NULL;
    }
    s_client_cap = 0u;
    s_pending_count = 0u;
    memset(s_pending, 0, sizeof(s_pending));
    memset(s_blocks, 0, sizeof(s_blocks));
    SemaphoreHandle_t lock = s_lock;
    s_lock = NULL;
    if (lock != NULL) {
        xSemaphoreGiveRecursive(lock);
        vSemaphoreDelete(lock);
    }
}

gc_client_t *gc_gate_find(const gc_mac_t *mac)
{
    if (mac == NULL || !gate_lock()) {
        return NULL;
    }
    gc_client_slot_t *slot = slot_find(mac);
    gc_client_t *client = (slot != NULL) ? &slot->client : NULL;
    gate_unlock();
    return client;
}

gc_err_t gc_gate_upsert(const gc_mac_t *mac, gc_client_t **out)
{
    if (mac == NULL || gc_mac_is_zero(mac) || !gate_lock()) {
        return GC_ERR_INVALID_ARG;
    }
    gc_client_slot_t *slot = slot_find(mac);
    bool created = false;
    if (slot == NULL) {
        slot = slot_create(mac);
        created = true;
        if (slot == NULL) {
            gate_unlock();
            return GC_ERR_FULL;
        }
    }
    slot_touch(slot);
    if (created && !key_is_zero(&slot->client.number_key)) {
        client_sync_block(&slot->client);
    }
    if (out != NULL) {
        *out = &slot->client;
    }
    gate_unlock();
    return GC_OK;
}

gc_err_t gc_gate_remove(const gc_mac_t *mac)
{
    if (mac == NULL || !gate_lock()) {
        return GC_ERR_INVALID_ARG;
    }
    gc_client_slot_t *slot = slot_find(mac);
    if (slot == NULL) {
        gate_unlock();
        return GC_ERR_NOT_FOUND;
    }
    memset(slot, 0, sizeof(*slot));
    gate_unlock();
    return GC_OK;
}

gc_err_t gc_gate_set_state(const gc_mac_t *mac, gc_client_state_t state, gc_deny_reason_t reason)
{
    if (mac == NULL || !gate_lock()) {
        return GC_ERR_INVALID_ARG;
    }
    gc_client_slot_t *slot = slot_find(mac);
    if (slot == NULL) {
        gate_unlock();
        return GC_ERR_NOT_FOUND;
    }
    gc_client_t *client = &slot->client;
    uint32_t now_s = gate_now_s();
    client->state = state;
    client->last_deny = reason;
    if (state == GC_CLIENT_ALLOWED) {
        client->permanent = false;
        client->blocked_until_s = 0u;
        if (client->allowed_until_s <= now_s) {
            client->allowed_until_s = now_s + allow_grace_s();
        }
        client->notice_served = true;
    } else if (state == GC_CLIENT_SOFT_BLOCKED) {
        client->allowed_until_s = 0u;
        if (client->blocked_until_s <= now_s) {
            client->blocked_until_s = now_s + soft_block_s();
        }
    } else if (state == GC_CLIENT_PERMANENTLY_BLOCKED) {
        client->permanent = true;
        client->allowed_until_s = 0u;
        client->blocked_until_s = 0u;
    } else {
        client->allowed_until_s = 0u;
    }
    slot_touch(slot);
    gate_unlock();
    return GC_OK;
}

gc_err_t gc_gate_apply_verdict(const gc_mac_t *mac,
                               const gc_key_t *number_key,
                               bool allow,
                               uint32_t allowed_until_s,
                               gc_deny_reason_t reason)
{
    if (mac == NULL || !gate_lock()) {
        return GC_ERR_INVALID_ARG;
    }
    gc_client_slot_t *slot = slot_find(mac);
    if (slot == NULL) {
        gate_unlock();
        return GC_ERR_NOT_FOUND;
    }
    gc_client_t *client = &slot->client;
    if (number_key != NULL && !key_is_zero(number_key)) {
        client->number_key = *number_key;
        client_sync_block(client);
    }
    gc_err_t err;
    if (allow) {
        err = client_register_allow(client, allowed_until_s);
    } else {
        err = client_register_deny(slot, 0u, reason);
    }
    slot_touch(slot);
    gate_unlock();
    return err;
}

gc_err_t gc_gate_soft_block(const gc_mac_t *mac, uint32_t seconds)
{
    if (mac == NULL || !gate_lock()) {
        return GC_ERR_INVALID_ARG;
    }
    gc_client_slot_t *slot = slot_find(mac);
    if (slot == NULL) {
        gate_unlock();
        return GC_ERR_NOT_FOUND;
    }
    uint32_t blocked_until_s = gate_now_s() + (seconds != 0u ? seconds : soft_block_s());
    gc_err_t err = client_register_deny(slot, blocked_until_s, GC_DENY_NOT_VERIFIED);
    gate_unlock();
    return err;
}

gc_err_t gc_gate_permanent_block(const gc_key_t *number_key, const gc_key_t *mac_key)
{
    if ((number_key == NULL || key_is_zero(number_key)) || !gate_lock()) {
        return GC_ERR_INVALID_ARG;
    }
    gc_block_entry_t *block = block_acquire(number_key, mac_key);
    if (block == NULL) {
        gate_unlock();
        return GC_ERR_NO_MEM;
    }
    if (mac_key != NULL && !key_is_zero(mac_key)) {
        block->rec.mac_key = *mac_key;
    }
    if (block->rec.strikes < strike_limit()) {
        block->rec.strikes = strike_limit();
    }
    block->rec.permanent = 1u;
    block->rec.blocked_until_s = 0u;
    block->updated_ms = gate_now_ms();

    size_t marked = 0u;
    for (size_t i = 0; i < s_client_cap; i++) {
        gc_client_t *client = &s_clients[i].client;
        if (!s_clients[i].used) {
            continue;
        }
        bool match = gc_key_equal(&client->number_key, number_key);
        if (!match && mac_key != NULL && !key_is_zero(mac_key) && !key_is_zero(&client->mac_key)) {
            match = gc_key_equal(&client->mac_key, mac_key);
        }
        if (!match) {
            continue;
        }
        client->number_key = block->rec.number_key;
        client->mac_key = block->rec.mac_key;
        client->strikes = block->rec.strikes;
        client->permanent = true;
        client->state = GC_CLIENT_PERMANENTLY_BLOCKED;
        client->last_deny = GC_DENY_STRIKE_LIMIT;
        client->allowed_until_s = 0u;
        client->blocked_until_s = 0u;
        slot_touch(&s_clients[i]);
        marked++;
    }

    gc_err_t err = gc_gate_persist();
    gate_unlock();
    GC_LOGW("gate", "permanent block installed on %u client(s)", (unsigned)marked);
    return err;
}

gc_err_t gc_gate_unblock(const gc_key_t *number_key)
{
    if ((number_key == NULL || key_is_zero(number_key)) || !gate_lock()) {
        return GC_ERR_INVALID_ARG;
    }
    gc_block_entry_t *block = block_find(number_key);
    if (block != NULL) {
        memset(&block->rec, 0, sizeof(block->rec));
        block->used = false;
        block->updated_ms = 0u;
    }
    for (size_t i = 0; i < s_client_cap; i++) {
        gc_client_t *client = &s_clients[i].client;
        if (!s_clients[i].used || !gc_key_equal(&client->number_key, number_key)) {
            continue;
        }
        client->permanent = false;
        client->strikes = 0u;
        client->blocked_until_s = 0u;
        client->allowed_until_s = 0u;
        client->state = GC_CLIENT_NEW;
        client->last_deny = GC_DENY_NONE;
        slot_touch(&s_clients[i]);
    }

    gc_err_t err = gc_gate_persist();
    gate_unlock();
    GC_LOGI("gate", "controller unblock accepted");
    return err;
}

gc_err_t gc_gate_unblock_all(void)
{
    if (!gate_lock()) {
        return GC_ERR_INVALID_ARG;
    }
    memset(s_blocks, 0, sizeof(s_blocks));
    for (size_t i = 0; i < s_client_cap; i++) {
        gc_client_t *client = &s_clients[i].client;
        if (!s_clients[i].used) {
            continue;
        }
        client->permanent = false;
        client->strikes = 0u;
        client->blocked_until_s = 0u;
        client->allowed_until_s = 0u;
        client->state = GC_CLIENT_NEW;
        client->last_deny = GC_DENY_NONE;
    }
    gc_err_t err = gc_nvs_erase_key(GC_GATE_BLOCKS_KEY);
    if (err == GC_OK || err == GC_ERR_NOT_FOUND) {
        err = gc_nvs_commit();
    }
    gate_unlock();
    GC_LOGW("gate", "operator unblock of every block key accepted");
    return err;
}

bool gc_gate_forward_allowed(const gc_mac_t *mac)
{
    if (mac == NULL || !gate_lock()) {
        return false;
    }
    gc_client_slot_t *slot = slot_find(mac);
    if (slot == NULL) {
        gate_unlock();
        return false;
    }
    gc_client_t *client = &slot->client;
    uint32_t now_s = gate_now_s();
    bool allowed = false;
    if (!client->permanent && client->state == GC_CLIENT_ALLOWED) {
        gc_block_entry_t *block = block_find(&client->number_key);
        bool key_permanent = (block != NULL && block->rec.permanent != 0u);
        bool soft_blocked = client->blocked_until_s > now_s ||
                            (block != NULL && block->rec.blocked_until_s > now_s);
        allowed = !key_permanent && !soft_blocked && client->allowed_until_s > now_s;
    }
    gate_unlock();
    return allowed;
}

bool gc_gate_permanently_blocked_key(const gc_key_t *number_key)
{
    if (number_key == NULL || key_is_zero(number_key) || !gate_lock()) {
        return false;
    }
    gc_block_entry_t *block = block_find(number_key);
    bool permanent = (block != NULL && block->rec.permanent != 0u);
    if (!permanent) {
        for (size_t i = 0; i < s_client_cap; i++) {
            if (s_clients[i].used && s_clients[i].client.permanent &&
                gc_key_equal(&s_clients[i].client.number_key, number_key)) {
                permanent = true;
                break;
            }
        }
    }
    gate_unlock();
    return permanent;
}

gc_err_t gc_gate_submit_number(const gc_mac_t *mac, const char *e164_number, gc_req_id_t *out_req)
{
    if (mac == NULL || gc_mac_is_zero(mac) || e164_number == NULL || out_req == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    char e164[GC_GATE_E164_DIGITS_MAX + 2u];
    gc_err_t err = normalise_e164(e164_number, e164, sizeof(e164));
    if (err != GC_OK) {
        GC_LOGW("gate", "number rejected by normaliser");
        return err;
    }

    uint8_t pepper[GC_PEPPER_LEN];
    if (gc_crypto_load_pepper(pepper) != GC_OK) {
        GC_LOGE("gate", "no pepper provisioned, verification refused");
        return GC_ERR_AUTH;
    }

    gc_key_t number_key;
    gc_key_t mac_key;
    if (gc_crypto_number_key(pepper, e164, &number_key) != GC_OK ||
        gc_crypto_mac_key(pepper, mac, &mac_key) != GC_OK) {
        return GC_ERR_IO;
    }
    memset(pepper, 0, sizeof(pepper));

    if (!gate_lock()) {
        return GC_ERR_INVALID_ARG;
    }
    gc_client_slot_t *slot = slot_find(mac);
    if (slot == NULL) {
        slot = slot_create(mac);
        if (slot == NULL) {
            gate_unlock();
            return GC_ERR_FULL;
        }
    }
    gc_client_t *client = &slot->client;
    client->number_key = number_key;
    client->mac_key = mac_key;
    client_sync_block(client);

    if (client->permanent) {
        gate_unlock();
        GC_LOGW("gate", "submit refused, number key permanently blocked");
        return GC_ERR_AUTH;
    }

    gc_req_id_t req;
    for (;;) {
        for (size_t i = 0; i < GC_REQ_ID_LEN; i++) {
            req.b[i] = (uint8_t)(esp_random() & 0xFFu);
        }
        bool zero = true;
        for (size_t i = 0; i < GC_REQ_ID_LEN; i++) {
            if (req.b[i] != 0u) {
                zero = false;
                break;
            }
        }
        if (!zero && pending_find(&req) == NULL) {
            break;
        }
    }

    client->state = GC_CLIENT_PENDING;
    client->last_deny = GC_DENY_PENDING;
    slot_touch(slot);
    err = pending_push(&req, &number_key, &mac_key, mac);
    gate_unlock();

    if (err == GC_OK) {
        *out_req = req;
    }
    return err;
}

gc_err_t gc_gate_pending_peek(gc_req_id_t *req,
                              gc_key_t *number_key,
                              gc_key_t *mac_key,
                              gc_mac_t *mac,
                              uint32_t *age_s)
{
    if (!gate_lock()) {
        return GC_ERR_INVALID_ARG;
    }
    if (s_pending_count == 0u) {
        gate_unlock();
        return GC_ERR_NOT_FOUND;
    }
    gc_pending_t *entry = &s_pending[0];
    if (req != NULL) {
        *req = entry->req;
    }
    if (number_key != NULL) {
        *number_key = entry->number_key;
    }
    if (mac_key != NULL) {
        *mac_key = entry->mac_key;
    }
    if (mac != NULL) {
        *mac = entry->mac;
    }
    if (age_s != NULL) {
        *age_s = (gate_now_ms() - entry->queued_ms) / 1000u;
    }
    gate_unlock();
    return GC_OK;
}

gc_err_t gc_gate_pending_resolve(const gc_req_id_t *req,
                                 bool allow,
                                 uint32_t allowed_until_s,
                                 uint32_t blocked_until_s,
                                 gc_deny_reason_t reason)
{
    if (req == NULL || !gate_lock()) {
        return GC_ERR_INVALID_ARG;
    }
    gc_pending_t *entry = pending_find(req);
    if (entry == NULL) {
        gate_unlock();
        return GC_ERR_NOT_FOUND;
    }
    gc_pending_t pending = *entry;
    pending_drop(entry);

    gc_client_slot_t *slot = slot_find(&pending.mac);
    if (slot == NULL) {
        if (allow) {
            gate_unlock();
            return GC_OK;
        }
        uint32_t blocked = (blocked_until_s != 0u) ? blocked_until_s : gate_now_s() + soft_block_s();
        gc_err_t err = block_strike(&pending.number_key, &pending.mac_key, blocked, NULL);
        if (err == GC_OK) {
            err = gc_gate_persist();
        }
        gate_unlock();
        return err;
    }

    gc_client_t *client = &slot->client;
    client->number_key = pending.number_key;
    client->mac_key = pending.mac_key;

    gc_err_t err;
    if (allow) {
        err = client_register_allow(client, allowed_until_s);
        if (err != GC_OK) {
            GC_LOGW("gate", "allow verdict rejected for a permanently blocked key");
        }
    } else {
        err = client_register_deny(slot, blocked_until_s, reason);
    }
    slot_touch(slot);
    gate_unlock();
    return err;
}

gc_err_t gc_gate_pending_expire(uint32_t older_than_s)
{
    if (!gate_lock()) {
        return GC_ERR_INVALID_ARG;
    }
    uint32_t now_ms = gate_now_ms();
    for (size_t i = 0; i < s_pending_count;) {
        uint32_t age_s = (now_ms - s_pending[i].queued_ms) / 1000u;
        if (age_s >= older_than_s) {
            GC_LOGW("gate", "pending verify request aged out after %us", (unsigned)age_s);
            pending_drop(&s_pending[i]);
            continue;
        }
        i++;
    }
    gate_unlock();
    return GC_OK;
}

gc_err_t gc_gate_account_bytes(const gc_mac_t *mac, bool uplink, size_t bytes)
{
    if (mac == NULL || !gate_lock()) {
        return GC_ERR_INVALID_ARG;
    }
    gc_client_slot_t *slot = slot_find(mac);
    if (slot == NULL) {
        gate_unlock();
        return GC_ERR_NOT_FOUND;
    }
    if (uplink) {
        slot->client.bytes_up += bytes;
    } else {
        slot->client.bytes_down += bytes;
    }
    slot_touch(slot);
    gate_unlock();
    return GC_OK;
}

bool gc_gate_rate_allow(const gc_mac_t *mac, size_t bytes)
{
    if (mac == NULL || !gate_lock()) {
        return false;
    }
    gc_client_slot_t *slot = slot_find(mac);
    if (slot == NULL) {
        gate_unlock();
        return false;
    }
    gc_client_t *client = &slot->client;
    uint32_t now_ms = gate_now_ms();
    uint32_t capacity = s_rate_byte_s != 0u ? s_rate_byte_s : 1024u;

    if (client->rate_last_ms == 0u) {
        client->rate_tokens_byte = capacity;
        client->rate_last_ms = now_ms;
    }

    uint32_t elapsed_ms = now_ms - client->rate_last_ms;
    client->rate_last_ms = now_ms;
    if (elapsed_ms != 0u && client->rate_tokens_byte < capacity) {
        uint64_t refill = ((uint64_t)elapsed_ms * (uint64_t)capacity) / 1000ULL;
        uint64_t tokens = (uint64_t)client->rate_tokens_byte + refill;
        client->rate_tokens_byte = (tokens > (uint64_t)capacity) ? capacity : (uint32_t)tokens;
    }

    bool allowed = client->rate_tokens_byte >= bytes;
    if (allowed) {
        client->rate_tokens_byte -= (uint32_t)bytes;
    }
    slot_touch(slot);
    gate_unlock();
    return allowed;
}

gc_err_t gc_gate_mark_notice_served(const gc_mac_t *mac)
{
    if (mac == NULL || !gate_lock()) {
        return GC_ERR_INVALID_ARG;
    }
    gc_client_slot_t *slot = slot_find(mac);
    if (slot == NULL) {
        gate_unlock();
        return GC_ERR_NOT_FOUND;
    }
    slot->client.notice_served = true;
    slot_touch(slot);
    gate_unlock();
    return GC_OK;
}

bool gc_gate_notice_served(const gc_mac_t *mac)
{
    if (mac == NULL || !gate_lock()) {
        return false;
    }
    gc_client_slot_t *slot = slot_find(mac);
    bool served = (slot != NULL) && slot->client.notice_served;
    gate_unlock();
    return served;
}

void gc_gate_tick(uint32_t now_s)
{
    if (!gate_lock()) {
        return;
    }
    s_clock_offset_s = (int64_t)now_s - (int64_t)(esp_timer_get_time() / 1000000ULL);
    for (size_t i = 0; i < s_client_cap; i++) {
        gc_client_t *client = &s_clients[i].client;
        if (!s_clients[i].used || client->permanent) {
            continue;
        }
        if (client->state == GC_CLIENT_SOFT_BLOCKED && client->blocked_until_s <= now_s) {
            client->state = GC_CLIENT_NEW;
            client->blocked_until_s = 0u;
            client->last_deny = GC_DENY_NONE;
            continue;
        }
        if (client->state == GC_CLIENT_ALLOWED && client->allowed_until_s <= now_s) {
            client->state = GC_CLIENT_NEW;
            client->allowed_until_s = 0u;
            client->last_deny = GC_DENY_EXPIRED;
        }
    }
    gate_unlock();
}

size_t gc_gate_client_count(void)
{
    if (!gate_lock()) {
        return 0u;
    }
    size_t count = 0u;
    for (size_t i = 0; i < s_client_cap; i++) {
        if (s_clients[i].used) {
            count++;
        }
    }
    gate_unlock();
    return count;
}

size_t gc_gate_allowed_count(void)
{
    if (!gate_lock()) {
        return 0u;
    }
    uint32_t now_s = gate_now_s();
    size_t count = 0u;
    for (size_t i = 0; i < s_client_cap; i++) {
        gc_client_t *client = &s_clients[i].client;
        if (s_clients[i].used && !client->permanent && client->state == GC_CLIENT_ALLOWED &&
            client->allowed_until_s > now_s) {
            count++;
        }
    }
    gate_unlock();
    return count;
}

gc_err_t gc_gate_foreach(gc_gate_visitor_t fn, void *ctx)
{
    if (fn == NULL || !gate_lock()) {
        return GC_ERR_INVALID_ARG;
    }
    for (size_t i = 0; i < s_client_cap; i++) {
        if (!s_clients[i].used) {
            continue;
        }
        if (!fn(&s_clients[i].client, ctx)) {
            break;
        }
    }
    gate_unlock();
    return GC_OK;
}

gc_err_t gc_gate_persist(void)
{
    if (!gate_lock()) {
        return GC_ERR_INVALID_ARG;
    }
    uint32_t now_s = gate_now_s();
    size_t count = 0u;
    for (size_t i = 0; i < GC_GATE_BLOCK_MAX; i++) {
        gc_block_entry_t *block = &s_blocks[i];
        if (!block->used) {
            continue;
        }
        if (block->rec.permanent == 0u && block->rec.strikes == 0u &&
            block->rec.blocked_until_s <= now_s) {
            continue;
        }
        count++;
    }

    size_t size = GC_GATE_BLOCK_HEADER_SIZE + (count * GC_GATE_BLOCK_RECORD_SIZE);
    uint8_t *buf = gate_alloc(size);
    if (buf == NULL) {
        gate_unlock();
        return GC_ERR_NO_MEM;
    }
    memset(buf, 0, size);
    memcpy(buf, GC_GATE_BLOCK_MAGIC, sizeof(GC_GATE_BLOCK_MAGIC));
    put_u16(buf + 4u, (uint16_t)GC_GATE_BLOCK_VERSION);
    put_u16(buf + 6u, (uint16_t)count);

    size_t offset = GC_GATE_BLOCK_HEADER_SIZE;
    for (size_t i = 0; i < GC_GATE_BLOCK_MAX; i++) {
        gc_block_entry_t *block = &s_blocks[i];
        if (!block->used) {
            continue;
        }
        if (block->rec.permanent == 0u && block->rec.strikes == 0u &&
            block->rec.blocked_until_s <= now_s) {
            continue;
        }
        block_record_write(buf + offset, &block->rec);
        offset += GC_GATE_BLOCK_RECORD_SIZE;
    }

    gc_err_t err = gc_nvs_set_blob(GC_GATE_BLOCKS_KEY, buf, size);
    if (err == GC_OK) {
        err = gc_nvs_commit();
    }
    heap_caps_free(buf);
    if (err != GC_OK) {
        GC_LOGE("gate", "block persist failed err=%s", gc_err_name(err));
    }
    gate_unlock();
    return err;
}

gc_err_t gc_gate_restore(void)
{
    if (!gate_lock()) {
        return GC_ERR_INVALID_ARG;
    }
    size_t max_size = GC_GATE_BLOCK_HEADER_SIZE + (GC_GATE_BLOCK_MAX * GC_GATE_BLOCK_RECORD_SIZE);
    uint8_t *buf = gate_alloc(max_size);
    if (buf == NULL) {
        gate_unlock();
        return GC_ERR_NO_MEM;
    }
    memset(buf, 0, max_size);

    size_t len = max_size;
    gc_err_t err = gc_nvs_get_blob(GC_GATE_BLOCKS_KEY, buf, &len);
    if (err != GC_OK) {
        heap_caps_free(buf);
        gate_unlock();
        if (err == GC_ERR_NOT_FOUND) {
            GC_LOGI("gate", "no persisted blocks to replay");
            return GC_OK;
        }
        GC_LOGE("gate", "block restore failed err=%s", gc_err_name(err));
        return err;
    }
    if (len < GC_GATE_BLOCK_HEADER_SIZE || len > max_size ||
        memcmp(buf, GC_GATE_BLOCK_MAGIC, sizeof(GC_GATE_BLOCK_MAGIC)) != 0 ||
        get_u16(buf + 4u) != (uint16_t)GC_GATE_BLOCK_VERSION) {
        heap_caps_free(buf);
        gate_unlock();
        GC_LOGE("gate", "persisted blocks rejected, header mismatch");
        return GC_ERR_IO;
    }

    size_t available = (len - GC_GATE_BLOCK_HEADER_SIZE) / GC_GATE_BLOCK_RECORD_SIZE;
    size_t count = get_u16(buf + 6u);
    if (count > available) {
        count = available;
    }
    if (count > GC_GATE_BLOCK_MAX) {
        count = GC_GATE_BLOCK_MAX;
    }

    memset(s_blocks, 0, sizeof(s_blocks));
    size_t loaded = 0u;
    for (size_t i = 0; i < count; i++) {
        gc_block_record_t rec;
        block_record_read(buf + GC_GATE_BLOCK_HEADER_SIZE + (i * GC_GATE_BLOCK_RECORD_SIZE), &rec);
        if (key_is_zero(&rec.number_key)) {
            continue;
        }
        gc_block_entry_t *block = block_acquire(&rec.number_key, &rec.mac_key);
        if (block == NULL) {
            break;
        }
        block->rec = rec;
        block->updated_ms = gate_now_ms();
        loaded++;
    }
    heap_caps_free(buf);

    for (size_t i = 0; i < s_client_cap; i++) {
        if (s_clients[i].used) {
            client_sync_block(&s_clients[i].client);
        }
    }
    gate_unlock();
    GC_LOGI("gate", "replayed %u persisted block record(s)", (unsigned)loaded);
    return GC_OK;
}

gc_err_t gc_gate_export_blocks(void (*emit)(void *ctx, const gc_key_t *number_key,
                                            const gc_key_t *mac_key, uint32_t strikes,
                                            bool permanent, uint32_t blocked_until_s),
                              void *ctx)
{
    if (emit == NULL || !gate_lock()) {
        return GC_ERR_INVALID_ARG;
    }
    for (size_t i = 0; i < GC_GATE_BLOCK_MAX; i++) {
        gc_block_entry_t *block = &s_blocks[i];
        if (!block->used) {
            continue;
        }
        emit(ctx, &block->rec.number_key, &block->rec.mac_key, block->rec.strikes,
             block->rec.permanent != 0u, block->rec.blocked_until_s);
    }
    gate_unlock();
    return GC_OK;
}
