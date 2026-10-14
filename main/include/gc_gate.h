#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "gc_types.h"
#include "gc_config.h"

typedef bool (*gc_gate_visitor_t)(const gc_client_t *client, void *ctx);

gc_err_t gc_gate_init(size_t max_clients, uint32_t client_rate_kbyte_s);
void gc_gate_deinit(void);

gc_client_t *gc_gate_find(const gc_mac_t *mac);
gc_err_t gc_gate_upsert(const gc_mac_t *mac, gc_client_t **out);
gc_err_t gc_gate_remove(const gc_mac_t *mac);

gc_err_t gc_gate_set_state(const gc_mac_t *mac,
                           gc_client_state_t state,
                           gc_deny_reason_t reason);

gc_err_t gc_gate_apply_verdict(const gc_mac_t *mac,
                               const gc_key_t *number_key,
                               bool allow,
                               uint32_t allowed_until_s,
                               gc_deny_reason_t reason);

gc_err_t gc_gate_soft_block(const gc_mac_t *mac, uint32_t seconds);
gc_err_t gc_gate_permanent_block(const gc_key_t *number_key, const gc_key_t *mac_key);
gc_err_t gc_gate_unblock(const gc_key_t *number_key);
gc_err_t gc_gate_unblock_all(void);

bool gc_gate_forward_allowed(const gc_mac_t *mac);
bool gc_gate_permanently_blocked_key(const gc_key_t *number_key);

gc_err_t gc_gate_submit_number(const gc_mac_t *mac,
                               const char *e164_number,
                               gc_req_id_t *out_req);

gc_err_t gc_gate_pending_peek(gc_req_id_t *req,
                              gc_key_t *number_key,
                              gc_key_t *mac_key,
                              gc_mac_t *mac,
                              uint32_t *age_s);

gc_err_t gc_gate_pending_resolve(const gc_req_id_t *req,
                                 bool allow,
                                 uint32_t allowed_until_s,
                                 uint32_t blocked_until_s,
                                 gc_deny_reason_t reason);

gc_err_t gc_gate_pending_expire(uint32_t older_than_s);

gc_err_t gc_gate_account_bytes(const gc_mac_t *mac, bool uplink, size_t bytes);
bool gc_gate_rate_allow(const gc_mac_t *mac, size_t bytes);

gc_err_t gc_gate_mark_notice_served(const gc_mac_t *mac);
bool gc_gate_notice_served(const gc_mac_t *mac);

void gc_gate_tick(uint32_t now_s);
size_t gc_gate_client_count(void);
size_t gc_gate_allowed_count(void);
gc_err_t gc_gate_foreach(gc_gate_visitor_t fn, void *ctx);

gc_err_t gc_gate_persist(void);
gc_err_t gc_gate_restore(void);
gc_err_t gc_gate_export_blocks(void (*emit)(void *ctx, const gc_key_t *number_key,
                                            const gc_key_t *mac_key, uint32_t strikes,
                                            bool permanent, uint32_t blocked_until_s),
                             void *ctx);
