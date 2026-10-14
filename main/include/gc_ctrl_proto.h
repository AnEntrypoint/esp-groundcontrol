#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "gc_types.h"
#include "gc_config.h"

#define GC_TOPIC_MAX 160
#define GC_VERDICT_REASON_MAX 32
#define GC_CMD_NAME_MAX 24

typedef enum {
    GC_CTRL_MSG_UNKNOWN = 0,
    GC_CTRL_MSG_VERDICT,
    GC_CTRL_MSG_UNBLOCK,
    GC_CTRL_MSG_ACK,
    GC_CTRL_MSG_COMMAND,
} gc_ctrl_msg_kind_t;

typedef struct {
    gc_req_id_t req_id;
    bool allow;
    uint32_t allowed_until_s;
    uint32_t blocked_until_s;
    uint32_t strikes;
    bool permanent;
    gc_deny_reason_t reason;
    char challenge_hint[GC_VERDICT_REASON_MAX + 1];
} gc_verdict_t;

typedef struct {
    gc_key_t number_key;
    gc_key_t mac_key;
    uint32_t sequence;
    uint8_t mac[GC_KEY_LEN];
    bool clear_strikes;
} gc_unblock_t;

typedef struct {
    uint32_t sequence;
    uint32_t server_time_s;
    bool heartbeat_seen;
} gc_ack_t;

typedef struct {
    char name[GC_CMD_NAME_MAX + 1];
    uint32_t sequence;
    uint8_t mac[GC_KEY_LEN];
    uint32_t uint_arg;
    bool bool_arg;
} gc_command_t;

typedef struct {
    gc_ctrl_msg_kind_t kind;
    union {
        gc_verdict_t verdict;
        gc_unblock_t unblock;
        gc_ack_t ack;
        gc_command_t command;
    } as;
} gc_ctrl_msg_t;

void gc_ctrl_topic_build(char *out,
                         size_t out_len,
                         const char *direction,
                         const char *channel,
                         uint16_t site_id,
                         uint16_t device_id);

void gc_ctrl_topics_for_identity(uint16_t site_id,
                                 uint16_t device_id,
                                 char *up_tele,
                                 size_t up_tele_len,
                                 char *up_event,
                                 size_t up_event_len,
                                 char *up_verify,
                                 size_t up_verify_len,
                                 char *up_hello,
                                 size_t up_hello_len,
                                 char *up_ota,
                                 size_t up_ota_len,
                                 char *dn_verdict,
                                 size_t dn_verdict_len,
                                 char *dn_unblock,
                                 size_t dn_unblock_len,
                                 char *dn_ack,
                                 size_t dn_ack_len,
                                 char *dn_cmd,
                                 size_t dn_cmd_len);

const char *gc_ctrl_channel_for_topic(const char *topic);

gc_err_t gc_ctrl_encode_verify_request(const gc_identity_t *id,
                                       const gc_req_id_t *req,
                                       const gc_key_t *number_key,
                                       const gc_key_t *mac_key,
                                       gc_verify_mode_t mode,
                                       char *out,
                                       size_t out_len);

gc_err_t gc_ctrl_encode_event(const gc_identity_t *id,
                              const char *event,
                              const gc_key_t *number_key,
                              const gc_key_t *mac_key,
                              uint32_t strikes,
                              const char *detail,
                              char *out,
                              size_t out_len);

gc_err_t gc_ctrl_encode_hello(const gc_identity_t *id,
                              uint8_t fw_version,
                              gc_slot_t slot,
                              bool trial_pending,
                              bool notice_pending,
                              char *out,
                              size_t out_len);

gc_err_t gc_ctrl_decode(const char *topic,
                        const char *json,
                        size_t json_len,
                        gc_ctrl_msg_t *out);

const char *gc_ctrl_kind_name(gc_ctrl_msg_kind_t kind);
