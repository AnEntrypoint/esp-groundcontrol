#pragma once

#include <stdint.h>
#include <stddef.h>
#include "gc_types.h"

#define GC_TELEMETRY_MAX_RECORDS 24
#define GC_TELEMETRY_FRAME_MAX 320

#define GC_TELEMETRY_FLAG_ALARM 0x01u
#define GC_TELEMETRY_FLAG_RESERVE_TRIPPED 0x02u
#define GC_TELEMETRY_FLAG_FORWARDING_PAUSED 0x04u
#define GC_TELEMETRY_FLAG_TUNNEL_UP 0x08u
#define GC_TELEMETRY_FLAG_TRIAL_PENDING 0x10u
#define GC_TELEMETRY_FLAG_CONTROLLER_UNREACHABLE 0x20u

#define GC_DEADBAND_RSSI_DBM 3
#define GC_DEADBAND_RSRP_DBM 3
#define GC_DEADBAND_RSRQ_DB 1
#define GC_DEADBAND_SINR_DB 2
#define GC_DEADBAND_CLIENTS 1

gc_err_t gc_telemetry_init(size_t capacity);
void gc_telemetry_reset(void);

gc_err_t gc_telemetry_push(const gc_reading_t *reading);
size_t gc_telemetry_pending(void);

gc_err_t gc_telemetry_encode(uint8_t flags,
                             const gc_identity_t *id,
                             uint8_t fw_version,
                             gc_slot_t slot,
                             uint8_t *out,
                             size_t out_len,
                             size_t *out_written);

gc_err_t gc_telemetry_encode_heartbeat(uint8_t flags,
                                       const gc_identity_t *id,
                                       uint8_t fw_version,
                                       gc_slot_t slot,
                                       uint8_t *out,
                                       size_t out_len,
                                       size_t *out_written);

bool gc_telemetry_deadband_passes(const gc_reading_t *candidate,
                                  const gc_reading_t *last_sent);

size_t gc_telemetry_varint_encode(uint64_t value, uint8_t *out, size_t out_len);
size_t gc_telemetry_varint_decode(const uint8_t *in, size_t in_len, uint64_t *out);
