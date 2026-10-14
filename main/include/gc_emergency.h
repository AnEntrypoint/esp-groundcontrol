#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "gc_types.h"

#define GC_BEACON_LEN 16
#define GC_BEACON_PAYLOAD_LEN (GC_BEACON_LEN - GC_KEY_LEN)

#define GC_BEACON_VERSION 1u
#define GC_BEACON_KIND_ROUTINE 1u
#define GC_BEACON_KIND_ALARM 2u

#define GC_BEACON_INTERVAL_S 900
#define GC_BEACON_INTERVAL_ALARM_S 120

gc_err_t gc_emergency_init(const gc_identity_t *id, const char *host, uint16_t port);
void gc_emergency_deinit(void);

gc_err_t gc_emergency_tick(uint32_t now_s);
void gc_emergency_set_alarm(bool alarm);
gc_err_t gc_emergency_beacon_send(bool alarm);
uint32_t gc_emergency_beacon_counter(void);

gc_err_t gc_emergency_encode_beacon(const gc_identity_t *id,
                                    bool alarm,
                                    uint32_t counter,
                                    uint8_t out[GC_BEACON_LEN]);

gc_err_t gc_emergency_tunnel_up(void);
gc_err_t gc_emergency_tunnel_down(void);
bool gc_emergency_tunnel_is_up(void);

gc_err_t gc_emergency_poll_reply(void);
bool gc_emergency_tunnel_requested(void);
