#pragma once

#include <stdint.h>
#include "gc_types.h"

gc_err_t gc_nat_enable(void);
gc_err_t gc_nat_disable(void);
bool gc_nat_enabled(void);

gc_err_t gc_nat_set_forwarding_paused(bool paused);
bool gc_nat_forwarding_paused(void);

uint64_t gc_nat_uplink_bytes_up(void);
uint64_t gc_nat_uplink_bytes_down(void);
uint64_t gc_nat_uplink_bytes(void);
void gc_nat_reset_counters(void);
