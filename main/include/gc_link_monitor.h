#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "gc_types.h"

#define GC_LINK_PROBE_INTERVAL_S 60
#define GC_LINK_FAULT_CONFIRM_COUNT 2

gc_err_t gc_link_monitor_init(const char *probe_host);
gc_err_t gc_link_monitor_set_probe_host(const char *host);

gc_err_t gc_link_monitor_tick(uint32_t now_s);
gc_err_t gc_link_monitor_report_internet(bool ok);
gc_err_t gc_link_monitor_report_mqtt(bool ok);

bool gc_link_monitor_internet_up(void);
gc_escalation_step_t gc_link_monitor_step(void);
uint32_t gc_link_monitor_fault_episode(void);

gc_err_t gc_link_monitor_claim_modem_api_reboot(uint32_t now_s, bool *granted);
gc_err_t gc_link_monitor_claim_modem_power_cycle(uint32_t now_s, bool *granted);
uint32_t gc_link_monitor_seconds_until_api_reboot_allowed(uint32_t now_s);
uint32_t gc_link_monitor_seconds_until_power_cycle_allowed(uint32_t now_s);
gc_err_t gc_link_monitor_clear_fault(void);
