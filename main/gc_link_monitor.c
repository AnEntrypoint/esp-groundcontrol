#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "gc_link_monitor.h"
#include "gc_log.h"
#include "gc_modem_api.h"
#include "gc_types.h"

#define GC_LINK_TAG "link_mon"

#define GC_LINK_API_REBOOT_INTERVAL_S 21600u
#define GC_LINK_POWER_CYCLE_INTERVAL_S 86400u
#define GC_LINK_POWER_CYCLE_COOLDOWN_S 300u

#define GC_LINK_STEP_DWELL_S 60u
#define GC_LINK_RETRY_LINK_ATTEMPTS 2u
#define GC_LINK_RERESOLVE_ATTEMPTS 2u
#define GC_LINK_MODEM_STEP_ATTEMPTS 1u

static struct {
    char probe_host[GC_HOST_MAX];
    uint32_t now_s;
    bool internet_up;
    bool mqtt_up;
    uint32_t probe_failures;
    uint32_t fault_episode;
    bool fault_confirmed;
    gc_escalation_step_t step;
    uint32_t step_entered_s;
    uint32_t step_attempts;
    uint32_t last_api_reboot_s;
    uint32_t last_power_cycle_s;
    uint32_t cooldown_until_s;
    uint32_t modem_api_silent_failures;
} s_link;

static bool link_deadline_passed(uint32_t now_s, uint32_t deadline_s)
{
    return (uint32_t)(now_s - deadline_s) < 0x80000000u;
}

static uint32_t link_seconds_until(uint32_t now_s, uint32_t deadline_s)
{
    if (link_deadline_passed(now_s, deadline_s)) {
        return 0;
    }
    return (uint32_t)(deadline_s - now_s);
}

static bool link_cooldown_active(uint32_t now_s)
{
    return s_link.cooldown_until_s != 0 && !link_deadline_passed(now_s, s_link.cooldown_until_s);
}

static const char *link_step_label(gc_escalation_step_t step)
{
    const char *name = gc_escalation_step_name(step);
    return name != NULL ? name : "unknown";
}

static void link_note_modem_api_silence(void)
{
    if (s_link.modem_api_silent_failures < UINT32_MAX) {
        s_link.modem_api_silent_failures++;
    }
    GC_LOGW(GC_LINK_TAG, "modem api silent fault %u, alarm only",
            (unsigned)s_link.modem_api_silent_failures);
}

static bool link_modem_reboot_escalation_allowed(void)
{
    if (s_link.internet_up) {
        return false;
    }
    if (!gc_modem_api_reachable()) {
        link_note_modem_api_silence();
        return false;
    }
    return true;
}

static gc_escalation_step_t link_next_step(gc_escalation_step_t current)
{
    switch (current) {
    case GC_ESCALATION_NONE:
    case GC_ESCALATION_RETRY_LINK:
        return GC_ESCALATION_RERESOLVE_DNS;
    case GC_ESCALATION_RERESOLVE_DNS:
        return link_modem_reboot_escalation_allowed() ? GC_ESCALATION_MODEM_API_REBOOT
                                                     : GC_ESCALATION_ALARM_ONLY;
    case GC_ESCALATION_MODEM_API_REBOOT:
        return GC_ESCALATION_MODEM_POWER_CYCLE;
    case GC_ESCALATION_MODEM_POWER_CYCLE:
    case GC_ESCALATION_ALARM_ONLY:
    default:
        return GC_ESCALATION_ALARM_ONLY;
    }
}

static uint32_t link_step_attempt_limit(gc_escalation_step_t step)
{
    switch (step) {
    case GC_ESCALATION_RETRY_LINK:
        return GC_LINK_RETRY_LINK_ATTEMPTS;
    case GC_ESCALATION_RERESOLVE_DNS:
        return GC_LINK_RERESOLVE_ATTEMPTS;
    case GC_ESCALATION_MODEM_API_REBOOT:
    case GC_ESCALATION_MODEM_POWER_CYCLE:
        return GC_LINK_MODEM_STEP_ATTEMPTS;
    default:
        return 1u;
    }
}

static void link_clear_fault_state(void)
{
    s_link.fault_confirmed = false;
    s_link.probe_failures = 0;
    s_link.step = GC_ESCALATION_NONE;
    s_link.step_entered_s = s_link.now_s;
    s_link.step_attempts = 0;
}

static void link_confirm_fault(void)
{
    if (s_link.fault_episode < UINT32_MAX) {
        s_link.fault_episode++;
    }
    s_link.fault_confirmed = true;
    s_link.step = GC_ESCALATION_RETRY_LINK;
    s_link.step_entered_s = s_link.now_s;
    s_link.step_attempts = 0;
    GC_LOGW(GC_LINK_TAG, "fault episode %u confirmed internet %u mqtt %u host %s",
            (unsigned)s_link.fault_episode,
            (unsigned)s_link.internet_up,
            (unsigned)s_link.mqtt_up,
            s_link.probe_host);
}

static void link_update_fault_state(void)
{
    bool probe_failed = !s_link.internet_up || !s_link.mqtt_up;
    if (!probe_failed) {
        if (s_link.fault_confirmed) {
            GC_LOGI(GC_LINK_TAG, "fault episode %u cleared", (unsigned)s_link.fault_episode);
            link_clear_fault_state();
            return;
        }
        s_link.probe_failures = 0;
        return;
    }
    if (s_link.probe_failures < UINT32_MAX) {
        s_link.probe_failures++;
    }
    if (!s_link.fault_confirmed && s_link.probe_failures >= GC_LINK_FAULT_CONFIRM_COUNT) {
        link_confirm_fault();
    }
}

static void link_advance_step_if_failed(uint32_t now_s)
{
    gc_escalation_step_t current = s_link.step;
    if (current == GC_ESCALATION_NONE || current == GC_ESCALATION_ALARM_ONLY) {
        return;
    }
    if (!link_deadline_passed(now_s, s_link.step_entered_s + GC_LINK_STEP_DWELL_S)) {
        return;
    }
    s_link.step_attempts++;
    if (s_link.step_attempts < link_step_attempt_limit(current)) {
        s_link.step_entered_s = now_s;
        GC_LOGI(GC_LINK_TAG, "step %s attempt %u episode %u",
                link_step_label(current), (unsigned)s_link.step_attempts,
                (unsigned)s_link.fault_episode);
        return;
    }
    gc_escalation_step_t next = link_next_step(current);
    s_link.step = next;
    s_link.step_entered_s = now_s;
    s_link.step_attempts = 0;
    GC_LOGW(GC_LINK_TAG, "escalation %s -> %s episode %u",
            link_step_label(current), link_step_label(next), (unsigned)s_link.fault_episode);
    if (next == GC_ESCALATION_ALARM_ONLY) {
        GC_LOGE(GC_LINK_TAG, "alarm episode %u api silent faults %u",
                (unsigned)s_link.fault_episode, (unsigned)s_link.modem_api_silent_failures);
    }
}

gc_err_t gc_link_monitor_init(const char *probe_host)
{
    memset(&s_link, 0, sizeof(s_link));
    s_link.internet_up = true;
    s_link.mqtt_up = true;
    s_link.step = GC_ESCALATION_NONE;
    return gc_link_monitor_set_probe_host(probe_host);
}

gc_err_t gc_link_monitor_set_probe_host(const char *host)
{
    if (host == NULL) {
        s_link.probe_host[0] = '\0';
        return GC_OK;
    }
    if (strlen(host) >= GC_HOST_MAX) {
        return GC_ERR_INVALID_ARG;
    }
    strcpy(s_link.probe_host, host);
    return GC_OK;
}

gc_err_t gc_link_monitor_tick(uint32_t now_s)
{
    s_link.now_s = now_s;
    if (!s_link.fault_confirmed) {
        return GC_OK;
    }
    if (link_cooldown_active(now_s)) {
        return GC_OK;
    }
    link_advance_step_if_failed(now_s);
    return GC_OK;
}

gc_err_t gc_link_monitor_report_internet(bool ok)
{
    s_link.internet_up = ok;
    link_update_fault_state();
    return GC_OK;
}

gc_err_t gc_link_monitor_report_mqtt(bool ok)
{
    s_link.mqtt_up = ok;
    link_update_fault_state();
    return GC_OK;
}

bool gc_link_monitor_internet_up(void)
{
    return s_link.internet_up;
}

gc_escalation_step_t gc_link_monitor_step(void)
{
    return s_link.step;
}

uint32_t gc_link_monitor_fault_episode(void)
{
    return s_link.fault_episode;
}

uint32_t gc_link_monitor_seconds_until_api_reboot_allowed(uint32_t now_s)
{
    if (s_link.last_api_reboot_s == 0) {
        return 0;
    }
    return link_seconds_until(now_s, s_link.last_api_reboot_s + GC_LINK_API_REBOOT_INTERVAL_S);
}

uint32_t gc_link_monitor_seconds_until_power_cycle_allowed(uint32_t now_s)
{
    if (s_link.last_power_cycle_s == 0) {
        return 0;
    }
    return link_seconds_until(now_s, s_link.last_power_cycle_s + GC_LINK_POWER_CYCLE_INTERVAL_S);
}

gc_err_t gc_link_monitor_claim_modem_api_reboot(uint32_t now_s, bool *granted)
{
    if (granted == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    *granted = false;
    if (link_cooldown_active(now_s)) {
        GC_LOGI(GC_LINK_TAG, "api reboot held, cooldown %u s",
                (unsigned)link_seconds_until(now_s, s_link.cooldown_until_s));
        return GC_OK;
    }
    uint32_t wait_s = gc_link_monitor_seconds_until_api_reboot_allowed(now_s);
    if (wait_s != 0) {
        GC_LOGI(GC_LINK_TAG, "api reboot rate limited, %u s remaining", (unsigned)wait_s);
        return GC_OK;
    }
    *granted = true;
    s_link.last_api_reboot_s = now_s;
    return GC_OK;
}

gc_err_t gc_link_monitor_claim_modem_power_cycle(uint32_t now_s, bool *granted)
{
    if (granted == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    *granted = false;
    uint32_t wait_s = gc_link_monitor_seconds_until_power_cycle_allowed(now_s);
    if (wait_s != 0) {
        GC_LOGI(GC_LINK_TAG, "power cycle rate limited, %u s remaining", (unsigned)wait_s);
        return GC_OK;
    }
    *granted = true;
    s_link.last_power_cycle_s = now_s;
    s_link.cooldown_until_s = now_s + GC_LINK_POWER_CYCLE_COOLDOWN_S;
    GC_LOGW(GC_LINK_TAG, "power cycle granted, %u s cooldown", (unsigned)GC_LINK_POWER_CYCLE_COOLDOWN_S);
    return GC_OK;
}

gc_err_t gc_link_monitor_clear_fault(void)
{
    link_clear_fault_state();
    return GC_OK;
}
