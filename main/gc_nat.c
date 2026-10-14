#include "gc_nat.h"

#include "esp_err.h"
#include "esp_netif.h"

#include "gc_log.h"
#include "gc_netif.h"
#include "gc_types.h"

static const char *gc_nat_tag = "gc_nat";

static bool gc_nat_enable_requested;
static bool gc_nat_napt_active;
static bool gc_nat_paused;
static uint64_t gc_nat_baseline_up;
static uint64_t gc_nat_baseline_down;

#ifdef CONFIG_LWIP_IPV4_NAPT

static gc_err_t gc_nat_napt_apply(bool active)
{
    esp_netif_t *sta = gc_netif_sta();
    esp_err_t err;

    if (sta == NULL) {
        GC_LOGE(gc_nat_tag, "station interface missing, napt not applied");
        return GC_ERR_NOT_FOUND;
    }
    if (active == gc_nat_napt_active) {
        return GC_OK;
    }

    err = active ? esp_netif_napt_enable(sta) : esp_netif_napt_disable(sta);
    if (err != ESP_OK) {
        GC_LOGE(gc_nat_tag, "napt %s failed: %s", active ? "enable" : "disable", esp_err_to_name(err));
        return GC_ERR_IO;
    }

    gc_nat_napt_active = active;
    GC_LOGI(gc_nat_tag, "napt %s", active ? "enabled" : "disabled");
    return GC_OK;
}

#endif

gc_err_t gc_nat_enable(void)
{
#ifdef CONFIG_LWIP_IPV4_NAPT
    gc_err_t status;

    gc_nat_enable_requested = true;
    gc_nat_paused = false;
    status = gc_nat_napt_apply(true);
    gc_nat_reset_counters();
    return status;
#else
    gc_nat_enable_requested = false;
    gc_nat_napt_active = false;
    gc_nat_paused = false;
    gc_nat_reset_counters();
    GC_LOGW(gc_nat_tag, "napt unavailable: CONFIG_LWIP_IPV4_NAPT is not set");
    return GC_ERR_UNSUPPORTED;
#endif
}

gc_err_t gc_nat_disable(void)
{
    gc_nat_enable_requested = false;
    gc_nat_paused = false;
#ifdef CONFIG_LWIP_IPV4_NAPT
    return gc_nat_napt_apply(false);
#else
    gc_nat_napt_active = false;
    return GC_OK;
#endif
}

bool gc_nat_enabled(void)
{
    return gc_nat_napt_active;
}

gc_err_t gc_nat_set_forwarding_paused(bool paused)
{
    if (gc_nat_paused == paused) {
        return GC_OK;
    }

    gc_nat_paused = paused;
#ifdef CONFIG_LWIP_IPV4_NAPT
    if (!gc_nat_enable_requested) {
        return GC_OK;
    }
    return gc_nat_napt_apply(!paused);
#else
    return GC_OK;
#endif
}

bool gc_nat_forwarding_paused(void)
{
    return gc_nat_paused;
}

uint64_t gc_nat_uplink_bytes_up(void)
{
    uint64_t total = gc_netif_sta_tx_bytes();
    return total > gc_nat_baseline_up ? total - gc_nat_baseline_up : 0u;
}

uint64_t gc_nat_uplink_bytes_down(void)
{
    uint64_t total = gc_netif_sta_rx_bytes();
    return total > gc_nat_baseline_down ? total - gc_nat_baseline_down : 0u;
}

uint64_t gc_nat_uplink_bytes(void)
{
    return gc_nat_uplink_bytes_up() + gc_nat_uplink_bytes_down();
}

void gc_nat_reset_counters(void)
{
    gc_nat_baseline_up = gc_netif_sta_tx_bytes();
    gc_nat_baseline_down = gc_netif_sta_rx_bytes();
}
