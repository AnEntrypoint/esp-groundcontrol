#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "driver/gpio.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include "gc_app.h"
#include "gc_config.h"
#include "gc_crypto.h"
#include "gc_dns_redirect.h"
#include "gc_emergency.h"
#include "gc_gate.h"
#include "gc_link_monitor.h"
#include "gc_log.h"
#include "gc_modem_api.h"
#include "gc_mqtt.h"
#include "gc_nat.h"
#include "gc_netif.h"
#include "gc_nvs.h"
#include "gc_ota.h"
#include "gc_pinmap.h"
#include "gc_portal.h"
#include "gc_quota.h"
#include "gc_selftest.h"
#include "gc_telemetry.h"
#include "gc_types.h"
#include "gc_watchdog.h"
#include "gc_wifi_uplink.h"

#define GC_MAIN_TICK_TASK_STACK_WORDS 4096
#define GC_MAIN_TICK_TASK_PRIORITY 5
#define GC_MAIN_BOOT_LONG_PRESS_MS 3000
#define GC_MAIN_BOOT_POLL_STEP_MS 100
#define GC_MAIN_NVS_KEY_BOOT_ID "bootid"

static void gc_main_nvs_flash_init(void)
{
    esp_err_t err = nvs_flash_init();

    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        if (nvs_flash_erase() == ESP_OK) {
            err = nvs_flash_init();
        }
    }
    if (err != ESP_OK) {
        GC_LOGE("main", "nvs_flash_init failed: %d", (int)err);
    }
}

static void gc_main_claim_pins(void)
{
    gc_pinmap_claim(GC_PIN_RELAY_GPIO, "relay");
    gc_pinmap_claim(GC_PIN_WATCHDOG_KICK_GPIO, "watchdog");
    gc_pinmap_claim(GC_PIN_STATUS_LED_GPIO, "led");

    gpio_reset_pin(GC_PIN_STATUS_LED_GPIO);
    gpio_set_direction(GC_PIN_STATUS_LED_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(GC_PIN_STATUS_LED_GPIO, 0);
}

static uint16_t gc_main_next_boot_id(void)
{
    uint32_t stored = 0;

    if (gc_nvs_get_u32(GC_MAIN_NVS_KEY_BOOT_ID, &stored) != GC_OK) {
        stored = esp_random() & 0xFFFFu;
    } else {
        stored++;
    }
    if (stored == 0 || stored > 0xFFFFu) {
        stored = 1;
    }
    gc_nvs_set_u32(GC_MAIN_NVS_KEY_BOOT_ID, stored);
    gc_nvs_commit();

    return (uint16_t)stored;
}

static bool gc_main_boot_button_long_pressed(void)
{
    gpio_config_t io = {
        .pin_bit_mask = 1ULL << GC_PIN_BOOT_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    uint32_t held_ms = 0;

    if (gpio_config(&io) != ESP_OK) {
        return false;
    }
    if (gpio_get_level(GC_PIN_BOOT_GPIO) != 0) {
        return false;
    }
    while (held_ms < GC_MAIN_BOOT_LONG_PRESS_MS) {
        vTaskDelay(pdMS_TO_TICKS(GC_MAIN_BOOT_POLL_STEP_MS));
        held_ms += GC_MAIN_BOOT_POLL_STEP_MS;
        if (gpio_get_level(GC_PIN_BOOT_GPIO) != 0) {
            return false;
        }
    }

    return true;
}

static void gc_main_report(const char *stage, gc_err_t err)
{
    if (err != GC_OK) {
        GC_LOGW("main", "%s failed: %s", stage, gc_err_name(err));
        return;
    }
    GC_LOGI("main", "%s ok", stage);
}

static void gc_main_report_configuration(const gc_config_t *cfg)
{
    const char *failed_field = NULL;

    if (gc_config_validate(cfg, &failed_field)) {
        GC_LOGI("main", "configuration valid for site %u device %u",
                (unsigned)cfg->site_id, (unsigned)cfg->device_id);
        return;
    }
    GC_LOGW("main", "configuration incomplete at %s; provision before field use",
            failed_field != NULL ? failed_field : "unknown");
}

static void gc_main_start_uplink(const gc_config_t *cfg)
{
    gc_main_report("wifi_uplink_init", gc_wifi_uplink_init());
    gc_main_report("sta_start", gc_netif_sta_start());
    gc_main_report("sta_join", gc_wifi_uplink_start(cfg->sta_ssid, cfg->sta_passphrase));
}

static void gc_main_start_portal(const gc_config_t *cfg)
{
    esp_netif_ip_info_t ap_ip;
    uint32_t ap_ip_addr = 0;

    gc_main_report("ap_start",
                   gc_netif_ap_start(cfg->ap_ssid, cfg->ap_passphrase, GC_MAX_CLIENTS));
    if (gc_netif_ap_ipv4(&ap_ip) == GC_OK) {
        ap_ip_addr = ap_ip.ip.addr;
    }
    if (gc_portal_dns_start(ap_ip_addr) != GC_OK) {
        gc_main_report("dns_redirect_start", gc_dns_redirect_start(ap_ip_addr));
    }
    gc_main_report("portal_init", gc_portal_init(GC_PORTAL_HTTP_PORT));
    gc_main_report("portal_start", gc_portal_start(cfg));
}

static void gc_main_tick_task(void *arg)
{
    (void)arg;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(GC_APP_TICK_PERIOD_MS));
        gc_app_tick_once(gc_app_uptime_s());
    }
}

void app_main(void)
{
    gc_config_t cfg;
    gc_identity_t id;
    uint16_t boot_id;

    gc_main_nvs_flash_init();
    gc_main_report("nvs_init", gc_nvs_init());
    gc_main_report("log_init", gc_log_init(64));

    gc_config_defaults(&cfg);
    gc_main_report("config_load", gc_config_load(&cfg));
    gc_main_report_configuration(&cfg);

    gc_main_claim_pins();
    gc_main_report("app_init", gc_app_init());

    boot_id = gc_main_next_boot_id();
    gc_app_set_boot_id(boot_id);

    id.site_id = cfg.site_id;
    id.device_id = cfg.device_id;
    id.boot_id = boot_id;
    id.seq = 0;

    esp_netif_init();
    esp_event_loop_create_default();

    gc_main_report("netif_init", gc_netif_init());
    gc_main_report("netif_counters", gc_netif_install_counters());

    gc_main_start_uplink(&cfg);
    gc_main_start_portal(&cfg);

    gc_main_report("nat_enable", gc_nat_enable());
    gc_main_report("gate_init", gc_gate_init(GC_MAX_CLIENTS, cfg.client_rate_kbyte_s));
    gc_main_report("gate_restore", gc_gate_restore());
    gc_main_report("quota_init", gc_quota_init(cfg.daily_budget_kb, cfg.monthly_reserve_kb));
    gc_main_report("quota_restore", gc_quota_restore());
    gc_main_report("telemetry_init", gc_telemetry_init(GC_TELEMETRY_MAX_RECORDS));
    gc_main_report("mqtt_start",
                   gc_mqtt_start(cfg.broker_url,
                                 cfg.broker_user,
                                 cfg.broker_pass,
                                 cfg.mqtt_keepalive_s));
    gc_main_report("modem_api_init",
                   gc_modem_api_init(cfg.modem_ip, cfg.modem_user, cfg.modem_pass));
    gc_main_report("link_monitor_init", gc_link_monitor_init(cfg.beacon_host));
    gc_main_report("crypto_init", gc_crypto_init());
    gc_main_report("emergency_init", gc_emergency_init(&id, cfg.beacon_host, cfg.beacon_port));
    gc_main_report("ota_init",
                   gc_ota_init(cfg.manifest_url,
                               cfg.ota_window_start_minute,
                               cfg.ota_window_end_minute,
                               cfg.ota_min_rsrp));

    GC_LOGI("main", "selftest state %d", (int)gc_selftest_result());

    gc_main_report("watchdog_init", gc_watchdog_init());
    gc_main_report("app_start", gc_app_start());
    gc_main_report("watchdog_start", gc_watchdog_start());

    if (gc_main_boot_button_long_pressed()) {
        GC_LOGI("main", "boot button long press, requesting tunnel");
        gc_app_request_tunnel(true);
    }

    if (xTaskCreatePinnedToCore(gc_main_tick_task,
                                "gc_tick",
                                GC_MAIN_TICK_TASK_STACK_WORDS,
                                NULL,
                                GC_MAIN_TICK_TASK_PRIORITY,
                                NULL,
                                tskNO_AFFINITY) != pdPASS) {
        GC_LOGE("main", "tick task create failed");
    }
}
