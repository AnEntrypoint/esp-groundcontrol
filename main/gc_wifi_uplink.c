#include "gc_wifi_uplink.h"

#include <string.h>

#include "esp_err.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"

#include "gc_log.h"
#include "gc_netif.h"
#include "gc_types.h"

#define GC_UPLINK_BACKOFF_JITTER_DIVISOR 4u
#define GC_UPLINK_US_PER_S 1000000ull

static const char *gc_uplink_tag = "gc_uplink";

static bool gc_uplink_initialized;
static bool gc_uplink_started;
static bool gc_uplink_connected;
static bool gc_uplink_has_ip;
static int gc_uplink_rssi_value = GC_UPLINK_RSSI_UNKNOWN;
static uint32_t gc_uplink_backoff_s = GC_UPLINK_BACKOFF_MIN_S;
static uint32_t gc_uplink_connect_attempts;
static esp_timer_handle_t gc_uplink_retry_timer;
static wifi_config_t gc_uplink_config;
static portMUX_TYPE gc_uplink_state_lock = portMUX_INITIALIZER_UNLOCKED;

static uint32_t gc_wifi_uplink_backoff_read(void)
{
    uint32_t value;

    portENTER_CRITICAL(&gc_uplink_state_lock);
    value = gc_uplink_backoff_s;
    portEXIT_CRITICAL(&gc_uplink_state_lock);
    return value;
}

static void gc_wifi_uplink_backoff_write(uint32_t backoff_s)
{
    portENTER_CRITICAL(&gc_uplink_state_lock);
    gc_uplink_backoff_s = backoff_s;
    portEXIT_CRITICAL(&gc_uplink_state_lock);
}

static void gc_wifi_uplink_state_write(bool connected, bool has_ip)
{
    portENTER_CRITICAL(&gc_uplink_state_lock);
    gc_uplink_connected = connected;
    gc_uplink_has_ip = has_ip;
    portEXIT_CRITICAL(&gc_uplink_state_lock);
}

static void gc_wifi_uplink_connect_now(void)
{
    esp_err_t err;

    portENTER_CRITICAL(&gc_uplink_state_lock);
    gc_uplink_connect_attempts++;
    portEXIT_CRITICAL(&gc_uplink_state_lock);

    err = esp_wifi_connect();
    if (err != ESP_OK) {
        GC_LOGW(gc_uplink_tag, "connect rejected: %s", esp_err_to_name(err));
    }
}

static void gc_wifi_uplink_schedule_retry(void)
{
    uint32_t delay_s = gc_wifi_uplink_backoff_read();
    uint32_t jitter = delay_s >= GC_UPLINK_BACKOFF_JITTER_DIVISOR
                          ? (uint32_t)(esp_random() % (delay_s / GC_UPLINK_BACKOFF_JITTER_DIVISOR))
                          : 0u;
    uint64_t delay_us = (uint64_t)(delay_s + jitter) * GC_UPLINK_US_PER_S;
    uint32_t next_backoff_s = delay_s * 2u > GC_UPLINK_BACKOFF_MAX_S ? GC_UPLINK_BACKOFF_MAX_S : delay_s * 2u;

    if (gc_uplink_retry_timer == NULL) {
        return;
    }

    esp_timer_stop(gc_uplink_retry_timer);
    if (esp_timer_start_once(gc_uplink_retry_timer, delay_us) != ESP_OK) {
        GC_LOGW(gc_uplink_tag, "retry timer start failed, delay %u s", (unsigned)(delay_s + jitter));
    }

    gc_wifi_uplink_backoff_write(next_backoff_s);
    GC_LOGI(gc_uplink_tag, "retry in %u s, next backoff %u s", (unsigned)(delay_s + jitter), (unsigned)next_backoff_s);
}

static void gc_wifi_uplink_refresh_rssi(void)
{
    wifi_ap_record_t ap_record;

    memset(&ap_record, 0, sizeof(ap_record));
    if (esp_wifi_sta_get_ap_info(&ap_record) != ESP_OK) {
        return;
    }

    portENTER_CRITICAL(&gc_uplink_state_lock);
    gc_uplink_rssi_value = (int)ap_record.rssi;
    portEXIT_CRITICAL(&gc_uplink_state_lock);
}

static void gc_wifi_uplink_retry_timer_cb(void *arg)
{
    (void)arg;

    if (!gc_uplink_started) {
        return;
    }
    gc_wifi_uplink_connect_now();
}

static void gc_wifi_uplink_event_handler(void *arg,
                                         esp_event_base_t event_base,
                                         int32_t event_id,
                                         void *event_data)
{
    (void)arg;

    if (event_base == WIFI_EVENT) {
        if (event_id == WIFI_EVENT_STA_START) {
            if (gc_uplink_started) {
                gc_wifi_uplink_connect_now();
            }
        } else if (event_id == WIFI_EVENT_STA_CONNECTED) {
            gc_wifi_uplink_state_write(true, false);
            gc_wifi_uplink_refresh_rssi();
            gc_wifi_uplink_backoff_write(GC_UPLINK_BACKOFF_MIN_S);
            GC_LOGI(gc_uplink_tag, "station connected, rssi %d", gc_wifi_uplink_rssi());
        } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
            wifi_event_sta_disconnected_t *disconnected = (wifi_event_sta_disconnected_t *)event_data;
            gc_wifi_uplink_state_write(false, false);
            GC_LOGW(gc_uplink_tag, "station disconnected, reason %d", (int)(disconnected != NULL ? disconnected->reason : 0));
            if (gc_uplink_started) {
                gc_wifi_uplink_schedule_retry();
            }
        }
        return;
    }

    if (event_base == IP_EVENT) {
        if (event_id == IP_EVENT_STA_GOT_IP) {
            ip_event_got_ip_t *got_ip = (ip_event_got_ip_t *)event_data;
            gc_wifi_uplink_state_write(true, true);
            gc_wifi_uplink_backoff_write(GC_UPLINK_BACKOFF_MIN_S);
            if (got_ip != NULL) {
                GC_LOGI(gc_uplink_tag, "uplink ip " IPSTR, IP2STR(&got_ip->ip_info.ip));
            }
        } else if (event_id == IP_EVENT_STA_LOST_IP) {
            gc_wifi_uplink_state_write(gc_uplink_connected, false);
            GC_LOGW(gc_uplink_tag, "uplink ip lost");
        }
    }
}

gc_err_t gc_wifi_uplink_init(void)
{
    wifi_init_config_t init_config = WIFI_INIT_CONFIG_DEFAULT();
    esp_timer_create_args_t timer_args;
    wifi_mode_t mode;
    esp_err_t err;

    if (gc_uplink_initialized) {
        return GC_OK;
    }

    err = esp_wifi_init(&init_config);
    if (err != ESP_OK) {
        GC_LOGE(gc_uplink_tag, "esp_wifi_init failed: %s", esp_err_to_name(err));
        return GC_ERR_IO;
    }

    mode = gc_netif_ap() != NULL ? WIFI_MODE_APSTA : WIFI_MODE_STA;
    err = esp_wifi_set_mode(mode);
    if (err != ESP_OK) {
        GC_LOGE(gc_uplink_tag, "mode %d rejected: %s", (int)mode, esp_err_to_name(err));
        return GC_ERR_IO;
    }

    err = esp_wifi_set_storage(WIFI_STORAGE_RAM);
    if (err != ESP_OK) {
        GC_LOGE(gc_uplink_tag, "storage mode rejected: %s", esp_err_to_name(err));
        return GC_ERR_IO;
    }

    err = esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, gc_wifi_uplink_event_handler, NULL);
    if (err != ESP_OK) {
        GC_LOGE(gc_uplink_tag, "wifi handler register failed: %s", esp_err_to_name(err));
        return GC_ERR_IO;
    }

    err = esp_event_handler_register(IP_EVENT, ESP_EVENT_ANY_ID, gc_wifi_uplink_event_handler, NULL);
    if (err != ESP_OK) {
        GC_LOGE(gc_uplink_tag, "ip handler register failed: %s", esp_err_to_name(err));
        return GC_ERR_IO;
    }

    memset(&timer_args, 0, sizeof(timer_args));
    timer_args.callback = gc_wifi_uplink_retry_timer_cb;
    timer_args.arg = NULL;
    timer_args.dispatch_method = ESP_TIMER_TASK;
    timer_args.name = "gc_uplink_retry";
    err = esp_timer_create(&timer_args, &gc_uplink_retry_timer);
    if (err != ESP_OK) {
        GC_LOGE(gc_uplink_tag, "retry timer create failed: %s", esp_err_to_name(err));
        return GC_ERR_NO_MEM;
    }

    gc_uplink_initialized = true;
    return GC_OK;
}

gc_err_t gc_wifi_uplink_start(const char *ssid, const char *passphrase)
{
    wifi_config_t config;
    esp_err_t err;
    gc_err_t status;
    size_t length;
    size_t copy_length;

    if (ssid == NULL || ssid[0] == '\0' || passphrase == NULL) {
        return GC_ERR_INVALID_ARG;
    }

    if (!gc_uplink_initialized) {
        status = gc_wifi_uplink_init();
        if (status != GC_OK) {
            return status;
        }
    }

    memset(&config, 0, sizeof(config));
    length = strlen(ssid);
    copy_length = length < sizeof(config.sta.ssid) ? length : sizeof(config.sta.ssid) - 1u;
    memcpy(config.sta.ssid, ssid, copy_length);
    config.sta.ssid[copy_length] = '\0';

    if (passphrase[0] != '\0') {
        config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
        length = strlen(passphrase);
        copy_length = length < sizeof(config.sta.password) ? length : sizeof(config.sta.password) - 1u;
        memcpy(config.sta.password, passphrase, copy_length);
        config.sta.password[copy_length] = '\0';
    } else {
        config.sta.threshold.authmode = WIFI_AUTH_OPEN;
    }

    err = esp_wifi_set_config(WIFI_IF_STA, &config);
    if (err != ESP_OK) {
        GC_LOGE(gc_uplink_tag, "station config rejected: %s", esp_err_to_name(err));
        return GC_ERR_IO;
    }

    gc_uplink_config = config;
    gc_uplink_started = true;
    gc_uplink_has_ip = false;
    gc_wifi_uplink_backoff_write(GC_UPLINK_BACKOFF_MIN_S);
    gc_wifi_uplink_connect_now();
    return GC_OK;
}

gc_err_t gc_wifi_uplink_stop(void)
{
    if (!gc_uplink_initialized) {
        return GC_OK;
    }

    if (gc_uplink_retry_timer != NULL) {
        esp_timer_stop(gc_uplink_retry_timer);
    }
    esp_wifi_disconnect();

    gc_uplink_started = false;
    gc_wifi_uplink_state_write(false, false);
    gc_uplink_rssi_value = GC_UPLINK_RSSI_UNKNOWN;
    gc_wifi_uplink_backoff_write(GC_UPLINK_BACKOFF_MIN_S);
    return GC_OK;
}

bool gc_wifi_uplink_connected(void)
{
    bool connected;

    portENTER_CRITICAL(&gc_uplink_state_lock);
    connected = gc_uplink_connected;
    portEXIT_CRITICAL(&gc_uplink_state_lock);
    return connected;
}

bool gc_wifi_uplink_has_ip(void)
{
    bool has_ip;

    portENTER_CRITICAL(&gc_uplink_state_lock);
    has_ip = gc_uplink_has_ip;
    portEXIT_CRITICAL(&gc_uplink_state_lock);
    return has_ip;
}

int gc_wifi_uplink_rssi(void)
{
    int rssi;

    if (!gc_wifi_uplink_connected()) {
        return GC_UPLINK_RSSI_UNKNOWN;
    }

    gc_wifi_uplink_refresh_rssi();

    portENTER_CRITICAL(&gc_uplink_state_lock);
    rssi = gc_uplink_rssi_value;
    portEXIT_CRITICAL(&gc_uplink_state_lock);
    return rssi;
}

uint32_t gc_wifi_uplink_backoff_s(void)
{
    return gc_wifi_uplink_backoff_read();
}

uint32_t gc_wifi_uplink_connect_attempts(void)
{
    uint32_t attempts;

    portENTER_CRITICAL(&gc_uplink_state_lock);
    attempts = gc_uplink_connect_attempts;
    portEXIT_CRITICAL(&gc_uplink_state_lock);
    return attempts;
}

gc_err_t gc_wifi_uplink_reset_backoff(void)
{
    gc_wifi_uplink_backoff_write(GC_UPLINK_BACKOFF_MIN_S);
    return GC_OK;
}

gc_err_t gc_wifi_uplink_forget_and_retry(void)
{
    if (!gc_uplink_initialized || !gc_uplink_started) {
        gc_wifi_uplink_reset_backoff();
        return GC_ERR_IO;
    }

    if (gc_uplink_retry_timer != NULL) {
        esp_timer_stop(gc_uplink_retry_timer);
    }

    esp_wifi_disconnect();
    gc_wifi_uplink_state_write(false, false);
    gc_uplink_rssi_value = GC_UPLINK_RSSI_UNKNOWN;
    gc_wifi_uplink_backoff_write(GC_UPLINK_BACKOFF_MIN_S);

    if (esp_wifi_set_config(WIFI_IF_STA, &gc_uplink_config) != ESP_OK) {
        return GC_ERR_IO;
    }

    gc_wifi_uplink_connect_now();
    return GC_OK;
}
