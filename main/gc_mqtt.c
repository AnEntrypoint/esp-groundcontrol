#include "gc_mqtt.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_event.h"
#include "esp_random.h"
#include "mqtt_client.h"

#include "gc_config.h"
#include "gc_ctrl_proto.h"
#include "gc_log.h"

#define GC_MQTT_TAG "gc_mqtt"

#define GC_MQTT_TLS_PREFIX "mqtts://"
#define GC_MQTT_BACKOFF_MIN_S 5u
#define GC_MQTT_BACKOFF_MAX_S 300u
#define GC_MQTT_BACKOFF_JITTER_S 5u
#define GC_MQTT_BACKOFF_BASE_MAX_S (GC_MQTT_BACKOFF_MAX_S - GC_MQTT_BACKOFF_JITTER_S)
#define GC_MQTT_SUB_MAX 8u
#define GC_MQTT_RX_STACK_MAX 1024u
#define GC_MQTT_BACKOFF_TASK_STACK 2560u
#define GC_MQTT_BACKOFF_TASK_PRIO 5u

static esp_mqtt_client_handle_t s_client;
static gc_mqtt_message_fn s_on_message;
static void *s_ctx;
static TaskHandle_t s_backoff_task;
static char s_uri[GC_URL_MAX];
static char s_username[GC_USER_MAX];
static char s_password[GC_USER_MAX];
static uint32_t s_keepalive_s;
static uint32_t s_attempts;
static uint32_t s_backoff_s;
static bool s_started;
static bool s_connected;
static size_t s_sub_count;
static int s_sub_qos[GC_MQTT_SUB_MAX];
static char s_sub_topics[GC_MQTT_SUB_MAX][GC_TOPIC_MAX];

static void gc_mqtt_event_handler(void *handler_arg,
                                  esp_event_base_t event_base,
                                  int32_t event_id,
                                  void *event_data);

static void gc_mqtt_build_config(esp_mqtt_client_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));

    cfg->broker.address.uri = s_uri;
    if (s_username[0] != '\0') {
        cfg->credentials.username = s_username;
    }
    if (s_password[0] != '\0') {
        cfg->credentials.authentication.password = s_password;
    }
    cfg->session.keepalive = (int)s_keepalive_s;
    cfg->network.disable_auto_reconnect = false;

    if (strncmp(s_uri, GC_MQTT_TLS_PREFIX, strlen(GC_MQTT_TLS_PREFIX)) == 0) {
        cfg->broker.verification.use_global_ca_store = true;
    }
}

static gc_err_t gc_mqtt_bringup(void)
{
    esp_mqtt_client_config_t cfg;
    gc_mqtt_build_config(&cfg);

    esp_mqtt_client_handle_t client = esp_mqtt_client_init(&cfg);
    if (client == NULL) {
        GC_LOGE(GC_MQTT_TAG, "client init failed");
        return GC_ERR_NO_MEM;
    }

    esp_err_t err = esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, gc_mqtt_event_handler, NULL);
    if (err != ESP_OK) {
        GC_LOGE(GC_MQTT_TAG, "event register failed %d", (int)err);
        esp_mqtt_client_destroy(client);
        return GC_ERR_IO;
    }

    err = esp_mqtt_client_start(client);
    if (err != ESP_OK) {
        GC_LOGE(GC_MQTT_TAG, "start failed %d", (int)err);
        esp_mqtt_client_destroy(client);
        return GC_ERR_IO;
    }

    s_client = client;
    s_started = true;
    s_attempts++;
    return GC_OK;
}

static void gc_mqtt_teardown(void)
{
    if (s_client == NULL) {
        return;
    }
    esp_mqtt_client_stop(s_client);
    esp_mqtt_client_destroy(s_client);
    s_client = NULL;
    s_started = false;
    s_connected = false;
}

static void gc_mqtt_resubscribe(void)
{
    for (size_t i = 0; i < s_sub_count; i++) {
        if (esp_mqtt_client_subscribe(s_client, s_sub_topics[i], s_sub_qos[i]) < 0) {
            GC_LOGW(GC_MQTT_TAG, "resubscribe failed %s", s_sub_topics[i]);
        }
    }
}

static void gc_mqtt_forward(esp_mqtt_event_handle_t event)
{
    if (s_on_message == NULL || event == NULL || event->topic == NULL || event->topic_len <= 0) {
        return;
    }

    char topic[GC_TOPIC_MAX];
    size_t topic_len = ((size_t)event->topic_len < (size_t)GC_TOPIC_MAX)
                           ? (size_t)event->topic_len
                           : (size_t)GC_TOPIC_MAX - 1u;
    memcpy(topic, event->topic, topic_len);
    topic[topic_len] = '\0';

    size_t payload_len = (event->data != NULL && event->data_len > 0) ? (size_t)event->data_len : 0u;
    size_t handed_len = payload_len;

    char stack_copy[GC_MQTT_RX_STACK_MAX];
    char *payload = stack_copy;

    if ((payload_len + 1u) <= sizeof(stack_copy)) {
        if (payload_len > 0u) {
            memcpy(stack_copy, event->data, payload_len);
        }
        stack_copy[payload_len] = '\0';
    } else {
        payload = (char *)malloc(payload_len + 1u);
        if (payload != NULL) {
            memcpy(payload, event->data, payload_len);
            payload[payload_len] = '\0';
        } else {
            GC_LOGW(GC_MQTT_TAG, "payload of %u bytes truncated", (unsigned)payload_len);
            memcpy(stack_copy, event->data, sizeof(stack_copy) - 1u);
            stack_copy[sizeof(stack_copy) - 1u] = '\0';
            payload = stack_copy;
            handed_len = sizeof(stack_copy) - 1u;
        }
    }

    s_on_message(topic, payload, handed_len, s_ctx);

    if (payload != stack_copy) {
        free(payload);
    }
}

static uint32_t gc_mqtt_next_backoff_s(void)
{
    if (s_backoff_s == 0u) {
        s_backoff_s = GC_MQTT_BACKOFF_MIN_S;
    } else if (s_backoff_s < GC_MQTT_BACKOFF_BASE_MAX_S) {
        uint32_t doubled = s_backoff_s * 2u;
        s_backoff_s = (doubled > GC_MQTT_BACKOFF_BASE_MAX_S) ? GC_MQTT_BACKOFF_BASE_MAX_S : doubled;
    }

    uint32_t jitter = esp_random() % (GC_MQTT_BACKOFF_JITTER_S + 1u);
    return s_backoff_s + jitter;
}

static void gc_mqtt_backoff_task(void *arg)
{
    (void)arg;

    for (;;) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

        uint32_t delay_s = gc_mqtt_next_backoff_s();
        vTaskDelay(pdMS_TO_TICKS(delay_s * 1000u));

        if (!s_started || s_connected || s_client == NULL) {
            continue;
        }
        GC_LOGW(GC_MQTT_TAG, "restarting after %u s of backoff", (unsigned)delay_s);
        (void)gc_mqtt_restart();
    }
}

static void gc_mqtt_event_handler(void *handler_arg,
                                  esp_event_base_t event_base,
                                  int32_t event_id,
                                  void *event_data)
{
    (void)handler_arg;
    (void)event_base;

    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;

    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        s_connected = true;
        s_backoff_s = 0u;
        GC_LOGI(GC_MQTT_TAG, "connected to %s", s_uri);
        gc_mqtt_resubscribe();
        break;
    case MQTT_EVENT_DISCONNECTED:
        s_connected = false;
        GC_LOGW(GC_MQTT_TAG, "disconnected");
        if (s_backoff_task != NULL) {
            xTaskNotifyGive(s_backoff_task);
        }
        break;
    case MQTT_EVENT_DATA:
        gc_mqtt_forward(event);
        break;
    case MQTT_EVENT_ERROR:
        if (event != NULL && event->error_handle != NULL) {
            GC_LOGE(GC_MQTT_TAG, "error type=%d tls=%d sock=%d",
                    (int)event->error_handle->error_type,
                    (int)event->error_handle->esp_tls_last_esp_err,
                    event->error_handle->esp_transport_sock_errno);
        } else {
            GC_LOGE(GC_MQTT_TAG, "error event %d", (int)event_id);
        }
        break;
    default:
        break;
    }
}

gc_err_t gc_mqtt_init(gc_mqtt_message_fn on_message, void *ctx)
{
    s_on_message = on_message;
    s_ctx = ctx;
    return GC_OK;
}

gc_err_t gc_mqtt_start(const char *uri,
                       const char *username,
                       const char *password,
                       uint32_t keepalive_s)
{
    if (uri == NULL || uri[0] == '\0') {
        return GC_ERR_INVALID_ARG;
    }

    gc_mqtt_teardown();

    strncpy(s_uri, uri, sizeof(s_uri) - 1u);
    s_uri[sizeof(s_uri) - 1u] = '\0';

    s_username[0] = '\0';
    if (username != NULL) {
        strncpy(s_username, username, sizeof(s_username) - 1u);
        s_username[sizeof(s_username) - 1u] = '\0';
    }

    s_password[0] = '\0';
    if (password != NULL) {
        strncpy(s_password, password, sizeof(s_password) - 1u);
        s_password[sizeof(s_password) - 1u] = '\0';
    }

    s_keepalive_s = keepalive_s;
    s_backoff_s = 0u;

    gc_err_t err = gc_mqtt_bringup();
    if (err != GC_OK) {
        return err;
    }

    if (s_backoff_task == NULL) {
        if (xTaskCreate(gc_mqtt_backoff_task, "gc_mqtt_backoff", GC_MQTT_BACKOFF_TASK_STACK,
                        NULL, GC_MQTT_BACKOFF_TASK_PRIO, &s_backoff_task) != pdPASS) {
            s_backoff_task = NULL;
            GC_LOGW(GC_MQTT_TAG, "backoff task not created");
        }
    }
    return GC_OK;
}

gc_err_t gc_mqtt_stop(void)
{
    if (s_client == NULL) {
        s_started = false;
        s_connected = false;
        return GC_OK;
    }

    esp_err_t err = esp_mqtt_client_stop(s_client);
    s_started = false;
    s_connected = false;
    s_backoff_s = 0u;
    return (err == ESP_OK) ? GC_OK : GC_ERR_IO;
}

gc_err_t gc_mqtt_restart(void)
{
    if (s_client == NULL) {
        return GC_ERR_INVALID_ARG;
    }

    gc_mqtt_teardown();
    return gc_mqtt_bringup();
}

bool gc_mqtt_connected(void)
{
    return s_connected;
}

uint32_t gc_mqtt_connect_attempts(void)
{
    return s_attempts;
}

gc_err_t gc_mqtt_publish(const char *topic, const void *payload, size_t len, int qos)
{
    if (topic == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    if (s_client == NULL) {
        return GC_ERR_IO;
    }

    if (payload == NULL) {
        len = 0u;
    }
    int send_qos = (qos < 0 || qos > 2) ? 0 : qos;
    int msg_id = esp_mqtt_client_publish(s_client, topic,
                                         (payload != NULL) ? (const char *)payload : "",
                                         (int)len, send_qos, 0);
    if (msg_id < 0) {
        GC_LOGW(GC_MQTT_TAG, "publish failed on %s", topic);
        return GC_ERR_IO;
    }
    return GC_OK;
}

gc_err_t gc_mqtt_publish_alarm(const char *topic, const void *payload, size_t len)
{
    return gc_mqtt_publish(topic, payload, len, 1);
}

gc_err_t gc_mqtt_subscribe(const char *topic, int qos)
{
    if (topic == NULL) {
        return GC_ERR_INVALID_ARG;
    }

    int want_qos = (qos < 0 || qos > 2) ? 0 : qos;
    size_t slot = s_sub_count;
    for (size_t i = 0; i < s_sub_count; i++) {
        if (strcmp(s_sub_topics[i], topic) == 0) {
            slot = i;
            break;
        }
    }

    if (slot < GC_MQTT_SUB_MAX) {
        strncpy(s_sub_topics[slot], topic, GC_TOPIC_MAX - 1u);
        s_sub_topics[slot][GC_TOPIC_MAX - 1u] = '\0';
        s_sub_qos[slot] = want_qos;
        if (slot == s_sub_count) {
            s_sub_count++;
        }
    } else {
        GC_LOGW(GC_MQTT_TAG, "subscription table full, %s not persisted", topic);
    }

    if (s_client == NULL || !s_connected) {
        return GC_OK;
    }
    if (esp_mqtt_client_subscribe(s_client, topic, want_qos) < 0) {
        GC_LOGW(GC_MQTT_TAG, "subscribe failed on %s", topic);
        return GC_ERR_IO;
    }
    return GC_OK;
}

gc_err_t gc_mqtt_set_keepalive(uint32_t seconds)
{
    s_keepalive_s = seconds;

    if (s_client == NULL) {
        return GC_OK;
    }
    if (!s_started) {
        return GC_OK;
    }

    gc_mqtt_teardown();
    return gc_mqtt_bringup();
}
