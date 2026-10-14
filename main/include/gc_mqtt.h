#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "gc_types.h"

typedef void (*gc_mqtt_message_fn)(const char *topic,
                                   const char *payload,
                                   size_t len,
                                   void *ctx);

gc_err_t gc_mqtt_init(gc_mqtt_message_fn on_message, void *ctx);
gc_err_t gc_mqtt_start(const char *uri,
                       const char *username,
                       const char *password,
                       uint32_t keepalive_s);
gc_err_t gc_mqtt_stop(void);
gc_err_t gc_mqtt_restart(void);

bool gc_mqtt_connected(void);
uint32_t gc_mqtt_connect_attempts(void);

gc_err_t gc_mqtt_publish(const char *topic, const void *payload, size_t len, int qos);
gc_err_t gc_mqtt_publish_alarm(const char *topic, const void *payload, size_t len);
gc_err_t gc_mqtt_subscribe(const char *topic, int qos);
gc_err_t gc_mqtt_set_keepalive(uint32_t seconds);
