cmake_minimum_required(VERSION 3.16)

set(GC_SOURCES
    "gc_types.c"
    "gc_log.c"
    "gc_nvs.c"
    "gc_crypto.c"
    "gc_config.c"
    "gc_pinmap.c"
    "gc_netif.c"
    "gc_nat.c"
    "gc_wifi_uplink.c"
    "gc_quota.c"
    "gc_gate.c"
    "gc_telemetry.c"
    "gc_ctrl_proto.c"
    "gc_mqtt.c"
    "gc_modem_api.c"
    "gc_link_monitor.c"
    "gc_emergency.c"
    "gc_ota.c"
    "gc_selftest.c"
    "gc_watchdog.c"
    "gc_dns_redirect.c"
    "gc_http_portal.c"
    "gc_portal.c"
    "gc_app.c"
    "gc_main.c"
)

idf_component_register(
    SRCS ${GC_SOURCES}
    INCLUDE_DIRS "include"
    REQUIRES
        esp_netif
        esp_wifi
        esp_event
        esp_http_server
        esp_http_client
        esp_https_ota
        esp_app_format
        app_update
        esp_partition
        esp_hw_support
        esp_timer
        esp_tls
        mbedtls
        mqtt
        nvs_flash
        lwip
        json
        driver
)

target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror=implicit-function-declaration)
