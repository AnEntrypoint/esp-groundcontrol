#pragma once

#include <stdint.h>
#include <stdbool.h>

#define GC_PIN_RELAY_GPIO 4
#define GC_PIN_WATCHDOG_KICK_GPIO 5
#define GC_PIN_STATUS_LED_GPIO 2

#define GC_PIN_W5500_CS_GPIO 10
#define GC_PIN_W5500_INT_GPIO 11
#define GC_PIN_W5500_RST_GPIO 12
#define GC_PIN_SPI_MOSI_GPIO 13
#define GC_PIN_SPI_MISO_GPIO 14
#define GC_PIN_SPI_SCLK_GPIO 15

#define GC_PIN_BOOT_GPIO 0
#define GC_PIN_USB_DM_GPIO 19
#define GC_PIN_USB_DP_GPIO 20
#define GC_PIN_EMBEDDED_FLASH_FIRST_GPIO 26
#define GC_PIN_EMBEDDED_FLASH_LAST_GPIO 32

#define GC_RELAY_ACTIVE_LEVEL 1
#define GC_WATCHDOG_KICK_PULSE_US 50

bool gc_pinmap_relay_allowed(int gpio);
bool gc_pinmap_claim(int gpio, const char *owner);
void gc_pinmap_release(int gpio);
const char *gc_pinmap_owner(int gpio);
