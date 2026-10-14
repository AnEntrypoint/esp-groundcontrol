#include "gc_pinmap.h"

#include "freertos/FreeRTOS.h"
#include "hal/gpio_types.h"

#include "gc_log.h"

#define GC_PINMAP_TAG "gc_pinmap"

static const char *s_owners[GPIO_NUM_MAX];
static portMUX_TYPE s_owners_lock = portMUX_INITIALIZER_UNLOCKED;

static bool gc_pinmap_index_valid(int gpio)
{
    return (gpio >= 0) && (gpio < (int)GPIO_NUM_MAX);
}

bool gc_pinmap_relay_allowed(int gpio)
{
    if (!gc_pinmap_index_valid(gpio)) {
        return false;
    }
    if (gpio == GC_PIN_BOOT_GPIO) {
        return false;
    }
    if (gpio == GC_PIN_USB_DM_GPIO || gpio == GC_PIN_USB_DP_GPIO) {
        return false;
    }
    if (gpio >= GC_PIN_EMBEDDED_FLASH_FIRST_GPIO && gpio <= GC_PIN_EMBEDDED_FLASH_LAST_GPIO) {
        return false;
    }
    return true;
}

bool gc_pinmap_claim(int gpio, const char *owner)
{
    if (owner == NULL) {
        return false;
    }
    if (!gc_pinmap_relay_allowed(gpio)) {
        GC_LOGW(GC_PINMAP_TAG, "gpio %d is not relay capable", gpio);
        return false;
    }

    portENTER_CRITICAL(&s_owners_lock);
    const char *holder = s_owners[gpio];
    if (holder == NULL) {
        s_owners[gpio] = owner;
    }
    portEXIT_CRITICAL(&s_owners_lock);

    if (holder != NULL) {
        GC_LOGW(GC_PINMAP_TAG, "gpio %d already claimed by %s", gpio, holder);
        return false;
    }
    return true;
}

void gc_pinmap_release(int gpio)
{
    if (!gc_pinmap_index_valid(gpio)) {
        return;
    }
    portENTER_CRITICAL(&s_owners_lock);
    s_owners[gpio] = NULL;
    portEXIT_CRITICAL(&s_owners_lock);
}

const char *gc_pinmap_owner(int gpio)
{
    if (!gc_pinmap_index_valid(gpio)) {
        return NULL;
    }
    portENTER_CRITICAL(&s_owners_lock);
    const char *owner = s_owners[gpio];
    portEXIT_CRITICAL(&s_owners_lock);
    return owner;
}
