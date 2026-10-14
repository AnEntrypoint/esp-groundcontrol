#include "gc_log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"

#include "gc_types.h"

#define GC_LOG_TAG_LEN 16
#define GC_LOG_TEXT_LEN 128

typedef struct {
    uint32_t uptime_ms;
    gc_log_level_t level;
    char tag[GC_LOG_TAG_LEN];
    char text[GC_LOG_TEXT_LEN];
} gc_log_record_t;

static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static gc_log_record_t *s_records;
static size_t s_capacity;
static size_t s_head;
static size_t s_used;
static size_t s_dropped;
static uint32_t s_errors;
static uint32_t s_warns;
static bool s_ready;

gc_err_t gc_log_init(size_t records)
{
    if (records == 0u || records > GC_LOG_RECORD_MAX) {
        records = GC_LOG_RECORD_MAX;
    }
    if (s_ready) {
        return GC_OK;
    }

    size_t bytes = records * sizeof(gc_log_record_t);
    void *mem = heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM);
    if (mem == NULL) {
        mem = heap_caps_malloc(bytes, MALLOC_CAP_8BIT);
    }
    if (mem == NULL) {
        return GC_ERR_NO_MEM;
    }
    memset(mem, 0, bytes);

    portENTER_CRITICAL(&s_lock);
    s_records = mem;
    s_capacity = records;
    s_head = 0;
    s_used = 0;
    s_dropped = 0;
    s_errors = 0;
    s_warns = 0;
    s_ready = true;
    portEXIT_CRITICAL(&s_lock);

    return GC_OK;
}

void gc_log_emit(gc_log_level_t level, const char *tag, const char *fmt, ...)
{
    if (!s_ready || fmt == NULL) {
        return;
    }

    va_list args;
    va_start(args, fmt);

    portENTER_CRITICAL(&s_lock);
    size_t slot = (s_head + s_used) % s_capacity;
    if (s_used < s_capacity) {
        s_used++;
    } else {
        s_head = (s_head + 1u) % s_capacity;
        s_dropped++;
    }

    gc_log_record_t *rec = &s_records[slot];
    rec->uptime_ms = (uint32_t)(esp_timer_get_time() / 1000);
    rec->level = level;
    snprintf(rec->tag, sizeof(rec->tag), "%s", (tag != NULL) ? tag : "");
    vsnprintf(rec->text, sizeof(rec->text), fmt, args);

    if (level == GC_LOG_LEVEL_ERROR) {
        s_errors++;
    } else if (level == GC_LOG_LEVEL_WARN) {
        s_warns++;
    }
    portEXIT_CRITICAL(&s_lock);

    va_end(args);
}

void gc_log_ring_dump(gc_log_level_t min_level,
                      void (*emit)(void *ctx, uint32_t uptime_ms, gc_log_level_t level,
                                   const char *tag, const char *text),
                      void *ctx)
{
    if (emit == NULL || !s_ready) {
        return;
    }

    portENTER_CRITICAL(&s_lock);
    for (size_t i = 0; i < s_used; i++) {
        const gc_log_record_t *rec = &s_records[(s_head + i) % s_capacity];
        if (rec->level <= min_level) {
            emit(ctx, rec->uptime_ms, rec->level, rec->tag, rec->text);
        }
    }
    portEXIT_CRITICAL(&s_lock);
}

size_t gc_log_dropped_count(void)
{
    portENTER_CRITICAL(&s_lock);
    size_t dropped = s_dropped;
    portEXIT_CRITICAL(&s_lock);
    return dropped;
}

uint32_t gc_log_error_count(void)
{
    portENTER_CRITICAL(&s_lock);
    uint32_t errors = s_errors;
    portEXIT_CRITICAL(&s_lock);
    return errors;
}

uint32_t gc_log_warn_count(void)
{
    portENTER_CRITICAL(&s_lock);
    uint32_t warns = s_warns;
    portEXIT_CRITICAL(&s_lock);
    return warns;
}
