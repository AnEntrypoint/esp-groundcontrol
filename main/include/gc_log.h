#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

#include "gc_types.h"

#define GC_LOG_RECORD_MAX 160

typedef enum {
    GC_LOG_LEVEL_ERROR = 0,
    GC_LOG_LEVEL_WARN,
    GC_LOG_LEVEL_INFO,
    GC_LOG_LEVEL_DEBUG,
} gc_log_level_t;

gc_err_t gc_log_init(size_t records);
void gc_log_emit(gc_log_level_t level, const char *tag, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
void gc_log_ring_dump(gc_log_level_t min_level,
                      void (*emit)(void *ctx, uint32_t uptime_ms, gc_log_level_t level,
                                   const char *tag, const char *text),
                      void *ctx);
size_t gc_log_dropped_count(void);
uint32_t gc_log_error_count(void);
uint32_t gc_log_warn_count(void);

#define GC_LOGE(tag, fmt, ...) gc_log_emit(GC_LOG_LEVEL_ERROR, tag, fmt, ##__VA_ARGS__)
#define GC_LOGW(tag, fmt, ...) gc_log_emit(GC_LOG_LEVEL_WARN, tag, fmt, ##__VA_ARGS__)
#define GC_LOGI(tag, fmt, ...) gc_log_emit(GC_LOG_LEVEL_INFO, tag, fmt, ##__VA_ARGS__)
#define GC_LOGD(tag, fmt, ...) gc_log_emit(GC_LOG_LEVEL_DEBUG, tag, fmt, ##__VA_ARGS__)
