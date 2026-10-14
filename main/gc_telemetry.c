#include "gc_telemetry.h"

#include <string.h>

#define GC_TELEMETRY_HEADER_LEN 13u
#define GC_TELEMETRY_RECORD_FIXED_LEN 4u
#define GC_TELEMETRY_VARINT_MAX_LEN 10u

typedef struct {
    gc_reading_t ring[GC_TELEMETRY_MAX_RECORDS];
    gc_reading_t last_pushed;
    gc_reading_t counters;
    size_t capacity;
    size_t count;
    size_t head;
    bool has_last;
} gc_telemetry_state_t;

static gc_telemetry_state_t s_tel;

static size_t ring_capacity(void)
{
    return (s_tel.capacity != 0u) ? s_tel.capacity : (size_t)GC_TELEMETRY_MAX_RECORDS;
}

static size_t ring_slot(size_t position)
{
    return (s_tel.head + position) % ring_capacity();
}

static const gc_reading_t *ring_peek(size_t position)
{
    return &s_tel.ring[ring_slot(position)];
}

static size_t varint_len(uint64_t value)
{
    size_t len = 0u;
    do {
        len++;
        value >>= 7;
    } while (value != 0u);
    return len;
}

static size_t record_len(const gc_reading_t *record)
{
    return varint_len(record->uptime_delta_s) + GC_TELEMETRY_RECORD_FIXED_LEN +
           varint_len(record->quota_delta_kb);
}

static void counters_fold(const gc_reading_t *reading)
{
    s_tel.counters.rssi = reading->rssi;
    s_tel.counters.rsrp = reading->rsrp;
    s_tel.counters.rsrq = reading->rsrq;
    s_tel.counters.sinr = reading->sinr;
    s_tel.counters.clients = reading->clients;
    s_tel.counters.quota_delta_kb += reading->quota_delta_kb;
    s_tel.counters.uptime_delta_s += reading->uptime_delta_s;
}

static void counters_clear(void)
{
    s_tel.counters.quota_delta_kb = 0u;
    s_tel.counters.uptime_delta_s = 0u;
}

typedef struct {
    uint8_t *buf;
    size_t pos;
} gc_frame_writer_t;

static void put_u8(gc_frame_writer_t *w, uint8_t value)
{
    w->buf[w->pos++] = value;
}

static void put_i8(gc_frame_writer_t *w, int8_t value)
{
    w->buf[w->pos++] = (uint8_t)value;
}

static void put_u16(gc_frame_writer_t *w, uint16_t value)
{
    put_u8(w, (uint8_t)(value & 0xFFu));
    put_u8(w, (uint8_t)((value >> 8) & 0xFFu));
}

static void put_varint(gc_frame_writer_t *w, uint64_t value)
{
    w->pos += gc_telemetry_varint_encode(value, &w->buf[w->pos], GC_TELEMETRY_VARINT_MAX_LEN);
}

static void put_header(gc_frame_writer_t *w,
                       uint8_t flags,
                       const gc_identity_t *id,
                       uint8_t fw_version,
                       gc_slot_t slot,
                       uint8_t record_count)
{
    put_u8(w, (uint8_t)GC_FRAME_VERSION);
    put_u8(w, flags);
    put_u16(w, id->site_id);
    put_u16(w, id->device_id);
    put_u16(w, id->boot_id);
    put_u16(w, id->seq);
    put_u8(w, record_count);
    put_u8(w, fw_version);
    put_u8(w, (uint8_t)slot);
}

static void put_record(gc_frame_writer_t *w, const gc_reading_t *record)
{
    put_varint(w, record->uptime_delta_s);
    put_i8(w, record->rssi);
    put_u8(w, record->clients);
    put_i8(w, record->rsrp);
    put_i8(w, record->rsrq);
    put_i8(w, record->sinr);
    put_varint(w, record->quota_delta_kb);
}

static size_t frame_len(size_t record_count)
{
    size_t total = GC_TELEMETRY_HEADER_LEN;
    for (size_t i = 0u; i < record_count; i++) {
        total += record_len(ring_peek(i));
    }
    return total;
}

static int32_t magnitude(int32_t delta)
{
    return (delta < 0) ? -delta : delta;
}

gc_err_t gc_telemetry_init(size_t capacity)
{
    if (capacity == 0u || capacity > (size_t)GC_TELEMETRY_MAX_RECORDS) {
        capacity = (size_t)GC_TELEMETRY_MAX_RECORDS;
    }
    gc_telemetry_reset();
    s_tel.capacity = capacity;
    return GC_OK;
}

void gc_telemetry_reset(void)
{
    memset(s_tel.ring, 0, sizeof(s_tel.ring));
    memset(&s_tel.last_pushed, 0, sizeof(s_tel.last_pushed));
    memset(&s_tel.counters, 0, sizeof(s_tel.counters));
    s_tel.count = 0u;
    s_tel.head = 0u;
    s_tel.has_last = false;
}

gc_err_t gc_telemetry_push(const gc_reading_t *reading)
{
    if (reading == NULL) {
        return GC_ERR_INVALID_ARG;
    }

    bool accept = (s_tel.count == 0u) ||
                  !s_tel.has_last ||
                  (reading->quota_delta_kb != 0u) ||
                  gc_telemetry_deadband_passes(reading, &s_tel.last_pushed);

    counters_fold(reading);

    if (!accept) {
        return GC_OK;
    }

    size_t capacity = ring_capacity();
    if (s_tel.count < capacity) {
        s_tel.ring[ring_slot(s_tel.count)] = *reading;
        s_tel.count++;
    } else {
        s_tel.ring[s_tel.head] = *reading;
        s_tel.head = ring_slot(1u);
    }

    s_tel.last_pushed = *reading;
    s_tel.has_last = true;
    return GC_OK;
}

size_t gc_telemetry_pending(void)
{
    return s_tel.count;
}

bool gc_telemetry_deadband_passes(const gc_reading_t *candidate, const gc_reading_t *last_sent)
{
    if (candidate == NULL) {
        return false;
    }
    if (last_sent == NULL) {
        return true;
    }

    if (magnitude((int32_t)candidate->rssi - (int32_t)last_sent->rssi) >= GC_DEADBAND_RSSI_DBM) {
        return true;
    }
    if (magnitude((int32_t)candidate->rsrp - (int32_t)last_sent->rsrp) >= GC_DEADBAND_RSRP_DBM) {
        return true;
    }
    if (magnitude((int32_t)candidate->rsrq - (int32_t)last_sent->rsrq) >= GC_DEADBAND_RSRQ_DB) {
        return true;
    }
    if (magnitude((int32_t)candidate->sinr - (int32_t)last_sent->sinr) >= GC_DEADBAND_SINR_DB) {
        return true;
    }
    if (magnitude((int32_t)candidate->clients - (int32_t)last_sent->clients) >= GC_DEADBAND_CLIENTS) {
        return true;
    }
    return false;
}

gc_err_t gc_telemetry_encode(uint8_t flags,
                             const gc_identity_t *id,
                             uint8_t fw_version,
                             gc_slot_t slot,
                             uint8_t *out,
                             size_t out_len,
                             size_t *out_written)
{
    if (out_written == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    *out_written = 0u;
    if (out == NULL || id == NULL) {
        return GC_ERR_INVALID_ARG;
    }

    size_t count = s_tel.count;
    size_t needed = frame_len(count);
    if (needed > out_len) {
        return GC_ERR_NO_MEM;
    }

    gc_frame_writer_t w = {.buf = out, .pos = 0u};
    put_header(&w, flags, id, fw_version, slot, (uint8_t)count);
    for (size_t i = 0u; i < count; i++) {
        put_record(&w, ring_peek(i));
    }

    *out_written = w.pos;
    s_tel.count = 0u;
    s_tel.head = 0u;
    counters_clear();
    return GC_OK;
}

gc_err_t gc_telemetry_encode_heartbeat(uint8_t flags,
                                       const gc_identity_t *id,
                                       uint8_t fw_version,
                                       gc_slot_t slot,
                                       uint8_t *out,
                                       size_t out_len,
                                       size_t *out_written)
{
    if (out_written == NULL) {
        return GC_ERR_INVALID_ARG;
    }
    *out_written = 0u;
    if (out == NULL || id == NULL) {
        return GC_ERR_INVALID_ARG;
    }

    gc_reading_t record = s_tel.counters;
    size_t needed = GC_TELEMETRY_HEADER_LEN + record_len(&record);
    if (needed > out_len) {
        return GC_ERR_NO_MEM;
    }

    gc_frame_writer_t w = {.buf = out, .pos = 0u};
    put_header(&w, flags, id, fw_version, slot, 1u);
    put_record(&w, &record);

    *out_written = w.pos;
    counters_clear();
    return GC_OK;
}

size_t gc_telemetry_varint_encode(uint64_t value, uint8_t *out, size_t out_len)
{
    if (out == NULL || out_len == 0u) {
        return 0u;
    }

    size_t needed = varint_len(value);
    if (needed > out_len) {
        return 0u;
    }

    size_t written = 0u;
    do {
        uint8_t byte = (uint8_t)(value & 0x7Fu);
        value >>= 7;
        if (value != 0u) {
            byte |= 0x80u;
        }
        out[written++] = byte;
    } while (value != 0u);

    return written;
}

size_t gc_telemetry_varint_decode(const uint8_t *in, size_t in_len, uint64_t *out)
{
    if (in == NULL || out == NULL || in_len == 0u) {
        return 0u;
    }

    uint64_t value = 0u;
    size_t shift = 0u;
    for (size_t i = 0u; i < in_len; i++) {
        uint8_t byte = in[i];
        if (shift >= 64u) {
            return 0u;
        }
        value |= ((uint64_t)(byte & 0x7Fu)) << shift;
        if ((byte & 0x80u) == 0u) {
            *out = value;
            return i + 1u;
        }
        shift += 7u;
    }
    return 0u;
}
