#include "gc_dns_redirect.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"

#include "gc_log.h"
#include "gc_types.h"

#define GC_DNS_TAG "gc_dns"

#define GC_DNS_TASK_STACK_WORDS 2048
#define GC_DNS_TASK_PRIO 6
#define GC_DNS_POLL_TIMEOUT_MS 200
#define GC_DNS_STOP_POLL_MS 10
#define GC_DNS_STOP_ATTEMPTS 40

#define GC_DNS_PACKET_MAX 512
#define GC_DNS_HEADER_LEN 12
#define GC_DNS_QUESTION_TAIL_LEN 4
#define GC_DNS_ANSWER_LEN 16
#define GC_DNS_ANSWER_RDATA_LEN 4

#define GC_DNS_QTYPE_A 1
#define GC_DNS_QCLASS_IN 1

#define GC_DNS_RCODE_NOERROR 0
#define GC_DNS_RCODE_NXDOMAIN 3
#define GC_DNS_RCODE_MASK 0x0F

#define GC_DNS_FLAG_QR 0x8000
#define GC_DNS_FLAG_AA 0x0400
#define GC_DNS_FLAG_RD 0x0100
#define GC_DNS_FLAG_RA 0x0080

#define GC_DNS_LABEL_POINTER_MASK 0xC0
#define GC_DNS_NAME_POINTER 0xC00C

static const char *const k_captive_probe_hosts[] = {
    "captive.apple.com",
    "connectivitycheck.gstatic.com",
    "clients3.google.com",
    "www.msftconnecttest.com",
    "detectportal.firefox.com",
    "connectivitycheck.android.com",
};

static TaskHandle_t s_task;
static int s_socket = -1;
static uint32_t s_ap_ip;
static volatile bool s_running;
static volatile bool s_allow_forwarding;
static uint32_t s_queries;
static uint32_t s_redirected;

static uint16_t dns_read_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static void dns_write_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFFu);
}

static void dns_write_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xFFu);
}

static char dns_lower(char c)
{
    if ((c >= 'A') && (c <= 'Z')) {
        return (char)(c + ('a' - 'A'));
    }
    return c;
}

static bool dns_host_suffix_matches(const char *host, const char *suffix)
{
    size_t host_len = strlen(host);
    size_t suffix_len = strlen(suffix);

    if ((suffix_len == 0u) || (host_len < suffix_len)) {
        return false;
    }

    const char *tail = &host[host_len - suffix_len];
    for (size_t i = 0u; i < suffix_len; i++) {
        if (dns_lower(tail[i]) != dns_lower(suffix[i])) {
            return false;
        }
    }

    if (host_len == suffix_len) {
        return true;
    }

    return host[host_len - suffix_len - 1u] == '.';
}

bool gc_dns_redirect_is_captive_probe(const char *host)
{
    if (host == NULL) {
        return false;
    }

    for (size_t i = 0u; i < (sizeof(k_captive_probe_hosts) / sizeof(k_captive_probe_hosts[0])); i++) {
        if (dns_host_suffix_matches(host, k_captive_probe_hosts[i])) {
            return true;
        }
    }

    return false;
}

void gc_dns_redirect_set_allow_forwarding(bool allow)
{
    s_allow_forwarding = allow;
}

static bool dns_parse_question(const uint8_t *packet,
                               size_t packet_len,
                               char *host,
                               size_t host_len,
                               uint16_t *qtype,
                               uint16_t *qclass,
                               size_t *question_len)
{
    size_t pos = GC_DNS_HEADER_LEN;
    size_t name_len = 0u;

    host[0] = '\0';

    for (;;) {
        if (pos >= packet_len) {
            return false;
        }

        uint8_t label_len = packet[pos];
        pos++;

        if (label_len == 0u) {
            break;
        }

        if ((label_len & GC_DNS_LABEL_POINTER_MASK) != 0u) {
            return false;
        }

        if (name_len != 0u) {
            if ((name_len + 1u) >= host_len) {
                return false;
            }
            host[name_len] = '.';
            name_len++;
        }

        if (((pos + label_len) > packet_len) || ((name_len + label_len) >= host_len)) {
            return false;
        }

        memcpy(&host[name_len], &packet[pos], label_len);
        name_len += label_len;
        pos += label_len;
    }

    host[name_len] = '\0';

    if ((pos + GC_DNS_QUESTION_TAIL_LEN) > packet_len) {
        return false;
    }

    *qtype = dns_read_u16(&packet[pos]);
    *qclass = dns_read_u16(&packet[pos + 2u]);
    *question_len = (pos + GC_DNS_QUESTION_TAIL_LEN) - GC_DNS_HEADER_LEN;

    return true;
}

static size_t dns_build_reply(uint8_t *out,
                              size_t out_max,
                              const uint8_t *query,
                              size_t question_len,
                              uint16_t qtype,
                              uint16_t qclass,
                              bool point_at_ap,
                              uint16_t rcode)
{
    bool with_answer = point_at_ap && (qtype == GC_DNS_QTYPE_A) && (qclass == GC_DNS_QCLASS_IN);
    size_t question_total = GC_DNS_HEADER_LEN + question_len;
    size_t total = question_total;

    if (with_answer) {
        total += GC_DNS_ANSWER_LEN;
    }

    if (total > out_max) {
        return 0u;
    }

    memcpy(out, query, question_total);

    uint16_t flags = (uint16_t)(GC_DNS_FLAG_QR | GC_DNS_FLAG_AA | GC_DNS_FLAG_RA);
    if ((dns_read_u16(&query[2]) & GC_DNS_FLAG_RD) != 0u) {
        flags |= GC_DNS_FLAG_RD;
    }
    flags |= (uint16_t)(rcode & GC_DNS_RCODE_MASK);

    dns_write_u16(&out[2], flags);
    dns_write_u16(&out[4], 1u);
    dns_write_u16(&out[6], with_answer ? 1u : 0u);
    dns_write_u16(&out[8], 0u);
    dns_write_u16(&out[10], 0u);

    if (with_answer) {
        size_t p = question_total;
        dns_write_u16(&out[p], (uint16_t)GC_DNS_NAME_POINTER);
        dns_write_u16(&out[p + 2u], (uint16_t)GC_DNS_QTYPE_A);
        dns_write_u16(&out[p + 4u], (uint16_t)GC_DNS_QCLASS_IN);
        dns_write_u32(&out[p + 6u], (uint32_t)GC_DNS_REDIRECT_TTL_S);
        dns_write_u16(&out[p + 10u], (uint16_t)GC_DNS_ANSWER_RDATA_LEN);
        memcpy(&out[p + 12u], &s_ap_ip, GC_DNS_ANSWER_RDATA_LEN);
    }

    return total;
}

static void dns_answer(uint8_t *packet,
                       size_t packet_len,
                       const struct sockaddr_storage *from,
                       socklen_t from_len)
{
    char host[GC_HOST_MAX];
    uint16_t qtype = 0u;
    uint16_t qclass = 0u;
    size_t question_len = 0u;

    if (packet_len <= GC_DNS_HEADER_LEN) {
        return;
    }

    if (!dns_parse_question(packet, packet_len, host, sizeof(host), &qtype, &qclass, &question_len)) {
        return;
    }

    s_queries++;

    bool probe = gc_dns_redirect_is_captive_probe(host);
    bool point_at_ap = probe || !s_allow_forwarding;
    uint16_t rcode = point_at_ap ? GC_DNS_RCODE_NOERROR : GC_DNS_RCODE_NXDOMAIN;

    uint8_t reply[GC_DNS_PACKET_MAX];
    size_t reply_len = dns_build_reply(reply, sizeof(reply), packet, question_len, qtype, qclass,
                                       point_at_ap, rcode);

    if (reply_len == 0u) {
        return;
    }

    if (point_at_ap && (qtype == GC_DNS_QTYPE_A) && (qclass == GC_DNS_QCLASS_IN)) {
        s_redirected++;
    }

    ssize_t sent = sendto(s_socket, reply, reply_len, 0, (const struct sockaddr *)from, from_len);
    if (sent < 0) {
        GC_LOGD(GC_DNS_TAG, "reply send failed");
    }
}

static void dns_task(void *arg)
{
    uint8_t packet[GC_DNS_PACKET_MAX];

    (void)arg;

    while (s_running) {
        int fd = s_socket;
        if (fd < 0) {
            break;
        }

        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(fd, &read_set);

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = GC_DNS_POLL_TIMEOUT_MS * 1000;

        int ready = select(fd + 1, &read_set, NULL, NULL, &timeout);
        if (ready <= 0) {
            continue;
        }

        if (!FD_ISSET(fd, &read_set)) {
            continue;
        }

        struct sockaddr_storage from;
        socklen_t from_len = (socklen_t)sizeof(from);
        int got = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr *)&from, &from_len);
        if (got <= 0) {
            continue;
        }

        dns_answer(packet, (size_t)got, &from, from_len);
    }

    s_task = NULL;
    vTaskDelete(NULL);
}

gc_err_t gc_dns_redirect_start(uint32_t ap_ip)
{
    if (s_running) {
        return GC_ERR_BUSY;
    }

    if (ap_ip == 0u) {
        return GC_ERR_INVALID_ARG;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        GC_LOGE(GC_DNS_TAG, "socket failed");
        return GC_ERR_IO;
    }

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_len = sizeof(bind_addr);
    bind_addr.sin_port = htons(GC_DNS_PORT);
    bind_addr.sin_addr.s_addr = ap_ip;

    if (bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0) {
        GC_LOGE(GC_DNS_TAG, "bind port %d failed", GC_DNS_PORT);
        closesocket(fd);
        return GC_ERR_IO;
    }

    s_ap_ip = ap_ip;
    s_socket = fd;
    s_running = true;

    BaseType_t created = xTaskCreate(dns_task, GC_DNS_TAG, GC_DNS_TASK_STACK_WORDS, NULL,
                                     GC_DNS_TASK_PRIO, &s_task);
    if (created != pdPASS) {
        GC_LOGE(GC_DNS_TAG, "task create failed");
        s_running = false;
        s_socket = -1;
        closesocket(fd);
        return GC_ERR_NO_MEM;
    }

    GC_LOGI(GC_DNS_TAG, "listening on port %d", GC_DNS_PORT);
    return GC_OK;
}

void gc_dns_redirect_stop(void)
{
    if (!s_running) {
        return;
    }

    s_running = false;

    int fd = s_socket;
    s_socket = -1;

    if (fd >= 0) {
        shutdown(fd, SHUT_RDWR);
        closesocket(fd);
    }

    for (int attempt = 0; attempt < GC_DNS_STOP_ATTEMPTS; attempt++) {
        if (s_task == NULL) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(GC_DNS_STOP_POLL_MS));
    }

    if (s_task != NULL) {
        vTaskDelete(s_task);
        s_task = NULL;
    }

    GC_LOGI(GC_DNS_TAG, "stopped");
}

bool gc_dns_redirect_running(void)
{
    return s_running;
}

uint32_t gc_dns_redirect_queries(void)
{
    return s_queries;
}

uint32_t gc_dns_redirect_redirected(void)
{
    return s_redirected;
}
