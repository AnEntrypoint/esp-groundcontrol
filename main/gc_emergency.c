#include "gc_emergency.h"

#include "gc_crypto.h"
#include "gc_log.h"
#include "gc_nvs.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "lwip/errno.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"

#define GC_EMERGENCY_TAG "gc_emergency"
#define GC_BEACON_VERSION_SHIFT 4
#define GC_BEACON_KIND_MASK 0x0Fu
#define GC_BEACON_REPLY_FLAG_TUNNEL 0x08u
#define GC_BEACON_SEND_ATTEMPTS 3
#define GC_BEACON_REPLY_DRAIN_MAX 4
#define GC_BEACON_RX_MAX (GC_BEACON_LEN * 2)
#define GC_WG_VALUE_MAX 64
#define GC_WG_PERSISTENT_KEEPALIVE_S 0u

#define GC_NVS_KEY_BEACON_REPLY_COUNTER "bcn_rly_ctr"
#define GC_NVS_KEY_WG_ADDRESS "wg_address"
#define GC_NVS_KEY_WG_PRIVATE_KEY "wg_privkey"
#define GC_NVS_KEY_WG_PEER_PUBLIC_KEY "wg_peerpub"
#define GC_NVS_KEY_WG_PEER_ENDPOINT "wg_endpoint"

__attribute__((weak)) int wireguard_setup(const char *ip, const char *privkey,
                                          const char *peerpubkey, const char *peerendpoint);
__attribute__((weak)) void wireguard_teardown(void);

__attribute__((weak)) int wireguard_setup(const char *ip, const char *privkey,
                                          const char *peerpubkey, const char *peerendpoint)
{
    (void)ip;
    (void)privkey;
    (void)peerpubkey;
    (void)peerendpoint;
    return -1;
}

__attribute__((weak)) void wireguard_teardown(void)
{
}

typedef struct {
    gc_identity_t id;
    char host[GC_HOST_MAX];
    uint16_t port;
    uint32_t counter;
    uint32_t reply_counter;
    uint32_t last_sent_s;
    uint32_t peer_addr;
    int socket_fd;
    bool initialised;
    bool alarm_active;
    bool tunnel_up;
    bool tunnel_requested;
    bool last_sent_valid;
    bool peer_addr_valid;
} gc_beacon_state_t;

static gc_beacon_state_t s_beacon = {
    .socket_fd = -1,
};

static void gc_beacon_store_be32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static uint32_t gc_beacon_load_be32(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static uint32_t gc_beacon_next_counter(uint32_t counter)
{
    return counter == UINT32_MAX ? counter : counter + 1u;
}

static gc_err_t gc_beacon_resolve(const char *host, uint16_t port, struct sockaddr_in *out)
{
    in_addr_t literal = inet_addr(host);
    if (literal != INADDR_NONE) {
        memset(out, 0, sizeof(*out));
        out->sin_family = AF_INET;
        out->sin_port = htons(port);
        out->sin_addr.s_addr = literal;
        return GC_OK;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo *resolved = NULL;
    if (getaddrinfo(host, NULL, &hints, &resolved) != 0 || resolved == NULL) {
        return GC_ERR_IO;
    }

    memset(out, 0, sizeof(*out));
    size_t copy_len = sizeof(*out);
    if ((size_t)resolved->ai_addrlen < copy_len) {
        copy_len = (size_t)resolved->ai_addrlen;
    }
    memcpy(out, resolved->ai_addr, copy_len);
    out->sin_family = AF_INET;
    out->sin_port = htons(port);
    freeaddrinfo(resolved);
    return GC_OK;
}

static gc_err_t gc_beacon_socket_open(void)
{
    if (s_beacon.socket_fd >= 0) {
        return GC_OK;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        GC_LOGW(GC_EMERGENCY_TAG, "udp socket unavailable errno=%d", errno);
        return GC_ERR_IO;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = 0;
    local.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        GC_LOGW(GC_EMERGENCY_TAG, "udp bind failed errno=%d", errno);
        close(fd);
        return GC_ERR_IO;
    }

    s_beacon.socket_fd = fd;
    return GC_OK;
}

static bool gc_beacon_secret_load(const char *key, char *out, size_t len)
{
    size_t out_len = len;
    if (gc_nvs_get_str(key, out, &out_len) != GC_OK) {
        return false;
    }
    return out[0] != '\0';
}

gc_err_t gc_emergency_encode_beacon(const gc_identity_t *id,
                                    bool alarm,
                                    uint32_t counter,
                                    uint8_t out[GC_BEACON_LEN])
{
    if (id == NULL || out == NULL) {
        return GC_ERR_INVALID_ARG;
    }

    uint8_t psk[GC_PSK_LEN];
    gc_err_t err = gc_crypto_load_psk(psk);
    if (err != GC_OK) {
        GC_LOGW(GC_EMERGENCY_TAG, "psk load failed err=%d", (int)err);
        return err;
    }

    uint8_t kind = alarm ? GC_BEACON_KIND_ALARM : GC_BEACON_KIND_ROUTINE;
    out[0] = (uint8_t)((GC_BEACON_VERSION << GC_BEACON_VERSION_SHIFT) | (kind & GC_BEACON_KIND_MASK));
    out[1] = (uint8_t)(id->site_id >> 8);
    out[2] = (uint8_t)(id->site_id & 0xFFu);
    out[3] = (uint8_t)(id->device_id & 0xFFu);
    gc_beacon_store_be32(&out[4], counter);

    err = gc_crypto_beacon_mac(psk, out, GC_BEACON_PAYLOAD_LEN, &out[GC_BEACON_PAYLOAD_LEN]);
    memset(psk, 0, sizeof(psk));
    if (err != GC_OK) {
        GC_LOGW(GC_EMERGENCY_TAG, "beacon mac failed err=%d", (int)err);
        return err;
    }
    return GC_OK;
}

gc_err_t gc_emergency_init(const gc_identity_t *id, const char *host, uint16_t port)
{
    if (id == NULL || host == NULL || host[0] == '\0' || port == 0) {
        return GC_ERR_INVALID_ARG;
    }

    gc_emergency_deinit();

    s_beacon.id = *id;
    snprintf(s_beacon.host, sizeof(s_beacon.host), "%s", host);
    s_beacon.port = port;

    uint32_t stored = 0;
    if (gc_crypto_beacon_counter_load(&stored) != GC_OK) {
        GC_LOGW(GC_EMERGENCY_TAG, "beacon counter unreadable, starting at 0");
        stored = 0;
    }
    s_beacon.counter = stored;

    uint32_t reply_counter = 0;
    if (gc_nvs_get_u32(GC_NVS_KEY_BEACON_REPLY_COUNTER, &reply_counter) != GC_OK) {
        reply_counter = 0;
    }
    s_beacon.reply_counter = reply_counter;

    s_beacon.initialised = true;
    GC_LOGI(GC_EMERGENCY_TAG, "beacon host=%s port=%u counter=%u",
            s_beacon.host, (unsigned)s_beacon.port, (unsigned)s_beacon.counter);
    return GC_OK;
}

void gc_emergency_deinit(void)
{
    if (s_beacon.tunnel_up) {
        wireguard_teardown();
    }
    if (s_beacon.socket_fd >= 0) {
        close(s_beacon.socket_fd);
    }
    memset(&s_beacon, 0, sizeof(s_beacon));
    s_beacon.socket_fd = -1;
}

void gc_emergency_set_alarm(bool alarm)
{
    s_beacon.alarm_active = alarm;
}

uint32_t gc_emergency_beacon_counter(void)
{
    return s_beacon.counter;
}

gc_err_t gc_emergency_beacon_send(bool alarm)
{
    if (!s_beacon.initialised) {
        return GC_ERR_BUSY;
    }

    s_beacon.alarm_active = alarm;

    gc_err_t err = gc_beacon_socket_open();
    if (err != GC_OK) {
        return err;
    }

    struct sockaddr_in peer;
    err = gc_beacon_resolve(s_beacon.host, s_beacon.port, &peer);
    if (err != GC_OK) {
        GC_LOGW(GC_EMERGENCY_TAG, "beacon host %s unresolved", s_beacon.host);
        return err;
    }

    uint32_t next = gc_beacon_next_counter(s_beacon.counter);
    uint8_t frame[GC_BEACON_LEN];
    err = gc_emergency_encode_beacon(&s_beacon.id, alarm, next, frame);
    if (err != GC_OK) {
        return err;
    }

    for (size_t attempt = 0; attempt < GC_BEACON_SEND_ATTEMPTS; attempt++) {
        ssize_t sent = sendto(s_beacon.socket_fd, frame, GC_BEACON_LEN, 0,
                              (struct sockaddr *)&peer, sizeof(peer));
        if (sent == (ssize_t)GC_BEACON_LEN) {
            s_beacon.counter = next;
            s_beacon.peer_addr = peer.sin_addr.s_addr;
            s_beacon.peer_addr_valid = true;
            gc_err_t stored = gc_crypto_beacon_counter_store(s_beacon.counter);
            if (stored != GC_OK) {
                GC_LOGW(GC_EMERGENCY_TAG, "counter persist failed err=%d", (int)stored);
            }
            GC_LOGD(GC_EMERGENCY_TAG, "beacon sent kind=%d counter=%u", alarm ? 2 : 1, (unsigned)next);
            return GC_OK;
        }
    }

    s_beacon.peer_addr_valid = false;
    GC_LOGW(GC_EMERGENCY_TAG, "beacon send failed after %d attempts errno=%d",
            GC_BEACON_SEND_ATTEMPTS, errno);
    return GC_ERR_IO;
}

gc_err_t gc_emergency_poll_reply(void)
{
    if (!s_beacon.initialised || s_beacon.socket_fd < 0) {
        return GC_ERR_BUSY;
    }

    uint8_t psk[GC_PSK_LEN];
    gc_err_t err = gc_crypto_load_psk(psk);
    if (err != GC_OK) {
        return err;
    }

    gc_err_t result = GC_ERR_TIMEOUT;
    uint8_t frame[GC_BEACON_RX_MAX];

    for (size_t drained = 0; drained < GC_BEACON_REPLY_DRAIN_MAX; drained++) {
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        memset(&from, 0, sizeof(from));

        ssize_t got = recvfrom(s_beacon.socket_fd, frame, sizeof(frame), 0,
                               (struct sockaddr *)&from, &from_len);
        if (got < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                result = GC_ERR_IO;
            }
            break;
        }

        if (got != (ssize_t)GC_BEACON_LEN) {
            result = GC_ERR_AUTH;
            continue;
        }

        if ((uint8_t)(frame[0] >> GC_BEACON_VERSION_SHIFT) != GC_BEACON_VERSION) {
            result = GC_ERR_AUTH;
            continue;
        }

        if (s_beacon.peer_addr_valid && from.sin_addr.s_addr != s_beacon.peer_addr) {
            result = GC_ERR_AUTH;
            continue;
        }

        uint8_t tag[GC_KEY_LEN];
        if (gc_crypto_beacon_mac(psk, frame, GC_BEACON_PAYLOAD_LEN, tag) != GC_OK) {
            result = GC_ERR_IO;
            break;
        }

        if (!gc_crypto_constant_time_equal(tag, &frame[GC_BEACON_PAYLOAD_LEN], GC_KEY_LEN)) {
            result = GC_ERR_AUTH;
            continue;
        }

        uint32_t counter = gc_beacon_load_be32(&frame[4]);
        if (counter <= s_beacon.reply_counter) {
            GC_LOGW(GC_EMERGENCY_TAG, "beacon reply replayed counter=%u", (unsigned)counter);
            result = GC_ERR_AUTH;
            continue;
        }

        s_beacon.reply_counter = counter;
        if (gc_nvs_set_u32(GC_NVS_KEY_BEACON_REPLY_COUNTER, counter) != GC_OK) {
            GC_LOGW(GC_EMERGENCY_TAG, "reply counter persist failed");
        }

        bool tunnel_flag = (frame[0] & GC_BEACON_REPLY_FLAG_TUNNEL) != 0;
        s_beacon.tunnel_requested = tunnel_flag;
        GC_LOGI(GC_EMERGENCY_TAG, "beacon reply counter=%u tunnel=%d",
                (unsigned)counter, tunnel_flag ? 1 : 0);
        result = GC_OK;
    }

    memset(psk, 0, sizeof(psk));
    return result;
}

gc_err_t gc_emergency_tunnel_up(void)
{
    if (s_beacon.tunnel_up) {
        return GC_OK;
    }

    char address[GC_WG_VALUE_MAX];
    char privkey[GC_WG_VALUE_MAX];
    char peerpubkey[GC_WG_VALUE_MAX];
    char peerendpoint[GC_WG_VALUE_MAX];

    if (!gc_beacon_secret_load(GC_NVS_KEY_WG_ADDRESS, address, sizeof(address)) ||
        !gc_beacon_secret_load(GC_NVS_KEY_WG_PRIVATE_KEY, privkey, sizeof(privkey)) ||
        !gc_beacon_secret_load(GC_NVS_KEY_WG_PEER_PUBLIC_KEY, peerpubkey, sizeof(peerpubkey)) ||
        !gc_beacon_secret_load(GC_NVS_KEY_WG_PEER_ENDPOINT, peerendpoint, sizeof(peerendpoint))) {
        GC_LOGW(GC_EMERGENCY_TAG, "wireguard credentials not provisioned");
        return GC_ERR_NOT_FOUND;
    }

    GC_LOGI(GC_EMERGENCY_TAG, "tunnel up endpoint=%s keepalive=%us",
            peerendpoint, (unsigned)GC_WG_PERSISTENT_KEEPALIVE_S);

    if (wireguard_setup(address, privkey, peerpubkey, peerendpoint) != 0) {
        GC_LOGE(GC_EMERGENCY_TAG, "wireguard setup failed");
        return GC_ERR_UNSUPPORTED;
    }

    s_beacon.tunnel_up = true;
    return GC_OK;
}

gc_err_t gc_emergency_tunnel_down(void)
{
    s_beacon.tunnel_requested = false;
    if (!s_beacon.tunnel_up) {
        return GC_OK;
    }

    wireguard_teardown();
    s_beacon.tunnel_up = false;
    GC_LOGI(GC_EMERGENCY_TAG, "tunnel down");
    return GC_OK;
}

bool gc_emergency_tunnel_is_up(void)
{
    return s_beacon.tunnel_up;
}

bool gc_emergency_tunnel_requested(void)
{
    return s_beacon.tunnel_requested;
}

gc_err_t gc_emergency_tick(uint32_t now_s)
{
    if (!s_beacon.initialised) {
        return GC_ERR_BUSY;
    }

    uint32_t interval_s = s_beacon.alarm_active ? GC_BEACON_INTERVAL_ALARM_S : GC_BEACON_INTERVAL_S;
    bool due = !s_beacon.last_sent_valid ||
               (uint32_t)(now_s - s_beacon.last_sent_s) >= interval_s;

    gc_err_t err = GC_OK;
    if (due) {
        err = gc_emergency_beacon_send(s_beacon.alarm_active);
        s_beacon.last_sent_s = now_s;
        s_beacon.last_sent_valid = true;
        if (err != GC_OK) {
            GC_LOGW(GC_EMERGENCY_TAG, "beacon tick send err=%d", (int)err);
        }
    }

    (void)gc_emergency_poll_reply();

    if (s_beacon.tunnel_requested && !s_beacon.tunnel_up) {
        (void)gc_emergency_tunnel_up();
    } else if (!s_beacon.tunnel_requested && s_beacon.tunnel_up) {
        (void)gc_emergency_tunnel_down();
    }

    return err;
}
