# esp-groundcontrol

Firmware for an ESP32-S2FN4R2 (D1 mini S2, 4 MB in-package flash, 2 MB in-package
PSRAM, native USB) that turns a Huawei B315 LTE link into a public Wi-Fi access
gate, plus a central controller service.

Three sites are deployed. One firmware image serves all three; provisioning
supplies the site id.

## Legal note, read first

This is South African deployment. Two acts bind this design:

- **RICA** (Regulation of Interception of Communications Act 70/2002) restricts
  intercepting or monitoring communications.
- **POPIA** (Protection of Personal Information Act 4 of 2013) governs personal
  information. A MAC address, a phone number and a per-client usage log are all
  personal information.

The design therefore stays at the device level. It gates access, counts bytes and
monitors modem health. It never inspects payloads, never logs destinations and
never tracks browsing. See [docs/PRIVACY.md](docs/PRIVACY.md) for what is
collected, what is not, retention, the hashing scheme and the notice text.

**This is not legal advice.** Get advice before deploying if the network serves
anyone other than you.

## Topology

```
   client phone / laptop
        |
        |  Wi-Fi  (device soft-AP)
        v
 +---------------------------------------------+
 |  ESP32-S2FN4R2            (the device)      |
 |                                             |
 |   soft-AP   ---> gate ---> NAPT ---> station|
 |   192.168.4.1             (lwIP)            |
 |     |                                       |
 |     +-> DNS redirect (53)                   |
 |     +-> HTTP portal (80)                    |
 +---------------------------------------------+
                                     |
                                     |  Wi-Fi  (station, to B315 LAN)
                                     v
                          +--------------------------+
                          |  Huawei B315  (LTE CPE)  |
                          +--------------------------+
                                     |
                                     |  carrier
                                     v
                    +--------------------------------+
                    |  internet                      |
                    |   controller   (MQTT/TLS 8883) |
                    |   VPS beacon   (UDP 41234)     |
                    +--------------------------------+
```

Every path the device originates is outbound:

| Path | Direction | When |
| --- | --- | --- |
| MQTT over TLS to the controller | outbound, device dials | always |
| UDP beacon to the VPS | outbound, one datagram, no handshake | 900 s routine, 120 s while an alarm is active |
| WireGuard tunnel | outbound, then bidirectional | only on a valid tunnel request in a beacon reply |
| B315 LAN API | outbound, station side only | modem poll, reboot-on-fault |

The device never opens a listening socket on the station interface.

## Module map

| Source | Header | Owns |
| --- | --- | --- |
| `gc_types.c` | `gc_types.h` | shared enums, `gc_client_t`, `gc_reading_t`, `gc_identity_t`, constant-time compares |
| `gc_log.c` | `gc_log.h` | PSRAM log ring, level counters, dump callback |
| `gc_nvs.c` | `gc_nvs.h` | namespaced NVS get/set for u32, u64, str, blob; commit |
| `gc_crypto.c` | `gc_crypto.h` | PSK and pepper storage, number and MAC key derivation, beacon and command MAC, RNG, persisted beacon counter and command sequence |
| `gc_config.c` | `gc_config.h` | the `gc_config_t` image, defaults, validation, per-site strings |
| `gc_pinmap.h` | `gc_pinmap.h` | GPIO ownership claims, relay pin policy |
| `gc_netif.c` | `gc_netif.h` | station and soft-AP netifs, byte counters, per-MAC accounting |
| `gc_nat.c` | `gc_nat.h` | lwIP NAPT enable/disable, forwarding pause, uplink counters |
| `gc_wifi_uplink.c` | `gc_wifi_uplink.h` | station connect, backoff 2..300 s with jitter, forget-and-retry |
| `gc_quota.c` | `gc_quota.h` | daily and monthly byte accounting, tier machine, rollover, persist |
| `gc_gate.c` | `gc_gate.h` | client table, states, strikes, soft and permanent blocks, pending verify queue, rate tokens |
| `gc_telemetry.c` | `gc_telemetry.h` | reading ring, deadband, frame encode, varint |
| `gc_ctrl_proto.c` | `gc_ctrl_proto.h` | topic builder, JSON encode of verify/event/hello, JSON decode of verdict/unblock/ack/cmd |
| `gc_mqtt.c` | `gc_mqtt.h` | broker connect, publish at QoS 0 routine and QoS 1 alarm, subscribe |
| `gc_modem_api.c` | `gc_modem_api.h` | B315 LAN API session, RSRP/RSRQ/SINR/PLMN poll, API reboot |
| `gc_link_monitor.c` | `gc_link_monitor.h` | internet-path probe, five-step escalation ladder, per-step rate limits |
| `gc_emergency.c` | `gc_emergency.h` | 16-byte beacon, beacon reply, WireGuard up/down |
| `gc_ota.c` | `gc_ota.h` | manifest fetch, preflight gates, Range download, verify, read back, trial boot, version block list |
| `gc_selftest.c` | `gc_selftest.h` | the seven trial-boot criteria and their deadline |
| `gc_watchdog.c` | `gc_watchdog.h` | hardware watchdog kick, registered health checks, stall count |
| `gc_dns_redirect.c` | `gc_dns_redirect.h` | captive-portal DNS, probe-host allow list |
| `gc_http_portal.c` | `gc_http_portal.h` | HTTP listener, notice page, number form, loopback probe |
| `gc_portal.c` | `gc_portal.h` | portal facade: DNS plus HTTP, E.164 normalisation, number status |
| `gc_app.c` | `gc_app.h` | phase machine, 1 s tick wiring every module together |
| `gc_main.c` | - | `app_main` entry |

## Quick start

Requires ESP-IDF v5.x with the `esp32s2` target installed.

```
idf.py set-target esp32s2
idf.py build
idf.py -p PORT flash
```

`PORT` is the native-USB CDC device, for example `/dev/ttyACM0` on Linux,
`/dev/cu.usbmodem*` on macOS, `COM*` on Windows. On the ESP32-S2 the native USB
port disappears while the chip is in reset, so flash with the chip running.

Monitor:

```
idf.py -p PORT monitor
```

Configuration lives under `Ground Control` in menuconfig:

```
idf.py menuconfig
```

Secrets are never in the repository. The provisioning tool writes the PSK, the
pepper, the broker password and the WireGuard key to NVS from a file outside the
tree. See [AGENTS.md](AGENTS.md).

Rescue image (factory slot, no portal, beacon and OTA only):

```
idf.py menuconfig    # Ground Control -> Build the factory rescue image = y
idf.py build
idf.py -p PORT flash
```

## Controller quick start

The controller is a TypeScript service in `controller/`.

```
cd controller
cp .env.example .env      # fill in MQTT, WhatsApp Cloud API, pepper per site
npm install
npm run dev               # development
npm run build && npm start  # production
```

The controller is the sole authority for allow, deny, strike count and unblock
(REQUIREMENTS 2.1). It refuses to start with no pepper configured for a site
(2.8). It stores a phone number only as `HMAC-SHA256(pepper, number)` truncated
to 8 bytes (2.7) and aggregates strikes across all three sites (3.9).

Minimum environment: broker URI and credentials, one pepper per site, WhatsApp
Cloud API token, verify-secret and phone-number id, the beacon PSK, and the
VPS UDP port.

## Three-site layout

| Site | id | Device id | Notes |
| --- | --- | --- | --- |
| site 1 | 1 | 1 | first deployed |
| site 2 | 2 | 1 | |
| site 3 | 3 | 1 | |

One image, three provisionings. Per site the provisioning tool sets: site id and
device id (NVS), soft-AP SSID and passphrase, B315 SSID and passphrase, broker
credentials, notice text, pepper, quota budget and reserve.

Site id and device id appear in every telemetry frame and in every MQTT topic
(REQUIREMENTS 8.4). Strike counting is global in the controller, so a client
that moves site does not reset its count (3.9).

## Build order

`main/CMakeLists.txt` lists sources in dependency order. Implement and review in
that order; a module is buildable only once everything above it exists.

```
 1 gc_types        12 gc_telemetry      23 gc_portal
 2 gc_log          13 gc_ctrl_proto     24 gc_app
 3 gc_nvs          14 gc_mqtt           25 gc_main
 4 gc_crypto       15 gc_modem_api
 5 gc_config       16 gc_link_monitor
 6 gc_pinmap       17 gc_emergency
 7 gc_netif        18 gc_ota
 8 gc_nat          19 gc_selftest
 9 gc_wifi_uplink  20 gc_watchdog
10 gc_quota        21 gc_dns_redirect
11 gc_gate         22 gc_http_portal
```

## Numbers to measure before you trust them

Every number below is an assumption baked into the configuration, the frame
layouts or the docs. None has been measured on hardware. Measure them before
you rely on the system.

| # | Assumed | Where it lives | How to measure |
| --- | --- | --- | --- |
| 1 | 4 MB flash, 2 MB PSRAM, in package | `sdkconfig.defaults`, `partitions.csv` | `idf.py size` and `heap_caps_get_free_size(MALLOC_CAP_SPIRAM)` at boot |
| 2 | 3 sites, 1 device each | deployment, `GC_SITE_ID` | count provisioned units; confirm site id in NVS per unit |
| 3 | telemetry 20 KB/day, 600 KB/month | budget note in `docs/PROTOCOL.md` | capture 7 days of MQTT payload bytes at the broker, divide |
| 4 | daily budget 1048576 KiB (1 GiB) | `GC_DAILY_BUDGET_KB` | compare `gc_quota_daily_used_kb()` against carrier-side usage for a week |
| 5 | monthly reserve 614400 KiB (600 MiB) | `GC_MONTHLY_RESERVE_KB` | set it just above measured worst-case telemetry plus beacon |
| 6 | per-client rate 128 KiB/s | `GC_CLIENT_RATE_KBYTE_S` | iperf3 from one client, confirm the token bucket holds the line |
| 7 | 24 concurrent clients | `GC_MAX_CLIENTS`, `CONFIG_LWIP_DHCPS_MAX_STATION_NUM` | associate 24 devices, watch heap and PSRAM; find the real ceiling |
| 8 | 8 pending verifications | `GC_MAX_PENDING_VERIFY` | burst 20 simultaneous number submits, count 503s |
| 9 | beacon is 16 bytes | `GC_BEACON_LEN` | capture on the VPS with `tcpdump -s 0 udp port 41234 -X` |
| 10 | beacon interval 900 s, 120 s alarm | `GC_BEACON_INTERVAL_S` | timestamp beacon arrivals at the VPS over 24 h |
| 11 | telemetry frame max 320 bytes, 24 records | `gc_telemetry.h` | log `*out_written` from `gc_telemetry_encode` and keep the max |
| 12 | batch 3600 s / 7200 s / 21600 s by tier | REQUIREMENTS 7.3-7.5 | drive `gc_quota_account_bytes` to each tier and observe publish times |
| 13 | MQTT keepalive 300 s | `GC_MQTT_KEEPALIVE_S` | check for unexpected PINGREQ storms or disconnects on a lossy link |
| 14 | modem poll 300 s | `GC_MODEM_POLL_S` | confirm the B315 session token survives the interval without re-auth |
| 15 | soft block 86400 s | `GC_SOFT_BLOCK_S` | this is policy, not physics; confirm it matches the notice text |
| 16 | strike limit 3 | `GC_STRIKE_LIMIT` | policy; confirm against the controller's own constant |
| 17 | allow grace 3600 s | `GC_ALLOW_GRACE_S` | policy; confirm it exceeds worst-case controller latency |
| 18 | self-test deadline 300 s | `GC_SELFTEST_DEADLINE_S` | time each of the seven criteria on the worst site; raise if tight |
| 19 | watchdog timeout 30000 ms | `GC_WATCHDOG_TIMEOUT_MS` | freeze the main loop with `GC_BENCH_FAULTS`, measure reset latency |
| 20 | watchdog kick pulse 50 us | `GC_WATCHDOG_KICK_PULSE_US` | scope GPIO5; confirm the external watchdog's minimum pulse |
| 21 | uplink backoff 2 s to 300 s | `GC_UPLINK_BACKOFF_MIN_S/MAX_S` | kill the B315 for an hour, log reconnect times |
| 22 | link probe 60 s, confirm count 2 | `gc_link_monitor.h` | count false escalations over a week; raise if noisy |
| 23 | modem API reboot at most every 6 h | REQUIREMENTS 5.3 | force a fault episode twice in an hour, confirm the second is refused |
| 24 | modem power cycle at most every 24 h | REQUIREMENTS 5.4 | same; confirm the relay does not chatter |
| 25 | deadbands RSSI 3 dBm, RSRP 3, RSRQ 1, SINR 2, clients 1 | `gc_telemetry.h` | record suppressed-vs-sent ratio; widen until volume matches budget 3 |
| 26 | log record 160 bytes | `GC_LOG_RECORD_MAX` | confirm truncation rate on the longest message |
| 27 | NVS 24 KB holds all persisted state | `partitions.csv` | `nvs_get_stats` after a month of quota, strikes and counters |
| 28 | factory image fits in 1 MB | `partitions.csv` | `idf.py size` on the `GC_RESCUE_IMAGE` build |
| 29 | main app fits in 1472 KB | `partitions.csv` | `idf.py size` on the default build; leave 10 percent headroom |
| 30 | no spare space at the top of flash | `partitions.csv` | confirmed: 0x290000 + 0x170000 = 0x400000 exactly. Shrink `ota_1` before adding a coredump slot |
| 31 | beacon counter wrap | 32-bit on the wire, bytes 4..7 | run past 2^32 or inject counters; confirm the VPS replay window handles wrap |
| 32 | OTA preflight: voltage or battery, free heap, free slot, RSRP, window, no alarm, no recent failure of this version | REQUIREMENTS 10.2 | pick each threshold on a bench unit by watching a real download succeed and fail |
| 33 | portal request timeout | `verification_timeout_ms` in `gc_config_t` | measure p99 controller round trip on the worst site, add margin |
| 34 | B315 API poll latency | `gc_modem_api_last_latency_ms` | log it for a week, set the API timeout above p99 |
| 35 | carrier cost per MiB | budget for numbers 4 and 5 | read the carrier's own usage figure, not the device counter, for one month |
| 36 | Range resume chunk size and per-chunk hash cost | `gc_ota.c` | time a full download over the real link at the worst RSRP |
| 37 | WireGuard persistent keepalive 0 | REQUIREMENTS 9.4 | confirm the tunnel stays usable without keepalive on this carrier's NAT |
| 38 | notice served once per client before the number field | REQUIREMENTS 1.8 | clear a client's entry, reconnect, confirm the notice precedes the form |

## Docs

| File | Contents |
| --- | --- |
| [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) | the EARS requirements. Source of truth. |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | module by module, and the failure matrix |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | MQTT topics, telemetry frame, beacon, JSON shapes |
| [docs/PARTITIONS.md](docs/PARTITIONS.md) | flash map, recovery, Secure Boot order |
| [docs/PRIVACY.md](docs/PRIVACY.md) | collection, retention, hashing, notice text |
| [docs/BENCH.md](docs/BENCH.md) | destructive bench matrix with expected outcomes |
| [docs/PINS.md](docs/PINS.md) | pin table, reserved pins, relay warning |
| [AGENTS.md](AGENTS.md) | how an agent works in this repo |
