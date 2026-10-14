# Architecture

Module by module: what each owns, what it must not do, and the failure matrix
derived from [REQUIREMENTS.md](REQUIREMENTS.md).

## Runtime shape

One FreeRTOS main loop drives a 1 s tick (`GC_APP_TICK_PERIOD_MS`). Every module
exposes `init`, a `tick(uint32_t now_s)` where it needs periodic work, and
getters. No module owns a thread that blocks the loop.

Phases (`gc_app_phase_t`):

| Phase | Meaning |
| --- | --- |
| `GC_APP_PHASE_BOOT` | configuring netifs, reading NVS, starting the watchdog |
| `GC_APP_PHASE_NO_UPLINK` | station down, no internet path; soft-AP and portal still up |
| `GC_APP_PHASE_PORTAL_ONLY` | station associated but no internet path; portal still served |
| `GC_APP_PHASE_ONLINE` | internet path up, MQTT up |
| `GC_APP_PHASE_TRIAL_BOOT` | trial boot running, self-test in progress |
| `GC_APP_PHASE_DEGRADED` | reserve tripped or an alarm is active |

Memory policy (REQUIREMENTS 11.4): Wi-Fi and lwIP buffers come from internal
RAM. The portal session table, the client list, the delta apply buffer and the
log ring come from PSRAM. `CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP=n` enforces the
first half of that sentence.

## Modules

### gc_types

Owns shared enums (`gc_client_state_t`, `gc_deny_reason_t`, `gc_quota_tier_t`,
`gc_slot_t`, `gc_escalation_step_t`), the wire-sized structs (`gc_client_t`,
`gc_reading_t`, `gc_identity_t`), and the fixed 8-byte key type `gc_key_t`
(`GC_KEY_LEN`). Also the constant-time compare helpers `gc_key_equal`,
`gc_mac_equal`, `gc_mac_is_zero`, and the `*_name` stringifiers used by the log.

Owns nothing else. It is a leaf.

### gc_log

PSRAM ring buffer of `GC_LOG_RECORD_MAX` (160) byte records. Levels
error/warn/info/debug. Keeps a dropped-record count and per-level counters:
`gc_log_error_count` and `gc_log_warn_count` feed telemetry and the watchdog.
`gc_log_ring_dump` pushes the ring to an emitter callback, used by the tunnel
console and by the `dump_log` command.

Must not log a payload, a destination or a phone number.

### gc_nvs

Namespace `gc`, keys at most `GC_NVS_KEY_MAX` (15) characters. Typed accessors
for u32, u64, string and blob, plus `commit`, `erase_key` and `has_key`.

Everything that must survive reboot goes through here: quota totals, strike
counters, the beacon counter, the command sequence, the version block list,
the site id.

### gc_crypto

Owns the two 32-byte secrets and every derivation:

| Function | Result |
| --- | --- |
| `gc_crypto_number_key` | 8-byte key = first 8 bytes of `HMAC-SHA256(pepper, E.164)` |
| `gc_crypto_mac_key` | 8-byte key = first 8 bytes of `HMAC-SHA256(pepper, MAC)` |
| `gc_crypto_beacon_mac` | 8-byte tag over the 8-byte beacon payload |
| `gc_crypto_command_mac` | 8-byte tag over a canonical command body |

Persists the monotonic beacon counter and the last accepted command sequence.
Seeds the RNG. Provides `gc_crypto_constant_time_equal` for every comparison of
a secret-derived value.

The pepper is per site (REQUIREMENTS 12.2) and is never in the repository
(13.1).

### gc_config

The `gc_config_t` struct is the whole runtime configuration: identities, SSIDs
and passphrases, modem and broker endpoints, beacon host and port, notice text,
verify mode, and every threshold and period. `gc_config_defaults` fills it from
Kconfig, `gc_config_load` overlays NVS, `gc_config_validate` returns the name of
the first bad field.

### gc_pinmap

GPIO ownership. `gc_pinmap_claim(gpio, owner)` records an owner;
`gc_pinmap_relay_allowed(gpio)` refuses GPIO0 for the relay (REQUIREMENTS 11.2).
See [PINS.md](PINS.md).

### gc_netif

Creates and starts the station and soft-AP netifs. Owns byte accounting:
`gc_netif_account_sta_tx/rx` for the uplink pair, `gc_netif_account_ap_tx/rx`
for per-client accounting keyed by MAC (REQUIREMENTS 7.1). Exposes
`gc_netif_rx_counter_wrapped` so the quota layer can detect a 32-bit lwIP
counter wrap.

### gc_nat

lwIP NAPT enable and disable (`CONFIG_LWIP_IPV4_NAPT=y`,
`CONFIG_LWIP_IP_FORWARD=y`). Owns `forwarding_paused`, which the reserve trip
sets and which stops client forwarding while telemetry and the beacon keep
running (REQUIREMENTS 7.6).

### gc_wifi_uplink

Station association to the B315 SSID, DHCP wait, and the reconnect backoff:
exponential from `GC_UPLINK_BACKOFF_MIN_S` (2) capped at
`GC_UPLINK_BACKOFF_MAX_S` (300) with jitter (REQUIREMENTS 4.2).
`gc_wifi_uplink_forget_and_retry` is the step the escalation ladder calls.

### gc_quota

Counts up and down bytes on the station interface, converts to KiB, keeps daily
and monthly totals, and derives the tier:

| Tier | Daily used / budget | Batch period | Telemetry content |
| --- | --- | --- | --- |
| `NORMAL` | < 70 % | 3600 s | normal keepalive, everything |
| `REDUCED` | 70 to 90 % | 7200 s | non-essential events dropped |
| `HEARTBEAT` | 90 to 100 % | 21600 s | heartbeat and alarms only |
| `RESERVE` | reserve reached | - | forwarding paused, telemetry and beacon continue |

Rollover resets the daily counter and persists totals (REQUIREMENTS 7.2, 7.7).
`gc_quota_restore` reloads counters after reboot.

### gc_gate

The client table and the whole access decision on the device side. Owns:

- the client state machine `NEW -> PENDING -> ALLOWED | SOFT_BLOCKED |
  PERMANENTLY_BLOCKED`
- `gc_gate_submit_number`, which normalises to E.164, derives the number key and
  the MAC key, and queues a pending verification (max
  `GC_MAX_PENDING_VERIFY`)
- `gc_gate_apply_verdict`, the only path that grants forwarding
- `gc_gate_soft_block` for 24 h, `gc_gate_permanent_block` for the strike limit
- `gc_gate_unblock`, reachable only from a signed command
- per-client rate tokens (`gc_gate_rate_allow`, `GC_CLIENT_RATE_KBYTE_S`)
- `notice_served`, which the portal sets and which gates showing the number
  field (REQUIREMENTS 1.8)

The authoritative block key is the number key; the MAC key is the secondary
signal (REQUIREMENTS 3.8). The device does not count strikes to the permanent
limit by itself: the controller is the sole authority for strike count and
unblock (2.1), and the device mirrors counters to it (3.11).

### gc_telemetry

A ring of at most `GC_TELEMETRY_MAX_RECORDS` (24) `gc_reading_t` values. A
reading is pushed only if it moved past its deadband since the last reading
sent (REQUIREMENTS 8.3). `gc_telemetry_encode` produces the frame in
[PROTOCOL.md](PROTOCOL.md); `gc_telemetry_encode_heartbeat` produces a frame
with zero records. Frames are capped at `GC_TELEMETRY_FRAME_MAX` (320) bytes.

### gc_ctrl_proto

Topic construction and the JSON codec. `gc_ctrl_topic_build` and
`gc_ctrl_topics_for_identity` produce the nine topics. Encoders:
`gc_ctrl_encode_verify_request`, `gc_ctrl_encode_event`,
`gc_ctrl_encode_hello`. Decoder: `gc_ctrl_decode`, which classifies an inbound
payload into verdict, unblock, ack or command.

### gc_mqtt

Broker connection over TLS (`CONFIG_ESP_HTTP_CLIENT_ENABLE_HTTPS=y`,
MBEDTLS TLS client only). Publishes routine telemetry at QoS 0 and alarms at
QoS 1 (REQUIREMENTS 8.2). Subscribes to the four down topics. Reports
connectivity to `gc_link_monitor`.

### gc_modem_api

B315 LAN API client. Polls RSRP, RSRQ, SINR, RSSI and PLMN every
`GC_MODEM_POLL_S`. Caches the session token and renews it before expiry
(REQUIREMENTS 6.3). On a session error it drops the token and re-authenticates
before the next poll (6.2). Owns `gc_modem_api_reboot`, which the escalation
ladder calls.

An unanswered API is recorded as its own fault. It is never by itself a reason
to power-cycle the modem (REQUIREMENTS 5.6).

### gc_link_monitor

Probes for an internet path every `GC_LINK_PROBE_INTERVAL_S` (60) and confirms
a fault after `GC_LINK_FAULT_CONFIRM_COUNT` (2) probes. Owns the five-step
escalation ladder and the rate limits on the two destructive steps:

```
RETRY_LINK -> RERESOLVE_DNS -> MODEM_API_REBOOT -> MODEM_POWER_CYCLE -> ALARM_ONLY
                                  >= 6 h apart         >= 24 h apart
```

`gc_link_monitor_claim_modem_api_reboot` and
`gc_link_monitor_claim_modem_power_cycle` are the rate-limit gates. At
`ALARM_ONLY` the beacon keeps running and exactly one alarm is sent per fault
episode (REQUIREMENTS 5.5).

### gc_emergency

The 16-byte beacon. `GC_BEACON_LEN` is 16: an 8-byte payload plus an 8-byte
truncated HMAC under the PSK (REQUIREMENTS 9.1, 9.2). Sent every
`GC_BEACON_INTERVAL_S` (900), or `GC_BEACON_INTERVAL_ALARM_S` (120) while an
alarm is active. No handshake, and the PSK is never on the wire.

`gc_emergency_poll_reply` looks for a valid tunnel request, then
`gc_emergency_tunnel_up` brings up WireGuard with persistent keepalive 0
(9.4). While the tunnel is up, the console and the B315 admin proxy are exposed
only on the tunnel interface (9.5).

### gc_ota

State machine `IDLE -> CHECKING -> PREFLIGHT -> DOWNLOADING -> VERIFYING ->
TRIAL`, with `ROLLING_BACK` and `FAILED` as exits.

- manifest: version, size, `min_security_version`, SHA-256 hex, URL, delta flag
  and delta base version
- preflight gates (REQUIREMENTS 10.2): supply voltage or battery above
  threshold, free heap above threshold, a free slot of adequate size, modem
  signal above threshold, inside the configured time window, no active alarm,
  no failure of this version inside the block-backoff period
- download to the inactive slot over HTTPS with Range resume, hashing each
  chunk (10.3, 10.4)
- verify: full-image hash and signature, then read back the written partition
  and compare (10.5, 10.6)
- trial: `gc_ota_mark_valid` on all seven criteria passing,
  `gc_ota_mark_invalid_and_reboot` on any failure or on the deadline passing,
  and block that version (10.7 to 10.9)
- `gc_ota_block_version` / `gc_ota_version_blocked` is the version block list,
  persisted in NVS

### gc_selftest

Seven criteria, run inside `GC_SELFTEST_DEADLINE_S`:

1. `AP_UP` soft-AP is up
2. `STA_IP` station has an IP
3. `MODEM_SIGNAL` RSRP above threshold
4. `CONTROLLER_REACHABLE` MQTT connected
5. `HEARTBEAT_ACKED` an ack came back from the controller
6. `PORTAL_LOOPBACK` the portal answered its own loopback probe
7. `QUOTA_INCREMENTED` the quota counter advanced

`gc_selftest_report` records each result; `gc_selftest_failed_criterion` names
the first failure for the log and the event.

### gc_watchdog

Hardware watchdog, timeout `GC_WATCHDOG_TIMEOUT_MS` (30000). Up to
`GC_WATCHDOG_MAX_CHECKS` (12) named checks register a predicate. The watchdog is
kicked from the main loop only after every registered check has passed
(REQUIREMENTS 11.1). `gc_watchdog_failing_check` names the blocker;
`gc_watchdog_stall_count` counts kicks that did not happen.

### gc_dns_redirect

UDP 53 listener on the soft-AP. Redirects everything to the portal while
forwarding is not allowed for that client, with `GC_DNS_REDIRECT_TTL_S` (5) to
stop clients caching the answer. `gc_dns_redirect_is_captive_probe` lets the
captive-portal detection hosts of Apple, Google, Windows and Android through
(REQUIREMENTS 1.3).

### gc_http_portal

HTTP listener on port 80, at most `GC_HTTP_MAX_CLIENTS` (4) concurrent
sessions. Serves the notice page, then the phone-number form. Fields are capped
at `GC_HTTP_FIELD_MAX` (32) and the body at `GC_HTTP_BODY_MAX` (256).
`gc_http_portal_probe_login` is the loopback probe used by self-test criterion
6. Never logs the submitted number in the clear.

### gc_portal

Facade over the DNS redirect and the HTTP listener.
`gc_portal_normalize_number` turns a typed number into E.164.
`gc_portal_number_status` answers `INVALID`, `OK`, `BLOCKED` or `PENDING`, with
the remaining block time for `BLOCKED`.

### gc_app

Wires everything. Owns the phase machine, the 1 s tick order, the alarm flag,
and the bench hooks `gc_app_request_tunnel` and
`gc_app_trip_reserve_for_bench`. `gc_app_status` renders a 512-byte status
string for the console.

## Failure matrix

Each row: the fault, how it is detected, what the device does, and the
requirement that closes it.

| # | Failure | Detected by | Device behaviour | Req |
| --- | --- | --- | --- | --- |
| 1 | client not yet allowed | gate state `NEW` | forward only to UDP 53, the portal listener, and the four captive-probe host sets | 1.3 |
| 2 | client submits a number | `gc_gate_submit_number` | queue a verify request, keep the client at `PENDING`, do not forward | 1.2 |
| 3 | allow verdict arrives | `gc_ctrl_decode` -> `gc_gate_apply_verdict` | install allow-list entry with MAC, expiry and a fresh byte counter, begin forwarding | 1.4 |
| 4 | deny verdict, number has not contacted the bot | verdict `reason = not_verified` | record a strike, soft block the MAC for 24 h, answer the portal with the reason and the remaining time | 1.5, 3.1, 3.2 |
| 5 | third strike against a block key | controller marks permanent | permanent block, persisted across reboot, slot switch and a reflash of both OTA slots | 3.3, 3.4 |
| 6 | permanent block needs lifting | signed unblock command | clear only if the signature verifies and the sequence exceeds the last accepted one; persist the new sequence | 3.5, 3.6, 3.7 |
| 7 | unblock replayed | sequence <= last accepted | reject | 3.7 |
| 8 | phone randomises its Wi-Fi MAC | - | block on the number key, relay the MAC key as the secondary signal | 3.8 |
| 9 | client moves site | - | strike count aggregates in the controller, so the count does not reset | 3.9 |
| 10 | allow entry expires | `gc_gate_tick` | drop forwarded traffic, return the client to the portal | 1.9 |
| 11 | soft block expires | `gc_gate_tick` | remove the block, keep the strike count | 3.10 |
| 12 | station disconnects | Wi-Fi event | backoff 2 to 300 s with jitter; soft-AP and portal keep running and keep serving the notice | 4.2, 4.3 |
| 13 | station has no DHCP lease | `gc_netif_sta_has_ip` | not link up; retry | 4.1 |
| 14 | no internet path | `gc_link_monitor_tick` | step 1: retry Wi-Fi and MQTT with backoff | 5.1 |
| 15 | step 1 failed twice | `GC_LINK_FAULT_CONFIRM_COUNT` | step 2: re-resolve DNS and reconnect | 5.2 |
| 16 | step 2 failed | ladder | step 3: ask the B315 to reboot through its API, at most once every 6 h | 5.3 |
| 17 | step 3 failed or rate limited | ladder | step 4: power-cycle the modem through the relay, at most once every 24 h, with a cooldown | 5.4 |
| 18 | step 4 rate limited | ladder | step 5: keep the beacon running, send exactly one alarm per fault episode | 5.5 |
| 19 | B315 API does not answer | `gc_modem_api_reachable` | record as its own fault; do not reboot the modem for this alone | 5.6 |
| 20 | B315 API session error | poll return | discard the cached token, re-authenticate before the next poll | 6.2 |
| 21 | daily usage crosses 70 % | `gc_quota_tier` | batch every 2 h, drop non-essential events | 7.4 |
| 22 | daily usage crosses 90 % | `gc_quota_tier` | heartbeat every 6 h, alarms only | 7.5 |
| 23 | monthly reserve reached | `gc_quota_reserve_tripped` | pause client forwarding; telemetry and beacon continue | 7.6 |
| 24 | reboot | - | quota and strike counters restored from NVS | 7.7, 3.11 |
| 25 | reading has not moved | `gc_telemetry_deadband_passes` | suppress | 8.3 |
| 26 | broker unreachable | `gc_mqtt_connected` | mark the controller unreachable flag, keep the beacon running, escalate through the ladder | 5.1 |
| 27 | manifest fetch fails | `gc_ota_tick` | stay `IDLE`, retry at the check interval | 10.1 |
| 28 | version on the block list | `gc_ota_version_blocked` | skip | 10.1 |
| 29 | any preflight gate fails | `GC_OTA_PREFLIGHT` | do not download, stay `IDLE` | 10.2 |
| 30 | download interrupted | HTTPS error | resume with Range; the running slot is untouched | 10.4 |
| 31 | hash or signature mismatch | `GC_OTA_VERIFYING` | discard the image, block that version | 10.5 |
| 32 | read-back mismatch | `GC_OTA_VERIFYING` | discard the image, block that version | 10.6 |
| 33 | self-test criterion fails, or the deadline passes | `gc_selftest_tick` | mark invalid and reboot, block that version | 10.9 |
| 34 | all seven criteria pass | `gc_selftest_result` | `esp_ota_mark_app_valid_cancel_rollback` | 10.8 |
| 35 | both OTA slots invalid | bootloader | boot the factory rescue image | 10.10 |
| 36 | rescue image running | - | beacon and emergency path only, able to reflash the main slots | 10.11 |
| 37 | a registered health check fails | `gc_watchdog_all_checks_pass` | do not kick the watchdog; the hardware resets the chip | 11.1 |
| 38 | main loop freezes | watchdog timeout | hardware reset, `gc_watchdog_stall_count` preserved across the reset where NVS allows | 11.1 |
| 39 | GPIO0 wired into the relay circuit | `gc_pinmap_relay_allowed` | refused at claim time | 11.2 |
| 40 | relay asked to switch mains | - | out of scope by design; the relay switches the DC side only | 11.3 |
| 41 | allocation of Wi-Fi or lwIP buffers from PSRAM | sdkconfig | disabled by `CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP=n` | 11.4 |
| 42 | no pepper for a site | controller start | controller refuses to start | 2.8 |
| 43 | WhatsApp webhook with a bad signature | controller | discard, record no contact | 2.6 |
| 44 | contact mode, number typed but never contacted the bot | controller | deny; see the forgery caveat in [PRIVACY.md](PRIVACY.md) and [PROTOCOL.md](PROTOCOL.md) | 2.4 |
| 45 | challenge mode, no challenge code sent | controller | deny | 2.5 |
