# Bench

Destructive procedures. Run them on a bench unit with a serial console and a way
to cut DC power, never on a deployed site. Each row is one case: how to cause it,
what must happen, and the observation that proves it happened.

Terms are those of [GLOSSARY.md](GLOSSARY.md). The rows close REQUIREMENTS 10.4
to 10.11, 7.6, 11.1 and the key derivation contract in
[TEST_VECTORS.md](TEST_VECTORS.md). The failure each row exercises, and the
requirement that closes it, are in the failure matrix in
[ARCHITECTURE.md](ARCHITECTURE.md).

Record the status line before each case. Without a before, an after proves
nothing.

## Setup every row assumes

| Item | Where |
| --- | --- |
| bench build | `CONFIG_GC_BENCH_FAULTS=y`, menuconfig under `Ground Control` |
| console | `idf.py -p PORT monitor`. On the ESP32-S2 the native USB port disappears while the chip is in reset, so flash with the chip running |
| status line | `gc_app_status`: phase, uptime, clients, allowed, quota, tier, mqtt, sta, inet, tun, alarm, trial, watchdog kicks and stalls, fw, slot, boot |
| ota state | `gc_ota_state_name(gc_ota_state())`: `IDLE CHECKING PREFLIGHT DOWNLOADING VERIFYING TRIAL ROLLING_BACK FAILED` |
| progress | `gc_ota_downloaded_bytes`, `gc_selftest_elapsed_s`, `gc_quota_daily_used_kb` |
| forced manifest check | signed `manifest_check` command, or `gc_app_force_manifest_check()` |
| forced reserve trip | signed `trip_reserve` command, or `gc_app_trip_reserve_for_bench()` |
| log | `gc_log_ring_dump`; the `ota` tag names the reason on every discard |

A command reaches the device only over MQTT, signed, and one whose sequence is
less than or equal to the last accepted one is dropped (3.7). Bump the sequence
on every repeat or the bench case silently does not run.

## Matrix

| # | Case | Procedure | Expected outcome | How to tell it happened |
| --- | --- | --- | --- | --- |
| 1 | Power cut during download | Force a manifest check, wait for `DOWNLOADING` with downloaded bytes past 65536, cut DC, restore | The running slot boots, no slot change, the download resumes by Range from the persisted partial (10.4) | `slot=` and `fw=` unchanged in the status line; state returns to `DOWNLOADING` and downloaded bytes restart at or above the last 64 KiB persist boundary (NVS `otapartv`, `otapartr`, `otaparts`); the `ota` log shows a Range resume; the version is not on the block list |
| 2 | Power cut during verification | Wait for `VERIFYING`, cut DC during the read-back, restore | The running slot boots, nothing is committed, verification restarts at the digest step or the download restarts, and the version is not blocked: a power cut is not an image fault | `slot=` and `fw=` unchanged; state is `VERIFYING` or `DOWNLOADING`; `gc_ota_version_blocked(v)` false; `trial=0` |
| 3 | Power cut during the slot switch | Watch for the commit step after the read-back passes, cut DC in that window, restore | One of the two slots boots and the two are never both invalid. If the new one boots it is a trial boot; if the old one boots, verification repeats (10.7) | `slot=` either flips to the other ota partition or stays. If flipped: `phase=TRIAL_BOOT trial=1` and the self-test runs. If not: state `VERIFYING` or `DOWNLOADING`. Both invalid is row 8's entry condition, and a power cut here must not be how you reach it |
| 4 | Power cut during trial boot | After the trial boots (`trial=1`), cut DC before the self-test passes | The rollback stays armed, the self-test restarts against a fresh deadline; if the deadline already elapsed, roll back and block that version (10.9) | `trial=1` with `gc_selftest_elapsed_s()` restarting near zero, or slot and fw back to the previous version with `gc_ota_last_failure_version()` equal to the new version and `gc_ota_version_blocked(new)` true |
| 5 | Flipped byte in the image, rejected before the slot changes | Serve an image with one byte flipped after signing, or flip a byte in the manifest SHA-256; force a manifest check; let the download finish | Download completes, verification fails, the image is discarded, the version is blocked, the running slot is untouched, and the device does not boot the new image (10.5, 10.6) | State goes `VERIFYING` to `FAILED` to `IDLE`, the `ota` log naming the step: digest or signature mismatch for a byte flipped on the wire, read-back mismatch for a byte wrong in flash. `slot=`, `fw=` and `trial=0` unchanged; `gc_ota_version_blocked(v)` true; the next manifest check skips that version |
| 6 | Forced self-test failure rolls back and blocks the version | Bench build that fails one criterion: drop the uplink for `CONTROLLER_REACHABLE` or `HEARTBEAT_ACKED`, or deauth the station for `STA_IP`; boot the new slot into a trial | Rollback and reboot into the previous slot, version blocked, failure recorded so preflight refuses that version for the block-backoff period of 86400 s (10.9, 10.2) | `ota` log `trial self-test failed on <criterion>`; slot and fw back to the previous version; `gc_selftest_failed_criterion()` names it; `gc_ota_version_blocked(v)` true; a `manifest_check` for that version produces no download |
| 7 | Uplink blocked during the trial, rollback after the deadline | Start a trial boot, then immediately block the uplink at the B315: change the station SSID or blackhole the default route | Criteria 4 and 5 can never pass; at `GC_SELFTEST_DEADLINE_S` the device rolls back and blocks the version; the soft-AP and portal stay up throughout (10.9, 4.3) | `gc_selftest_elapsed_s()` climbs to the deadline with `trial=1`, then slot and fw flip back; the log names `CONTROLLER_REACHABLE` or `HEARTBEAT_ACKED`. If the self-test never starts at all, rollback comes at the 120 s trial-start timeout with `trial self-test never started` |
| 8 | Rescue image boots, reaches the emergency path, reflashes the main slots | Build with `CONFIG_GC_RESCUE_IMAGE=y`, flash it, invalidate both ota slots, power cycle | The factory slot boots with no portal, the beacon runs, a valid tunnel request in a beacon reply brings up WireGuard, and over that path the main slots are reflashed (10.10, 10.11, 9.3) | `gc_ota_running_slot()` is `GC_SLOT_FACTORY`; nothing listens on 80 or 53 on the soft-AP; 16-byte datagrams with a monotonic counter reach the beacon port every 900 s, or 120 s while an alarm is active; after a tunnel request `gc_emergency_tunnel_is_up()` is true and the console answers only on the tunnel interface; after the reflash slot is an ota partition and fw is the expected version; permanent blocks and strike counts survived |
| 9 | Crash loop in the new image rolls back | Bench build that panics early in a trial, repeatedly, never reaching `gc_ota_mark_valid` | The device ends up running the previous good slot and the crashing version is blocked (10.9) | Slot and fw are the previous version and the crash stops repeating. Cover both paths separately: a crash late enough to call `gc_ota_mark_app_invalid_rollback_and_reboot`, and one before that, where only the bootloader's own rollback can recover. If the early crash does not recover, the trial design rests on the late path and the deadline must be shorter than the bootloader's patience |
| 10 | Freeze the device, hardware watchdog recovers it | Bench build that spins in the main loop, or hold one registered check failing; scope GPIO5 | The kick pulse stops, the external watchdog asserts reset once its own timeout passes, and the device boots normally (11.1) | The 50 us pulse train on GPIO5 stops; `gc_watchdog_status` shows `failing=<check>` with the age climbing; the log carries `check <name> failing for <n>ms beyond 30000ms`; reset follows within the external watchdog's own timeout; after reboot kicks restart from zero and stalls are non-zero where NVS preserved them. A single failing check must withhold the kick without resetting before the hardware timer expires |
| 11 | Reserve trip: forwarding pauses, telemetry and the beacon continue | Send the signed `trip_reserve` command, or call `gc_app_trip_reserve_for_bench()` | Client forwarding pauses while telemetry and the beacon keep running and the device stays reachable (7.6) | Status line shows `tier=RESERVE`; allowed clients get no traffic off the soft-AP while the portal still answers; MQTT frames keep arriving at the broker and beacon datagrams keep arriving at the VPS; the `bench_reserve_trip` event is published; quota counters still advance. The reserve is monthly, so confirm it survives `gc_quota_force_rollover` |
| 12 | Number-key derivation matches the vectors | Bench build: `gc_crypto_number_key` with the vector pepper (32 bytes of `0x11`) and `+27821234567`, print the 8 bytes lowercase hex; repeat with `27 82 123 4567`, `27821234567`, `+27-82-123-4567`. Then `gc_crypto_mac_key` for `aa:bb:cc:dd:ee:ff` and `gc_crypto_beacon_mac` for payload `1100010200000007` under the vector PSK (32 bytes of `0x22`). Controller: `node tools/keycheck.mjs` | `cdbdd22167e29534`, `c60f22d908a65bea`, `bc296784e9518e5e`; both halves agree; every spelling of the number yields the same key | Printed hex equals the table in [TEST_VECTORS.md](TEST_VECTORS.md); `node tools/keycheck.mjs` prints `ok` for all six cases and exits 0. Then end to end: a number that has contacted the bot gets an allow verdict. A disagreement shows up only as `not_verified` and a 24 h soft block, with no error anywhere |

### Two notes on row 10

`GC_WATCHDOG_TIMEOUT_MS` (30000) is the software side: it decides when to stop
kicking and when to log. The reset is performed by the external watchdog chip fed
from GPIO5. Measure both: the point at which the software withholds the kick, and
the latency from that point to the hardware reset.

### One note on row 8

The rescue image is the last resort, not a recovery step. If a bench case reaches
it unexpectedly, the case failed and the reason is a bug in the slot bookkeeping,
not a property of the rescue image.

## Reset between cases

- Restore power and wait for `phase=ONLINE` before the next case.
- Re-provision secrets if a case wiped NVS.
- Clear the version block list (NVS `blkver`) before reusing a version, or bump
  the manifest version.
- Bump the command sequence. A replayed command is dropped by design (3.7).

## Numbers to measure in the field before trusting them

The matrix proves the recovery paths. It says nothing about whether the
thresholds that drive them are right. Every value below is an assumption in
Kconfig or in a frame layout. Measure each one on the real hardware and the real
carrier before relying on it, and fill the Measured column as you go: a blank is
an assumption, not a result.

The full assumption list, 38 rows, is in `README.md` under "Numbers to measure
before you trust them". The seven below are the ones a bench run cannot do
without.

| # | Number | Assumed | How to measure | What it sets | Measured |
| --- | --- | --- | --- | --- | --- |
| 1 | Real bytes per day with no clients | dominated by beacon, telemetry, MQTT TLS handshakes and keepalives, DNS, NTP, modem polls | Idle the unit for 7 days; read `gc_quota_daily_used_kb` and compare against the carrier's own figure | The floor under `GC_MONTHLY_RESERVE_KB`. The reserve must exceed this or the device eventually stops its own telemetry and beacon | |
| 2 | Real bytes per day with clients | row 1 plus per-client overhead: portal, DHCP, NAT, retries | A week at the expected client count; divide by client-days | `GC_DAILY_BUDGET_KB` and the tier thresholds at 70 and 90 percent. Wrong here and the governor throttles a healthy day or lets a bad one run dry | |
| 3 | Carrier NAT timeout | the carrier drops an idle flow eventually | Open a flow, idle it, raise the idle in steps until it dies; do it for TCP and for UDP | `GC_MQTT_KEEPALIVE_S` (300). Keepalive must be below the timeout, or the broker link dies silently and the escalation ladder climbs for nothing | |
| 4 | NAT throughput under load | the ESP32-S2 NAT is not the bottleneck | iperf3 through the soft-AP at 1, 8 and 24 clients, TCP and UDP, both directions; watch heap and PSRAM while you do | `GC_CLIENT_RATE_KBYTE_S` (128 KiB/s) and `GC_MAX_CLIENTS` (24). Set both below the measured ceiling, not at it | |
| 5 | B315 API latency and session-token lifetime | the API answers and the token outlives the poll interval | Log `gc_modem_api_last_latency_ms` for a week and take p99; then raise the poll interval until a session error appears | The API timeout, above p99, and `GC_MODEM_POLL_S` (300), which must sit inside the token lifetime or every poll pays a re-authentication (6.2, 6.3) | |
| 6 | Self-test duration | the seven criteria finish well inside the deadline | Time each criterion on the worst site; sum the worst cases, not the typical ones | `GC_SELFTEST_DEADLINE_S` (300). Too tight rolls back a healthy image; too loose keeps a broken one up for the whole deadline | |
| 7 | Flash and PSRAM of the real build | the image fits its slot and 24 clients fit in PSRAM | `idf.py size` and `idf.py size-files` against `partitions.csv` (factory `0x100000`, `ota_0` and `ota_1` `0x170000`; CI fails when the image does not fit); `heap_caps_get_free_size(MALLOC_CAP_SPIRAM)` at boot and again at 24 clients | Whether the image fits at all, and how many clients fit. Wi-Fi and lwIP buffers come from internal RAM; the portal sessions, client list, delta buffer and log ring from PSRAM (11.4) | |
