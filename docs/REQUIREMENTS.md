# Requirements (EARS)

Every requirement below is written so it can be checked. `SHALL` is mandatory,
`SHALL NOT` is a prohibition, `MAY` is a permitted option. Each row carries the
verification that closes it: `B` bench procedure in `docs/BENCH.md`, `S` self-test
on device, `C` CI job, `R` code review against this file.

Terms: **device** is the ESP32-S2FN4R2 node. **controller** is the central
control service. **client** is a station associated to the device soft-AP.
**number** is the phone number a client reports in the portal. **contact** means
that number sent a message to the configured WhatsApp bot.

## 1 Access

1.1 Ubiquitous: the device SHALL run a soft-AP whose SSID and passphrase come
from provisioned configuration.

1.2 Event-driven: on receiving an HTTP POST of a phone number from a client that
is not yet allowed, the device SHALL forward a verification request to the
controller over MQTT and SHALL NOT grant forwarding before an allow verdict
arrives.

1.3 State-driven: while a client is not allowed, the device SHALL forward from
that client only to UDP port 53, to the portal HTTP listener, and to the
captive-portal detection hosts of Apple, Google, Windows and Android.

1.4 Event-driven: on receiving an allow verdict for a client and number, the
device SHALL install an allow-list entry carrying the client MAC, the verdict
expiry and a fresh byte counter, and SHALL begin forwarding.

1.5 Event-driven: on receiving a deny verdict, the device SHALL record a strike
against the client and SHALL answer the portal with the block reason and the
time until the block lifts.

1.6 Unwanted: the device SHALL NOT inspect, buffer or log packet payloads.

1.7 Unwanted: the device SHALL NOT log destination addresses, hostnames, URLs or
per-client browse history.

1.8 Ubiquitous: the portal SHALL display the usage notice on first connection,
before the phone-number field is shown, and the client SHALL NOT be allowed
before the notice has been served at least once to that client.

1.9 State-driven: while an allow-list entry is past its expiry, the device SHALL
drop that client's forwarded traffic and SHALL return that client to the portal.

1.10 Ubiquitous: the device SHALL rate limit each allowed client independently.

## 2 Verification authority

2.1 Ubiquitous: the device SHALL NOT decide verification itself; the controller
is the sole authority for allow, deny, strike count and unblock.

2.2 Ubiquitous: the controller SHALL answer a verification request with `allow`
and an expiry, or `deny` and a reason, within the portal's request timeout.

2.3 Event-driven: on receiving a message addressed to the configured WhatsApp
bot, the controller SHALL record the sender's last-contact time.

2.4 State-driven: in `contact` mode, while a number's last-contact time is inside
the configured window, the controller SHALL answer `allow` for that number.

2.5 State-driven: in `challenge` mode, the controller SHALL answer `allow` only
when the number has sent the challenge code the controller issued for that
request inside the challenge window.

2.6 Event-driven: on receiving a WhatsApp webhook whose signature does not
verify, the controller SHALL discard it and SHALL NOT record a contact.

2.7 Ubiquitous: the controller SHALL store a phone number only as
`HMAC-SHA256(pepper, number)` truncated to 8 bytes.

2.8 State-driven: while no pepper is configured for a site, the controller SHALL
refuse to start.

## 3 Blocks

3.1 Event-driven: on a deny caused by the number not having contacted the bot,
the device SHALL soft block the client MAC for 24 hours.

3.2 State-driven: while a client MAC is soft blocked, the device SHALL drop its
forwarded traffic and SHALL answer the portal with the remaining block time.

3.3 Event-driven: on the third strike recorded against a block key, the
controller SHALL mark that block key permanently blocked.

3.4 Ubiquitous: a permanent block SHALL persist across device reboot, across an
OTA slot switch and across a reflash of both OTA slots.

3.5 Unwanted: the device SHALL NOT clear a permanent block except on a signed
unblock command from the controller.

3.6 Event-driven: on receiving an unblock command whose signature verifies and
whose sequence number exceeds the last accepted sequence, the device SHALL clear
the block and SHALL persist the new sequence.

3.7 Unwanted: the device SHALL NOT accept an unblock command whose sequence
number is less than or equal to the last accepted one.

3.8 Ubiquitous: the authoritative block key SHALL be the number HMAC; the device
SHALL also record and relay the hashed MAC as the secondary signal.

3.9 Ubiquitous: strike counting SHALL aggregate across all three sites in the
controller, so a client moving between sites does not reset the count.

3.10 Event-driven: on a soft block expiring, the device SHALL remove the block
and SHALL keep the strike count.

3.11 Ubiquitous: strike counters SHALL be persisted in NVS and SHALL be mirrored
to the controller so a replacement device inherits the count.

## 4 Uplink

4.1 Ubiquitous: the device SHALL connect its station interface to the configured
B315 SSID and SHALL wait for a DHCP lease before declaring the link up.

4.2 Event-driven: on station disconnect, the device SHALL reconnect with
exponential backoff capped at 300 s with jitter.

4.3 State-driven: while the station link is down, the device SHALL keep the
soft-AP and the portal running and SHALL keep serving the usage notice.

4.4 Unwanted: the device SHALL NOT open a listening socket on the station
interface.

## 5 Escalation

5.1 Event-driven: on detecting no internet path, the device SHALL retry Wi-Fi and
MQTT with backoff.

5.2 Event-driven: when step 5.1 has failed twice, the device SHALL re-resolve DNS
and reconnect.

5.3 Event-driven: when 5.2 has failed, the device SHALL ask the B315 to reboot
through its API, at most once every 6 hours.

5.4 Event-driven: when 5.3 has failed or has been rate limited, the device SHALL
power-cycle the modem through the relay, at most once every 24 hours, with a
cooldown after the cycle.

5.5 Event-driven: when 5.4 has been rate limited, the device SHALL keep the
beacon running and SHALL send exactly one alarm per fault episode.

5.6 Unwanted: the device SHALL NOT reboot the modem because the modem API did not
answer; an unanswered API SHALL be recorded as its own fault.

## 6 Modem

6.1 Ubiquitous: the device SHALL poll the B315 LAN API for RSRP, RSRQ, SINR and
connection state.

6.2 Event-driven: on a poll answering with a session error, the device SHALL
discard the cached session token and SHALL re-authenticate before the next poll.

6.3 Ubiquitous: the device SHALL cache the session token and SHALL renew it
before expiry.

## 7 Quota

7.1 Ubiquitous: the device SHALL count bytes on the station interface in both
directions and per allowed client.

7.2 Event-driven: on the daily rollover, the device SHALL reset the daily counter
and SHALL persist the totals.

7.3 State-driven: while daily usage is below 70 percent of the budget, the device
SHALL batch telemetry hourly and SHALL use the normal MQTT keepalive.

7.4 State-driven: while daily usage is from 70 to 90 percent, the device SHALL
batch every 2 hours and SHALL drop non-essential events.

7.5 State-driven: while daily usage is from 90 to 100 percent, the device SHALL
send a heartbeat every 6 hours and SHALL send alarms only.

7.6 Event-driven: on the monthly reserve being reached, the device SHALL pause
client forwarding and SHALL keep telemetry and the beacon running.

7.7 Ubiquitous: quota counters SHALL survive reboot.

## 8 Telemetry

8.1 Ubiquitous: the device SHALL encode telemetry in the frame layout given in
`docs/PROTOCOL.md`.

8.2 Ubiquitous: the device SHALL publish routine telemetry at MQTT QoS 0 and
alarms at QoS 1.

8.3 Ubiquitous: the device SHALL suppress a reading that has not moved beyond its
deadband since the last reading sent.

8.4 Ubiquitous: the device SHALL include site id and device id in every frame and
in every MQTT topic.

## 9 Emergency

9.1 Ubiquitous: the device SHALL send a 16-byte UDP beacon carrying a monotonic
counter and an 8-byte truncated HMAC under the provisioned pre-shared key.

9.2 Unwanted: the beacon SHALL NOT require a handshake and SHALL NOT carry the
pre-shared key.

9.3 Event-driven: on a beacon reply carrying a valid tunnel request, the device
SHALL bring up WireGuard.

9.4 Ubiquitous: WireGuard SHALL be configured with persistent keepalive 0.

9.5 State-driven: while the tunnel is up, the device SHALL expose the console and
the B315 admin proxy only on the tunnel interface.

## 10 Update

10.1 Event-driven: on the manifest check interval, the device SHALL fetch the
signed manifest and SHALL skip versions on its blocked list.

10.2 State-driven: before downloading, the device SHALL require supply voltage or
battery above threshold, free heap above threshold, a free slot of adequate size,
modem signal above threshold, the configured time window, no active alarm, and no
failure of this version inside the block-backoff period.

10.3 Ubiquitous: the device SHALL download to the inactive slot over HTTPS with
Range resume and SHALL hash each chunk as it arrives.

10.4 Event-driven: on a download interruption, the device SHALL resume with Range
and SHALL leave the running slot untouched.

10.5 Event-driven: on a full-image hash or signature mismatch, the device SHALL
discard the image and SHALL block that version.

10.6 Ubiquitous: after writing, the device SHALL read back the written partition
and SHALL compare it against the expected hash.

10.7 Event-driven: on entering a trial boot, the device SHALL run the self-test
and SHALL finish it inside the configured deadline.

10.8 Event-driven: on every self-test criterion passing, the device SHALL call
`esp_ota_mark_app_valid_cancel_rollback`.

10.9 Event-driven: on any self-test criterion failing or on the deadline passing,
the device SHALL call `esp_ota_mark_app_invalid_rollback_and_reboot` and SHALL
block that version.

10.10 State-driven: while both OTA slots are invalid, the bootloader SHALL boot
the factory rescue image.

10.11 Ubiquitous: the rescue image SHALL bring up the beacon and the emergency
path and SHALL be able to reflash the main slots.

## 11 Health

11.1 Ubiquitous: the device SHALL kick the hardware watchdog from the main loop
only after every registered health check has passed.

11.2 Ubiquitous: GPIO0 SHALL NOT be part of the relay circuit.

11.3 Ubiquitous: the relay SHALL switch the DC side only.

11.4 Ubiquitous: Wi-Fi and lwIP buffers SHALL be allocated from internal RAM; the
portal session table, the client list, the delta apply buffer and the log buffer
SHALL be allocated from PSRAM.

## 12 Multi-site

12.1 Ubiquitous: every device SHALL carry a site id in NVS.

12.2 Ubiquitous: quota, portal notice text and pepper SHALL be configurable per
site.

12.3 Ubiquitous: one firmware image SHALL serve all three sites, with
provisioning supplying the site id.

## 13 Secrets

13.1 Unwanted: the repository SHALL NOT contain a private key, a pre-shared key,
a broker password, a pepper or a WireGuard private key.

13.2 Ubiquitous: CI SHALL fail on a file that looks like a real secret.

13.3 Ubiquitous: the provisioning tool SHALL write secrets to NVS from a file
outside the repository.
