# Protocol

Wire format between the **device** and the **controller**, plus the **beacon**
between the device and the emergency receiver. Terms are the ones in
`docs/GLOSSARY.md`. `docs/TEST_VECTORS.md` is authoritative for every key and
tag derivation; nothing here overrides it.

Conventions used below:

- Little-endian means least significant byte first. Big-endian means most
  significant byte first. Both appear; each field names its own order.
- All hex is lowercase on the wire. Hex readers accept either case.
- `u32` is 4 bytes, `u16` is 2 bytes, `i8` is one two's-complement byte.
- "key" always means an 8-byte truncated HMAC (`GC_KEY_LEN` 8), written as 16
  hex characters.

## 1 MQTT topic layout

Built by `gc_ctrl_topic_build` (device, `main/gc_ctrl_proto.c`) and
`buildTopic` (controller, `controller/src/broker.ts`). Both produce:

```
gc/v1/<site_id>/<device_id>/<up|dn>/<channel>
```

`<site_id>` and `<device_id>` are decimal, no padding, range 0..65535.
`up` is device to controller, `dn` is controller to device.

| Direction | Channel | Carries | QoS | Codec |
| --- | --- | --- | --- | --- |
| up | `tele` | binary telemetry frame | 0 routine, 1 alarm | `gc_telemetry_encode` / `gc_telemetry_encode_heartbeat`; decoded by `decodeTelemetry` |
| up | `event` | JSON event | 0 | `gc_ctrl_encode_event` |
| up | `verify` | JSON verification request | 1 | `gc_ctrl_encode_verify_request` |
| up | `hello` | JSON hello | 1 | `gc_ctrl_encode_hello` |
| up | `ota` | reserved; topic is built by `gc_ctrl_topics_for_identity` but nothing publishes it yet | - | none |
| dn | `verdict` | JSON verdict | subscribed at 1 | `gc_ctrl_decode_verdict` |
| dn | `unblock` | JSON unblock | subscribed at 1 | `gc_ctrl_decode_unblock` |
| dn | `ack` | JSON ack | subscribed at 1 | `gc_ctrl_decode_ack` |
| dn | `cmd` | JSON command | subscribed at 1 | `gc_ctrl_decode_command` |

The device subscribes to its own four `dn` topics individually
(`gc_app_start`). The controller subscribes `gc/v1/+/+/up/+`
(`UPLINK_FILTER`) and publishes `gc/v1/<site>/<device>/dn/<channel>`
(`downlinkTopic`). Both sides reject any topic that is not exactly six
segments.

`GC_TOPIC_MAX` is 160 bytes. The longest real topic,
`gc/v1/65535/65535/dn/verdict`, is 28 bytes.

Control payloads are bounded by `GC_APP_CTRL_PAYLOAD_MAX` (512) on the device
and by `GC_MQTT_RX_STACK_MAX` (1024) before the MQTT layer heap-allocates.

## 2 Telemetry frame

One **frame** carries `record_count` **readings**. Encoded by
`gc_telemetry_encode` (batched) and `gc_telemetry_encode_heartbeat` (one
accumulated record). Multi-byte header fields are little-endian. Records start
at offset 13. Maximum frame size `GC_TELEMETRY_FRAME_MAX` = 320 bytes, maximum
records `GC_TELEMETRY_MAX_RECORDS` = 24.

### 2.1 Header, 13 bytes

| Offset | Size | Field | Type | Notes |
| --- | --- | --- | --- | --- |
| 0 | 1 | `version` | u8 | 1 (`GC_FRAME_VERSION`) |
| 1 | 1 | `flags` | u8 | see 2.2 |
| 2 | 2 | `site_id` | u16 LE | |
| 4 | 2 | `device_id` | u16 LE | |
| 6 | 2 | `boot_id` | u16 LE | increments per boot, wraps at 65535 |
| 8 | 2 | `seq` | u16 LE | increments per frame published (telemetry, event, verify, hello share it), wraps |
| 10 | 1 | `record_count` | u8 | 0..24 |
| 11 | 1 | `fw_version` | u8 | from configuration |
| 12 | 1 | `slot` | u8 | 0 unknown, 1 factory, 2 ota_0, 3 ota_1 (`gc_slot_t`) |

There is no magic byte, no length field and no checksum. The varints and
`record_count` define the frame length.

### 2.2 Flags, one byte

| Bit | Value | Name | Meaning |
| --- | --- | --- | --- |
| 0 | 0x01 | `GC_TELEMETRY_FLAG_ALARM` | an alarm is active |
| 1 | 0x02 | `GC_TELEMETRY_FLAG_RESERVE_TRIPPED` | monthly reserve reached, forwarding paused |
| 2 | 0x04 | `GC_TELEMETRY_FLAG_FORWARDING_PAUSED` | client forwarding paused |
| 3 | 0x08 | `GC_TELEMETRY_FLAG_TUNNEL_UP` | WireGuard tunnel is up |
| 4 | 0x10 | `GC_TELEMETRY_FLAG_TRIAL_PENDING` | trial boot not yet confirmed |
| 5 | 0x20 | `GC_TELEMETRY_FLAG_CONTROLLER_UNREACHABLE` | MQTT has not been answered recently |

Bits 6 and 7 are unused and read as zero.

### 2.3 Record, `record_count` times

| Order | Field | Type | Notes |
| --- | --- | --- | --- |
| 1 | `uptime_delta_s` | varint | seconds since the previous reading |
| 2 | `rssi` | i8 | dBm |
| 3 | `clients` | u8 | associated station count |
| 4 | `rsrp` | i8 | dBm |
| 5 | `rsrq` | i8 | dB |
| 6 | `sinr` | i8 | dB |
| 7 | `quota_delta_kb` | varint | KiB consumed since the previous reading |

Varints are unsigned LEB128: 7 bits per byte, low group first, bit 7 set on
every byte except the last. Value 0 encodes as one `0x00` byte. Maximum 10
bytes (`GC_TELEMETRY_VARINT_MAX_LEN`).

A record is 6 bytes minimum (1 + 4 + 1) and 24 bytes maximum (10 + 4 + 10).
With typical two-byte varints a record is 8 bytes, so 24 records plus the
header is 205 bytes, inside the 320 byte cap. A batch whose total exceeds the
cap is refused whole by `gc_telemetry_encode` (`GC_ERR_NO_MEM`) and retried on
the next tick; it is never truncated.

Deltas are per reading, not per frame: each reading carries the change since
the previous reading was taken. A reading is pushed only when it moves beyond a
deadband since the last reading sent, or when `quota_delta_kb` is non-zero
(`gc_telemetry_push`, REQUIREMENTS 8.3). Deadbands: RSSI 3 dBm, RSRP 3 dBm,
RSRQ 1 dB, SINR 2 dB, clients 1.

### 2.4 Worked frame

site 1, device 1, boot 3, seq 42, flags 0x09 (ALARM | TUNNEL_UP), fw 1,
slot 2 (ota_0), two readings:
(uptime 900, rssi -67, clients 3, rsrp -104, rsrq -12, sinr 9, quota 512) and
(uptime 900, rssi -70, clients 3, rsrp -106, rsrq -12, sinr 7, quota 640).

```
01 09 0100 0100 0300 2a00 02 01 02    header, 13 bytes
84 07 bd 03 98 f4 09 80 04            reading 0, 9 bytes
84 07 ba 03 96 f4 07 80 05            reading 1, 9 bytes
```

One line, 31 bytes:

```
01090100010003002a000201028407bd0398f40980048407ba0396f4078005
```

Field check of reading 0: `84 07` is varint 900; `bd` is -67; `03` is 3
clients; `98` is -104; `f4` is -12; `09` is 9; `80 04` is varint 512.

## 3 Beacon

`GC_BEACON_LEN` is 16. `GC_BEACON_PAYLOAD_LEN` is 8: bytes 0..7 are the
payload, bytes 8..15 are the tag. The beacon is **one UDP datagram, sent with
no handshake, no session and no reply requirement**. The pre-shared key is
never transmitted (REQUIREMENTS 9.1, 9.2). All multi-byte fields are
big-endian.

| Offset | Size | Field | Notes |
| --- | --- | --- | --- |
| 0 | 1 | `version` and `kind` | `(GC_BEACON_VERSION << 4) \| kind`, version 1, kind 1 routine (`GC_BEACON_KIND_ROUTINE`) or 2 alarm (`GC_BEACON_KIND_ALARM`) |
| 1 | 2 | `site_id` | u16 big-endian |
| 3 | 1 | device index | low byte of `device_id` |
| 4 | 4 | `counter` | u32 big-endian, monotonic, persisted in NVS |
| 8 | 8 | tag | first 8 bytes of `HMAC-SHA256(psk, "beacon" \|\| bytes 0..7)` |

Cadence: every `GC_BEACON_INTERVAL_S` (900) routinely, every
`GC_BEACON_INTERVAL_ALARM_S` (120) while an alarm is active; three send
attempts per due beacon. The counter advances by one per successful send and
saturates at `UINT32_MAX`; it is loaded and stored by
`gc_crypto_beacon_counter_load` / `_store`.

### 3.1 Worked beacon

site 1, device 2, counter 7, routine, pre-shared key 32 bytes of `0x22`
(the key used by `docs/TEST_VECTORS.md`):

```
payload  11 00 01 02 00 00 00 07
tag      bc 29 67 84 e9 51 8e 5e
frame    1100010200000007bc296784e9518e5e
```

Byte 0 is `0x11`: version 1, kind 1. The tag is the third test vector.

### 3.2 Replay and reply

The receiver drops a beacon whose counter is not strictly greater than the last
counter seen for that site and device (`controller/src/beaconRx.ts`), and
persists what it accepted. There is no wrap window to consider: the wire
carries the full u32, which takes 136 years to wrap at 900 s.

A controller reply is also 16 bytes with the same layout. Its byte 0 is
`(version << 4) | 0x08`, where `0x08` is the tunnel request flag in the kind
nibble, and it carries the counter the device just sent. The device accepts a
reply only when it is 16 bytes, its version matches, it comes from the peer the
beacon went to, its tag verifies, and its counter exceeds the last accepted
reply counter (`gc_emergency_poll_reply`). A valid reply with the tunnel flag
brings the tunnel up (REQUIREMENTS 9.3). Default beacon port is UDP 41234
(`GC_BEACON_PORT`); the port in the field comes from device configuration.

## 4 JSON messages

Every message is a single compact JSON object: no insignificant whitespace,
UTF-8, keys in the order shown. Key names are short and fixed. Every object
carries `v`, the protocol version, currently 1.

Two rules hold for all four `dn` messages, because that is what
`gc_ctrl_decode` does:

- A key that is absent reads as 0, `false` or the empty string. Only the keys
  marked required below can cause a reject.
- `req`, `num`, `mac` and `sig` must be exactly 16 hex characters or the
  message is rejected. Upper or lower case hex is accepted.

`v` is not checked by the decoder; senders still send it.

### 4.1 verify (up, `gc_ctrl_encode_verify_request`)

| Field | Type | Notes |
| --- | --- | --- |
| `v` | number | 1 |
| `req` | 16 hex | request id (`GC_REQ_ID_LEN` 8), echoed by the verdict |
| `num` | 16 hex | number key |
| `mac` | 16 hex | mac key, secondary signal |
| `mode` | string | `contact` or `challenge` |
| `ts` | number | device unix seconds at encode time |

```json
{"v":1,"req":"9f2c1a04b7e6d5c8","num":"cdbdd22167e29534","mac":"c60f22d908a65bea","mode":"contact","ts":1760000000}
```

The device sends keys only; the number and the client MAC are never sent in the
clear (REQUIREMENTS 1.6, 2.7). The number key above is the test-vector key for
`+27821234567`; the mac key is the one for `aa:bb:cc:dd:ee:ff`.

### 4.2 event (up, `gc_ctrl_encode_event`)

| Field | Type | Notes |
| --- | --- | --- |
| `v` | number | 1 |
| `ev` | string | event name |
| `num` | 16 hex | number key, or all-zero when the event is not client-scoped |
| `mac` | 16 hex | mac key, or all-zero |
| `strikes` | number | strike count the device holds for that key |
| `detail` | string | free text, empty when unused |

```json
{"v":1,"ev":"verdict_deny","num":"cdbdd22167e29534","mac":"c60f22d908a65bea","strikes":1,"detail":"not_verified"}
```

Events are suppressed entirely while the quota tier is `heartbeat`
(REQUIREMENTS 7.5). The controller's strike count is authoritative, not the
device's (REQUIREMENTS 2.1, 3.9).

### 4.3 hello (up, `gc_ctrl_encode_hello`)

| Field | Type | Notes |
| --- | --- | --- |
| `v` | number | 1 |
| `fw` | number | firmware version |
| `slot` | string | `factory`, `ota_0` or `ota_1` |
| `trial` | bool | trial boot not yet confirmed |
| `notice` | bool | usage notice not yet served to a pending client |

```json
{"v":1,"fw":3,"slot":"ota_0","trial":false,"notice":false}
```

Sent on every MQTT start and restart, which makes it the connect announcement.

### 4.4 verdict (dn, `gc_ctrl_decode_verdict`)

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `req` | 16 hex | yes | must match a pending request, else the verdict is dropped |
| `allow` | bool | no | |
| `until` | number | no | unix seconds the allow expires; 0 when `allow` is false |
| `blocked_until` | number | no | unix seconds a soft block lifts |
| `strikes` | number | no | strike count after this verdict |
| `permanent` | bool | no | installs a permanent block |
| `reason` | string | no | see below |
| `hint` | string | no | challenge mode text for the portal, truncated to `GC_VERDICT_REASON_MAX` 32 |

```json
{"v":1,"req":"9f2c1a04b7e6d5c8","allow":true,"until":1760086400,"blocked_until":0,"strikes":0,"permanent":false,"reason":"none","hint":""}
```

Note the field is `until`, not `allowed_until`.

`reason` is one of `none`, `pending`, `not_verified`, `strike_limit`,
`controller_unreachable`, `quota_reserve`, `expired` (`gc_deny_reason_t`).
Any other spelling reads as `none`. Forwarding is granted only on `allow`
(REQUIREMENTS 1.4). A deny with `blocked_until` in the future installs a soft
block; `permanent` installs a permanent block.

### 4.5 unblock (dn, `gc_ctrl_decode_unblock`)

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `num` | 16 hex | yes | block key to clear |
| `mac` | 16 hex | yes | mac key, secondary signal |
| `sig` | 16 hex | yes | signature, 8 bytes, see section 5 |
| `seq` | number | no | must exceed the last accepted sequence |
| `clear_strikes` | bool | no | also reset the strike counter |

```json
{"v":1,"num":"cdbdd22167e29534","mac":"c60f22d908a65bea","sig":"5c2a1f9b0d4e7a63","seq":91,"clear_strikes":true}
```

A permanent block is cleared only by an unblock command (REQUIREMENTS 3.5).

### 4.6 ack (dn, `gc_ctrl_decode_ack`)

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `seq` | number | no | sequence |
| `time` | number | no | controller unix seconds |

```json
{"v":1,"seq":91,"time":1760000000}
```

Any ack that decodes clears the device's controller-unreachable state and marks
the heartbeat self-test criterion as met; there is no separate boolean to send.

### 4.7 cmd (dn, `gc_ctrl_decode_command`)

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `cmd` | string | yes | command name, non-empty, truncated to `GC_CMD_NAME_MAX` 24 |
| `sig` | 16 hex | yes | signature, 8 bytes, see section 5 |
| `seq` | number | no | must exceed the last accepted sequence |
| `arg` | number | no | u32 numeric argument |
| `flag` | bool | no | boolean argument |

```json
{"v":1,"cmd":"manifest_check","sig":"0a22e23d34b45173","seq":92,"arg":0,"flag":false}
```

The signature above is the real tag for this body under the test-vector key,
computed in section 5.

Commands the device implements (`gc_app_dispatch_command`):

| `cmd` | `arg` | `flag` | Effect |
| --- | --- | --- | --- |
| `tunnel_up` | - | true up, false down | request or release the tunnel |
| `manifest_check` | - | - | run a manifest check now |
| `unblock_all` | - | - | clear every block, maintenance only |
| `reset_counters` | - | - | reset the NAT byte counters |

Any other name is logged and ignored.

## 5 Command signing rule

Applies to every `cmd` message and to `unblock`. The pre-shared key is 32 bytes
(`GC_PSK_LEN`, `PSK_BYTES`).

```
tag = first 8 bytes of HMAC-SHA256(psk, "cmd" || u32 big-endian sequence || body)
```

- `"cmd"` is the three ASCII bytes `63 6d 64` (domain separator, per
  `docs/TEST_VECTORS.md`).
- The sequence is the same value carried in `seq`, four bytes, big-endian.
- `body` is the canonical command body. The reference canonicalisation is the
  compact UTF-8 JSON of the command with `sig` removed and keys in the order
  `cmd`, `seq`, `arg`, `flag`: `{"cmd":"manifest_check","seq":92,"arg":0,"flag":false}`.
  Both halves must agree on these bytes; this is the only part of the rule the
  tree leaves to the caller (`commandPayload(sequence, body)` in
  `controller/src/crypto.ts`).
- The tag is carried as `sig`, 16 lowercase hex characters, and compared with
  `gc_crypto_constant_time_equal`.

Worked example, pre-shared key 32 bytes of `0x22`:

```
signed message  "cmd" || 00 00 00 5c || {"cmd":"manifest_check","seq":92,"arg":0,"flag":false}
sig             0a22e23d34b45173
```

Sequence rule: a device rejects any command or unblock whose sequence is less
than or equal to the last accepted one, and remembers the new sequence when it
accepts (REQUIREMENTS 3.6, 3.7). Applied in `gc_app_dispatch_command`, which
returns without acting when `sequence <= last_command_sequence`.

That acceptance is not persisted in this tree: `app.last_command_sequence`
starts at 0 on every boot and `gc_crypto_command_sequence_store` has no callers,
so a reboot reopens the sequence window.

Status of the check in this tree: the sequence rule is enforced. The tag
comparison is not yet wired: `gc_crypto_command_mac` has no callers, and
`gc_ctrl_decode` accepts a `cmd` or `unblock` message on signature shape alone
(16 hex characters). Treat any deployment before that is fixed as unsigned.

## 6 Verification modes

`contact` mode (`GC_VERIFY_MODE_CONTACT`, default): the controller answers
`allow` when the number's last-contact time is inside the configured window
(REQUIREMENTS 2.4).

`challenge` mode (`GC_VERIFY_MODE_CHALLENGE`): the controller answers `allow`
only when the number has sent the challenge code the controller issued for that
request inside the challenge window (REQUIREMENTS 2.5). A pending or expired
challenge answers `pending` or `expired` with a `hint` for the portal.

**Forgery caveat, stated plainly.** A typed phone number is an unauthenticated
assertion. In `contact` mode anyone who knows or guesses a number that has
recently messaged the bot can type it and be allowed, and neither half can tell
the difference: the device only ever sees the number key, and the controller
only knows that the number contacted the bot inside the window. `contact` mode
is a low-friction filter, not identity. Use `challenge` mode wherever the gate
protects anything that matters. In both modes the WhatsApp webhook is trusted
only after its signature verifies (REQUIREMENTS 2.6).
