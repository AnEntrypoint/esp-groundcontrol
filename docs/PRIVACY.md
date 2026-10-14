# Privacy

What this system records about the people who use it, how long it is kept, and
how an operator deletes it. Source of truth for requirements is
`docs/REQUIREMENTS.md`; terms come from `docs/GLOSSARY.md`.

## What is collected

| Data | Form | Where it lives |
| --- | --- | --- |
| number key | 8-byte HMAC of the phone number | NVS allow list on the device; `contacts.number_key` and `strikes.number_key` on the controller; verify requests over MQTT |
| mac key | 8-byte HMAC of the client MAC | `strikes.mac_key` on the controller; relayed in telemetry |
| byte counters | KiB, per allowed client and on the station interface in both directions | NVS (survives reboot, requirement 7.7); `quota_delta_kb` in telemetry records |
| modem signal readings | RSSI, RSRP, RSRQ, SINR, connection state | telemetry records, delta-encoded against the previous record |
| firmware version and slot | version integer, `factory`/`ota_0`/`ota_1`, trial-pending flag | `devices` table on the controller |
| strike count and block expiry | count, permanent flag, `blocked_until`, `updated_at` | NVS on the device; `strikes` table on the controller (requirement 3.11) |
| last contact time | unix seconds for a number key | `contacts.last_contact_at` |
| site id, device id, uptime, client count, flags | per frame | telemetry frame header |

The beacon carries site id, device id, the low 16 bits of a monotonic counter
and an 8-byte HMAC tag. It carries no identity and no key material
(requirements 9.1, 9.2).

## What is not collected

| Not collected | Why not |
| --- | --- |
| Packet payloads | Requirement 1.6: the device does not inspect, buffer or log payloads. |
| Destination addresses | Requirement 1.7. |
| Hostnames and URLs | Requirement 1.7. |
| Per-client browse history | Requirement 1.7. |
| A raw phone number at rest | Requirement 2.7. The number exists only in the portal POST body and in RAM for the life of that request. No column on either side can hold it. |
| A raw client MAC at rest | Hashed for anything durable. The clear MAC appears only in the volatile allow-list entry. |
| Beacon PSK, WireGuard keys, pepper, broker password | Requirement 13.1: never in the repository. The provisioning tool writes them to NVS from a file outside the tree (13.3). |

## Hashing scheme

HMAC-SHA256 under a 32-byte per-site pepper, domain-separated by a one-byte
prefix, digest truncated to its first 8 bytes:

- pepper: `GC_PEPPER_LEN` 32 on the device (`main/include/gc_crypto.h`),
  `PEPPER_BYTES` 32 on the controller (`controller/src/crypto.ts`).
- prefixes: `n` for a phone number, `m` for a MAC, `beacon` and `cmd` for the
  tag and the unblock command.
- output: 8 bytes (`GC_KEY_LEN`), 16 hex characters.

Two consequences, both intended:

1. Nothing on the device and nothing in the controller database can hold a phone
   number. The identifier is 8 bytes everywhere, including in the allow list,
   the strike record and every MQTT frame.
2. Truncation is one-way. A key cannot be reversed into a number, and the same
   number under two different peppers produces unrelated keys.

Pepper handling:

- One pepper per site (requirement 12.2). On the device it is loaded from NVS by
  `gc_crypto_load_pepper`; on the controller it comes from the environment.
- No pepper for a site: the controller refuses to start (requirement 2.8) and
  the device refuses verification (`main/gc_gate.c` logs and returns an error).
- Rotating a site pepper invalidates every key derived from it. That is the
  fastest way to make a whole site's stored history unlinkable, and it also
  invalidates every block for that site.

Why 8 bytes and not 32: the key only has to be unique inside one site's client
population. At 64 bits the collision probability stays below 1e-9 for tens of
thousands of clients. The other 24 bytes would be paid on every NVS record and
every MQTT frame to buy nothing.

## Retention

| Data | Kept for | Deleted by |
| --- | --- | --- |
| contacts (number key, last contact time) | Until the last-contact time falls outside the site's contact window; nothing prunes it automatically yet | `store.forgetContactsBefore(cutoffS)` → `DELETE FROM contacts WHERE last_contact_at < ?` |
| strikes and block expiries | A soft block lifts at its expiry and keeps the count (requirement 3.10); a permanent block is kept until a signed unblock, and survives reboot, slot switch and reflash of both OTA slots (3.4, 3.5) | A signed unblock command from the controller, or deleting the row by number key |
| telemetry frames | Ring buffer on the device, overwritten; on the controller until trimmed | `store.trimTelemetryBefore(cutoffS)` → `DELETE FROM telemetry WHERE ts < ?` |
| logs | RAM ring only, dropped when the ring wraps | Power cycle. Logs never reach flash. |

State of the code: `forgetContactsBefore` and `trimTelemetryBefore` exist in
`controller/src/store.ts` and nothing schedules them yet. Until a scheduler
lands, the operator runs them.

How an operator deletes one person's records:

1. Derive the key from the number under that site's pepper, for example with
   `numberKey()` exported from `tools/keycheck.mjs`. The controller database
   holds only the key, so lookup is by key, never by number.
2. `sqlite3 <controller.db> "DELETE FROM contacts WHERE number_key = x'<hex>'"`
   and the same against `strikes`.
3. Device-side: a permanent block lives in NVS and the device will not clear it
   except on a signed unblock from the controller (requirement 3.5), and will
   reject any unblock whose sequence number does not exceed the last accepted one
   (3.7).

## Notice shown on first connection

The portal serves this before the phone-number field, at least once per client
(requirement 1.8). It is `GC_CONFIG_DEFAULT_NOTICE` in `main/gc_config.c`:

> This network is public and shared. To connect you must enter your phone
> number. The number is used only to check whether it has sent a message to the
> WhatsApp bot for this network, and it is stored hashed, never in the clear.
> Traffic is metered and may be paused when the data budget runs low. A number
> that has not contacted the bot is blocked for 24 hours, and is blocked
> permanently after three strikes.

It is overridable per site through the `notice` key in NVS (`gc_config_set`,
`GC_NOTICE_MAX`). A notice longer than the field is rejected; the device keeps
the previous one and logs a warning. Keep any override consistent with the real
soft-block duration (86400 s, `GC_SOFT_BLOCK_S`) and strike limit (3,
`GC_STRIKE_LIMIT`), because the notice is the only place a client is told them.

## Jurisdiction

This system is deployed in South Africa, and two statutes bear on it. RICA, the
Regulation of Interception of Communications and Provision of Communication-Related
Information Act 70 of 2002, restricts intercepting communications and monitoring
communications-related information. POPIA, the Protection of Personal Information
Act 4 of 2013, governs personal information, and a phone number, a MAC address
and a usage log that ties the two to a person are all personal information under
it. The design deliberately stays at the device level: the device counts bytes,
reads signal strength and decides whether a client is on the allow list. It does
not inspect traffic, does not record where a client went and does not keep a
browse history. Refusing to forward a client is not interception, but where the
line between the two falls is a legal question rather than an engineering one,
and a hashed identifier is still personal information if it singles someone out.
If the network serves anyone other than the operator — tenants, customers, staff
or visitors — get advice before deploying it, tell those people what is
collected, and be able to delete it on request. This document is not legal
advice.
