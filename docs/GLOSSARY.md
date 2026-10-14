# Glossary

One name per concept. Code, docs, commit messages and MQTT topics all use these
words and no synonyms. If you are about to write "user", "subscriber", "router",
"blacklist entry" or "ban", use the word below instead.

| Term | Means | Never call it |
| --- | --- | --- |
| device | The ESP32-S2FN4R2 node running this firmware. | node, box, esp, router |
| controller | The central control service. Sole authority for allow, deny, strike count and unblock. | server, backend, cloud, VPS |
| site | One of the three physical deployments. Identified by `site_id`. | location, branch, premises |
| client | A station associated to the device soft-AP. | user, subscriber, device (that word means ours) |
| number | The phone number a client types into the portal. | msisdn, subscriber id, account |
| contact | The event of a number sending a message to the WhatsApp bot. | engagement, activation, opt-in |
| verification | The controller's decision on whether a number may open access. | auth, authentication, login |
| verdict | The controller's answer to a verification request: allow or deny with a reason. | response, result, decision |
| allow list | The device-side table of clients currently permitted to be forwarded. | whitelist |
| block | A refusal to forward, keyed on a block key, with an expiry or permanent. | ban, blacklist entry |
| block key | The 8-byte HMAC of the phone number. Authoritative identity for blocks. | identity, uid |
| mac key | The 8-byte HMAC of the client MAC. Secondary signal; relayed, never authoritative. | mac address (never stored in the clear) |
| strike | One counted deny of the `not_verified` reason against a block key. | violation, offence, warning |
| soft block | A block with an expiry, default 24 hours. | temporary ban, cooldown |
| permanent block | A block with no expiry, cleared only by a signed unblock command. | lifetime ban, blacklist |
| unblock | The signed controller command that clears a block and optionally resets strikes. | amnesty, pardon, reset |
| uplink | The device's station link to the B315 and hence the carrier. | WAN, internet, backhaul |
| reserve | The monthly byte allowance held back so telemetry and the beacon keep working. | safety margin, buffer |
| governor | The logic that changes telemetry behaviour as the daily budget is consumed. | throttler, limiter |
| ladder | The bounded sequence of recovery steps taken when the uplink fails. | escalation policy, retry chain |
| beacon | The 16-byte signed UDP packet the device sends so it stays findable. | ping, heartbeat (a heartbeat is an MQTT message) |
| tunnel | WireGuard, brought up only when the controller asks. | VPN |
| slot | One of `factory`, `ota_0`, `ota_1`. | partition, bank, image slot |
| trial boot | The first boot of a newly written slot, pending verify. | canary boot, test boot |
| self-test | The seven criteria a trial boot must pass before the slot is committed. | smoke test, health check |
| frame | One MQTT payload carrying telemetry records. | message, packet, sample |
| reading | One set of signal and counter values inside a frame. | sample, datapoint |
