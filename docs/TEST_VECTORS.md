# Test vectors

These exist because the two halves of the system derive the same secret
independently and nothing else catches a disagreement. If the device and the
controller derive different keys for the same phone number, the portal accepts
the number, the controller answers `not_verified`, and every client is soft
blocked with no error anywhere. That failure is invisible in the logs and looks
like "the bot is not working".

So: run these on both halves before the first field pilot, and re-run them after
any change to `gc_crypto.c` or `controller/src/crypto.ts`.

## Key derivation

`key = HMAC-SHA256(pepper, domain || message)` truncated to its first 8 bytes.

| Derivation | Domain byte(s) | Message |
| --- | --- | --- |
| number key | `0x6E` (`"n"`) | the digits of the E.164 number, no `+`, no spaces, no separators |
| mac key | `0x6D` (`"m"`) | the 6 MAC bytes |
| beacon tag | `"beacon"` | the first 8 bytes of the beacon |
| command tag | `"cmd"` | `u32` big-endian sequence || command body |

Peppers and pre-shared keys are 32 bytes. A number is rejected below 7 digits or
above 15 digits after digit stripping.

## Vectors

Pepper is 32 bytes of `0x11`. Pre-shared key is 32 bytes of `0x22`.

| Input | Expected 8-byte key, lowercase hex |
| --- | --- |
| number `+27821234567` | `cdbdd22167e29534` |
| mac `aa:bb:cc:dd:ee:ff` | `c60f22d908a65bea` |
| beacon payload `1100010200000007` | `bc296784e9518e5e` |

The same number written as `27 82 123 4567`, `27821234567` or `+27-82-123-4567`
must produce the same number key. That is the whole point of stripping before
hashing rather than hashing the formatted string.

## How to check

- Controller: `node tools/keycheck.mjs` recomputes every vector above and exits
  non-zero on any mismatch. It runs in CI.
- Device: build with `CONFIG_GC_BENCH_FAULTS=y`, call `gc_crypto_number_key` with
  the vector pepper and number, and compare the printed hex. The bench procedure
  is in `docs/BENCH.md`.

## Regenerating

If you change the domain string, the truncation length or the pepper size, these
vectors change and every deployed device stops matching its controller. Treat a
change here as a coordinated rollout, not an edit.
