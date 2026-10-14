# Partitions

Scope: ESP32-S2FN4R2, 4 MB of in-package flash. `sdkconfig.defaults` pins
`CONFIG_ESPTOOLPY_FLASHSIZE_4MB=y`, `CONFIG_PARTITION_TABLE_OFFSET=0x8000` and
`CONFIG_BOOTLOADER_OFFSET_IN_FLASH=0x1000`. The map below is `partitions.csv`
verbatim; nothing here overrides it.

## Flash map

| Name | Type | SubType | Offset | Size | Bytes |
| --- | --- | --- | --- | --- | --- |
| (partition table) | - | - | 0x8000 | 0x1000 | 4 KiB |
| nvs | data | nvs | 0x9000 | 0x6000 | 24 KiB |
| otadata | data | ota | 0xf000 | 0x2000 | 8 KiB |
| phy_init | data | phy | 0x11000 | 0x1000 | 4 KiB |
| factory | app | factory | 0x20000 | 0x100000 | 1024 KiB |
| ota_0 | app | ota_0 | 0x120000 | 0x170000 | 1472 KiB |
| ota_1 | app | ota_1 | 0x290000 | 0x170000 | 1472 KiB |

Gaps: 0x12000 to 0x20000 (56 KiB) is unused between `phy_init` and `factory`,
kept so `factory` stays 0x10000-aligned.

Discrepancy: the comment in `partitions.csv` claims `factory + ota_0 + ota_1`
leave 0x10000 free at the top for a future coredump slot. They do not.
0x290000 + 0x170000 = 0x400000, which is exactly the top of a 4 MB part, so
there is no spare and no coredump slot. A coredump partition requires shrinking
`ota_1`. Same finding as row 30 of "Numbers to measure" in the README.

## Why factory is smaller

`factory` is 1024 KiB against 1472 KiB for each OTA slot. It holds a rescue
image built with `CONFIG_GC_RESCUE_IMAGE=y` (`main/Kconfig.projbuild`): beacon,
WireGuard and the emergency path, no portal, no client table, no NAPT client
state. Requirements 10.10 and 10.11: when both OTA slots are invalid the
bootloader boots `factory`, and `factory` must be able to reflash the main
slots.

Consequences of that split:

- OTA writes only to `ota_0` or `ota_1`, never to `factory`. So `factory` is
  written at provisioning and thereafter only over a wire. It does not need
  room for the portal or for 24 concurrent clients, and 1 MiB is enough.
- The two slots that must each hold a full application *plus* the downloaded
  image get the rest of the flash.
- `factory` cannot reflash itself (10.11 covers the main slots only). A bad
  rescue image is a wire recovery, which is why the recovery procedure below is
  non-negotiable.

## Why there is no filesystem partition

There is no SPIFFS, FATFS or LittleFS partition.

- **Logs are a RAM ring buffer.** `gc_log_init(size_t records)`,
  `gc_log_ring_dump()`, `gc_log_dropped_count()`, `gc_log_error_count()` and
  `gc_log_warn_count()` (`main/include/gc_log.h`), 160 bytes per record
  (`GC_LOG_RECORD_MAX`). Requirement 11.4 puts the log buffer in PSRAM. Only
  counters and summaries reach NVS; no log line is ever written to flash.
- **State is NVS.** 24 KiB holds config, quota counters, strike counters, the
  beacon counter, the accepted unblock sequence and the site id (requirements
  3.11, 7.7, 12.1).
- **A filesystem buys nothing here.** Every durable byte is either a counter or
  a config item. A filesystem would add wear levelling and a GC pause inside
  the forwarding path, a file that can be half-written when a trial boot rolls
  back, and a log file that can grow until it collides with an OTA slot. It
  would also have to be made to survive flash encryption and rollback for no
  return.

## Recovery

Even when the application is broken, this works:

1. Get at the BOOT pad or button on the enclosure.
2. Hold BOOT (GPIO0, `GC_PIN_BOOT_GPIO`) low.
3. Tap reset (EN).
4. Flash over native USB: `idf.py -p <port> flash`, or `esptool.py`. Release
   BOOT once the tool connects.

Why: ROM serial download mode is mask ROM. It runs before flash, before the
bootloader and before any signature check of the application. A corrupt OTA
image, a failed self-test that invalidated both slots, a bad partition table or
an unsigned image cannot stop the ROM from accepting a download. On the ESP32-S2
the native USB pins (GPIO19/20) are also a download path.

Limits of that guarantee:

- Secure Boot v2 does not block download; it blocks *running* unsigned code.
  Once the key is burned, what you flash must be signed with it.
- Flash encryption does not block download of ciphertext, but a plaintext flash
  written after encryption is enabled will not run.
- Burning the download-disable eFuses removes this path for good. Do it last.

### Enclosure and wiring rules

- **BOOT must be reachable from outside the closed enclosure.** A pinhole or an
  external pad. A recovery that needs the sealed box opened in the field is not
  a recovery.
- **GPIO0 must stay out of the relay circuit.** `gc_pinmap_relay_allowed()`
  (`main/gc_pinmap.c`) returns false for GPIO0, for GPIO19 and GPIO20, and for
  the embedded-flash GPIOs 26 to 32; `gc_pinmap_claim()` refuses those pins
  outright. Requirements 11.2 and 11.3: GPIO0 is never part of the relay
  circuit, and the relay switches the DC side only.
- Reason: the relay drives modem power (requirement 5.4). A relay driver on
  GPIO0 fights the BOOT button for that pin, so either the button cannot force
  download mode, or pressing it power-cycles the modem. Both are field failures.

## Order for lighting up the security features

All of these burn eFuses. eFuse bits are one-way: there is no unburn, no
restore and no factory reset. Order is therefore fixed by reversibility, not by
convenience.

| # | Step | Do it | Why here |
| --- | --- | --- | --- |
| 0 | Recovery rehearsal | Before anything is burned | Prove BOOT + reset + USB download restores a deliberately bricked bench unit. Costs nothing, reversible, and every later step depends on it being true. |
| 1 | Secure Boot v2 | Bench units first | Burns the public-key digest. One-way. A unit carrying the wrong key can never again run unsigned code, so make the first mistake on a unit you can scrap. |
| 2 | Flash encryption, release mode | Bench units first, after step 1 | Burns the encryption key and the flash-crypt counter. One-way. Release mode decides the key in hardware; after it, plaintext reflashing stops working. |
| 3 | Prove the update path | With 1 and 2 on | Download to the inactive slot, Range resume, trial boot, the seven self-test criteria, `esp_ota_mark_app_valid_cancel_rollback`, then force a rollback and confirm it lands back on the previous slot. Step 4 is only safe once this passes. |
| 4 | Anti-rollback | Last | Raises the monotonic secure-version eFuse. One-way. Once raised, no image with a lower security version will ever boot again. If the update path is not already proven, a unit that cannot be updated is a unit that can never be fixed. |
| 5 | Download-disable eFuses | After the recovery test passes with 1 to 4 on | This deletes the only recovery path that does not depend on the application. Re-run the BOOT + reset procedure immediately after burning. If it fails, that unit is scrap. |

Where `sdkconfig.defaults` stands today: `CONFIG_SECURE_BOOT=n`,
`CONFIG_SECURE_FLASH_ENCRYPTION_ENABLED=n`,
`CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y`,
`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=n`. Rollback-on-failure costs no eFuse and
is already on; anti-rollback is the irreversible half and is off by default, so
it waits for step 4. The `SECURE_BOOT_ALLOW_*` options currently leave the ROM
basic console, JTAG and eFuse read-disable reachable; tighten them only after
step 3.

## What to check with `idf.py size` before committing a build

- `idf.py size`, two figures: `Total image size` and `Used Flash size`. Take the
  larger.
  - Default build: must fit 0x170000 (1472 KiB), the size of `ota_0` and
    `ota_1`. Both slots are the same size, so any build must fit whichever slot
    happens to be inactive. Keep to 90 percent (1325 KiB); a build at 99 percent
    is one feature away from overflowing.
  - `CONFIG_GC_RESCUE_IMAGE=y` build: must fit 0x100000 (1024 KiB), the size of
    `factory`. Check this build too, not just the default one.
- `idf.py size-files`: find which object grew before deciding whether the growth
  is real.
- DRAM: `Used static DRAM`. The portal session table, the client list, the delta
  apply buffer and the log ring belong in PSRAM (requirement 11.4). Growth in
  static DRAM is a defect, not a budget question.
- Re-run size after enabling Secure Boot v2 and flash encryption. Signed and
  encrypted images are larger: the bootloader grows and encrypted partitions are
  32-byte aligned. A build that fit at 97 percent before can overflow after.
- CI already gates this: `.github/workflows/firmware.yml` parses both size
  figures, `stat`s every app `.bin` under `build/`, compares against
  `factory 0x100000` and `ota_0`/`ota_1 0x170000`, and fails the job on any
  overflow.
- `idf.py size` does not cover NVS. Check `nvs_get_stats` after a month of
  quota, strikes and counters; 24 KiB is the whole budget (README row 27).
