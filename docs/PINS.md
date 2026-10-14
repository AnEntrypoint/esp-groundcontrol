# Pins

GPIO assignment for the D1 mini ESP32-S2FN4R2 (4 MB in-package flash, 2 MB
in-package PSRAM). The numbers in `main/include/gc_pinmap.h` are the ones the
firmware drives; this file says why each is safe and what must be checked
before anything is soldered.

## 1 Check first

**Check this assignment against the module datasheet before soldering.** Board
authors move pins between revisions, and the reasons below are about the
ESP32-S2FN4R2 silicon and the reserved set enforced in `gc_pinmap_relay_allowed`,
not about any particular carrier board's silkscreen. Confirm each number on the
physical header against the datasheet for the exact module in hand, then wire.

## 2 Assignment

| GPIO | Function | Direction | Idle level | Why this pin is free |
| --- | --- | --- | --- | --- |
| 4 | relay | output | inactive | General purpose on ESP32-S2. No boot strapping role, not USB, not in-package memory. Allowed by `gc_pinmap_relay_allowed`. Driven to the inactive level in `gc_app_init` before any tick runs, so the modem supply is not switched during boot. |
| 5 | watchdog kick | output | low | General purpose. Carries a 50 us high pulse (`GC_WATCHDOG_KICK_PULSE_US`) once per pass of the health checks, so it needs no special function and no strapping tolerance. |
| 2 | status LED | output | low | General purpose and low current through a series resistor. Unlike the ESP8266 D1 mini, GPIO2 on ESP32-S2 has no boot strapping role, so an LED on it cannot change the boot mode. |
| 10 | W5500 CS | output | high | General purpose. SPI chip selects are ordinary GPIO on ESP32-S2. |
| 11 | W5500 INT | input | pulled up | General purpose and interrupt-capable; any GPIO can be routed to the GPIO matrix as an interrupt source. |
| 12 | W5500 RST | output | high | General purpose. Held high in idle so the W5500 runs; pulsed low to reset. |
| 13 | SPI MOSI | output | - | General purpose. On ESP32-S2 the SPI2 (FSPI) signals are routed through the GPIO matrix, so MOSI is not tied to a fixed pin. |
| 14 | SPI MISO | input | - | Same as MOSI. |
| 15 | SPI SCLK | output | - | Same as MOSI. |

`GC_RELAY_ACTIVE_LEVEL` is 1: relay on means GPIO4 high. The firmware inverts
that to set the inactive level at init.

The W5500 is optional. If it is not fitted, GPIO10 through GPIO15 stay
unclaimed and the uplink stays Wi-Fi only.

Claims are tracked at runtime: `gc_pinmap_claim(gpio, owner)` records an owner
and refuses a second claim, `gc_pinmap_release(gpio)` frees it, and
`gc_pinmap_owner(gpio)` reports the holder. A failed claim is logged, not
fatal.

## 3 Reserved pins

Do not use these for anything, and keep them out of every circuit you add.

| Pins | Why |
| --- | --- |
| GPIO0 | Boot strapping. Sampled at reset to choose the boot mode; also the BOOT button. |
| GPIO19, GPIO20 | USB D- and D+. These are the native USB serial used for flashing and the console. |
| GPIO26..GPIO32 | In-package flash and PSRAM. Not available as GPIO on this part. |

`gc_pinmap_relay_allowed` refuses exactly this set, so a claim on any of them
fails and is logged.

## 4 GPIO0 must stay out of the relay circuit

GPIO0 selects the boot mode at reset. A low level on GPIO0 while the chip comes
out of reset puts the ROM bootloader into serial download mode, and the device
then never runs the firmware: it sits waiting for a flash command that nothing
sends. A relay driver, an optocoupler or a pull-down on the relay board that
touches GPIO0 is enough to do this, and the failure looks like a dead device
that recovers only when the relay board is unplugged.

Keep GPIO0 out of the relay circuit entirely: no coil drive, no sense line, no
shared pull resistor (REQUIREMENTS 11.2). This is enforced in software by
`gc_pinmap_relay_allowed` and checked in review, but the wiring is the real
control.

## 5 The relay switches DC only

The relay exists to power-cycle the modem. It switches the modem's DC supply,
on the low-voltage side of that modem's own supply.

Never switch mains with this relay (REQUIREMENTS 11.3). Not 110 V, not 230 V,
not a mains lead cut and screwed into the terminal block. The board is not
rated for it, the clearances are not rated for it, and the enclosure is not
rated for it.

Use a rated enclosure for whatever is wired: the relay contacts, the modem DC
supply and every low-voltage connection must be inside something that keeps
fingers and stray conductor off the terminals. If the modem supply is mains
powered, the mains side stays inside its own approved adapter and only the DC
output comes to the relay.

## 6 Watchdog

The device kicks the hardware watchdog from the main loop only, and only after
every registered health check has passed (REQUIREMENTS 11.1). A failing check
stops the kicks, and the external watchdog resets the board. The kick is a
50 us high pulse on GPIO5; confirm the external watchdog's minimum pulse width
against `GC_WATCHDOG_KICK_PULSE_US` before relying on it.
