#!/usr/bin/env node
import { createHmac, timingSafeEqual } from "node:crypto";

const HEADER_FIELDS = 13;
const VARINT_MAX_BYTES = 10;

const TELEMETRY_FLAGS = [
  [0x01, "ALARM"],
  [0x02, "RESERVE_TRIPPED"],
  [0x04, "FORWARDING_PAUSED"],
  [0x08, "TUNNEL_UP"],
  [0x10, "TRIAL_PENDING"],
  [0x20, "CONTROLLER_UNREACHABLE"],
];

const SLOTS = ["unknown", "factory", "ota_0", "ota_1"];

const BEACON_LEN = 16;
const BEACON_PAYLOAD_LEN = 8;
const BEACON_TAG_LEN = 8;
const BEACON_VERSION = 1;
const BEACON_VERSION_SHIFT = 4;
const BEACON_KIND_MASK = 0x0f;
const BEACON_KINDS = { 1: "ROUTINE", 2: "ALARM" };
const BEACON_DOMAIN = Buffer.from("beacon", "ascii");
const PSK_BYTES = 32;

const USAGE = [
  "usage: node tools/frame_dump.mjs --tele <hex>",
  "       node tools/frame_dump.mjs --beacon <hex> [--psk <hex>]",
  "",
  "  --tele <hex>     decode a telemetry frame:",
  "                   u8 version, u8 flags, u16 site_id, u16 device_id,",
  "                   u16 boot_id, u16 seq, u8 record_count, u8 fw_version,",
  "                   u8 slot, then record_count records of",
  "                   (varint uptime_delta_s, i8 rssi, u8 clients, i8 rsrp,",
  "                    i8 rsrq, i8 sinr, varint quota_delta_kb)",
  "  --beacon <hex>   decode the 16-byte big-endian beacon: version and kind",
  "                   from byte 0, u16 site_id, u8 device index, u32 counter,",
  "                   then the 8-byte tag",
  "  --psk <hex>      32-byte pre-shared key; recomputes",
  "                   HMAC-SHA256(psk, \"beacon\" || payload[0..8)) and reports",
  "                   whether the first 8 bytes match the tag",
].join("\n");

class DecodeError extends Error {
  constructor(offset, detail) {
    super("decode failed at offset " + offset + ": " + detail);
    this.name = "DecodeError";
    this.offset = offset;
  }
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith("--")) {
      continue;
    }
    const eq = arg.indexOf("=");
    if (eq > 0) {
      out[arg.slice(2, eq)] = arg.slice(eq + 1);
      continue;
    }
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) {
      out[key] = "true";
      continue;
    }
    out[key] = next;
    i += 1;
  }
  return out;
}

function parseHex(label, raw) {
  const text = String(raw).replace(/^0[xX]/, "").replace(/[\s:,_-]/g, "");
  if (!/^[0-9a-f]*$/.test(text)) {
    throw new Error(label + ": not hex: " + JSON.stringify(String(raw)));
  }
  if (text.length % 2 !== 0) {
    throw new Error(label + ": odd number of hex digits (" + text.length + ")");
  }
  return Buffer.from(text, "hex");
}

function createReader(buf) {
  let offset = 0;

  const bounds = (needed, field) => {
    if (offset + needed > buf.length) {
      throw new DecodeError(
        offset,
        "short read of " + field + ": need " + needed + " byte(s), buffer holds " + buf.length,
      );
    }
  };

  const u8 = (field) => {
    bounds(1, field);
    const value = buf.readUInt8(offset);
    offset += 1;
    return value;
  };

  const i8 = (field) => {
    bounds(1, field);
    const value = buf.readInt8(offset);
    offset += 1;
    return value;
  };

  const u16le = (field) => {
    bounds(2, field);
    const value = buf.readUInt16LE(offset);
    offset += 2;
    return value;
  };

  const u16be = (field) => {
    bounds(2, field);
    const value = buf.readUInt16BE(offset);
    offset += 2;
    return value;
  };

  const u32be = (field) => {
    bounds(4, field);
    const value = buf.readUInt32BE(offset);
    offset += 4;
    return value;
  };

  const varint = (field) => {
    let value = 0n;
    let shift = 0n;
    const start = offset;
    for (let index = 0; index < VARINT_MAX_BYTES; index += 1) {
      const byte = u8(field + " varint byte " + index);
      value |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) {
        return { value, bytes: offset - start };
      }
      shift += 7n;
    }
    throw new DecodeError(start, field + " varint exceeds " + VARINT_MAX_BYTES + " bytes");
  };

  return { u8, i8, u16le, u16be, u32be, varint, at: () => offset };
}

function flagNames(mask) {
  const names = TELEMETRY_FLAGS.filter((entry) => (mask & entry[0]) !== 0).map((entry) => entry[1]);
  return names.length === 0 ? "none" : names.join(" | ");
}

function pad(label, width) {
  return label + " ".repeat(Math.max(1, width - label.length));
}

function dumpTelemetry(buf) {
  if (buf.length === 0) {
    throw new DecodeError(0, "empty buffer: telemetry frame needs at least " + HEADER_FIELDS + " byte(s)");
  }
  const read = createReader(buf);
  const out = [];
  const width = 14;

  const version = read.u8("version");
  const flags = read.u8("flags");
  const siteId = read.u16le("site_id");
  const deviceId = read.u16le("device_id");
  const bootId = read.u16le("boot_id");
  const seq = read.u16le("seq");
  const recordCount = read.u8("record_count");
  const fwVersion = read.u8("fw_version");
  const slot = read.u8("slot");

  out.push("telemetry frame  " + buf.length + " byte(s)");
  out.push("  " + pad("version", width) + version);
  out.push("  " + pad("flags", width) + "0x" + flags.toString(16).padStart(2, "0") + "  " + flagNames(flags));
  out.push("  " + pad("site_id", width) + siteId);
  out.push("  " + pad("device_id", width) + deviceId);
  out.push("  " + pad("boot_id", width) + bootId);
  out.push("  " + pad("seq", width) + seq);
  out.push("  " + pad("record_count", width) + recordCount);
  out.push("  " + pad("fw_version", width) + fwVersion);
  out.push("  " + pad("slot", width) + (SLOTS[slot] ?? "unknown") + " (" + slot + ")");

  for (let index = 0; index < recordCount; index += 1) {
    const at = "records[" + index + "]";
    const uptime = read.varint(at + ".uptime_delta_s");
    const rssi = read.i8(at + ".rssi");
    const clients = read.u8(at + ".clients");
    const rsrp = read.i8(at + ".rsrp");
    const rsrq = read.i8(at + ".rsrq");
    const sinr = read.i8(at + ".sinr");
    const quota = read.varint(at + ".quota_delta_kb");
    out.push(
      "  " +
        pad(at, width) +
        "uptime_delta_s=" + uptime.value.toString() +
        " (varint " + uptime.bytes + "B)" +
        "  rssi=" + rssi +
        "  clients=" + clients +
        "  rsrp=" + rsrp +
        "  rsrq=" + rsrq +
        "  sinr=" + sinr +
        "  quota_delta_kb=" + quota.value.toString() +
        " (varint " + quota.bytes + "B)",
    );
  }

  const consumed = read.at();
  out.push("  " + pad("consumed", width) + consumed + " of " + buf.length + " byte(s)");
  if (consumed < buf.length) {
    process.stderr.write(
      "warning: " + (buf.length - consumed) + " trailing byte(s) at offset " + consumed + "\n",
    );
  }
  return out;
}

function dumpBeacon(buf, psk) {
  if (buf.length === 0) {
    throw new DecodeError(0, "empty buffer: beacon needs " + BEACON_LEN + " bytes");
  }
  const read = createReader(buf);
  const out = [];
  const width = 14;

  const header = read.u8("version_and_kind");
  const version = header >>> BEACON_VERSION_SHIFT;
  const kind = header & BEACON_KIND_MASK;
  const siteId = read.u16be("site_id");
  const deviceIndex = read.u8("device_index");
  const counter = read.u32be("counter");
  if (read.at() + BEACON_TAG_LEN > buf.length) {
    throw new DecodeError(
      read.at(),
      "short read of tag: need " + BEACON_TAG_LEN + " byte(s), buffer holds " + buf.length,
    );
  }
  const tag = buf.subarray(BEACON_PAYLOAD_LEN, BEACON_LEN);

  out.push("beacon  " + buf.length + " byte(s)");
  out.push(
    "  " + pad("byte0", width) + "0x" + header.toString(16).padStart(2, "0") +
      "  version=" + version + "  kind=" + (BEACON_KINDS[kind] ?? "unknown") + " (" + kind + ")",
  );
  out.push("  " + pad("site_id", width) + siteId);
  out.push("  " + pad("device_index", width) + deviceIndex);
  out.push("  " + pad("counter", width) + counter);
  out.push("  " + pad("tag", width) + tag.toString("hex"));

  if (version !== BEACON_VERSION) {
    process.stderr.write("warning: beacon version " + version + ", expected " + BEACON_VERSION + "\n");
  }

  if (psk === undefined) {
    out.push("  " + pad("tag_check", width) + "skipped (pass --psk to verify)");
    return { lines: out, verified: true };
  }

  const payload = buf.subarray(0, BEACON_PAYLOAD_LEN);
  const expected = createHmac("sha256", psk)
    .update(BEACON_DOMAIN)
    .update(payload)
    .digest()
    .subarray(0, BEACON_TAG_LEN);
  const matches = expected.length === tag.length && timingSafeEqual(expected, tag);
  out.push(
    "  " + pad("tag_check", width) +
      (matches
        ? "verified  HMAC-SHA256(psk, \"beacon\" || payload)[0..8] == " + expected.toString("hex")
        : "MISMATCH  expected " + expected.toString("hex") + ", presented " + tag.toString("hex")),
  );
  out.push("  " + pad("payload", width) + payload.toString("hex"));
  return { lines: out, verified: matches };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help !== undefined) {
    process.stdout.write(USAGE + "\n");
    return 0;
  }

  const hasTele = args.tele !== undefined;
  const hasBeacon = args.beacon !== undefined;
  if (hasTele === hasBeacon) {
    throw new Error("pass exactly one of --tele <hex> or --beacon <hex>");
  }

  if (hasTele) {
    const buf = parseHex("--tele", args.tele);
    process.stdout.write(dumpTelemetry(buf).join("\n") + "\n");
    return 0;
  }

  const buf = parseHex("--beacon", args.beacon);
  const psk = args.psk === undefined ? undefined : parseHex("--psk", args.psk);
  if (psk !== undefined && psk.length !== PSK_BYTES) {
    throw new Error("--psk must be " + PSK_BYTES + " bytes (64 hex digits), got " + psk.length);
  }
  if (buf.length !== BEACON_LEN) {
    process.stderr.write(
      "warning: beacon is " + buf.length + " byte(s), expected " + BEACON_LEN + "\n",
    );
  }
  const result = dumpBeacon(buf, psk);
  process.stdout.write(result.lines.join("\n") + "\n");
  return result.verified ? 0 : 1;
}

try {
  process.exitCode = main();
} catch (error) {
  console.error("frame_dump: " + error.message);
  process.exitCode = 1;
}
