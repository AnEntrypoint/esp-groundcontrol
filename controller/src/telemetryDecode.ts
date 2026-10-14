import {
  SLOTS,
  decodeTelemetryFlags,
  type Slot,
  type TelemetryFlags,
  type TelemetryReading,
} from "./types.js";

const VARINT_MAX_BYTES = 10;
const VERSION_SHIFT = 4;
const KIND_MASK = 0x0f;

export class DecodeError extends Error {
  readonly offset: number;

  constructor(offset: number, detail: string) {
    super(`telemetry decode failed at offset ${offset}: ${detail}`);
    this.name = "DecodeError";
    this.offset = offset;
  }
}

export type TelemetryRecord = TelemetryReading;

export type TelemetryFrame = {
  readonly version: number;
  readonly flags: number;
  readonly siteId: number;
  readonly deviceId: number;
  readonly bootId: number;
  readonly seq: number;
  readonly fwVersion: number;
  readonly slot: Slot;
  readonly records: readonly TelemetryRecord[];
};

export function decodeFlags(flags: number): TelemetryFlags {
  return decodeTelemetryFlags(flags);
}

function slotOf(raw: number): Slot {
  return SLOTS[raw] ?? "unknown";
}

function createReader(buf: Buffer) {
  let offset = 0;

  const bounds = (needed: number, field: string): void => {
    if (offset + needed > buf.length) {
      throw new DecodeError(
        offset,
        `short read of ${field}: need ${needed} byte(s), buffer holds ${buf.length}`,
      );
    }
  };

  const u8 = (field: string): number => {
    bounds(1, field);
    const value = buf.readUInt8(offset);
    offset += 1;
    return value;
  };

  const i8 = (field: string): number => {
    bounds(1, field);
    const value = buf.readInt8(offset);
    offset += 1;
    return value;
  };

  const u16 = (field: string): number => {
    bounds(2, field);
    const value = buf.readUInt16LE(offset);
    offset += 2;
    return value;
  };

  const varint = (field: string): number => {
    let value = 0n;
    let shift = 0n;
    for (let index = 0; index < VARINT_MAX_BYTES; index += 1) {
      const byte = u8(`${field} varint byte ${index}`);
      value |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) {
        return Number(value);
      }
      shift += 7n;
    }
    throw new DecodeError(offset, `${field} varint exceeds ${VARINT_MAX_BYTES} bytes`);
  };

  return { u8, i8, u16, varint };
}

export function decodeTelemetry(buf: Buffer): TelemetryFrame {
  const read = createReader(buf);

  const version = read.u8("version");
  const flags = read.u8("flags");
  const siteId = read.u16("siteId");
  const deviceId = read.u16("deviceId");
  const bootId = read.u16("bootId");
  const seq = read.u16("seq");
  const recordCount = read.u8("recordCount");
  const fwVersion = read.u8("fwVersion");
  const slot = read.u8("slot");

  const records: TelemetryRecord[] = [];
  for (let index = 0; index < recordCount; index += 1) {
    const at = `records[${index}]`;
    records.push({
      uptimeDeltaS: read.varint(`${at}.uptimeDeltaS`),
      rssi: read.i8(`${at}.rssi`),
      clients: read.u8(`${at}.clients`),
      rsrp: read.i8(`${at}.rsrp`),
      rsrq: read.i8(`${at}.rsrq`),
      sinr: read.i8(`${at}.sinr`),
      quotaDeltaKb: read.varint(`${at}.quotaDeltaKb`),
    });
  }

  return { version, flags, siteId, deviceId, bootId, seq, fwVersion, slot: slotOf(slot), records };
}

export function frameVersionOf(buf: Buffer): number {
  return buf.readUInt8(0) >>> VERSION_SHIFT;
}

export function frameKindOf(buf: Buffer): number {
  return buf.readUInt8(0) & KIND_MASK;
}
