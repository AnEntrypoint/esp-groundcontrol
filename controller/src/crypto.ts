import { createHmac, timingSafeEqual } from "node:crypto";
import {
  KEY_BYTES,
  MAC_BYTES,
  MacKey,
  NumberKey,
  asMacKey,
  asNumberKey,
} from "./types.js";

export const PEPPER_BYTES = 32;
export const PSK_BYTES = 32;

const NUMBER_PREFIX = Buffer.from("n", "ascii");
const MAC_PREFIX = Buffer.from("m", "ascii");
const BEACON_PREFIX = Buffer.from("beacon", "ascii");
const COMMAND_PREFIX = Buffer.from("cmd", "ascii");

const E164_MIN_DIGITS = 7;
const E164_MAX_DIGITS = 15;

export function digitsOfE164(e164: string): string {
  return e164.replace(/[^0-9]/g, "");
}

export function macBytesOf(mac: Uint8Array | string): Uint8Array {
  if (typeof mac !== "string") {
    if (mac.length !== MAC_BYTES) {
      throw new Error(`invalid MAC: expected ${MAC_BYTES} bytes, got ${mac.length}`);
    }
    return mac;
  }
  const hex = mac.replace(/[^0-9a-fA-F]/g, "");
  if (hex.length !== MAC_BYTES * 2) {
    throw new Error(`invalid MAC string: ${mac}`);
  }
  const out = new Uint8Array(MAC_BYTES);
  for (let i = 0; i < MAC_BYTES; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function keyBuffer(key: Uint8Array): Buffer {
  if (key.length === 0) {
    throw new Error("invalid key: empty");
  }
  return Buffer.from(key);
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Buffer {
  return createHmac("sha256", keyBuffer(key)).update(Buffer.from(data)).digest();
}

function truncatedHmacHex(key: Uint8Array, parts: readonly Uint8Array[]): string {
  const hmac = createHmac("sha256", keyBuffer(key));
  for (const part of parts) {
    hmac.update(Buffer.from(part));
  }
  return hmac.digest().subarray(0, KEY_BYTES).toString("hex");
}

export function numberKey(pepper: Uint8Array, e164: string): NumberKey {
  const digits = digitsOfE164(e164);
  if (digits.length < E164_MIN_DIGITS || digits.length > E164_MAX_DIGITS) {
    throw new Error(`invalid E.164 number: ${e164}`);
  }
  if (pepper.length !== PEPPER_BYTES) {
    throw new Error(`invalid pepper: expected ${PEPPER_BYTES} bytes, got ${pepper.length}`);
  }
  return asNumberKey(truncatedHmacHex(pepper, [NUMBER_PREFIX, Buffer.from(digits, "ascii")]));
}

export function macKey(pepper: Uint8Array, mac: Uint8Array | string): MacKey {
  if (pepper.length !== PEPPER_BYTES) {
    throw new Error(`invalid pepper: expected ${PEPPER_BYTES} bytes, got ${pepper.length}`);
  }
  return asMacKey(truncatedHmacHex(pepper, [MAC_PREFIX, macBytesOf(mac)]));
}

export function beaconTag(psk: Uint8Array, payload: Uint8Array): string {
  if (payload.length !== 8) {
    throw new Error(`invalid beacon payload: expected 8 bytes, got ${payload.length}`);
  }
  return truncatedHmacHex(psk, [BEACON_PREFIX, payload]);
}

export function commandTag(psk: Uint8Array, payload: Uint8Array): string {
  return truncatedHmacHex(psk, [COMMAND_PREFIX, payload]);
}

export function commandPayload(sequence: number, body: Uint8Array): Buffer {
  if (!Number.isInteger(sequence) || sequence < 0 || sequence > 0xffffffff) {
    throw new Error(`invalid command sequence: ${sequence}`);
  }
  const head = Buffer.alloc(4);
  head.writeUInt32BE(sequence, 0);
  return Buffer.concat([head, Buffer.from(body)]);
}

export function toBytes(value: string | Uint8Array): Buffer {
  return typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value);
}

export function constantTimeEqual(a: string | Uint8Array, b: string | Uint8Array): boolean {
  const left = toBytes(a);
  const right = toBytes(b);
  if (left.length !== right.length) {
    timingSafeEqual(left, left);
    return false;
  }
  return timingSafeEqual(left, right);
}

export function constantTimeEqualHex(a: string, b: string): boolean {
  const left = Buffer.from(a, "hex");
  const right = Buffer.from(b, "hex");
  if (left.length !== right.length) {
    timingSafeEqual(left, left);
    return false;
  }
  return timingSafeEqual(left, right);
}

export function verifyCommandSignature(
  psk: Uint8Array,
  sequence: number,
  body: Uint8Array,
  presented: string | Uint8Array,
): boolean {
  const expected = commandTag(psk, commandPayload(sequence, body));
  return constantTimeEqual(expected, presented);
}

export function verifyBeaconTag(psk: Uint8Array, payload: Uint8Array, presented: string): boolean {
  return constantTimeEqualHex(beaconTag(psk, payload), presented);
}
