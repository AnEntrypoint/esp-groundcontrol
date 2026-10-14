import { createHmac } from "node:crypto";

const KEY_BYTES = 8;
const PEPPER_BYTES = 32;
const PSK_BYTES = 32;
const E164_MIN_DIGITS = 7;
const E164_MAX_DIGITS = 15;

const NUMBER_PREFIX = Buffer.from("n", "ascii");
const MAC_PREFIX = Buffer.from("m", "ascii");
const BEACON_PREFIX = Buffer.from("beacon", "ascii");
const COMMAND_PREFIX = Buffer.from("cmd", "ascii");

function truncatedHmacHex(key, parts) {
  const hmac = createHmac("sha256", Buffer.from(key));
  for (const part of parts) {
    hmac.update(Buffer.from(part));
  }
  return hmac.digest().subarray(0, KEY_BYTES).toString("hex");
}

export function numberKey(pepper, e164) {
  const digits = e164.replace(/[^0-9]/g, "");
  if (digits.length < E164_MIN_DIGITS || digits.length > E164_MAX_DIGITS) {
    throw new Error(`invalid E.164 number: ${e164}`);
  }
  if (pepper.length !== PEPPER_BYTES) {
    throw new Error(`invalid pepper: expected ${PEPPER_BYTES} bytes, got ${pepper.length}`);
  }
  return truncatedHmacHex(pepper, [NUMBER_PREFIX, Buffer.from(digits, "ascii")]);
}

export function macKey(pepper, mac) {
  return truncatedHmacHex(pepper, [MAC_PREFIX, Buffer.from(mac)]);
}

export function beaconTag(psk, payload) {
  if (payload.length !== 8) {
    throw new Error(`invalid beacon payload: expected 8 bytes, got ${payload.length}`);
  }
  return truncatedHmacHex(psk, [BEACON_PREFIX, Buffer.from(payload)]);
}

export function commandTag(psk, sequence, body) {
  const head = Buffer.alloc(4);
  head.writeUInt32BE(sequence, 0);
  return truncatedHmacHex(psk, [COMMAND_PREFIX, head, Buffer.from(body)]);
}

const VECTOR_PEPPER = Buffer.alloc(PEPPER_BYTES, 0x11);
const VECTOR_PSK = Buffer.alloc(PSK_BYTES, 0x22);
const VECTOR_MAC = Buffer.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
const VECTOR_BEACON_PAYLOAD = Buffer.from("1100010200000007", "hex");

const CASES = [
  ["number +27821234567", () => numberKey(VECTOR_PEPPER, "+27821234567"), "cdbdd22167e29534"],
  ["number 27 82 123 4567", () => numberKey(VECTOR_PEPPER, "27 82 123 4567"), "cdbdd22167e29534"],
  ["number 27821234567", () => numberKey(VECTOR_PEPPER, "27821234567"), "cdbdd22167e29534"],
  ["number +27-82-123-4567", () => numberKey(VECTOR_PEPPER, "+27-82-123-4567"), "cdbdd22167e29534"],
  ["mac aa:bb:cc:dd:ee:ff", () => macKey(VECTOR_PEPPER, VECTOR_MAC), "c60f22d908a65bea"],
  ["beacon 1100010200000007", () => beaconTag(VECTOR_PSK, VECTOR_BEACON_PAYLOAD), "bc296784e9518e5e"],
];

function main() {
  let failures = 0;
  for (const [name, run, expected] of CASES) {
    let actual;
    try {
      actual = run();
    } catch (error) {
      console.error(`FAIL ${name}: threw ${error.message}`);
      failures += 1;
      continue;
    }
    if (actual !== expected) {
      console.error(`FAIL ${name}: got ${actual}, expected ${expected}`);
      failures += 1;
    } else {
      console.log(`ok   ${name} -> ${actual}`);
    }
  }
  const commandSequence = 7;
  const commandBody = Buffer.from("unblock", "ascii");
  const tag = commandTag(VECTOR_PSK, commandSequence, commandBody);
  console.log(`info command tag seq=7 body=unblock -> ${tag}`);

  if (failures > 0) {
    console.error(`${failures} vector(s) disagree with docs/TEST_VECTORS.md`);
    process.exitCode = 1;
  }
}

main();
