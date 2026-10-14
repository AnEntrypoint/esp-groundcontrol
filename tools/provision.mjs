#!/usr/bin/env node
import { randomBytes, createHash } from "node:crypto";
import { mkdirSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..");
const DEFAULT_OUT_DIR = resolve(REPO_ROOT, "..", "gc-secrets");

const SECRET_BYTES = 32;
const ID_MAX = 65535;
const PORT_MIN = 1;
const PORT_MAX = 65535;

const DEFAULTS = {
  site: "1",
  device: "1",
  broker: "mqtts://broker.example.net:8883",
  manifest: "https://ota.example.net/esp-groundcontrol/manifest.json",
  "beacon-host": "beacon.example.net",
  "beacon-port": "41234",
};

const ENV_FOR = {
  site: "GC_SITE_ID",
  device: "GC_DEVICE_ID",
  broker: "GC_BROKER_URL",
  manifest: "GC_MANIFEST_URL",
  "beacon-host": "GC_BEACON_HOST",
  "beacon-port": "GC_BEACON_PORT",
};

const USAGE = [
  "usage: node tools/provision.mjs --site <n> --device <n> [options]",
  "",
  "  --site <0-65535>          site id           env GC_SITE_ID",
  "  --device <0-65535>        device id         env GC_DEVICE_ID",
  "  --broker <url>            MQTT broker URI   env GC_BROKER_URL",
  "  --manifest <url>          OTA manifest URL  env GC_MANIFEST_URL",
  "  --beacon-host <host>      beacon UDP host   env GC_BEACON_HOST",
  "  --beacon-port <1-65535>   beacon UDP port   env GC_BEACON_PORT",
  "  --out <dir>               output directory, must resolve outside the repo",
  "                            default: ../gc-secrets",
  "",
  "Writes <site>-<device>.json and <site>-<device>.nvs.csv into <dir>.",
  "Prints only sha256 fingerprints and controller env lines; the secrets",
  "themselves are written to disk and never to stdout.",
].join("\n");

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

function integerInRange(label, raw, lo, hi) {
  const text = String(raw).trim();
  if (!/^[0-9]{1,5}$/.test(text)) {
    throw new Error(label + " must be a decimal integer in [" + lo + ", " + hi + "], got " + JSON.stringify(raw));
  }
  const value = Number(text);
  if (value < lo || value > hi) {
    throw new Error(label + " must be in [" + lo + ", " + hi + "], got " + text);
  }
  return value;
}

function fingerprint(bytes) {
  return createHash("sha256").update(bytes).digest("hex").slice(0, 8);
}

function csvCell(value) {
  const text = String(value);
  return /[",\n]/.test(text) ? '"' + text.split('"').join('""') + '"' : text;
}

function settleOutDir(raw) {
  const target = raw === undefined ? DEFAULT_OUT_DIR : resolve(process.cwd(), raw);
  try {
    mkdirSync(target, { recursive: true });
  } catch (error) {
    throw new Error("cannot create output directory " + target + ": " + error.message);
  }
  if (!statSync(target).isDirectory()) {
    throw new Error("output path is not a directory: " + target);
  }
  const settled = realpathSync(target);
  const rel = relative(realpathSync(REPO_ROOT), settled);
  if (rel === "" || (!rel.startsWith("..") && !isAbsolute(rel))) {
    throw new Error(
      "refusing to write secrets inside the repo: " + settled + " is under " + REPO_ROOT + "; pass --out outside it",
    );
  }
  return settled;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help !== undefined) {
    process.stdout.write(USAGE + "\n");
    return 0;
  }

  const pick = (name) => args[name] ?? process.env[ENV_FOR[name]] ?? DEFAULTS[name];
  const site = integerInRange("site", pick("site"), 0, ID_MAX);
  const device = integerInRange("device", pick("device"), 0, ID_MAX);
  const beaconPort = integerInRange("beacon-port", pick("beacon-port"), PORT_MIN, PORT_MAX);
  const brokerUrl = String(pick("broker"));
  const manifestUrl = String(pick("manifest"));
  const beaconHost = String(pick("beacon-host"));

  const psk = randomBytes(SECRET_BYTES);
  const pepper = randomBytes(SECRET_BYTES);

  const outDir = settleOutDir(args.out);
  const stem = site + "-" + device;
  const outJson = join(outDir, stem + ".json");
  const outCsv = join(outDir, stem + ".nvs.csv");

  const secret = {
    site_id: site,
    device_id: device,
    broker_url: brokerUrl,
    manifest_url: manifestUrl,
    beacon_host: beaconHost,
    beacon_port: beaconPort,
    psk_hex: psk.toString("hex"),
    psk_base64: psk.toString("base64"),
    pepper_hex: pepper.toString("hex"),
    pepper_base64: pepper.toString("base64"),
    psk_sha256_prefix: fingerprint(psk),
    pepper_sha256_prefix: fingerprint(pepper),
  };

  const nvsRows = [
    ["gc", "namespace", "", ""],
    ["site", "data", "u16", site],
    ["dev", "data", "u16", device],
    ["psk", "data", "hex2bin", psk.toString("hex")],
    ["pep", "data", "hex2bin", pepper.toString("hex")],
    ["bcnt", "data", "u32", 0],
    ["cseq", "data", "u32", 0],
    ["brkurl", "data", "string", brokerUrl],
    ["manurl", "data", "string", manifestUrl],
    ["bcnhost", "data", "string", beaconHost],
    ["bcnport", "data", "u16", beaconPort],
  ];

  const csv = ["key,type,encoding,value"]
    .concat(nvsRows.map((row) => row.map(csvCell).join(",")))
    .join("\n") + "\n";

  writeFileSync(outJson, JSON.stringify(secret, null, 2) + "\n", { mode: 0o600 });
  writeFileSync(outCsv, csv, { mode: 0o600 });

  const jsonName = basename(outJson);
  const lines = [
    "site " + site + "  device " + device,
    "psk     sha256:" + fingerprint(psk) + "  (" + SECRET_BYTES + " bytes)  " + outJson,
    "pepper  sha256:" + fingerprint(pepper) + "  (" + SECRET_BYTES + " bytes)  " + outJson,
    "nvs csv  " + outCsv,
    "",
    "controller env:",
    "GC_SITES=" + site,
    "GC_PEPPER_" + site + "=<see " + jsonName + ":pepper_base64>",
    "GC_PSK_" + site + "=<see " + jsonName + ":psk_base64>",
    "GC_MQTT_URL=" + brokerUrl,
    "GC_BEACON_PORT=" + beaconPort,
    "GC_HTTP_PORT=8080",
    "GC_DB_PATH=data/groundcontrol.db",
    "GC_CONTACT_WINDOW_S=3600",
    "GC_CHALLENGE_WINDOW_S=600",
    "GC_OPERATOR_TOKEN=<set-me>",
    "GC_WHATSAPP_VERIFY_TOKEN=<set-me>",
    "GC_WHATSAPP_APP_SECRET=<set-me>",
  ];
  process.stdout.write(lines.join("\n") + "\n");
  return 0;
}

try {
  process.exitCode = main();
} catch (error) {
  console.error("provision: " + error.message);
  process.exitCode = 1;
}
