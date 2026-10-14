import { SiteId, asSiteId, isSiteId } from "./types.js";
import { PEPPER_BYTES, PSK_BYTES } from "./crypto.js";

export type Env = Readonly<Record<string, string | undefined>>;

export const PREFIX = "GC_";

export const FIELD_SITES = "GC_SITES";
export const FIELD_PEPPER = "GC_PEPPER";
export const FIELD_MQTT_URL = "GC_MQTT_URL";
export const FIELD_HTTP_PORT = "GC_HTTP_PORT";
export const FIELD_OPERATOR_TOKEN = "GC_OPERATOR_TOKEN";
export const FIELD_WHATSAPP_VERIFY_TOKEN = "GC_WHATSAPP_VERIFY_TOKEN";
export const FIELD_WHATSAPP_APP_SECRET = "GC_WHATSAPP_APP_SECRET";
export const FIELD_CONTACT_WINDOW_S = "GC_CONTACT_WINDOW_S";
export const FIELD_CHALLENGE_WINDOW_S = "GC_CHALLENGE_WINDOW_S";
export const FIELD_PSK = "GC_PSK";
export const FIELD_DB_PATH = "GC_DB_PATH";
export const FIELD_BEACON_PORT = "GC_BEACON_PORT";
export const FIELD_CONTACT_RETENTION_S = "GC_CONTACT_RETENTION_S";
export const FIELD_TELEMETRY_RETENTION_S = "GC_TELEMETRY_RETENTION_S";

export const DEFAULT_DB_PATH = "data/groundcontrol.db";
export const DEFAULT_BEACON_PORT = 4444;

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const PORT_MIN = 1;
const PORT_MAX = 65535;
const WINDOW_MIN_S = 1;
const WINDOW_MAX_S = 365 * 24 * 60 * 60;
const RETENTION_MIN_S = 60;
const RETENTION_MAX_S = 365 * 24 * 60 * 60;
export const DEFAULT_CONTACT_RETENTION_S = 90 * 24 * 60 * 60;
export const DEFAULT_TELEMETRY_RETENTION_S = 30 * 24 * 60 * 60;

export type ControllerConfig = {
  readonly sites: readonly SiteId[];
  readonly peppers: ReadonlyMap<SiteId, Buffer>;
  readonly psks: ReadonlyMap<SiteId, Buffer>;
  readonly psk: Buffer | undefined;
  readonly mqttUrl: string;
  readonly brokerUri: string;
  readonly httpPort: number;
  readonly beaconPort: number;
  readonly operatorToken: string;
  readonly whatsappVerifyToken: string;
  readonly whatsappAppSecret: string;
  readonly contactWindowS: number;
  readonly challengeWindowS: number;
  readonly contactRetentionS: number;
  readonly telemetryRetentionS: number;
  readonly dbPath: string;
};

export type ConfigSummary = {
  readonly sites: readonly string[];
  readonly peppersConfigured: readonly string[];
  readonly psksConfigured: readonly string[];
  readonly pskConfigured: boolean;
  readonly mqttUrl: string;
  readonly httpPort: number;
  readonly beaconPort: number;
  readonly operatorTokenConfigured: boolean;
  readonly whatsappVerifyTokenConfigured: boolean;
  readonly whatsappAppSecretConfigured: boolean;
  readonly contactWindowS: number;
  readonly challengeWindowS: number;
  readonly contactRetentionS: number;
  readonly telemetryRetentionS: number;
  readonly dbPath: string;
};

export function pepperFieldForSite(siteId: SiteId): string {
  return `${FIELD_PEPPER}_${siteId.toUpperCase()}`;
}

export function pskFieldForSite(siteId: SiteId): string {
  return `${FIELD_PSK}_${siteId.toUpperCase()}`;
}

function readRequired(env: Env, name: string): string {
  const raw = env[name];
  if (raw === undefined || raw.trim() === "") {
    throw new Error(`missing required environment variable ${name}`);
  }
  return raw.trim();
}

function readRequiredInt(env: Env, name: string, min: number, max: number): number {
  const raw = readRequired(env, name);
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`invalid ${name}: expected an integer in [${min}, ${max}], got "${raw}"`);
  }
  return parsed;
}

function readOptionalInt(
  env: Env,
  name: string,
  min: number,
  max: number,
  fallback: number,
): number {
  const raw = env[name];
  if (raw === undefined || raw.trim() === "") {
    return fallback;
  }
  return readRequiredInt(env, name, min, max);
}

function decodeSecretBytes(name: string, raw: string, expectedBytes: number): Buffer {
  const trimmed = raw.trim();
  if (!BASE64_RE.test(trimmed)) {
    throw new Error(`invalid ${name}: expected base64`);
  }
  const decoded = Buffer.from(trimmed, "base64");
  if (decoded.length !== expectedBytes) {
    throw new Error(
      `invalid ${name}: expected ${expectedBytes} bytes of base64, got ${decoded.length}`,
    );
  }
  return decoded;
}

function readRequiredSecret(env: Env, name: string, expectedBytes: number): Buffer {
  return decodeSecretBytes(name, readRequired(env, name), expectedBytes);
}

function readOptionalSecret(
  env: Env,
  name: string,
  expectedBytes: number,
): Buffer | undefined {
  const raw = env[name];
  if (raw === undefined || raw.trim() === "") {
    return undefined;
  }
  return decodeSecretBytes(name, raw, expectedBytes);
}

function readSites(env: Env): SiteId[] {
  const raw = readRequired(env, FIELD_SITES);
  const parts = raw
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
  if (parts.length === 0) {
    throw new Error(`invalid ${FIELD_SITES}: no site ids given`);
  }
  const seen = new Set<string>();
  const sites: SiteId[] = [];
  for (const part of parts) {
    if (!isSiteId(part)) {
      throw new Error(`invalid ${FIELD_SITES}: "${part}" is not a site id in [0, 65535]`);
    }
    if (seen.has(part)) {
      throw new Error(`invalid ${FIELD_SITES}: duplicate site id "${part}"`);
    }
    seen.add(part);
    sites.push(asSiteId(part));
  }
  return sites;
}

function readOptionalPerSiteSecrets(
  env: Env,
  sites: readonly SiteId[],
  globalName: string,
  fieldForSite: (siteId: SiteId) => string,
  expectedBytes: number,
): Map<SiteId, Buffer> {
  const out = new Map<SiteId, Buffer>();
  for (const site of sites) {
    const field = fieldForSite(site);
    const raw = env[field] ?? env[globalName];
    if (raw === undefined || raw.trim() === "") {
      continue;
    }
    out.set(site, decodeSecretBytes(field, raw, expectedBytes));
  }
  return out;
}

export function loadConfig(env: Env = process.env): ControllerConfig {
  const sites = readSites(env);
  const basePepper = readRequiredSecret(env, FIELD_PEPPER, PEPPER_BYTES);
  const peppers = new Map<SiteId, Buffer>();
  for (const site of sites) {
    const field = pepperFieldForSite(site);
    const raw = env[field];
    peppers.set(
      site,
      raw === undefined || raw.trim() === "" ? basePepper : decodeSecretBytes(field, raw, PEPPER_BYTES),
    );
  }
  const psks = readOptionalPerSiteSecrets(
    env,
    sites,
    FIELD_PSK,
    pskFieldForSite,
    PSK_BYTES,
  );
  const psk = readOptionalSecret(env, FIELD_PSK, PSK_BYTES);
  const mqttUrl = readRequired(env, FIELD_MQTT_URL);
  const httpPort = readRequiredInt(env, FIELD_HTTP_PORT, PORT_MIN, PORT_MAX);
  const beaconPort = env[FIELD_BEACON_PORT] === undefined
    ? DEFAULT_BEACON_PORT
    : readRequiredInt(env, FIELD_BEACON_PORT, PORT_MIN, PORT_MAX);
  const operatorToken = readRequired(env, FIELD_OPERATOR_TOKEN);
  const whatsappVerifyToken = readRequired(env, FIELD_WHATSAPP_VERIFY_TOKEN);
  const whatsappAppSecret = readRequired(env, FIELD_WHATSAPP_APP_SECRET);
  const contactWindowS = readRequiredInt(env, FIELD_CONTACT_WINDOW_S, WINDOW_MIN_S, WINDOW_MAX_S);
  const challengeWindowS = readRequiredInt(
    env,
    FIELD_CHALLENGE_WINDOW_S,
    WINDOW_MIN_S,
    WINDOW_MAX_S,
  );
  const dbPath = env[FIELD_DB_PATH]?.trim() ?? DEFAULT_DB_PATH;
  const contactRetentionS = readOptionalInt(
    env,
    FIELD_CONTACT_RETENTION_S,
    RETENTION_MIN_S,
    RETENTION_MAX_S,
    DEFAULT_CONTACT_RETENTION_S,
  );
  const telemetryRetentionS = readOptionalInt(
    env,
    FIELD_TELEMETRY_RETENTION_S,
    RETENTION_MIN_S,
    RETENTION_MAX_S,
    DEFAULT_TELEMETRY_RETENTION_S,
  );

  return {
    sites,
    peppers,
    psks,
    psk,
    mqttUrl,
    brokerUri: mqttUrl,
    httpPort,
    beaconPort,
    operatorToken,
    whatsappVerifyToken,
    whatsappAppSecret,
    contactWindowS,
    challengeWindowS,
    contactRetentionS,
    telemetryRetentionS,
    dbPath: dbPath.length > 0 ? dbPath : DEFAULT_DB_PATH,
  };
}

export function pepperFor(config: ControllerConfig, siteId: SiteId): Buffer {
  const pepper = config.peppers.get(siteId);
  if (pepper === undefined) {
    throw new Error(`no pepper configured for site ${siteId}`);
  }
  return pepper;
}

export function pskFor(config: ControllerConfig, siteId: SiteId): Buffer {
  const psk = config.psks.get(siteId) ?? config.psk;
  if (psk === undefined) {
    throw new Error(`no psk configured for site ${siteId}`);
  }
  return psk;
}

export function pskForSiteNumber(config: ControllerConfig, siteId: number): Buffer | undefined {
  const wanted = String(siteId);
  for (const [key, value] of config.psks) {
    if (String(key) === wanted) {
      return value;
    }
  }
  return config.psk;
}

export function describeConfig(config: ControllerConfig): ConfigSummary {
  return {
    sites: config.sites.map((site) => String(site)),
    peppersConfigured: [...config.peppers.keys()].map((site) => String(site)),
    psksConfigured: [...config.psks.keys()].map((site) => String(site)),
    pskConfigured: config.psk !== undefined,
    mqttUrl: config.mqttUrl,
    httpPort: config.httpPort,
    beaconPort: config.beaconPort,
    operatorTokenConfigured: config.operatorToken.length > 0,
    whatsappVerifyTokenConfigured: config.whatsappVerifyToken.length > 0,
    whatsappAppSecretConfigured: config.whatsappAppSecret.length > 0,
    contactWindowS: config.contactWindowS,
    challengeWindowS: config.challengeWindowS,
    contactRetentionS: config.contactRetentionS,
    telemetryRetentionS: config.telemetryRetentionS,
    dbPath: config.dbPath,
  };
}
