declare const brand: unique symbol;

type Brand<B extends string> = { readonly [brand]: B };

export type SiteId = string & Brand<"SiteId">;
export type DeviceKey = string & Brand<"DeviceKey">;
export type NumberKey = string & Brand<"NumberKey">;
export type MacKey = string & Brand<"MacKey">;

export const KEY_HEX_LEN = 16;
export const KEY_BYTES = 8;
export const MAC_BYTES = 6;
export const REQ_ID_HEX_LEN = 16;
export const SITE_ID_MAX = 65535;
export const DEVICE_ID_MAX = 65535;
export const BEACON_LEN = 16;
export const BEACON_PAYLOAD_LEN = 8;

const KEY_HEX_RE = /^[0-9a-f]{16}$/;
const REQ_ID_HEX_RE = /^[0-9a-f]{16}$/;

export function isSiteId(value: string): boolean {
  if (!/^[0-9]{1,5}$/.test(value)) {
    return false;
  }
  return Number(value) <= SITE_ID_MAX;
}

export function isDeviceId(value: number): boolean {
  return Number.isInteger(value) && value >= 0 && value <= DEVICE_ID_MAX;
}

export function isKeyHex(value: string): boolean {
  return KEY_HEX_RE.test(value);
}

export function isReqIdHex(value: string): boolean {
  return REQ_ID_HEX_RE.test(value);
}

export function asSiteId(value: string): SiteId {
  if (!isSiteId(value)) {
    throw new Error(`invalid SiteId: ${value}`);
  }
  return value as SiteId;
}

export function siteIdNumber(siteId: SiteId): number {
  return Number(siteId);
}

export function asNumberKey(value: string): NumberKey {
  if (!isKeyHex(value)) {
    throw new Error(`invalid NumberKey: ${value}`);
  }
  return value as NumberKey;
}

export function asMacKey(value: string): MacKey {
  if (!isKeyHex(value)) {
    throw new Error(`invalid MacKey: ${value}`);
  }
  return value as MacKey;
}

export function asDeviceKey(value: string): DeviceKey {
  if (!isKeyHex(value)) {
    throw new Error(`invalid DeviceKey: ${value}`);
  }
  return value as DeviceKey;
}

export function asReqId(value: string): string {
  if (!isReqIdHex(value)) {
    throw new Error(`invalid request id: ${value}`);
  }
  return value;
}

export const VERIFY_MODES = ["contact", "challenge"] as const;
export type VerifyMode = (typeof VERIFY_MODES)[number];

export const DENY_REASONS = [
  "none",
  "pending",
  "not_verified",
  "strike_limit",
  "controller_unreachable",
  "quota_reserve",
  "expired",
] as const;
export type DenyReason = (typeof DENY_REASONS)[number];

export const CLIENT_STATES = [
  "new",
  "pending",
  "allowed",
  "soft_blocked",
  "permanently_blocked",
] as const;
export type ClientState = (typeof CLIENT_STATES)[number];

export const SLOTS = ["unknown", "factory", "ota_0", "ota_1"] as const;
export type Slot = (typeof SLOTS)[number];

export const QUOTA_TIERS = ["normal", "reduced", "heartbeat", "reserve"] as const;
export type QuotaTier = (typeof QUOTA_TIERS)[number];

export const ESCALATION_STEPS = [
  "none",
  "retry_link",
  "reresolve_dns",
  "modem_api_reboot",
  "modem_power_cycle",
  "alarm_only",
] as const;
export type EscalationStep = (typeof ESCALATION_STEPS)[number];

export const TELEMETRY_FLAG_ALARM = 0x01;
export const TELEMETRY_FLAG_RESERVE_TRIPPED = 0x02;
export const TELEMETRY_FLAG_FORWARDING_PAUSED = 0x04;
export const TELEMETRY_FLAG_TUNNEL_UP = 0x08;
export const TELEMETRY_FLAG_TRIAL_PENDING = 0x10;
export const TELEMETRY_FLAG_CONTROLLER_UNREACHABLE = 0x20;

export const TELEMETRY_MAX_RECORDS = 24;
export const TELEMETRY_FRAME_MAX = 320;

export type VerifyModeName = VerifyMode;

export type VerificationRequest = {
  readonly reqId: string;
  readonly siteId: SiteId;
  readonly deviceId: number;
  readonly numberKey: NumberKey;
  readonly macKey: MacKey;
  readonly mode: VerifyMode;
  readonly receivedAtS: number;
};

export type Verdict = {
  readonly reqId: string;
  readonly allow: boolean;
  readonly allowedUntilS: number;
  readonly blockedUntilS: number;
  readonly strikes: number;
  readonly permanent: boolean;
  readonly reason: DenyReason;
  readonly challengeHint: string;
};

export type StrikeRecord = {
  readonly numberKey: NumberKey;
  readonly macKey: MacKey;
  readonly siteId: SiteId;
  readonly deviceId: number;
  readonly reason: DenyReason;
  readonly strikes: number;
  readonly atS: number;
};

export type BlockRecord = {
  readonly numberKey: NumberKey;
  readonly macKey: MacKey;
  readonly strikes: number;
  readonly permanent: boolean;
  readonly blockedUntil: number;
  readonly updatedAt: number;
};

export type DeviceRecord = {
  readonly siteId: SiteId;
  readonly deviceId: number;
  readonly lastSeenAt: number;
  readonly fwVersion: number;
  readonly slot: Slot;
  readonly trialPending: boolean;
};

export type TelemetryReading = {
  readonly rssi: number;
  readonly rsrp: number;
  readonly rsrq: number;
  readonly sinr: number;
  readonly clients: number;
  readonly quotaDeltaKb: number;
  readonly uptimeDeltaS: number;
};

export type TelemetryFlags = {
  readonly alarm: boolean;
  readonly reserveTripped: boolean;
  readonly forwardingPaused: boolean;
  readonly tunnelUp: boolean;
  readonly trialPending: boolean;
  readonly controllerUnreachable: boolean;
};

export type TelemetryRecord = {
  readonly siteId: number;
  readonly deviceId: number;
  readonly bootId: number;
  readonly seq: number;
  readonly fwVersion: number;
  readonly slot: Slot;
  readonly flagsMask: number;
  readonly flags: TelemetryFlags;
  readonly readings: readonly TelemetryReading[];
  readonly receivedAtS: number;
};

export type UnblockCommand = {
  readonly numberKey: NumberKey;
  readonly macKey: MacKey;
  readonly sequence: number;
  readonly mac: Uint8Array;
  readonly clearStrikes: boolean;
};

export function decodeTelemetryFlags(mask: number): TelemetryFlags {
  return {
    alarm: (mask & TELEMETRY_FLAG_ALARM) !== 0,
    reserveTripped: (mask & TELEMETRY_FLAG_RESERVE_TRIPPED) !== 0,
    forwardingPaused: (mask & TELEMETRY_FLAG_FORWARDING_PAUSED) !== 0,
    tunnelUp: (mask & TELEMETRY_FLAG_TUNNEL_UP) !== 0,
    trialPending: (mask & TELEMETRY_FLAG_TRIAL_PENDING) !== 0,
    controllerUnreachable: (mask & TELEMETRY_FLAG_CONTROLLER_UNREACHABLE) !== 0,
  };
}

export function encodeTelemetryFlags(flags: TelemetryFlags): number {
  let mask = 0;
  if (flags.alarm) mask |= TELEMETRY_FLAG_ALARM;
  if (flags.reserveTripped) mask |= TELEMETRY_FLAG_RESERVE_TRIPPED;
  if (flags.forwardingPaused) mask |= TELEMETRY_FLAG_FORWARDING_PAUSED;
  if (flags.tunnelUp) mask |= TELEMETRY_FLAG_TUNNEL_UP;
  if (flags.trialPending) mask |= TELEMETRY_FLAG_TRIAL_PENDING;
  if (flags.controllerUnreachable) mask |= TELEMETRY_FLAG_CONTROLLER_UNREACHABLE;
  return mask;
}

export function isDenyReason(value: string): value is DenyReason {
  return (DENY_REASONS as readonly string[]).includes(value);
}

export function isVerifyMode(value: string): value is VerifyMode {
  return (VERIFY_MODES as readonly string[]).includes(value);
}

export function isSlot(value: string): value is Slot {
  return (SLOTS as readonly string[]).includes(value);
}
