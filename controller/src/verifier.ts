import { randomInt } from "node:crypto";
import { ControllerConfig } from "./config.js";
import { constantTimeEqual } from "./crypto.js";
import { Store } from "./store.js";
import {
  DenyReason,
  MacKey,
  NumberKey,
  SiteId,
  Verdict,
  VerifyMode,
  isVerifyMode,
} from "./types.js";
import {
  getBlock,
  initStrikes,
  isBlocked,
  recordEvent,
  recordStrike,
} from "./strikes.js";

export type PortalRequestBody = {
  readonly code?: string | number;
};

export type DecideVerificationInput = {
  readonly siteId: SiteId;
  readonly deviceId: number;
  readonly req: PortalRequestBody;
  readonly numberKey: NumberKey;
  readonly macKey: MacKey;
  readonly mode: VerifyMode;
  readonly reqId?: string;
};

export type VerificationDeps = {
  readonly store: Store;
  readonly config: ControllerConfig;
  readonly softBlockS?: number;
  readonly strikeLimit?: number;
};

export type VerificationOutcome = Verdict & {
  readonly allowedUntil: number;
  readonly blockedUntil: number;
  readonly hint: string;
};

type PendingChallenge = {
  readonly code: string;
  readonly expiresAtS: number;
  matchedAtS: number;
  attempts: number;
};

const DEFAULT_ACCESS_TTL_S = 86400;
const CHALLENGE_CODE_SPACE = 1000000;
const CHALLENGE_CODE_LEN = 6;
const MAX_CODE_ATTEMPTS = 10;
const SWEEP_INTERVAL_S = 60;

let deps: VerificationDeps | undefined;
let lastSweepAtS = 0;
const challenges = new Map<NumberKey, PendingChallenge>();

export function initVerification(next: VerificationDeps): void {
  deps = next;
  initStrikes({
    store: next.store,
    ...(next.softBlockS === undefined ? {} : { softBlockS: next.softBlockS }),
    ...(next.strikeLimit === undefined ? {} : { strikeLimit: next.strikeLimit }),
  });
}

export function decideVerification(input: DecideVerificationInput): VerificationOutcome {
  const current = deps;
  const nowS = nowSeconds();
  if (current === undefined) {
    return denyOutcome(input, "controller_unreachable", 0, 0, false, "");
  }
  sweepChallenges(nowS);
  if (!isVerifyMode(input.mode)) {
    return denyUnverified(input, nowS);
  }
  const block = isBlocked(input.numberKey, input.macKey);
  const record = getBlock(input.numberKey);
  const strikes = record === undefined ? 0 : record.strikes;
  if (block.permanent) {
    return denyOutcome(input, "strike_limit", strikes, 0, true, "");
  }
  if (block.blocked) {
    const blockedUntil = record === undefined ? nowS + block.remainingSeconds : record.blockedUntil;
    return denyOutcome(input, "not_verified", strikes, blockedUntil, false, "");
  }
  return input.mode === "contact"
    ? decideContact(current, input, nowS, strikes)
    : decideChallenge(current, input, nowS, strikes);
}

export function matchChallengeCode(numberKey: NumberKey, code: string): boolean {
  const pending = challenges.get(numberKey);
  if (pending === undefined) {
    return false;
  }
  const candidate = normalizeCode(code);
  if (candidate.length !== CHALLENGE_CODE_LEN) {
    return false;
  }
  const nowS = nowSeconds();
  if (pending.expiresAtS <= nowS || pending.matchedAtS > 0) {
    return false;
  }
  pending.attempts += 1;
  if (pending.attempts > MAX_CODE_ATTEMPTS) {
    challenges.delete(numberKey);
    return false;
  }
  if (!constantTimeEqual(candidate, pending.code)) {
    return false;
  }
  pending.matchedAtS = nowS;
  return true;
}

export function matchChallenge(numberKey: NumberKey, text: string): boolean {
  for (const candidate of codeCandidates(text)) {
    if (matchChallengeCode(numberKey, candidate)) {
      return true;
    }
  }
  return false;
}

export function toVerdict(reqId: string, outcome: VerificationOutcome): Verdict {
  return {
    reqId,
    allow: outcome.allow,
    allowedUntilS: outcome.allowedUntilS,
    blockedUntilS: outcome.blockedUntilS,
    strikes: outcome.strikes,
    permanent: outcome.permanent,
    reason: outcome.reason,
    challengeHint: outcome.challengeHint,
  };
}

function decideContact(
  current: VerificationDeps,
  input: DecideVerificationInput,
  nowS: number,
  strikes: number,
): VerificationOutcome {
  const windowS = current.config.contactWindowS;
  const last = current.store.lastContactAt(input.numberKey);
  if (last === undefined || nowS - last >= windowS) {
    return denyUnverified(input, nowS);
  }
  logEvent(input, nowS, "none", strikes);
  return allowOutcome(input, last + windowS, strikes);
}

function decideChallenge(
  current: VerificationDeps,
  input: DecideVerificationInput,
  nowS: number,
  strikes: number,
): VerificationOutcome {
  if (current.store.lastContactAt(input.numberKey) === undefined) {
    return denyUnverified(input, nowS);
  }
  const expired = dropExpiredChallenge(input.numberKey, nowS);
  const pending = challenges.get(input.numberKey);
  if (pending !== undefined) {
    if (pending.matchedAtS > 0 || matchesCode(pending, normalizeCode(input.req.code))) {
      challenges.delete(input.numberKey);
      logEvent(input, nowS, "none", strikes);
      return allowOutcome(input, nowS + accessTtlSeconds(), strikes);
    }
    if (pending.attempts >= MAX_CODE_ATTEMPTS) {
      challenges.delete(input.numberKey);
      return denyUnverified(input, nowS);
    }
    return denyOutcome(input, "pending", strikes, 0, false, challengeHint(pending.code));
  }
  const code = issueCode();
  challenges.set(input.numberKey, {
    code,
    expiresAtS: nowS + current.config.challengeWindowS,
    matchedAtS: 0,
    attempts: 0,
  });
  const reason: DenyReason = expired ? "expired" : "pending";
  logEvent(input, nowS, reason, strikes);
  return denyOutcome(input, reason, strikes, 0, false, challengeHint(code));
}

function dropExpiredChallenge(numberKey: NumberKey, nowS: number): boolean {
  const pending = challenges.get(numberKey);
  if (pending === undefined || pending.expiresAtS > nowS) {
    return false;
  }
  challenges.delete(numberKey);
  return true;
}

function matchesCode(pending: PendingChallenge, candidate: string): boolean {
  if (candidate.length !== CHALLENGE_CODE_LEN) {
    return false;
  }
  pending.attempts += 1;
  if (!constantTimeEqual(candidate, pending.code)) {
    return false;
  }
  pending.matchedAtS = nowSeconds();
  return true;
}

function denyUnverified(input: DecideVerificationInput, nowS: number): VerificationOutcome {
  const record = recordStrike(input.numberKey, input.macKey);
  logEvent(input, nowS, "not_verified", record.strikes);
  return denyOutcome(
    input,
    "not_verified",
    record.strikes,
    record.blockedUntil,
    record.permanent,
    "",
  );
}

function allowOutcome(
  input: DecideVerificationInput,
  allowedUntil: number,
  strikes: number,
): VerificationOutcome {
  return {
    reqId: input.reqId ?? "",
    allow: true,
    allowedUntilS: allowedUntil,
    allowedUntil,
    blockedUntilS: 0,
    blockedUntil: 0,
    strikes,
    permanent: false,
    reason: "none",
    challengeHint: "",
    hint: "",
  };
}

function denyOutcome(
  input: DecideVerificationInput,
  reason: DenyReason,
  strikes: number,
  blockedUntil: number,
  permanent: boolean,
  hint: string,
): VerificationOutcome {
  return {
    reqId: input.reqId ?? "",
    allow: false,
    allowedUntilS: 0,
    allowedUntil: 0,
    blockedUntilS: blockedUntil,
    blockedUntil,
    strikes,
    permanent,
    reason,
    challengeHint: hint,
    hint,
  };
}

function logEvent(
  input: DecideVerificationInput,
  atS: number,
  reason: DenyReason,
  strikes: number,
): void {
  recordEvent({
    numberKey: input.numberKey,
    macKey: input.macKey,
    siteId: input.siteId,
    deviceId: input.deviceId,
    reason,
    strikes,
    atS,
  });
}

function sweepChallenges(nowS: number): void {
  if (nowS - lastSweepAtS < SWEEP_INTERVAL_S) {
    return;
  }
  lastSweepAtS = nowS;
  for (const [numberKey, pending] of challenges) {
    if (pending.expiresAtS <= nowS) {
      challenges.delete(numberKey);
    }
  }
}

function challengeHint(code: string): string {
  return `send ${code} to the WhatsApp bot`;
}

function normalizeCode(raw: string | number | undefined): string {
  return raw === undefined ? "" : String(raw).replace(/[^0-9]/g, "");
}

function codeCandidates(text: string): string[] {
  const trimmed = text.trim();
  if (trimmed === "") {
    return [];
  }
  const out = new Set<string>();
  const whole = normalizeCode(trimmed);
  if (whole !== "") {
    out.add(whole);
  }
  for (const token of trimmed.split(/\s+/)) {
    const digits = normalizeCode(token);
    if (digits !== "") {
      out.add(digits);
    }
  }
  return [...out];
}

function issueCode(): string {
  return String(randomInt(CHALLENGE_CODE_SPACE)).padStart(CHALLENGE_CODE_LEN, "0");
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function readEnvInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined) {
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function accessTtlSeconds(): number {
  return readEnvInt("GC_ACCESS_TTL_S", DEFAULT_ACCESS_TTL_S);
}
