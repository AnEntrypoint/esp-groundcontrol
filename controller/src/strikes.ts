import { blockedForS, isBlockActive, Store } from "./store.js";
import { BlockRecord, MacKey, NumberKey, StrikeRecord } from "./types.js";

export type BlockState = {
  readonly blocked: boolean;
  readonly permanent: boolean;
  readonly remainingSeconds: number;
};

export type StrikeDeps = {
  readonly store: Store;
  readonly softBlockS?: number;
  readonly strikeLimit?: number;
};

export const DEFAULT_SOFT_BLOCK_S = 86400;
export const DEFAULT_STRIKE_LIMIT = 3;

const EVENT_LOG_CAP = 1000;

let deps: StrikeDeps | undefined;
const macIndex = new Map<MacKey, NumberKey>();
const events: StrikeRecord[] = [];

export function initStrikes(next: StrikeDeps): void {
  deps = next;
}

function requireDeps(): StrikeDeps {
  if (deps === undefined) {
    throw new Error("strikes not initialised: call initStrikes({ store })");
  }
  return deps;
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

function softBlockSeconds(current: StrikeDeps): number {
  return current.softBlockS ?? readEnvInt("GC_SOFT_BLOCK_S", DEFAULT_SOFT_BLOCK_S);
}

function strikeLimitOf(current: StrikeDeps): number {
  return current.strikeLimit ?? readEnvInt("GC_STRIKE_LIMIT", DEFAULT_STRIKE_LIMIT);
}

export function getBlock(numberKey: NumberKey): BlockRecord | undefined {
  return requireDeps().store.getBlock(numberKey);
}

export function recordStrike(numberKey: NumberKey, macKey: MacKey): BlockRecord {
  const current = requireDeps();
  const block = current.store.recordStrike({
    numberKey,
    macKey,
    atS: nowSeconds(),
    softBlockS: softBlockSeconds(current),
    strikeLimit: strikeLimitOf(current),
  });
  macIndex.set(macKey, numberKey);
  return block;
}

export function recordEvent(event: StrikeRecord): StrikeRecord {
  events.push(event);
  if (events.length > EVENT_LOG_CAP) {
    events.splice(0, events.length - EVENT_LOG_CAP);
  }
  return event;
}

export function listEvents(limit = 100): StrikeRecord[] {
  const capped = limit > 0 ? limit : 100;
  return events.slice(Math.max(0, events.length - capped));
}

export function isBlocked(numberKey: NumberKey, macKey: MacKey): BlockState {
  const current = requireDeps();
  const nowS = nowSeconds();
  const block = current.store.getBlock(numberKey) ?? blockForMac(current, macKey);
  if (block === undefined) {
    return { blocked: false, permanent: false, remainingSeconds: 0 };
  }
  const blocked = isBlockActive(block, nowS);
  return {
    blocked,
    permanent: block.permanent,
    remainingSeconds: blocked ? blockedForS(block, nowS) : 0,
  };
}

function blockForMac(current: StrikeDeps, macKey: MacKey): BlockRecord | undefined {
  const numberKey = macIndex.get(macKey);
  return numberKey === undefined ? undefined : current.store.getBlock(numberKey);
}

export function unblock(numberKey: NumberKey): BlockRecord | undefined {
  const current = requireDeps();
  current.store.unblock(numberKey, true, nowSeconds());
  return current.store.getBlock(numberKey);
}

export function listBlocked(): BlockRecord[] {
  return requireDeps().store.listPermanentBlocks();
}
