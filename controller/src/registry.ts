import { store as sharedStore } from "./store.js";
import {
  type BlockRecord,
  type DeviceRecord,
  type SiteId,
  type Slot,
  type TelemetryRecord,
  asSiteId,
  isDeviceId,
} from "./types.js";

export const FW_VERSION_MAX = 255;
export const DEFAULT_SLOT: Slot = "unknown";

export type RegistryStore = {
  open(path: string): Promise<void>;
  upsertDevice(record: DeviceRecord): Promise<void>;
  getDevice(siteId: SiteId, deviceId: number): Promise<DeviceRecord | undefined>;
  listDevices(siteId?: SiteId): Promise<DeviceRecord[]>;
  listPermanentBlocks(): Promise<BlockRecord[]>;
  insertTelemetry(record: TelemetryRecord): Promise<number>;
  recentTelemetry(siteId: number, deviceId: number, limit?: number): Promise<TelemetryRecord[]>;
  nextCommandSeq(siteId: SiteId, deviceId: number): Promise<number>;
  currentCommandSeq(siteId: SiteId, deviceId: number): Promise<number>;
};

export type RegistryStartOptions = {
  readonly dbPath?: string;
};

export type Registry = {
  start(options?: RegistryStartOptions): Promise<void>;
  close(): Promise<void>;
  upsertDevice(record: DeviceRecord): Promise<DeviceRecord>;
  touchDevice(siteId: SiteId, deviceId: number, atS?: number): Promise<DeviceRecord>;
  getDevice(siteId: SiteId, deviceId: number): Promise<DeviceRecord | undefined>;
  listDevices(siteId?: SiteId): Promise<DeviceRecord[]>;
  listPermanentlyBlocked(): Promise<BlockRecord[]>;
  takeCommandSequence(siteId: SiteId, deviceId: number): Promise<number>;
  currentCommandSequence(siteId: SiteId, deviceId: number): Promise<number>;
  recordTelemetry(record: TelemetryRecord): Promise<number>;
  recentTelemetry(
    siteId: number,
    deviceId: number,
    limit?: number,
  ): Promise<TelemetryRecord[]>;
};

export function nowS(): number {
  return Math.floor(Date.now() / 1000);
}

function assertSiteId(value: string): SiteId {
  return asSiteId(value);
}

function assertDeviceId(value: number): number {
  if (!isDeviceId(value)) {
    throw new Error(`invalid device id: ${String(value)}`);
  }
  return value;
}

function clampInt(value: number, min: number, max: number, fallback: number): number {
  if (!Number.isFinite(value)) {
    return fallback;
  }
  const rounded = Math.floor(value);
  if (rounded < min) {
    return min;
  }
  if (rounded > max) {
    return max;
  }
  return rounded;
}

function normalize(record: DeviceRecord): DeviceRecord {
  return {
    siteId: assertSiteId(String(record.siteId)),
    deviceId: assertDeviceId(Math.floor(record.deviceId)),
    lastSeenAt: clampInt(record.lastSeenAt, 0, Number.MAX_SAFE_INTEGER, nowS()),
    fwVersion: clampInt(record.fwVersion, 0, FW_VERSION_MAX, 0),
    slot: record.slot,
    trialPending: record.trialPending === true,
  };
}

export function createRegistry(store: RegistryStore): Registry {
  return {
    async start(options?: RegistryStartOptions): Promise<void> {
      const dbPath = options?.dbPath;
      if (dbPath !== undefined) {
        await store.open(dbPath);
      }
    },

    async close(): Promise<void> {
      await Promise.resolve();
    },

    async upsertDevice(record: DeviceRecord): Promise<DeviceRecord> {
      const next = normalize(record);
      await store.upsertDevice(next);
      return next;
    },

    async touchDevice(siteId: SiteId, deviceId: number, atS?: number): Promise<DeviceRecord> {
      const at = clampInt(atS ?? nowS(), 0, Number.MAX_SAFE_INTEGER, nowS());
      const site = assertSiteId(String(siteId));
      const device = assertDeviceId(deviceId);
      const known = await store.getDevice(site, device);
      const next: DeviceRecord =
        known === undefined
          ? {
              siteId: site,
              deviceId: device,
              lastSeenAt: at,
              fwVersion: 0,
              slot: DEFAULT_SLOT,
              trialPending: false,
            }
          : { ...known, lastSeenAt: at };
      await store.upsertDevice(next);
      return next;
    },

    async getDevice(siteId: SiteId, deviceId: number): Promise<DeviceRecord | undefined> {
      return store.getDevice(assertSiteId(String(siteId)), assertDeviceId(deviceId));
    },

    async listDevices(siteId?: SiteId): Promise<DeviceRecord[]> {
      return siteId === undefined
        ? store.listDevices()
        : store.listDevices(assertSiteId(String(siteId)));
    },

    async listPermanentlyBlocked(): Promise<BlockRecord[]> {
      return store.listPermanentBlocks();
    },

    async takeCommandSequence(siteId: SiteId, deviceId: number): Promise<number> {
      return store.nextCommandSeq(assertSiteId(String(siteId)), assertDeviceId(deviceId));
    },

    async currentCommandSequence(siteId: SiteId, deviceId: number): Promise<number> {
      return store.currentCommandSeq(assertSiteId(String(siteId)), assertDeviceId(deviceId));
    },

    async recordTelemetry(record: TelemetryRecord): Promise<number> {
      return store.insertTelemetry(record);
    },

    async recentTelemetry(
      siteId: number,
      deviceId: number,
      limit?: number,
    ): Promise<TelemetryRecord[]> {
      return limit === undefined
        ? store.recentTelemetry(siteId, deviceId)
        : store.recentTelemetry(siteId, deviceId, limit);
    },
  };
}

let current: Registry = createRegistry(sharedStore);

export function configureRegistry(store: RegistryStore): Registry {
  current = createRegistry(store);
  return current;
}

export function registryStore(): Registry {
  return current;
}

export const registry: Registry = {
  start: (options?: RegistryStartOptions) => current.start(options),
  close: () => current.close(),
  upsertDevice: (record: DeviceRecord) => current.upsertDevice(record),
  touchDevice: (siteId: SiteId, deviceId: number, atS?: number) =>
    current.touchDevice(siteId, deviceId, atS),
  getDevice: (siteId: SiteId, deviceId: number) => current.getDevice(siteId, deviceId),
  listDevices: (siteId?: SiteId) => current.listDevices(siteId),
  listPermanentlyBlocked: () => current.listPermanentlyBlocked(),
  takeCommandSequence: (siteId: SiteId, deviceId: number) =>
    current.takeCommandSequence(siteId, deviceId),
  currentCommandSequence: (siteId: SiteId, deviceId: number) =>
    current.currentCommandSequence(siteId, deviceId),
  recordTelemetry: (record: TelemetryRecord) => current.recordTelemetry(record),
  recentTelemetry: (siteId: number, deviceId: number, limit?: number) =>
    current.recentTelemetry(siteId, deviceId, limit),
};

export function upsertDevice(record: DeviceRecord): Promise<DeviceRecord> {
  return current.upsertDevice(record);
}

export function touchDevice(
  siteId: SiteId,
  deviceId: number,
  atS?: number,
): Promise<DeviceRecord> {
  return current.touchDevice(siteId, deviceId, atS);
}

export function getDevice(siteId: SiteId, deviceId: number): Promise<DeviceRecord | undefined> {
  return current.getDevice(siteId, deviceId);
}

export function listDevices(siteId?: SiteId): Promise<DeviceRecord[]> {
  return current.listDevices(siteId);
}

export function takeCommandSequence(siteId: SiteId, deviceId: number): Promise<number> {
  return current.takeCommandSequence(siteId, deviceId);
}

export function currentCommandSequence(siteId: SiteId, deviceId: number): Promise<number> {
  return current.currentCommandSequence(siteId, deviceId);
}

export function recordTelemetry(record: TelemetryRecord): Promise<number> {
  return current.recordTelemetry(record);
}

export function recentTelemetry(
  siteId: number,
  deviceId: number,
  limit?: number,
): Promise<TelemetryRecord[]> {
  return current.recentTelemetry(siteId, deviceId, limit);
}
