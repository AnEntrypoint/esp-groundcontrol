import Database from "better-sqlite3";
import {
  BlockRecord,
  DeviceRecord,
  MacKey,
  NumberKey,
  SiteId,
  Slot,
  TelemetryRecord,
  asMacKey,
  asNumberKey,
  asSiteId,
  isSlot,
} from "./types.js";

export type StrikeInput = {
  readonly numberKey: NumberKey;
  readonly macKey: MacKey;
  readonly atS: number;
  readonly softBlockS: number;
  readonly strikeLimit: number;
};

export type CommandSeqInput = {
  readonly siteId: SiteId;
  readonly deviceId: number;
};

type ContactRow = {
  last_contact_at: number;
};

type StrikeRow = {
  number_key: string;
  mac_key: string;
  strikes: number;
  permanent: number;
  blocked_until: number;
  updated_at: number;
};

type DeviceRow = {
  site: string;
  device: string;
  last_seen_at: number;
  fw: number;
  slot: string;
  trial: number;
};

type TelemetryRow = {
  id: number;
  ts: number;
  site: number;
  device: number;
  record: string;
};

type SeqRow = {
  seq: number;
};

export type Store = {
  readonly db: Database.Database;
  close(): void;
  recordContact(numberKey: NumberKey, atS: number): void;
  lastContactAt(numberKey: NumberKey): number | undefined;
  forgetContactsBefore(cutoffS: number): number;
  getBlock(numberKey: NumberKey): BlockRecord | undefined;
  recordStrike(input: StrikeInput): BlockRecord;
  unblock(numberKey: NumberKey, clearStrikes: boolean, atS: number): void;
  listPermanentBlocks(): BlockRecord[];
  liftExpiredBlocks(nowS: number): number;
  upsertDevice(record: DeviceRecord): void;
  getDevice(siteId: SiteId, deviceId: number): DeviceRecord | undefined;
  listDevices(siteId?: SiteId): DeviceRecord[];
  setTrialPending(siteId: SiteId, deviceId: number, trialPending: boolean): void;
  insertTelemetry(record: TelemetryRecord): number;
  recentTelemetry(siteId?: number, deviceId?: number, limit?: number): TelemetryRecord[];
  trimTelemetryBefore(cutoffS: number): number;
  nextCommandSeq(siteId: SiteId, deviceId: number): number;
  currentCommandSeq(siteId: SiteId, deviceId: number): number;
};

export function isBlockActive(block: BlockRecord, nowS: number): boolean {
  if (block.permanent) {
    return true;
  }
  return block.blockedUntil > nowS;
}

export function blockedForS(block: BlockRecord, nowS: number): number {
  if (block.permanent) {
    return Number.POSITIVE_INFINITY;
  }
  const remaining = block.blockedUntil - nowS;
  return remaining > 0 ? remaining : 0;
}

function toBlockRecord(row: StrikeRow): BlockRecord {
  return {
    numberKey: asNumberKey(row.number_key),
    macKey: asMacKey(row.mac_key),
    strikes: row.strikes,
    permanent: row.permanent !== 0,
    blockedUntil: row.blocked_until,
    updatedAt: row.updated_at,
  };
}

function slotOf(raw: string): Slot {
  return isSlot(raw) ? raw : "unknown";
}

function toDeviceRecord(row: DeviceRow): DeviceRecord {
  return {
    siteId: asSiteId(row.site),
    deviceId: Number(row.device),
    lastSeenAt: row.last_seen_at,
    fwVersion: row.fw,
    slot: slotOf(row.slot),
    trialPending: row.trial !== 0,
  };
}

function toTelemetryRecord(row: TelemetryRow): TelemetryRecord {
  const parsed: unknown = JSON.parse(row.record);
  return parsed as TelemetryRecord;
}

export type AsyncStore = {
  open(path: string): Promise<void>;
  close(): Promise<void>;
  recordContact(numberKey: NumberKey, atS: number): Promise<void>;
  lastContactAt(numberKey: NumberKey): Promise<number | undefined>;
  getBlock(numberKey: NumberKey): Promise<BlockRecord | undefined>;
  recordStrike(input: StrikeInput): Promise<BlockRecord>;
  unblock(numberKey: NumberKey, clearStrikes: boolean, atS: number): Promise<void>;
  listPermanentBlocks(): Promise<BlockRecord[]>;
  liftExpiredBlocks(nowS: number): Promise<number>;
  upsertDevice(record: DeviceRecord): Promise<void>;
  getDevice(siteId: SiteId, deviceId: number): Promise<DeviceRecord | undefined>;
  listDevices(siteId?: SiteId): Promise<DeviceRecord[]>;
  insertTelemetry(record: TelemetryRecord): Promise<number>;
  recentTelemetry(siteId?: number, deviceId?: number, limit?: number): Promise<TelemetryRecord[]>;
  trimTelemetryBefore(cutoffS: number): Promise<number>;
  nextCommandSeq(siteId: number | SiteId, deviceId: number): Promise<number>;
  currentCommandSeq(siteId: number | SiteId, deviceId: number): Promise<number>;
};

let active: Store | undefined;

function requireStore(): Store {
  if (active === undefined) {
    throw new Error("store is not open");
  }
  return active;
}

function siteIdOf(siteId: number | SiteId): SiteId {
  return typeof siteId === "number" ? asSiteId(String(siteId)) : siteId;
}

export const store: AsyncStore = {
  async open(path: string): Promise<void> {
    if (active !== undefined) {
      return;
    }
    active = openStore(path);
  },

  async close(): Promise<void> {
    const current = active;
    active = undefined;
    current?.close();
  },

  async recordContact(numberKey: NumberKey, atS: number): Promise<void> {
    requireStore().recordContact(numberKey, atS);
  },

  async lastContactAt(numberKey: NumberKey): Promise<number | undefined> {
    return requireStore().lastContactAt(numberKey);
  },

  async getBlock(numberKey: NumberKey): Promise<BlockRecord | undefined> {
    return requireStore().getBlock(numberKey);
  },

  async recordStrike(input: StrikeInput): Promise<BlockRecord> {
    return requireStore().recordStrike(input);
  },

  async unblock(numberKey: NumberKey, clearStrikes: boolean, atS: number): Promise<void> {
    requireStore().unblock(numberKey, clearStrikes, atS);
  },

  async listPermanentBlocks(): Promise<BlockRecord[]> {
    return requireStore().listPermanentBlocks();
  },

  async liftExpiredBlocks(nowS: number): Promise<number> {
    return requireStore().liftExpiredBlocks(nowS);
  },

  async upsertDevice(record: DeviceRecord): Promise<void> {
    requireStore().upsertDevice(record);
  },

  async getDevice(siteId: SiteId, deviceId: number): Promise<DeviceRecord | undefined> {
    return requireStore().getDevice(siteId, deviceId);
  },

  async listDevices(siteId?: SiteId): Promise<DeviceRecord[]> {
    return requireStore().listDevices(siteId);
  },

  async insertTelemetry(record: TelemetryRecord): Promise<number> {
    return requireStore().insertTelemetry(record);
  },

  async recentTelemetry(
    siteId?: number,
    deviceId?: number,
    limit = 100,
  ): Promise<TelemetryRecord[]> {
    return requireStore().recentTelemetry(siteId, deviceId, limit);
  },

  async trimTelemetryBefore(cutoffS: number): Promise<number> {
    return requireStore().trimTelemetryBefore(cutoffS);
  },

  async nextCommandSeq(siteId: number | SiteId, deviceId: number): Promise<number> {
    return requireStore().nextCommandSeq(siteIdOf(siteId), deviceId);
  },

  async currentCommandSeq(siteId: number | SiteId, deviceId: number): Promise<number> {
    return requireStore().currentCommandSeq(siteIdOf(siteId), deviceId);
  },
};

export function openStore(path: string): Store {
  const db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = NORMAL");
  db.pragma("foreign_keys = ON");
  db.pragma("busy_timeout = 5000");

  db.exec(`
CREATE TABLE IF NOT EXISTS contacts (
  number_key TEXT PRIMARY KEY,
  last_contact_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS strikes (
  number_key TEXT PRIMARY KEY,
  mac_key TEXT NOT NULL,
  strikes INTEGER NOT NULL DEFAULT 0,
  permanent INTEGER NOT NULL DEFAULT 0,
  blocked_until INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS devices (
  site TEXT NOT NULL,
  device TEXT NOT NULL,
  last_seen_at INTEGER NOT NULL DEFAULT 0,
  fw INTEGER NOT NULL DEFAULT 0,
  slot TEXT NOT NULL DEFAULT 'unknown',
  trial INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (site, device)
);
CREATE TABLE IF NOT EXISTS telemetry (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  site INTEGER NOT NULL,
  device INTEGER NOT NULL,
  record JSON NOT NULL
);
CREATE TABLE IF NOT EXISTS command_seq (
  site TEXT NOT NULL,
  device TEXT NOT NULL,
  seq INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (site, device)
);
CREATE INDEX IF NOT EXISTS telemetry_site_device_ts ON telemetry (site, device, ts DESC);
CREATE INDEX IF NOT EXISTS strikes_blocked_until ON strikes (blocked_until);
`);

  const insertContact = db.prepare(`
INSERT INTO contacts (number_key, last_contact_at) VALUES (?, ?)
ON CONFLICT (number_key) DO UPDATE SET last_contact_at = excluded.last_contact_at
WHERE excluded.last_contact_at > contacts.last_contact_at
`);

  const selectContact = db.prepare(
    `SELECT last_contact_at FROM contacts WHERE number_key = ?`,
  );

  const deleteContactsBefore = db.prepare(
    `DELETE FROM contacts WHERE last_contact_at < ?`,
  );

  const selectBlock = db.prepare(`
SELECT number_key, mac_key, strikes, permanent, blocked_until, updated_at
FROM strikes WHERE number_key = ?
`);

  const insertStrike = db.prepare(`
INSERT INTO strikes (number_key, mac_key, strikes, permanent, blocked_until, updated_at)
VALUES (@numberKey, @macKey, 1, 0, @blockedUntil, @atS)
ON CONFLICT (number_key) DO UPDATE SET
  mac_key = excluded.mac_key,
  strikes = strikes.strikes + 1,
  permanent = CASE WHEN strikes.strikes + 1 >= @strikeLimit THEN 1 ELSE strikes.permanent END,
  blocked_until = CASE WHEN strikes.strikes + 1 >= @strikeLimit THEN 0 ELSE excluded.blocked_until END,
  updated_at = excluded.updated_at
RETURNING number_key, mac_key, strikes, permanent, blocked_until, updated_at
`);

  const updateUnblock = db.prepare(`
UPDATE strikes SET
  permanent = 0,
  blocked_until = 0,
  strikes = CASE WHEN @clearStrikes THEN 0 ELSE strikes END,
  updated_at = @atS
WHERE number_key = @numberKey
`);

  const selectPermanent = db.prepare(`
SELECT number_key, mac_key, strikes, permanent, blocked_until, updated_at
FROM strikes WHERE permanent = 1 ORDER BY updated_at DESC
`);

  const updateLiftExpired = db.prepare(`
UPDATE strikes SET blocked_until = 0, updated_at = ?
WHERE permanent = 0 AND blocked_until > 0 AND blocked_until <= ?
`);

  const upsertDeviceRow = db.prepare(`
INSERT INTO devices (site, device, last_seen_at, fw, slot, trial)
VALUES (@site, @device, @lastSeenAt, @fw, @slot, @trial)
ON CONFLICT (site, device) DO UPDATE SET
  last_seen_at = excluded.last_seen_at,
  fw = excluded.fw,
  slot = excluded.slot,
  trial = excluded.trial
`);

  const selectDevice = db.prepare(`
SELECT site, device, last_seen_at, fw, slot, trial
FROM devices WHERE site = ? AND device = ?
`);

  const selectAllDevices = db.prepare(`
SELECT site, device, last_seen_at, fw, slot, trial
FROM devices ORDER BY site, device
`);

  const selectSiteDevices = db.prepare(`
SELECT site, device, last_seen_at, fw, slot, trial
FROM devices WHERE site = ? ORDER BY device
`);

  const updateTrial = db.prepare(`
UPDATE devices SET trial = ? WHERE site = ? AND device = ?
`);

  const insertTelemetryRow = db.prepare(`
INSERT INTO telemetry (ts, site, device, record) VALUES (@ts, @site, @device, @record)
`);

  const selectTelemetry = db.prepare(`
SELECT id, ts, site, device, record FROM telemetry
WHERE (@site IS NULL OR site = @site) AND (@device IS NULL OR device = @device)
ORDER BY ts DESC, id DESC LIMIT @limit
`);

  const deleteTelemetryBefore = db.prepare(`DELETE FROM telemetry WHERE ts < ?`);

  const bumpCommandSeq = db.prepare(`
INSERT INTO command_seq (site, device, seq) VALUES (?, ?, 1)
ON CONFLICT (site, device) DO UPDATE SET seq = command_seq.seq + 1
RETURNING seq
`);

  const selectCommandSeq = db.prepare(
    `SELECT seq FROM command_seq WHERE site = ? AND device = ?`,
  );

  return {
    db,

    close(): void {
      db.close();
    },

    recordContact(numberKey: NumberKey, atS: number): void {
      insertContact.run(numberKey, atS);
    },

    lastContactAt(numberKey: NumberKey): number | undefined {
      const row = selectContact.get(numberKey) as ContactRow | undefined;
      return row?.last_contact_at;
    },

    forgetContactsBefore(cutoffS: number): number {
      return deleteContactsBefore.run(cutoffS).changes;
    },

    getBlock(numberKey: NumberKey): BlockRecord | undefined {
      const row = selectBlock.get(numberKey) as StrikeRow | undefined;
      return row === undefined ? undefined : toBlockRecord(row);
    },

    recordStrike(input: StrikeInput): BlockRecord {
      const row = insertStrike.get({
        numberKey: input.numberKey,
        macKey: input.macKey,
        blockedUntil: input.atS + input.softBlockS,
        atS: input.atS,
        strikeLimit: input.strikeLimit,
      }) as StrikeRow | undefined;
      if (row === undefined) {
        throw new Error("recordStrike returned no row");
      }
      return toBlockRecord(row);
    },

    unblock(numberKey: NumberKey, clearStrikes: boolean, atS: number): void {
      updateUnblock.run({ numberKey, clearStrikes: clearStrikes ? 1 : 0, atS });
    },

    listPermanentBlocks(): BlockRecord[] {
      const rows = selectPermanent.all() as StrikeRow[];
      return rows.map(toBlockRecord);
    },

    liftExpiredBlocks(nowS: number): number {
      return updateLiftExpired.run(nowS, nowS).changes;
    },

    upsertDevice(record: DeviceRecord): void {
      upsertDeviceRow.run({
        site: record.siteId,
        device: String(record.deviceId),
        lastSeenAt: record.lastSeenAt,
        fw: record.fwVersion,
        slot: record.slot,
        trial: record.trialPending ? 1 : 0,
      });
    },

    getDevice(siteId: SiteId, deviceId: number): DeviceRecord | undefined {
      const row = selectDevice.get(siteId, String(deviceId)) as DeviceRow | undefined;
      return row === undefined ? undefined : toDeviceRecord(row);
    },

    listDevices(siteId?: SiteId): DeviceRecord[] {
      const rows =
        siteId === undefined
          ? (selectAllDevices.all() as DeviceRow[])
          : (selectSiteDevices.all(siteId) as DeviceRow[]);
      return rows.map(toDeviceRecord);
    },

    setTrialPending(siteId: SiteId, deviceId: number, trialPending: boolean): void {
      updateTrial.run(trialPending ? 1 : 0, siteId, String(deviceId));
    },

    insertTelemetry(record: TelemetryRecord): number {
      const result = insertTelemetryRow.run({
        ts: record.receivedAtS,
        site: record.siteId,
        device: record.deviceId,
        record: JSON.stringify(record),
      });
      return Number(result.lastInsertRowid);
    },

    recentTelemetry(siteId?: number, deviceId?: number, limit = 100): TelemetryRecord[] {
      const rows = selectTelemetry.all({
        site: siteId ?? null,
        device: deviceId ?? null,
        limit,
      }) as TelemetryRow[];
      return rows.map(toTelemetryRecord);
    },

    trimTelemetryBefore(cutoffS: number): number {
      return deleteTelemetryBefore.run(cutoffS).changes;
    },

    nextCommandSeq(siteId: SiteId, deviceId: number): number {
      const row = bumpCommandSeq.get(siteId, String(deviceId)) as SeqRow | undefined;
      if (row === undefined) {
        throw new Error("nextCommandSeq returned no row");
      }
      return row.seq;
    },

    currentCommandSeq(siteId: SiteId, deviceId: number): number {
      const row = selectCommandSeq.get(siteId, String(deviceId)) as SeqRow | undefined;
      return row?.seq ?? 0;
    },
  };
}

export function syncStore(): Store {
  return requireStore();
}
