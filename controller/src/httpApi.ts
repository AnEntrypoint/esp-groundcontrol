import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { beaconRx } from "./beaconRx.js";
import { type ControllerConfig, pskForSiteNumber } from "./config.js";
import { commandPayload, commandTag } from "./crypto.js";
import {
  type CommandRequest,
  commandBodyText,
  deviceLink,
  unblockBodyText,
} from "./deviceLink.js";
import { registry } from "./registry.js";
import { store } from "./store.js";
import { handleVerify, handleWebhook } from "./whatsappWebhook.js";

const MAX_BODY_BYTES = 65536;
const DEFAULT_TELEMETRY_LIMIT = 100;
const MAX_TELEMETRY_LIMIT = 1000;
const MAX_SITE_ID = 65535;
const MAX_DEVICE_ID = 65535;
const MAX_QUOTA_KB = 16777216;
const U32_MAX = 4294967295;
const NUMBER_KEY_HEX_LEN = 16;
const BEARER_PREFIX = "bearer ";

export class HttpError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "HttpError";
    this.status = status;
  }
}

export interface HttpApiOptions {
  port: number;
  operatorToken: string;
  host?: string;
  config?: ControllerConfig;
}

export interface HttpApi {
  readonly port: number;
  close(): Promise<void>;
}

export async function startHttpApi(options: HttpApiOptions): Promise<HttpApi> {
  const server = createServer((req, res) => {
    void dispatch(req, res, options);
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port, options.host ?? "0.0.0.0", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });

  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : options.port;

  return {
    port,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error === undefined || error === null) {
            resolve();
          } else {
            reject(error);
          }
        });
      }),
  };
}

async function dispatch(req: IncomingMessage, res: ServerResponse, options: HttpApiOptions): Promise<void> {
  const method = req.method ?? "GET";
  const url = new URL(req.url ?? "/", "http://groundcontrol.invalid");
  const path = url.pathname;

  try {
    if (path === "/webhooks/whatsapp") {
      if (method === "GET") {
        await guard(res, async () => {
          handleVerify(req, res);
        });
        return;
      }
      if (method === "POST") {
        await guard(res, async () => {
          await handleWebhook(req, res);
        });
        return;
      }
      sendJson(res, 405, { error: "method_not_allowed" });
      return;
    }

    if (!authorized(req, options.operatorToken)) {
      sendJson(res, 401, { error: "unauthorized" });
      return;
    }

    if (method === "GET" && path === "/healthz") {
      await guard(res, async () => {
        sendJson(res, 200, { ok: true });
      });
      return;
    }

    if (method === "GET" && path === "/v1/devices") {
      await guard(res, async () => {
        const devices = await registry.listDevices();
        sendJson(res, 200, { devices });
      });
      return;
    }

    if (method === "GET" && path === "/v1/blocked") {
      await guard(res, async () => {
        const blocked = await registry.listPermanentlyBlocked();
        sendJson(res, 200, { blocked });
      });
      return;
    }

    if (method === "POST" && path === "/v1/unblock") {
      await guard(res, async () => {
        const config = requireConfig(options);
        const body = await readJson(req);
        const site = requireInt(body, "site", 1, MAX_SITE_ID);
        const device = requireInt(body, "device", 0, MAX_DEVICE_ID);
        const numberKey = requireKey(body, "numberKey");
        const numberKeyHex = numberKey.toString("hex");
        const sequence = await store.nextCommandSeq(site, device);
        const sig = signCommand(config, site, sequence, unblockBodyText(numberKeyHex, true));
        await deviceLink.sendUnblock(site, device, { sequence, numberKey, clearStrikes: true, sig });
        sendJson(res, 200, { ok: true, sequence });
      });
      return;
    }

    if (method === "POST" && path === "/v1/tunnel") {
      await guard(res, async () => {
        const config = requireConfig(options);
        const body = await readJson(req);
        const site = requireInt(body, "site", 1, MAX_SITE_ID);
        const device = requireInt(body, "device", 0, MAX_DEVICE_ID);
        const up = requireBool(body, "up");
        beaconRx.requestTunnel(site, device, up);
        const sequence = await store.nextCommandSeq(site, device);
        const command: CommandRequest = { sequence, name: "tunnel_up", boolArg: up };
        const sig = signCommand(config, site, sequence, commandBodyText(command));
        await deviceLink.sendCommand(site, device, { ...command, sig });
        sendJson(res, 200, { ok: true, site, device, tunnelRequested: up, sequence });
      });
      return;
    }

    if (method === "POST" && path === "/v1/quota") {
      await guard(res, async () => {
        const config = requireConfig(options);
        const body = await readJson(req);
        const site = requireInt(body, "site", 1, MAX_SITE_ID);
        const device = requireInt(body, "device", 0, MAX_DEVICE_ID);
        const dailyBudgetKb = requireInt(body, "dailyBudgetKb", 0, MAX_QUOTA_KB);
        const monthlyReserveKb = requireInt(body, "monthlyReserveKb", 0, MAX_QUOTA_KB);
        const dailySequence = await store.nextCommandSeq(site, device);
        const reserveSequence = await store.nextCommandSeq(site, device);
        const daily: CommandRequest = {
          sequence: dailySequence,
          name: "quota_daily",
          uintArg: dailyBudgetKb,
          boolArg: false,
        };
        const reserve: CommandRequest = {
          sequence: reserveSequence,
          name: "quota_reserve",
          uintArg: monthlyReserveKb,
          boolArg: false,
        };
        await deviceLink.sendCommand(site, device, {
          ...daily,
          sig: signCommand(config, site, dailySequence, commandBodyText(daily)),
        });
        await deviceLink.sendCommand(site, device, {
          ...reserve,
          sig: signCommand(config, site, reserveSequence, commandBodyText(reserve)),
        });
        sendJson(res, 200, { ok: true, sequences: [dailySequence, reserveSequence] });
      });
      return;
    }

    if (method === "GET" && path === "/v1/telemetry") {
      await guard(res, async () => {
        const siteId = optionalInt(url, "site", 0, MAX_SITE_ID);
        const deviceId = optionalInt(url, "device", 0, MAX_DEVICE_ID);
        const limit = optionalInt(url, "limit", 1, MAX_TELEMETRY_LIMIT) ?? DEFAULT_TELEMETRY_LIMIT;
        const telemetry = await store.recentTelemetry(siteId, deviceId, limit);
        sendJson(res, 200, { telemetry });
      });
      return;
    }

    sendJson(res, 404, { error: "not_found" });
  } catch (error) {
    sendFailure(res, error);
  }
}

function requireConfig(options: HttpApiOptions): ControllerConfig {
  if (options.config === undefined) {
    throw new HttpError(503, "controller configuration is not loaded");
  }
  return options.config;
}

function clampU32(value: number): number {
  if (!Number.isFinite(value)) {
    return 0;
  }
  const rounded = Math.trunc(value);
  if (rounded < 0) {
    return 0;
  }
  return rounded > U32_MAX ? U32_MAX : rounded;
}

function signCommand(config: ControllerConfig, site: number, sequence: number, body: string): string {
  const psk = pskForSiteNumber(config, site);
  if (psk === undefined) {
    throw new HttpError(503, `no psk configured for site ${String(site)}`);
  }
  return commandTag(psk, commandPayload(clampU32(sequence), Buffer.from(body, "utf8")));
}

async function guard(res: ServerResponse, handler: () => Promise<void>): Promise<void> {
  try {
    await handler();
  } catch (error) {
    sendFailure(res, error);
  }
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  if (res.writableEnded || res.headersSent) {
    return;
  }
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": payload.length,
    "cache-control": "no-store",
  });
  res.end(payload);
}

function sendFailure(res: ServerResponse, error: unknown): void {
  if (res.writableEnded || res.headersSent) {
    return;
  }
  if (error instanceof HttpError) {
    sendJson(res, error.status, { error: error.message });
    return;
  }
  const detail = error instanceof Error ? error.message : "unknown error";
  console.error(`http: handler failed: ${detail}`);
  sendJson(res, 500, { error: "internal_error" });
}

function authorized(req: IncomingMessage, operatorToken: string): boolean {
  if (operatorToken.length === 0) {
    return false;
  }
  const header = req.headers.authorization;
  if (typeof header !== "string") {
    return false;
  }
  if (header.slice(0, BEARER_PREFIX.length).toLowerCase() !== BEARER_PREFIX) {
    return false;
  }
  const provided = header.slice(BEARER_PREFIX.length).trim();
  const a = createHash("sha256").update(provided, "utf8").digest();
  const b = createHash("sha256").update(operatorToken, "utf8").digest();
  return timingSafeEqual(a, b);
}

function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > limit) {
        reject(new HttpError(413, "payload_too_large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      resolve(Buffer.concat(chunks));
    });
    req.on("error", (error: Error) => {
      reject(error);
    });
  });
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const raw = await readBody(req, MAX_BODY_BYTES);
  if (raw.length === 0) {
    return {};
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new HttpError(400, "body must be valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new HttpError(400, "body must be a JSON object");
  }
  return parsed as Record<string, unknown>;
}

function requireInt(body: Record<string, unknown>, field: string, min: number, max: number): number {
  const value = optionalNumber(body[field]);
  if (value === undefined || !Number.isInteger(value) || value < min || value > max) {
    throw new HttpError(400, `${field} must be an integer between ${min} and ${max}`);
  }
  return value;
}

function requireBool(body: Record<string, unknown>, field: string): boolean {
  const raw = body[field];
  if (typeof raw === "boolean") {
    return raw;
  }
  if (raw === "true") {
    return true;
  }
  if (raw === "false") {
    return false;
  }
  throw new HttpError(400, `${field} must be a boolean`);
}

function requireKey(body: Record<string, unknown>, field: string): Buffer {
  const raw = body[field];
  const pattern = new RegExp(`^[0-9a-fA-F]{${NUMBER_KEY_HEX_LEN}}$`);
  if (typeof raw !== "string" || !pattern.test(raw)) {
    throw new HttpError(400, `${field} must be ${NUMBER_KEY_HEX_LEN} hex characters`);
  }
  return Buffer.from(raw, "hex");
}

function optionalNumber(raw: unknown): number | undefined {
  if (typeof raw === "number") {
    return raw;
  }
  if (typeof raw === "string" && /^[0-9]+$/.test(raw)) {
    return Number(raw);
  }
  return undefined;
}

function optionalInt(url: URL, field: string, min: number, max: number): number | undefined {
  const raw = url.searchParams.get(field);
  if (raw === null || raw === "") {
    return undefined;
  }
  const value = optionalNumber(raw);
  if (value === undefined || !Number.isInteger(value) || value < min || value > max) {
    throw new HttpError(400, `${field} must be an integer between ${min} and ${max}`);
  }
  return value;
}
