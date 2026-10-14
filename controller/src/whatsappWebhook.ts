import type { IncomingMessage, ServerResponse } from "node:http";
import { ControllerConfig } from "./config.js";
import { constantTimeEqual, constantTimeEqualHex, hmacSha256, numberKey } from "./crypto.js";
import { Store } from "./store.js";
import { NumberKey } from "./types.js";
import { matchChallenge as matchChallengeCode } from "./verifier.js";

const MAX_BODY_BYTES = 1048576;
const SIGNATURE_PREFIX = "sha256=";
const SIGNATURE_HEX_RE = /^[0-9a-f]{64}$/;
const MESSAGES_FIELD = "messages";

export type WebhookDeps = {
  readonly config: ControllerConfig;
  readonly store: Store;
};

const failures = new Map<string, number>();

let deps: WebhookDeps | undefined;

export function initWhatsappWebhook(next: WebhookDeps): void {
  deps = next;
}

export function handleVerify(req: IncomingMessage, res: ServerResponse): void {
  const params = queryParams(req);
  const mode = params.get("hub.mode");
  const presented = params.get("hub.verify_token");
  const challenge = params.get("hub.challenge");
  const config = deps?.config;
  if (config === undefined || mode !== "subscribe" || presented === null || challenge === null) {
    recordFailure("verify_rejected");
    respond(res, 403, "forbidden");
    return;
  }
  if (!constantTimeEqual(presented, config.whatsappVerifyToken)) {
    recordFailure("verify_token_mismatch");
    respond(res, 403, "forbidden");
    return;
  }
  respond(res, 200, challenge);
}

export async function handleWebhook(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const raw = await readRawBody(req);
  if (raw === undefined) {
    recordFailure("body_unreadable");
    respond(res, 200, "ok");
    return;
  }
  const signature = headerValue(req.headers["x-hub-signature-256"]);
  const appSecret = deps?.config.whatsappAppSecret;
  if (!signatureMatches(raw, signature, appSecret)) {
    recordFailure("signature_invalid");
    respond(res, 401, "unauthorized");
    return;
  }
  const current = deps;
  if (current === undefined) {
    recordFailure("deps_uninitialized");
    respond(res, 200, "ok");
    return;
  }
  const payload = parseJson(raw);
  if (payload === undefined) {
    recordFailure("payload_unparsable");
    respond(res, 200, "ok");
    return;
  }
  ingest(current, payload);
  respond(res, 200, "ok");
}

function ingest(current: WebhookDeps, payload: unknown): void {
  const peppers = distinctPeppers(current.config);
  const root = asRecord(payload);
  if (root === undefined) {
    return;
  }
  for (const entry of asArray(root["entry"])) {
    const entryRecord = asRecord(entry);
    if (entryRecord === undefined) {
      continue;
    }
    for (const change of asArray(entryRecord["changes"])) {
      const changeRecord = asRecord(change);
      if (changeRecord === undefined) {
        continue;
      }
      const value = asRecord(changeRecord["value"]);
      if (value === undefined) {
        continue;
      }
      for (const message of asArray(value[MESSAGES_FIELD])) {
        ingestMessage(current, peppers, asRecord(message));
      }
    }
  }
}

function ingestMessage(
  current: WebhookDeps,
  peppers: readonly Buffer[],
  message: Record<string, unknown> | undefined,
): void {
  if (message === undefined) {
    return;
  }
  const from = stringField(message, "from");
  if (from === "") {
    recordFailure("sender_missing");
    return;
  }
  const text = messageText(message);
  const atS = messageTime(message);
  for (const pepper of peppers) {
    const key = numberKeyFor(pepper, from);
    if (key === undefined) {
      recordFailure("sender_key_failed");
      continue;
    }
    current.store.recordContact(key, atS);
    if (text !== "") {
      matchChallengeCode(key, text);
    }
  }
}

function distinctPeppers(config: ControllerConfig): Buffer[] {
  const seen = new Set<string>();
  const out: Buffer[] = [];
  for (const pepper of config.peppers.values()) {
    const hex = pepper.toString("hex");
    if (seen.has(hex)) {
      continue;
    }
    seen.add(hex);
    out.push(pepper);
  }
  return out;
}

function numberKeyFor(pepper: Buffer, from: string): NumberKey | undefined {
  try {
    return numberKey(pepper, from);
  } catch {
    return undefined;
  }
}

function messageText(message: Record<string, unknown>): string {
  const text = asRecord(message["text"]);
  if (text !== undefined) {
    const body = text["body"];
    if (typeof body === "string") {
      return body;
    }
  }
  const button = asRecord(message["button"]);
  if (button !== undefined) {
    const label = button["text"];
    if (typeof label === "string") {
      return label;
    }
  }
  const interactive = asRecord(message["interactive"]);
  const reply = interactive === undefined ? undefined : asRecord(interactive["button_reply"]);
  if (reply !== undefined) {
    const title = reply["title"];
    if (typeof title === "string") {
      return title;
    }
  }
  return "";
}

function messageTime(message: Record<string, unknown>): number {
  const raw = message["timestamp"];
  const seconds = typeof raw === "number" ? raw : typeof raw === "string" ? Number(raw) : Number.NaN;
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return Math.floor(Date.now() / 1000);
  }
  return Math.floor(seconds);
}

function queryParams(req: IncomingMessage): URLSearchParams {
  return new URL(req.url ?? "/", "http://groundcontrol.invalid").searchParams;
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function signatureMatches(
  raw: Buffer,
  signature: string | undefined,
  appSecret: string | undefined,
): boolean {
  if (appSecret === undefined || appSecret.length === 0) {
    return false;
  }
  if (signature === undefined || !signature.startsWith(SIGNATURE_PREFIX)) {
    return false;
  }
  const presented = signature.slice(SIGNATURE_PREFIX.length).toLowerCase();
  if (!SIGNATURE_HEX_RE.test(presented)) {
    return false;
  }
  const expected = hmacSha256(Buffer.from(appSecret, "utf8"), raw).toString("hex");
  return constantTimeEqualHex(presented, expected);
}

function parseJson(raw: Buffer): unknown {
  try {
    return JSON.parse(raw.toString("utf8")) as unknown;
  } catch {
    return undefined;
  }
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return undefined;
  }
  return value as Record<string, unknown>;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function stringField(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  return typeof value === "string" ? value : "";
}

function readRawBody(req: IncomingMessage): Promise<Buffer | undefined> {
  return new Promise<Buffer | undefined>((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    const finish = (body: Buffer | undefined): void => {
      if (settled) {
        return;
      }
      settled = true;
      resolve(body);
    };
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        finish(undefined);
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => finish(Buffer.concat(chunks)));
    req.on("error", () => finish(undefined));
  });
}

function recordFailure(reason: string): void {
  const count = (failures.get(reason) ?? 0) + 1;
  failures.set(reason, count);
  console.error(`whatsapp webhook: ${reason} (${count})`);
}

function respond(res: ServerResponse, status: number, body: string): void {
  if (res.writableEnded || res.headersSent) {
    return;
  }
  const payload = Buffer.from(body, "utf8");
  res.writeHead(status, {
    "content-type": "text/plain; charset=utf-8",
    "content-length": payload.length,
    "cache-control": "no-store",
  });
  res.end(payload);
}
