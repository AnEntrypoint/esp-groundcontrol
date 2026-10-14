import { type ControllerConfig, pskFor } from "./config.js";
import { commandPayload, commandTag } from "./crypto.js";
import {
  type BrokerHandle,
  type ChannelHandler,
  type ChannelHandlers,
  type UplinkMessage,
  closeBroker,
  publishToDevice,
  publishToDeviceQos1,
  startBroker,
} from "./broker.js";
import { nowS, registry } from "./registry.js";
import { getBlock, recordEvent } from "./strikes.js";
import { type TelemetryFrame, decodeFlags, decodeTelemetry } from "./telemetryDecode.js";
import { decideVerification, toVerdict } from "./verifier.js";
import {
  type DenyReason,
  type DeviceRecord,
  type NumberKey,
  type SiteId,
  type Slot,
  type TelemetryRecord,
  type Verdict,
  asMacKey,
  asNumberKey,
  asSiteId,
  isDenyReason,
  isDeviceId,
  isKeyHex,
  isReqIdHex,
  isSiteId,
  isSlot,
  isVerifyMode,
} from "./types.js";

export const CHANNEL_TELE = "tele";
export const CHANNEL_EVENT = "event";
export const CHANNEL_VERIFY = "verify";
export const CHANNEL_HELLO = "hello";
export const CHANNEL_OTA = "ota";
export const CHANNEL_VERDICT = "verdict";
export const CHANNEL_UNBLOCK = "unblock";
export const CHANNEL_ACK = "ack";
export const CHANNEL_CMD = "cmd";

const U32_MAX = 4294967295;
const FW_MAX = 255;
const CMD_NAME_MAX = 24;
const REASON_MAX = 32;
const KEY_HEX_LEN = 16;
const SIG_HEX_LEN = 16;
const ZERO_HEX = "0000000000000000";

export type LogLine = (line: string) => void;

export type DeviceLinkOptions = {
  readonly config?: ControllerConfig;
  readonly broker?: BrokerHandle;
  readonly log?: LogLine;
};

export type CommandRequest = {
  readonly sequence: number;
  readonly name: string;
  readonly uintArg?: number;
  readonly boolArg?: boolean;
  readonly mac?: Uint8Array;
  readonly sig?: string;
};

export type UnblockRequest = {
  readonly sequence: number;
  readonly numberKey: Buffer | string;
  readonly macKey?: Buffer | string;
  readonly mac?: Uint8Array;
  readonly clearStrikes?: boolean;
  readonly sig?: string;
};

export type DeviceLink = {
  start(config: ControllerConfig): Promise<void>;
  stop(): Promise<void>;
  register(options?: DeviceLinkOptions): ChannelHandlers;
  sendCommand(site: number, device: number, command: CommandRequest): Promise<void>;
  sendUnblock(site: number, device: number, request: UnblockRequest): Promise<void>;
  publishVerdict(site: SiteId, device: number, verdict: Verdict): Promise<void>;
  publishCommand(site: SiteId, device: number, command: CommandRequest): Promise<void>;
  publishAck(site: SiteId, device: number, sequence: number, serverTimeS?: number): Promise<void>;
};

type JsonObject = Readonly<Record<string, unknown>>;

type Address = {
  readonly siteId: SiteId;
  readonly deviceId: number;
};

type LinkState = {
  config: ControllerConfig | undefined;
  broker: BrokerHandle | null;
  log: LogLine;
};

const defaultLog: LogLine = (line) => {
  console.log(line);
};

const state: LinkState = { config: undefined, broker: null, log: defaultLog };
const pskWarnings = new Set<string>();

function logLine(line: string): void {
  state.log(`deviceLink: ${line}`);
}

function describeError(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}

function label(address: Address): string {
  return `${String(address.siteId)}/${String(address.deviceId)}`;
}

function clampInt(value: number, min: number, max: number, fallback: number): number {
  if (!Number.isFinite(value)) {
    return fallback;
  }
  const rounded = Math.trunc(value);
  if (rounded < min) {
    return min;
  }
  if (rounded > max) {
    return max;
  }
  return rounded;
}

function clampU32(value: number): number {
  return clampInt(value, 0, U32_MAX, 0);
}

function parseJsonObject(payload: Uint8Array): JsonObject | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(payload).toString("utf8"));
  } catch {
    return undefined;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return undefined;
  }
  return parsed as JsonObject;
}

function readString(body: JsonObject, field: string): string | undefined {
  const raw = body[field];
  return typeof raw === "string" ? raw : undefined;
}

function readInteger(body: JsonObject, field: string): number | undefined {
  const raw = body[field];
  if (typeof raw === "number" && Number.isInteger(raw)) {
    return raw;
  }
  if (typeof raw === "string" && /^[0-9]{1,10}$/.test(raw)) {
    return Number(raw);
  }
  return undefined;
}

function readBool(body: JsonObject, field: string): boolean | undefined {
  const raw = body[field];
  if (typeof raw === "boolean") {
    return raw;
  }
  if (raw === 0 || raw === 1) {
    return raw === 1;
  }
  return undefined;
}

function hexKeyOf(value: Buffer | string, expectedBytes: number): string | undefined {
  if (typeof value === "string") {
    return value.length === expectedBytes * 2 && isKeyHex(value.toLowerCase()) ? value.toLowerCase() : undefined;
  }
  const hex = Buffer.from(value).toString("hex");
  return hex.length === expectedBytes * 2 ? hex : undefined;
}

function addressOf(site: string, device: string): Address | undefined {
  if (site.length === 0 || device.length === 0 || !isSiteId(site)) {
    return undefined;
  }
  const deviceId = Number(device);
  if (!isDeviceId(deviceId)) {
    return undefined;
  }
  return { siteId: asSiteId(site), deviceId };
}

function addressOfIds(site: number, device: number): Address | undefined {
  if (!Number.isInteger(site) || !Number.isInteger(device)) {
    return undefined;
  }
  return addressOf(String(site), String(device));
}

function slotOf(text: string): Slot | undefined {
  return isSlot(text) ? text : undefined;
}

function reasonOf(body: JsonObject): DenyReason {
  const detail = readString(body, "detail");
  if (detail !== undefined && isDenyReason(detail)) {
    return detail;
  }
  const event = readString(body, "ev");
  if (event !== undefined && isDenyReason(event)) {
    return event;
  }
  return "none";
}

function pskForSite(siteId: SiteId): Buffer | undefined {
  const config = state.config;
  if (config === undefined) {
    return undefined;
  }
  try {
    return pskFor(config, siteId);
  } catch (error) {
    const text = String(siteId);
    if (!pskWarnings.has(text)) {
      pskWarnings.add(text);
      logLine(`no psk for site ${text}, downlink signatures will be zeroed: ${describeError(error)}`);
    }
    return undefined;
  }
}

function macKeyFor(numberKey: NumberKey, requested: string | undefined): string {
  if (requested !== undefined) {
    return requested;
  }
  try {
    const block = getBlock(numberKey);
    if (block !== undefined) {
      return block.macKey;
    }
  } catch (error) {
    logLine(`cannot recover the mac key for this number key: ${describeError(error)}`);
  }
  return ZERO_HEX;
}

function signature(siteId: SiteId, deviceId: number, sequence: number, body: Buffer): string {
  const psk = pskForSite(siteId);
  if (psk === undefined) {
    return ZERO_HEX.slice(0, SIG_HEX_LEN);
  }
  try {
    return commandTag(psk, commandPayload(clampU32(sequence), body));
  } catch (error) {
    logLine(
      `cannot sign sequence ${String(sequence)} for ${label({ siteId, deviceId })}: ${describeError(error)}`,
    );
    return ZERO_HEX.slice(0, SIG_HEX_LEN);
  }
}

export function commandBodyText(command: CommandRequest): string {
  const name = command.name.slice(0, CMD_NAME_MAX).toLowerCase();
  const arg = String(clampU32(command.uintArg ?? 0));
  return `${name}::${arg}:${command.boolArg === true ? "1" : "0"}`;
}

export function unblockBodyText(numberKeyHex: string, clearStrikes: boolean): string {
  return `unblock:${numberKeyHex}:${clearStrikes ? "1" : "0"}:0`;
}

function commandBody(command: CommandRequest): Buffer {
  return Buffer.from(commandBodyText(command), "utf8");
}

function unblockBody(numberKeyHex: string, clearStrikes: boolean): Buffer {
  return Buffer.from(unblockBodyText(numberKeyHex, clearStrikes), "utf8");
}

async function downlink(
  siteId: SiteId,
  deviceId: number,
  channel: string,
  payload: string,
  qos1: boolean,
): Promise<void> {
  const site = String(siteId);
  const device = String(deviceId);
  const handle = state.broker;
  try {
    if (handle !== null) {
      if (qos1) {
        await handle.publishToDeviceQos1(site, device, channel, payload);
      } else {
        await handle.publishToDevice(site, device, channel, payload);
      }
      return;
    }
    if (qos1) {
      await publishToDeviceQos1(site, device, channel, payload);
    } else {
      await publishToDevice(site, device, channel, payload);
    }
  } catch (error) {
    logLine(`publish to ${channel} for ${site}/${device} failed: ${describeError(error)}`);
  }
}

export async function publishVerdict(
  siteId: SiteId,
  deviceId: number,
  verdict: Verdict,
): Promise<void> {
  const payload = JSON.stringify({
    req: verdict.reqId,
    allow: verdict.allow === true,
    until: clampU32(verdict.allowedUntilS),
    blocked_until: clampU32(verdict.blockedUntilS),
    strikes: clampU32(verdict.strikes),
    permanent: verdict.permanent === true,
    reason: verdict.reason.slice(0, REASON_MAX),
    hint: verdict.challengeHint.slice(0, REASON_MAX),
  });
  await downlink(siteId, deviceId, CHANNEL_VERDICT, payload, true);
}

export async function publishCommand(
  siteId: SiteId,
  deviceId: number,
  command: CommandRequest,
): Promise<void> {
  const name = command.name.slice(0, CMD_NAME_MAX);
  if (name.length === 0) {
    logLine(`command for ${label({ siteId, deviceId })} has an empty name, dropped`);
    return;
  }
  const payload = JSON.stringify({
    cmd: name,
    sig: command.sig ?? signature(siteId, deviceId, command.sequence, commandBody(command)),
    seq: clampU32(command.sequence),
    arg: clampU32(command.uintArg ?? 0),
    flag: command.boolArg === true,
  });
  await downlink(siteId, deviceId, CHANNEL_CMD, payload, true);
}

export async function publishAck(
  siteId: SiteId,
  deviceId: number,
  sequence: number,
  serverTimeS?: number,
): Promise<void> {
  const payload = JSON.stringify({
    seq: clampU32(sequence),
    time: clampU32(serverTimeS ?? nowS()),
  });
  await downlink(siteId, deviceId, CHANNEL_ACK, payload, false);
}

async function sendCommand(
  site: number,
  device: number,
  command: CommandRequest,
): Promise<void> {
  const address = addressOfIds(site, device);
  if (address === undefined) {
    logLine(`command rejected, bad site or device ${String(site)}/${String(device)}`);
    return;
  }
  await publishCommand(address.siteId, address.deviceId, command);
}

async function sendUnblock(site: number, device: number, request: UnblockRequest): Promise<void> {
  const address = addressOfIds(site, device);
  if (address === undefined) {
    logLine(`unblock rejected, bad site or device ${String(site)}/${String(device)}`);
    return;
  }
  const numberKey = hexKeyOf(request.numberKey, 8);
  if (numberKey === undefined) {
    logLine(`unblock for ${label(address)} rejected, number key is not ${KEY_HEX_LEN} hex characters`);
    return;
  }
  const requestedMac = request.macKey === undefined ? undefined : hexKeyOf(request.macKey, 8);
  const macKey = macKeyFor(asNumberKey(numberKey), requestedMac);
  const clearStrikes = request.clearStrikes === true;
  const sequence = clampU32(request.sequence);
  const payload = JSON.stringify({
    num: numberKey,
    mac: macKey,
    sig:
      request.sig ??
      signature(address.siteId, address.deviceId, sequence, unblockBody(numberKey, clearStrikes)),
    seq: sequence,
    clear_strikes: clearStrikes,
  });
  await downlink(address.siteId, address.deviceId, CHANNEL_UNBLOCK, payload, true);
}

async function handleHello(message: UplinkMessage): Promise<void> {
  const address = addressOf(message.site, message.device);
  if (address === undefined) {
    logLine(`hello from a bad topic "${message.topic}" ignored`);
    return;
  }
  const body = parseJsonObject(message.payload);
  if (body === undefined) {
    logLine(`hello from ${label(address)} is not a JSON object, ignored`);
    return;
  }
  const fw = readInteger(body, "fw");
  const slotText = readString(body, "slot");
  if (fw === undefined || slotText === undefined) {
    logLine(`hello from ${label(address)} is missing "fw" or "slot", ignored`);
    return;
  }
  const slot = slotOf(slotText);
  if (slot === undefined) {
    logLine(`hello from ${label(address)} has an unknown slot "${slotText}", ignored`);
    return;
  }
  const trial = readBool(body, "trial");
  const atS = nowS();
  const record: DeviceRecord = {
    siteId: address.siteId,
    deviceId: address.deviceId,
    lastSeenAt: atS,
    fwVersion: clampInt(fw, 0, FW_MAX, 0),
    slot,
    trialPending: trial === true,
  };
  await registry.upsertDevice(record);
  const sequence = await registry.takeCommandSequence(address.siteId, address.deviceId);
  await publishAck(address.siteId, address.deviceId, sequence, atS);
}

async function handleVerify(message: UplinkMessage): Promise<void> {
  const address = addressOf(message.site, message.device);
  if (address === undefined) {
    logLine(`verify from a bad topic "${message.topic}" ignored`);
    return;
  }
  const body = parseJsonObject(message.payload);
  if (body === undefined) {
    logLine(`verify from ${label(address)} is not a JSON object, no verdict sent`);
    return;
  }
  const reqId = readString(body, "req");
  const numberText = readString(body, "num");
  const macText = readString(body, "mac");
  const modeText = readString(body, "mode");
  if (reqId === undefined || numberText === undefined || macText === undefined || modeText === undefined) {
    logLine(`verify from ${label(address)} is missing a required field, no verdict sent`);
    return;
  }
  if (!isReqIdHex(reqId) || !isKeyHex(numberText) || !isKeyHex(macText) || !isVerifyMode(modeText)) {
    logLine(`verify from ${label(address)} has a malformed field, no verdict sent`);
    return;
  }
  const outcome = decideVerification({
    siteId: address.siteId,
    deviceId: address.deviceId,
    req: {},
    numberKey: asNumberKey(numberText),
    macKey: asMacKey(macText),
    mode: modeText,
    reqId,
  });
  await publishVerdict(address.siteId, address.deviceId, toVerdict(reqId, outcome));
}

async function handleEvent(message: UplinkMessage): Promise<void> {
  const address = addressOf(message.site, message.device);
  if (address === undefined) {
    logLine(`event from a bad topic "${message.topic}" ignored`);
    return;
  }
  const body = parseJsonObject(message.payload);
  if (body === undefined) {
    logLine(`event from ${label(address)} is not a JSON object, ignored`);
    return;
  }
  const event = readString(body, "ev");
  const numberText = readString(body, "num");
  const macText = readString(body, "mac");
  if (event === undefined || numberText === undefined || macText === undefined) {
    logLine(`event from ${label(address)} is missing "ev", "num" or "mac", ignored`);
    return;
  }
  if (!isKeyHex(numberText) || !isKeyHex(macText)) {
    logLine(`event from ${label(address)} has a malformed key, ignored`);
    return;
  }
  const atS = nowS();
  const strikes = clampU32(readInteger(body, "strikes") ?? 0);
  recordEvent({
    numberKey: asNumberKey(numberText),
    macKey: asMacKey(macText),
    siteId: address.siteId,
    deviceId: address.deviceId,
    reason: reasonOf(body),
    strikes,
    atS,
  });
  await registry.touchDevice(address.siteId, address.deviceId, atS);
  logLine(`event "${event}" from ${label(address)} strikes=${String(strikes)}`);
}

async function handleTele(message: UplinkMessage): Promise<void> {
  const address = addressOf(message.site, message.device);
  if (address === undefined) {
    logLine(`telemetry from a bad topic "${message.topic}" ignored`);
    return;
  }
  let frame: TelemetryFrame;
  try {
    frame = decodeTelemetry(Buffer.from(message.payload));
  } catch (error) {
    logLine(`telemetry from ${label(address)} failed to decode: ${describeError(error)}`);
    return;
  }
  const atS = nowS();
  const record: TelemetryRecord = {
    siteId: Number(address.siteId),
    deviceId: address.deviceId,
    bootId: frame.bootId,
    seq: frame.seq,
    fwVersion: frame.fwVersion,
    slot: frame.slot,
    flagsMask: frame.flags,
    flags: decodeFlags(frame.flags),
    readings: frame.records,
    receivedAtS: atS,
  };
  await registry.recordTelemetry(record);
  await registry.touchDevice(address.siteId, address.deviceId, atS);
}

async function handleOta(message: UplinkMessage): Promise<void> {
  const address = addressOf(message.site, message.device);
  const who = address === undefined ? message.topic : label(address);
  logLine(`ota notice from ${who}, ${String(message.payload.length)} bytes, not acted on`);
}

function guardChannel(
  channel: string,
  handler: (message: UplinkMessage) => Promise<void>,
): ChannelHandler {
  return (message: UplinkMessage): void => {
    void (async () => {
      try {
        await handler(message);
      } catch (error) {
        logLine(`${channel} handler for "${message.topic}" failed: ${describeError(error)}`);
      }
    })();
  };
}

const HANDLERS: ChannelHandlers = {
  [CHANNEL_TELE]: guardChannel(CHANNEL_TELE, handleTele),
  [CHANNEL_EVENT]: guardChannel(CHANNEL_EVENT, handleEvent),
  [CHANNEL_VERIFY]: guardChannel(CHANNEL_VERIFY, handleVerify),
  [CHANNEL_HELLO]: guardChannel(CHANNEL_HELLO, handleHello),
  [CHANNEL_OTA]: guardChannel(CHANNEL_OTA, handleOta),
};

export function registerDeviceLink(options: DeviceLinkOptions = {}): ChannelHandlers {
  if (options.config !== undefined) {
    state.config = options.config;
  }
  if (options.broker !== undefined) {
    state.broker = options.broker;
  }
  if (options.log !== undefined) {
    state.log = options.log;
  }
  return HANDLERS;
}

async function start(config: ControllerConfig): Promise<void> {
  state.config = config;
  const handle = await startBroker({
    url: config.brokerUri,
    handlers: registerDeviceLink({ config }),
    log: state.log,
  });
  state.broker = handle;
}

async function stop(): Promise<void> {
  const handle = state.broker;
  state.broker = null;
  if (handle === null) {
    await closeBroker();
    return;
  }
  await handle.close();
}

export const deviceLink: DeviceLink = {
  start,
  stop,
  register: registerDeviceLink,
  sendCommand,
  sendUnblock,
  publishVerdict,
  publishCommand,
  publishAck,
};
