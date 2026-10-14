import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { Aedes } from "aedes";
import { connect as connectMqtt, type IClientOptions, type MqttClient } from "mqtt";
import { WebSocketServer, createWebSocketStream } from "ws";

export const TOPIC_ROOT = "gc";
export const TOPIC_VERSION = "v1";
export const UPLINK_DIRECTION = "up";
export const DOWNLINK_DIRECTION = "dn";
export const UPLINK_FILTER = "gc/v1/+/+/up/+";

export const FIELD_MQTT_WS = "GC_MQTT_WS";
export const FIELD_MQTT_URL = "GC_MQTT_URL";
export const FIELD_MQTT_USER = "GC_MQTT_USER";
export const FIELD_MQTT_PASS = "GC_MQTT_PASS";
export const FIELD_MQTT_CLIENT_ID = "GC_MQTT_CLIENT_ID";
export const FIELD_MQTT_KEEPALIVE_S = "GC_MQTT_KEEPALIVE_S";
export const FIELD_MQTT_CA_FILE = "GC_MQTT_CA_FILE";

const BACKOFF_BASE_MS = 1000;
const BACKOFF_MAX_MS = 300000;
const BACKOFF_MAX_EXPONENT = 8;
const BACKOFF_JITTER = 0.3;
const DEFAULT_KEEPALIVE_S = 60;
const TOPIC_SEGMENTS = 6;

export type RouteTarget = {
  readonly site: string;
  readonly device: string;
  readonly direction: string;
  readonly channel: string;
};

export type UplinkMessage = {
  readonly topic: string;
  readonly site: string;
  readonly device: string;
  readonly channel: string;
  readonly payload: Uint8Array;
  readonly receivedAtMs: number;
};

export type ChannelHandler = (message: UplinkMessage) => void | Promise<void>;
export type ChannelHandlers = Readonly<Record<string, ChannelHandler>>;
export type BrokerMode = "embedded" | "bridge";
export type BrokerLog = (line: string) => void;
export type BrokerEnv = Readonly<Record<string, string | undefined>>;

export type BrokerOptions = {
  readonly url?: string;
  readonly ws?: string;
  readonly user?: string;
  readonly password?: string;
  readonly clientId?: string;
  readonly keepaliveSeconds?: number;
  readonly uplinkFilter?: string;
  readonly handlers?: ChannelHandlers;
  readonly log?: BrokerLog;
  readonly env?: BrokerEnv;
};

export type BrokerHandle = {
  readonly mode: BrokerMode;
  readonly target: string;
  publishRaw(topic: string, payload: string | Uint8Array, qos?: 0 | 1): Promise<void>;
  publishToDevice(
    site: string,
    device: string,
    channel: string,
    payload: string | Uint8Array,
  ): Promise<void>;
  publishToDeviceQos1(
    site: string,
    device: string,
    channel: string,
    payload: string | Uint8Array,
  ): Promise<void>;
  close(): Promise<void>;
};

type WsBinding = {
  readonly port: number;
  readonly host: string | undefined;
  readonly path: string | undefined;
};

const defaultLog: BrokerLog = (line) => {
  console.log(line);
};

let active: BrokerHandle | null = null;

function describeError(error: unknown): string {
  if (error instanceof Error) {
    return `${error.name}: ${error.message}`;
  }
  return String(error);
}

function envValue(env: BrokerEnv, name: string): string | undefined {
  const raw = env[name];
  if (raw === undefined) {
    return undefined;
  }
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function optionalInt(raw: string | undefined): number | undefined {
  if (raw === undefined) {
    return undefined;
  }
  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
}

export function buildTopic(
  direction: string,
  site: string,
  device: string,
  channel: string,
): string {
  return `${TOPIC_ROOT}/${TOPIC_VERSION}/${site}/${device}/${direction}/${channel}`;
}

export function uplinkTopic(site: string, device: string, channel: string): string {
  return buildTopic(UPLINK_DIRECTION, site, device, channel);
}

export function downlinkTopic(site: string, device: string, channel: string): string {
  return buildTopic(DOWNLINK_DIRECTION, site, device, channel);
}

export function parseTopic(topic: string): RouteTarget | undefined {
  const parts = topic.split("/");
  if (parts.length !== TOPIC_SEGMENTS) {
    return undefined;
  }
  const [root, version, site, device, direction, channel] = parts;
  if (
    root !== TOPIC_ROOT ||
    version !== TOPIC_VERSION ||
    site === undefined ||
    site.length === 0 ||
    device === undefined ||
    device.length === 0 ||
    direction === undefined ||
    direction.length === 0 ||
    channel === undefined ||
    channel.length === 0
  ) {
    return undefined;
  }
  return { site, device, direction, channel };
}

function toBuffer(payload: string | Uint8Array): Buffer {
  return typeof payload === "string" ? Buffer.from(payload, "utf8") : Buffer.from(payload);
}

export function backoffMs(attempt: number): number {
  const exponent = Math.min(Math.max(attempt, 0), BACKOFF_MAX_EXPONENT);
  const base = Math.min(BACKOFF_BASE_MS * 2 ** exponent, BACKOFF_MAX_MS);
  const jitter = Math.floor(base * BACKOFF_JITTER * Math.random());
  return Math.min(base + jitter, BACKOFF_MAX_MS);
}

function parseWsBinding(raw: string): WsBinding {
  if (raw.includes("://")) {
    const url = new URL(raw);
    const port = url.port.length > 0 ? Number(url.port) : url.protocol === "wss:" ? 443 : 80;
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
      throw new Error(`invalid ${FIELD_MQTT_WS} port in "${raw}"`);
    }
    return {
      port,
      host: url.hostname.length > 0 && url.hostname !== "0.0.0.0" ? url.hostname : undefined,
      path: url.pathname.length > 1 ? url.pathname : undefined,
    };
  }
  if (raw.includes(":")) {
    const separator = raw.lastIndexOf(":");
    const host = raw.slice(0, separator).trim();
    const port = Number(raw.slice(separator + 1).trim());
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
      throw new Error(`invalid ${FIELD_MQTT_WS} port in "${raw}"`);
    }
    return { port, host: host.length > 0 ? host : undefined, path: undefined };
  }
  const port = Number(raw);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`invalid ${FIELD_MQTT_WS}: "${raw}" is not a port or URL`);
  }
  return { port, host: undefined, path: undefined };
}

function isSecureUrl(url: string): boolean {
  return /^(mqtts|wss):\/\//i.test(url);
}

function mqttOptions(url: string, options: BrokerOptions, env: BrokerEnv): IClientOptions {
  const user = options.user ?? envValue(env, FIELD_MQTT_USER);
  const password = options.password ?? envValue(env, FIELD_MQTT_PASS);
  const clientId = options.clientId ?? envValue(env, FIELD_MQTT_CLIENT_ID);
  const keepalive =
    options.keepaliveSeconds ??
    optionalInt(envValue(env, FIELD_MQTT_KEEPALIVE_S)) ??
    DEFAULT_KEEPALIVE_S;
  const caFile = envValue(env, FIELD_MQTT_CA_FILE);
  const clientOptions: IClientOptions = {
    keepalive,
    reconnectPeriod: 0,
    connectTimeout: 15000,
    rejectUnauthorized: true,
    resubscribe: true,
    queueQoSZero: false,
  };
  if (user !== undefined) {
    clientOptions.username = user;
  }
  if (password !== undefined) {
    clientOptions.password = Buffer.from(password, "utf8");
  }
  if (clientId !== undefined) {
    clientOptions.clientId = clientId;
  }
  if (caFile !== undefined) {
    try {
      clientOptions.ca = readFileSync(caFile);
    } catch (error) {
      throw new Error(`cannot read ${FIELD_MQTT_CA_FILE} "${caFile}": ${describeError(error)}`);
    }
  }
  if (!isSecureUrl(url)) {
    defaultLog(`broker: ${url} is not a TLS URL, device traffic will cross the link in clear`);
  }
  return clientOptions;
}

async function runHandler(
  handler: ChannelHandler,
  message: UplinkMessage,
  log: BrokerLog,
): Promise<void> {
  try {
    await handler(message);
  } catch (error) {
    log(`broker: handler for channel "${message.channel}" failed: ${describeError(error)}`);
  }
}

function routeMessage(
  topic: string,
  payload: Uint8Array,
  handlers: ChannelHandlers,
  log: BrokerLog,
): void {
  const target = parseTopic(topic);
  if (target === undefined) {
    return;
  }
  if (target.direction !== UPLINK_DIRECTION) {
    return;
  }
  const handler = handlers[target.channel];
  if (handler === undefined) {
    log(`broker: no handler registered for uplink channel "${target.channel}"`);
    return;
  }
  const message: UplinkMessage = {
    topic,
    site: target.site,
    device: target.device,
    channel: target.channel,
    payload,
    receivedAtMs: Date.now(),
  };
  void runHandler(handler, message, log);
}

async function listen(server: Server, binding: WsBinding): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => {
      reject(error);
    };
    server.once("error", onError);
    const done = (): void => {
      server.off("error", onError);
      resolve();
    };
    if (binding.host === undefined) {
      server.listen(binding.port, done);
    } else {
      server.listen(binding.port, binding.host, done);
    }
  });
}

async function startEmbeddedBroker(
  raw: string,
  options: BrokerOptions,
  log: BrokerLog,
): Promise<BrokerHandle> {
  const binding = parseWsBinding(raw);
  const handlers = options.handlers ?? {};
  const broker = await Aedes.createBroker();
  const server = createServer();
  const wssOptions: { server: Server; path?: string } = { server };
  if (binding.path !== undefined) {
    wssOptions.path = binding.path;
  }
  const wss = new WebSocketServer(wssOptions);

  wss.on("connection", (socket) => {
    const stream = createWebSocketStream(socket);
    stream.on("error", (error: unknown) => {
      log(`broker: websocket stream error: ${describeError(error)}`);
    });
    broker.handle(stream);
  });
  wss.on("error", (error: unknown) => {
    log(`broker: websocket server error: ${describeError(error)}`);
  });
  broker.on("clientError", (_client, error: unknown) => {
    log(`broker: client error: ${describeError(error)}`);
  });
  broker.on("publish", (packet, client) => {
    if (client === null || client === undefined) {
      return;
    }
    routeMessage(packet.topic, toBuffer(packet.payload as string | Uint8Array), handlers, log);
  });

  await listen(server, binding);
  log(`broker: embedded aedes broker listening for the operator UI on port ${binding.port}`);

  const publish = async (topic: string, payload: Buffer, qos: 0 | 1): Promise<void> => {
    await new Promise<void>((resolve) => {
      const done = (error?: Error | null): void => {
        if (error !== undefined && error !== null) {
          log(`broker: publish to ${topic} failed: ${describeError(error)}`);
        }
        resolve();
      };
      try {
        const packet = {
          topic,
          payload,
          qos,
          retain: false,
          cmd: "publish",
        } as unknown as Parameters<Aedes["publish"]>[0];
        broker.publish(packet, done);
      } catch (error) {
        done(error instanceof Error ? error : new Error(describeError(error)));
      }
    });
  };

  const handle: BrokerHandle = {
    mode: "embedded",
    target: `ws://${binding.host ?? "0.0.0.0"}:${binding.port}${binding.path ?? ""}`,
    publishRaw: (topic, payload, qos = 0) => publish(topic, toBuffer(payload), qos),
    publishToDevice: (site, device, channel, payload) =>
      publish(downlinkTopic(site, device, channel), toBuffer(payload), 0),
    publishToDeviceQos1: (site, device, channel, payload) =>
      publish(downlinkTopic(site, device, channel), toBuffer(payload), 1),
    close: async () => {
      await new Promise<void>((resolve) => {
        wss.close(() => {
          resolve();
        });
      });
      await new Promise<void>((resolve) => {
        server.close(() => {
          resolve();
        });
      });
      await new Promise<void>((resolve) => {
        broker.close(() => {
          resolve();
        });
      });
    },
  };
  return handle;
}

async function startBridgeBroker(
  url: string,
  options: BrokerOptions,
  log: BrokerLog,
  env: BrokerEnv,
): Promise<BrokerHandle> {
  const handlers = options.handlers ?? {};
  const filter = options.uplinkFilter ?? UPLINK_FILTER;
  const clientOptions = mqttOptions(url, options, env);
  let client: MqttClient | null = null;
  let timer: NodeJS.Timeout | null = null;
  let attempt = 0;
  let closed = false;

  const subscribe = (mqtt: MqttClient): void => {
    mqtt.subscribe(filter, { qos: 1 }, (error) => {
      if (error !== undefined && error !== null) {
        log(`broker: subscribe to ${filter} failed: ${describeError(error)}`);
        return;
      }
      log(`broker: subscribed to ${filter}`);
    });
  };

  const reconnect = (): void => {
    if (closed) {
      return;
    }
    const delay = backoffMs(attempt);
    attempt += 1;
    log(`broker: reconnecting to ${url} in ${Math.round(delay / 1000)}s`);
    timer = setTimeout(() => {
      timer = null;
      connect();
    }, delay);
    timer.unref();
  };

  const connect = (): void => {
    if (closed) {
      return;
    }
    let mqtt: MqttClient;
    try {
      mqtt = connectMqtt(url, clientOptions);
    } catch (error) {
      log(`broker: cannot connect to ${url}: ${describeError(error)}`);
      reconnect();
      return;
    }
    client = mqtt;
    mqtt.on("connect", () => {
      attempt = 0;
      log(`broker: connected to ${url}`);
      subscribe(mqtt);
    });
    mqtt.on("message", (topic, payload) => {
      routeMessage(topic, payload, handlers, log);
    });
    mqtt.on("error", (error) => {
      log(`broker: mqtt error: ${describeError(error)}`);
    });
    mqtt.on("close", () => {
      if (closed) {
        return;
      }
      log(`broker: connection to ${url} closed`);
      reconnect();
    });
  };

  connect();

  const publish = async (topic: string, payload: Buffer, qos: 0 | 1): Promise<void> => {
    const mqtt = client;
    if (mqtt === null || !mqtt.connected) {
      log(`broker: dropping publish to ${topic}, not connected`);
      return;
    }
    await new Promise<void>((resolve) => {
      const done = (error?: Error): void => {
        if (error !== undefined) {
          log(`broker: publish to ${topic} failed: ${describeError(error)}`);
        }
        resolve();
      };
      try {
        mqtt.publish(topic, payload, { qos }, done);
      } catch (error) {
        done(error instanceof Error ? error : new Error(describeError(error)));
      }
    });
  };

  return {
    mode: "bridge",
    target: url,
    publishRaw: (topic, payload, qos = 0) => publish(topic, toBuffer(payload), qos),
    publishToDevice: (site, device, channel, payload) =>
      publish(downlinkTopic(site, device, channel), toBuffer(payload), 0),
    publishToDeviceQos1: (site, device, channel, payload) =>
      publish(downlinkTopic(site, device, channel), toBuffer(payload), 1),
    close: async () => {
      closed = true;
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
      const mqtt = client;
      client = null;
      if (mqtt === null) {
        return;
      }
      await new Promise<void>((resolve) => {
        mqtt.end(true, {}, () => {
          resolve();
        });
      });
    },
  };
}

export async function startBroker(options: BrokerOptions = {}): Promise<BrokerHandle> {
  const env = options.env ?? process.env;
  const log = options.log ?? defaultLog;
  const ws = options.ws ?? envValue(env, FIELD_MQTT_WS);
  const url = options.url ?? envValue(env, FIELD_MQTT_URL);

  if (ws !== undefined) {
    active = await startEmbeddedBroker(ws, options, log);
    return active;
  }
  if (url !== undefined) {
    active = await startBridgeBroker(url, options, log, env);
    return active;
  }
  throw new Error(`broker requires ${FIELD_MQTT_WS} or ${FIELD_MQTT_URL} to be set`);
}

export function activeBroker(): BrokerHandle | null {
  return active;
}

export async function publishToDevice(
  site: string,
  device: string,
  channel: string,
  payload: string | Uint8Array,
): Promise<void> {
  if (active === null) {
    defaultLog(`broker: publishToDevice ${site}/${device}/${channel} dropped, no broker running`);
    return;
  }
  await active.publishToDevice(site, device, channel, payload);
}

export async function publishToDeviceQos1(
  site: string,
  device: string,
  channel: string,
  payload: string | Uint8Array,
): Promise<void> {
  if (active === null) {
    defaultLog(`broker: publishToDeviceQos1 ${site}/${device}/${channel} dropped, no broker running`);
    return;
  }
  await active.publishToDeviceQos1(site, device, channel, payload);
}

export async function closeBroker(): Promise<void> {
  const handle = active;
  active = null;
  if (handle === null) {
    return;
  }
  await handle.close();
}
