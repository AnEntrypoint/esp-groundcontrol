import { createSocket, type RemoteInfo, type Socket } from "node:dgram";
import { beaconTag, verifyBeaconTag } from "./crypto.js";
import { BEACON_LEN, BEACON_PAYLOAD_LEN } from "./types.js";

export const GC_BEACON_PORT = 41234;
export const GC_BEACON_VERSION = 1;
export const GC_BEACON_KIND_ROUTINE = 1;
export const GC_BEACON_KIND_ALARM = 2;

const VERSION_SHIFT = 4;
const KIND_MASK = 0x0f;
const REPLY_FLAG_TUNNEL = 0x08;

export type PskLookup = (siteId: number, deviceIndex: number) => Buffer | undefined;

export type ReachabilitySink = (siteId: number, deviceIndex: number, seenAtMs: number) => void;

export type BeaconRxOptions = {
  readonly port: number;
  readonly pskFor: PskLookup;
  readonly onReachable: ReachabilitySink;
};

export type BeaconStats = {
  readonly accepted: number;
  readonly dropped: number;
  readonly trackedDevices: number;
};

function deviceKey(siteId: number, deviceIndex: number): string {
  return `${siteId}:${deviceIndex}`;
}

export class BeaconReceiver {
  private readonly lastCounter = new Map<string, number>();
  private readonly tunnelPending = new Set<string>();
  private socket: Socket | undefined;
  private pskFor: PskLookup = () => undefined;
  private onReachable: ReachabilitySink = () => undefined;
  private accepted = 0;
  private dropped = 0;
  private boundPort = 0;

  get port(): number {
    return this.boundPort;
  }

  start(options: BeaconRxOptions): void {
    if (this.socket !== undefined) {
      return;
    }
    this.pskFor = options.pskFor;
    this.onReachable = options.onReachable;
    this.boundPort = options.port;

    const socket = createSocket({ type: "udp4", reuseAddr: true });
    socket.on("message", (msg: Buffer, rinfo: RemoteInfo) => {
      this.receive(msg, rinfo);
    });
    socket.on("error", () => {
      this.dropped += 1;
    });
    socket.bind(options.port);
    this.socket = socket;
  }

  stop(): void {
    const socket = this.socket;
    this.socket = undefined;
    this.boundPort = 0;
    if (socket !== undefined) {
      socket.close();
    }
  }

  requestTunnel(siteId: number, deviceIndex: number, up: boolean): void {
    const key = deviceKey(siteId, deviceIndex);
    if (up) {
      this.tunnelPending.add(key);
    } else {
      this.tunnelPending.delete(key);
    }
  }

  tunnelRequested(siteId: number, deviceIndex: number): boolean {
    return this.tunnelPending.has(deviceKey(siteId, deviceIndex));
  }

  stats(): BeaconStats {
    return {
      accepted: this.accepted,
      dropped: this.dropped,
      trackedDevices: this.lastCounter.size,
    };
  }

  private receive(msg: Buffer, rinfo: RemoteInfo): void {
    if (msg.length !== BEACON_LEN) {
      this.drop();
      return;
    }

    const header = msg.readUInt8(0);
    if (header >>> VERSION_SHIFT !== GC_BEACON_VERSION) {
      this.drop();
      return;
    }
    const kind = header & KIND_MASK;
    if (kind !== GC_BEACON_KIND_ROUTINE && kind !== GC_BEACON_KIND_ALARM) {
      this.drop();
      return;
    }

    const siteId = msg.readUInt16BE(1);
    const deviceIndex = msg.readUInt8(3);
    const counter = msg.readUInt32BE(4);

    const psk = this.pskFor(siteId, deviceIndex);
    if (psk === undefined || psk.length === 0) {
      this.drop();
      return;
    }

    const payload = msg.subarray(0, BEACON_PAYLOAD_LEN);
    const presented = msg.subarray(BEACON_PAYLOAD_LEN, BEACON_LEN).toString("hex");
    if (!verifyBeaconTag(psk, payload, presented)) {
      this.drop();
      return;
    }

    const key = deviceKey(siteId, deviceIndex);
    const previous = this.lastCounter.get(key);
    if (previous !== undefined && counter <= previous) {
      this.drop();
      return;
    }
    this.lastCounter.set(key, counter);
    this.accepted += 1;
    this.onReachable(siteId, deviceIndex, Date.now());

    if (!this.tunnelPending.delete(key)) {
      return;
    }

    const socket = this.socket;
    if (socket === undefined) {
      return;
    }
    const reply = this.buildTunnelReply(psk, siteId, deviceIndex, counter);
    socket.send(reply, 0, reply.length, rinfo.port, rinfo.address, (error: Error | null) => {
      if (error !== null) {
        this.dropped += 1;
      }
    });
  }

  private buildTunnelReply(psk: Buffer, siteId: number, deviceIndex: number, counter: number): Buffer {
    const reply = Buffer.alloc(BEACON_LEN);
    reply.writeUInt8((GC_BEACON_VERSION << VERSION_SHIFT) | REPLY_FLAG_TUNNEL, 0);
    reply.writeUInt16BE(siteId, 1);
    reply.writeUInt8(deviceIndex, 3);
    reply.writeUInt32BE(counter, 4);
    const tag = Buffer.from(beaconTag(psk, reply.subarray(0, BEACON_PAYLOAD_LEN)), "hex");
    tag.copy(reply, BEACON_PAYLOAD_LEN);
    return reply;
  }

  private drop(): void {
    this.dropped += 1;
  }
}

export const beaconRx: BeaconReceiver = new BeaconReceiver();
