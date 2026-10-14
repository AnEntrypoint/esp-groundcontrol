import { pskForSiteNumber } from "./config.js";
import { asSiteId, isSiteId } from "./types.js";

import { beaconRx } from "./beaconRx.js";
import { loadConfig } from "./config.js";
import { deviceLink } from "./deviceLink.js";
import { startHttpApi, type HttpApi } from "./httpApi.js";
import { registry } from "./registry.js";
import { store, syncStore } from "./store.js";
import { initVerification } from "./verifier.js";
import { initWhatsappWebhook } from "./whatsappWebhook.js";

const RETENTION_SWEEP_MS = 6 * 60 * 60 * 1000;

async function main(): Promise<void> {
  const config = loadConfig();
  console.log("controller: config loaded");

  await store.open(config.dbPath);
  console.log(`controller: store open at ${config.dbPath}`);

  const sync = syncStore();
  initVerification({ store: sync, config });
  initWhatsappWebhook({ config, store: sync });
  console.log("controller: verification and whatsapp webhook wired");

  await registry.start();
  console.log("controller: registry started");

  await deviceLink.start(config);
  console.log(`controller: device link up against ${config.brokerUri}`);

  beaconRx.start({
    port: config.beaconPort,
    pskFor: (siteId: number) => pskForSiteNumber(config, siteId),
    onReachable: (siteId: number, deviceId: number, seenAtMs: number) => {
      if (!isSiteId(String(siteId))) {
        return;
      }
      void registry.touchDevice(asSiteId(String(siteId)), deviceId, Math.floor(seenAtMs / 1000));
    },
  });
  console.log(`controller: beacon receiver listening on udp/${config.beaconPort}`);

  const httpApi: HttpApi = await startHttpApi({
    port: config.httpPort,
    operatorToken: config.operatorToken,
    config,
  });
  console.log(`controller: http api listening on tcp/${httpApi.port}`);

  const retentionSweep = setInterval(() => {
    const nowS = Math.floor(Date.now() / 1000);
    const contactsRemoved = sync.forgetContactsBefore(nowS - config.contactRetentionS);
    const telemetryRemoved = sync.trimTelemetryBefore(nowS - config.telemetryRetentionS);
    if (contactsRemoved > 0 || telemetryRemoved > 0) {
      console.log(
        `controller: retention swept ${contactsRemoved} contact(s) and ${telemetryRemoved} telemetry row(s)`,
      );
    }
  }, RETENTION_SWEEP_MS);
  retentionSweep.unref();

  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    clearInterval(retentionSweep);
    console.log(`controller: ${signal} received, shutting down`);
    await httpApi.close();
    beaconRx.stop();
    await deviceLink.stop();
    await registry.close();
    await store.close();
    console.log("controller: stopped");
    process.exit(0);
  };

  process.on("SIGINT", () => {
    void shutdown("SIGINT");
  });
  process.on("SIGTERM", () => {
    void shutdown("SIGTERM");
  });
}

main().catch((error: unknown) => {
  const detail = error instanceof Error ? error.message : String(error);
  console.error(`controller: fatal: ${detail}`);
  process.exit(1);
});
