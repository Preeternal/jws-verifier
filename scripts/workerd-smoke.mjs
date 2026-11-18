import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import { stdout } from "node:process";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";
import { Log, LogLevel, Miniflare } from "miniflare";

const compatibilityDate = "2026-08-15";
const { outputFiles } = await build({
  entryPoints: [fileURLToPath(new URL("../.github/workerd/worker.mjs", import.meta.url))],
  bundle: true,
  write: false,
  format: "esm",
  platform: "neutral",
  external: ["node:*"],
});

const start = performance.now();
const worker = new Miniflare({
  workers: [
    {
      config: {
        name: "jws-verifier-smoke",
        compatibilityDate,
        manifest: {
          mainModule: "worker.mjs",
          modules: { "worker.mjs": { type: "esm", contents: outputFiles[0].text } },
        },
      },
    },
  ],
  host: "127.0.0.1",
  port: 0,
  cf: false,
  log: new Log(LogLevel.ERROR),
  logRequests: false,
  enableDevRegistry: false,
});
try {
  await worker.ready;
  const startupWallMicros = Math.round((performance.now() - start) * 1000);
  const request = async () => {
    const before = performance.now();
    const response = await worker.dispatchFetch("http://localhost/verify", {
      signal: AbortSignal.timeout(5_000),
    });
    assert.equal(response.status, 200, response.ok ? undefined : await response.text());
    assert.deepEqual(await response.json(), {
      application: "com.example.benchmark",
      environment: "test",
      sequence: 1,
    });
    return Math.round((performance.now() - before) * 1000);
  };
  const firstRequestWallMicros = await request();
  const samples = [];
  for (let index = 0; index < 20; index += 1) samples.push(await request());
  const sorted = samples.toSorted((a, b) => a - b);
  stdout.write(
    `${JSON.stringify({
      compatibilityDate,
      startupWallMicros,
      firstRequestWallMicros,
      warmRequestWallMicrosMedian: (sorted[9] + sorted[10]) / 2,
      warmRequestWallMicrosP95: sorted[18],
      warmRequestWallMicrosSamples: samples,
    })}\n`,
  );
} finally {
  await worker.dispose();
}
