import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { performance } from "node:perf_hooks";
import { stdout } from "node:process";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";
import { Log, LogLevel, Miniflare } from "miniflare";

import { ocspRequestKey } from "../benchmark/ocsp-replay.mjs";
import { benchmarkFixtures } from "../test/fixtures/benchmark-fixtures.ts";

const fixture = benchmarkFixtures.find(({ id }) => id === "jws.synthetic.valid-cold");
const replay = new Map(
  fixture.transport.map(({ url, requestBase64, responseBase64 }) => [
    url,
    {
      key: ocspRequestKey(Buffer.from(requestBase64, "base64")),
      response: Buffer.from(responseBase64, "base64"),
    },
  ]),
);

const compatibilityDate = "2026-08-15";
const { outputFiles } = await build({
  entryPoints: [fileURLToPath(new URL("../.github/workerd/worker.mjs", import.meta.url))],
  bundle: true,
  write: false,
  format: "esm",
  platform: "neutral",
  external: ["node:*"],
});

const ocspResponse = (bytes) =>
  new Response(bytes, { headers: { "content-type": "application/ocsp-response" } });
const wallMicros = (start) => Math.round((performance.now() - start) * 1000);

const withWorker = async (run, respond = (_url, bytes) => ocspResponse(bytes)) => {
  const outboundUrls = [];
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
        dev: {
          outboundService: {
            type: "fetcher",
            async handler(request) {
              const { url } = request;
              outboundUrls.push(url);
              const entry = replay.get(url);
              assert.ok(entry, `unexpected OCSP URL: ${url}`);
              assert.equal(request.method, "POST");
              assert.equal(request.headers.get("accept"), "application/ocsp-response");
              assert.equal(request.headers.get("content-type"), "application/ocsp-request");
              assert.equal(ocspRequestKey(new Uint8Array(await request.arrayBuffer())), entry.key);
              return respond(url, entry.response);
            },
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
    return await run(worker, outboundUrls, wallMicros(start));
  } finally {
    await worker.dispose();
  }
};

const requestVerification = (worker) =>
  worker.dispatchFetch("http://localhost/verify", { signal: AbortSignal.timeout(6_000) });
const verifySuccessfully = async (worker) => {
  const response = await requestVerification(worker);
  assert.equal(response.status, 200, response.ok ? undefined : await response.text());
  assert.deepEqual(await response.json(), {
    application: "com.example.benchmark",
    environment: "test",
    sequence: 1,
  });
};
const assertOcspMiss = (urls) => {
  assert.deepEqual(
    urls.toSorted(),
    [...replay.keys()].sort(),
    "expected one POST to each responder",
  );
};

const timings = await withWorker(async (worker, outboundUrls, startupWallMicros) => {
  const timedVerify = async () => {
    const start = performance.now();
    await verifySuccessfully(worker);
    return wallMicros(start);
  };
  const firstRequestWallMicros = await timedVerify();
  const firstCalls = outboundUrls.splice(0);
  assertOcspMiss(firstCalls);
  const samples = [];
  for (let index = 0; index < 20; index += 1) samples.push(await timedVerify());
  assert.equal(outboundUrls.length, 0, "cache hits must issue no OCSP POSTs");
  const sorted = samples.toSorted((a, b) => a - b);
  return {
    startupWallMicros,
    firstRequestWallMicros,
    firstRequestOcspCalls: firstCalls.length,
    warmRequestWallMicrosMedian: (sorted[9] + sorted[10]) / 2,
    warmRequestWallMicrosP95: sorted[18],
    warmRequestWallMicrosSamples: samples,
  };
});

const arrivals = new Set();
let releaseResponses;
const responsesReleased = new Promise((resolve) => {
  releaseResponses = resolve;
});
await withWorker(
  async (worker, outboundUrls) => {
    try {
      await verifySuccessfully(worker);
      assertOcspMiss(outboundUrls);
    } finally {
      releaseResponses();
    }
  },
  async (url, bytes) => {
    arrivals.add(url);
    if (arrivals.size === replay.size) releaseResponses();
    await responsesReleased;
    return ocspResponse(bytes);
  },
);

const redirectTarget = "http://redirect.example.test/";
await withWorker(
  async (worker, outboundUrls) => {
    const response = await requestVerification(worker);
    assert.equal(response.status, 500);
    const body = await response.json();
    assert.equal(body.code, "transport-error");
    assert.equal(body.cause, "Error: OCSP responder returned HTTP 302");
    assert.ok(!outboundUrls.includes(redirectTarget));
  },
  (url, bytes) =>
    url === fixture.transport[0].url
      ? new Response(null, { status: 302, headers: { location: redirectTarget } })
      : ocspResponse(bytes),
);

stdout.write(
  `${JSON.stringify({
    compatibilityDate,
    ...timings,
    parallelOcspVerified: true,
    redirectRejected: true,
  })}\n`,
);
