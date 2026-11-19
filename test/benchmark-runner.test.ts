import { spawnSync } from "node:child_process";
import { execPath } from "node:process";
import { fileURLToPath } from "node:url";

import { describe, expect, it, vi } from "vitest";

import { ocspRequestKey } from "../benchmark/ocsp-replay.mjs";
import { createReplayTransport, parseArgs, summarizeSamples } from "../benchmark/runner.mjs";
import { benchmarkVectors } from "./fixtures/benchmark-vectors.js";

const runner = fileURLToPath(new URL("../benchmark/runner.mjs", import.meta.url));
const benchmark = (...args: string[]) =>
  spawnSync(execPath, ["--experimental-strip-types", runner, "--json", ...args], {
    encoding: "utf8",
  });

describe("benchmark runner primitives", () => {
  it("normalizes Yarn's argument separator", () => {
    const options = parseArgs([
      "--",
      "--mode",
      "cold",
      "--samples",
      "4",
      "--baseline",
      "./benchmark/reference-adapter.mjs",
    ]);

    expect(options.mode).toBe("cold");
    expect(options.samples).toBe(4);
    expect(options.baseline).toBeInstanceOf(URL);
  });

  it("counts every replay attempt and records mismatches across resets", async () => {
    const transport = createReplayTransport([
      { url: "http://example.test/", requestBase64: "AQI=", responseBase64: "AwQ=" },
      { url: "http://other.test/", requestBase64: "BQ==", responseBase64: "Bg==" },
    ]);

    await expect(transport.request("http://other.test/", Uint8Array.of(5))).resolves.toEqual(
      Uint8Array.of(6),
    );
    await expect(
      transport.request("http://example.test/", Uint8Array.from([1, 2])),
    ).resolves.toEqual(Uint8Array.from([3, 4]));
    expect(transport.requestCount).toBe(2);
    expect(transport.requestIntervals).toHaveLength(2);
    transport.reset();
    await expect(transport.request("http://example.test/", Uint8Array.from([9]))).rejects.toThrow(
      "replay-mismatch",
    );
    expect(transport.requestCount).toBe(1);
    expect(transport.mismatchCount).toBe(1);
    expect(transport.requestIntervals).toHaveLength(1);
    transport.reset();
    expect(transport.mismatchCount).toBe(0);
    expect(transport.requestIntervals).toHaveLength(0);
  });

  it("records controlled replay delays as request intervals", async () => {
    const transport = createReplayTransport([
      {
        url: "http://example.test/",
        requestBase64: "AQI=",
        responseBase64: "AwQ=",
        delayMs: 1,
      },
    ]);

    await expect(
      transport.request("http://example.test/", Uint8Array.from([1, 2])),
    ).resolves.toEqual(Uint8Array.from([3, 4]));
    expect(transport.requestIntervals[0]).toMatchObject({
      url: "http://example.test/",
      durationMs: expect.any(Number),
    });
  });

  it("keeps late completions out of the next replay sample", async () => {
    vi.useFakeTimers();
    try {
      const url = "http://example.test/";
      const transport = createReplayTransport([
        { url, requestBase64: "AQ==", responseBase64: "Ag==", delayMs: 10 },
      ]);
      const first = transport.request(url, Uint8Array.of(1));
      transport.reset();
      const second = transport.request(url, Uint8Array.of(1));
      await vi.advanceTimersByTimeAsync(10);
      await Promise.all([first, second]);

      expect(transport.requestCount).toBe(1);
      expect(transport.mismatchCount).toBe(0);
      expect(transport.requestIntervals).toHaveLength(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("matches equivalent CertIDs with omitted algorithm parameters", () => {
    const request = Buffer.from(benchmarkVectors.leafRequest, "base64");
    const withoutNull = Buffer.concat([request.subarray(0, 23), request.subarray(25)]);
    for (const offset of [1, 3, 5, 7, 9, 11]) withoutNull[offset] -= 2;
    expect(ocspRequestKey(withoutNull)).toBe(ocspRequestKey(request));
    expect(() => ocspRequestKey(request.subarray(0, -1))).toThrow();
  });

  it("exits unsuccessfully and omits ratios when a candidate fails validation", () => {
    const module =
      'export const adapter={name:"reject",version:"1",capabilities:["jws"],create:()=>({verify:async()=>({outcome:"reject"})})}';
    const result = benchmark(
      "--mode",
      "warm",
      "--fixture",
      "jws.synthetic.valid-cold",
      "--samples",
      "1",
      "--batch",
      "1",
      "--warmup",
      "1",
      "--baseline",
      "./benchmark/reference-adapter.mjs",
      "--adapter",
      `data:text/javascript,${encodeURIComponent(module)}`,
    );
    expect(result.status, result.stderr).toBe(1);
    expect(JSON.parse(result.stdout)).toMatchObject({
      validationFailed: true,
      comparison: [],
      results: [{ validation: { passed: false } }],
    });
  });

  it("records cold phases and verifies expired cache entries again", () => {
    const result = benchmark(
      "--samples",
      "1",
      "--batch",
      "2",
      "--warmup",
      "1",
      "--fixture",
      "jws.synthetic.valid-cold",
      "--fixture",
      "jws.synthetic.valid-expired-cache",
    );
    expect(result.status, result.stderr).toBe(0);
    const { results } = JSON.parse(result.stdout);
    expect(results.map(({ mode, cacheState }) => [mode, cacheState])).toEqual([
      ["warm", "warm-miss"],
      ["cold", "cold"],
      ["warm", "warm-expired"],
    ]);
    expect(results[1].samples[0]).toMatchObject({
      load: { cpuMicros: expect.any(Number), wallMicros: expect.any(Number) },
      create: { cpuMicros: expect.any(Number), wallMicros: expect.any(Number) },
    });
    expect(results[2].samples[0].observations.map(({ requestCount }) => requestCount)).toEqual([
      2, 2,
    ]);
  });

  it("invalidates a series if the adapter catches a replay mismatch", () => {
    const module = `export const adapter = {
      name: "caught-mismatch",
      version: "1",
      capabilities: ["ocsp"],
      create: ({ transport }) => ({
        verify: async () => {
          try {
            await transport.request("http://unexpected.example.test/", Uint8Array.of(0));
          } catch {
            return { outcome: "reject", reason: "revoked" };
          }
        },
      }),
    }`;
    const result = benchmark(
      "--mode",
      "warm",
      "--fixture",
      "ocsp.synthetic.revoked",
      "--samples",
      "1",
      "--batch",
      "1",
      "--warmup",
      "1",
      "--adapter",
      `data:text/javascript,${encodeURIComponent(module)}`,
    );
    expect(result.status, result.stderr).toBe(1);
    expect(JSON.parse(result.stdout).results[0]).toMatchObject({
      validation: { passed: false, failures: expect.arrayContaining(["replay mismatches=1"]) },
      samples: [{ observations: [{ outcome: "reject", requestCount: 1, mismatchCount: 1 }] }],
    });
  });

  it("reports median and p95 independently for CPU and wall time", () => {
    expect(
      summarizeSamples([
        { cpuMicros: 10, wallMicros: 100 },
        { cpuMicros: 20, wallMicros: 200 },
        { cpuMicros: 30, wallMicros: 300 },
      ]),
    ).toMatchObject({
      count: 3,
      cpuMicrosMedian: 20,
      cpuMicrosP95: 30,
      wallMicrosMedian: 200,
      wallMicrosP95: 300,
    });
  });
});
