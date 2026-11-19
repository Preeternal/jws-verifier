import { benchmarkPolicy, verificationClockMs } from "../test/fixtures/benchmark-fixtures.ts";
import { benchmarkVectors } from "../test/fixtures/benchmark-vectors.ts";

export { benchmarkPolicy };

export const benchmarkFixtures = [
  {
    id: "ocsp.synthetic.parallel-delay-80-120",
    kind: "ocsp",
    jws: benchmarkVectors.validJws,
    clockMs: verificationClockMs,
    mode: "online",
    cacheState: "warm-miss",
    expectation: "accept",
    expectedRequests: 2,
    provenance: "synthetic-v1",
    transport: [
      {
        url: "http://leaf.example.test/",
        requestBase64: benchmarkVectors.leafRequest,
        responseBase64: benchmarkVectors.leafGood,
        delayMs: 80,
      },
      {
        url: "http://intermediate.example.test/",
        requestBase64: benchmarkVectors.intermediateRequest,
        responseBase64: benchmarkVectors.intermediateGood,
        delayMs: 120,
      },
    ],
  },
] as const;
