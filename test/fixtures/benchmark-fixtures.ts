import { benchmarkVectors } from "./benchmark-vectors.ts";

export const verificationClockMs = Date.parse("2026-11-18T18:26:00Z");
const staleClockMs = Date.parse("2026-11-20T18:26:00Z");

export const benchmarkPolicy = {
  application: "com.example.benchmark",
  environment: "test",
  algorithm: "ES256",
  trustedRootsBase64: [benchmarkVectors.rootDerBase64],
} as const;

const goodReplay = [
  {
    url: "http://leaf.example.test/",
    requestBase64: benchmarkVectors.leafRequest,
    responseBase64: benchmarkVectors.leafGood,
  },
  {
    url: "http://intermediate.example.test/",
    requestBase64: benchmarkVectors.intermediateRequest,
    responseBase64: benchmarkVectors.intermediateGood,
  },
] as const;

const signatureStart = benchmarkVectors.validJws.lastIndexOf(".") + 1;
const signatureFirstChar = benchmarkVectors.validJws[signatureStart];
const invalidSignatureJws =
  benchmarkVectors.validJws.slice(0, signatureStart) +
  (signatureFirstChar === "A" ? "B" : "A") +
  benchmarkVectors.validJws.slice(signatureStart + 1);

const online = {
  jws: benchmarkVectors.validJws,
  clockMs: verificationClockMs,
  mode: "online",
  transport: goodReplay,
  provenance: "synthetic-v1",
} as const;

export const benchmarkFixtures = [
  {
    ...online,
    id: "jws.synthetic.valid-cold",
    kind: "jws",
    expectation: "accept",
    cacheState: "cold",
    expectedRequests: 2,
  },
  {
    ...online,
    id: "jws.synthetic.invalid-signature",
    kind: "jws",
    jws: invalidSignatureJws,
    expectation: "reject",
    reason: "invalid-signature",
    cacheState: "warm-miss",
    expectedRequests: 0,
  },
  {
    ...online,
    id: "jws.synthetic.unsupported-algorithm",
    kind: "jws",
    jws: benchmarkVectors.unsupportedAlgorithmJws,
    expectation: "reject",
    reason: "unsupported-algorithm",
    cacheState: "cold",
    expectedRequests: 0,
  },
  {
    ...online,
    id: "ocsp.synthetic.good-cache-miss",
    kind: "ocsp",
    expectation: "accept",
    cacheState: "warm-miss",
    expectedRequests: 2,
  },
  {
    ...online,
    id: "ocsp.synthetic.revoked",
    kind: "ocsp",
    transport: [{ ...goodReplay[0], responseBase64: benchmarkVectors.leafRevoked }, goodReplay[1]],
    expectation: "reject",
    reason: "revoked",
    cacheState: "warm-miss",
  },
  {
    ...online,
    id: "ocsp.synthetic.stale",
    kind: "ocsp",
    clockMs: staleClockMs,
    expectation: "reject",
    reason: "stale",
    cacheState: "warm-miss",
  },
  {
    ...online,
    id: "ocsp.synthetic.transport-error",
    kind: "ocsp",
    transport: [
      {
        url: goodReplay[0].url,
        requestBase64: goodReplay[0].requestBase64,
        error: "timeout",
      },
      goodReplay[1],
    ],
    expectation: "transport-error",
    reason: "timeout",
    cacheState: "cold",
  },
  {
    ...online,
    id: "jws.synthetic.valid-warm-hit",
    kind: "jws",
    jws: benchmarkVectors.nextJws,
    expectation: "accept",
    cacheState: "warm-hit",
    primeWithJws: benchmarkVectors.validJws,
    expectedRequests: 0,
  },
  {
    ...online,
    id: "jws.synthetic.valid-expired-cache",
    kind: "jws",
    jws: benchmarkVectors.nextJws,
    clockMs: verificationClockMs + 60 * 60 * 1000,
    primeWithJws: benchmarkVectors.validJws,
    primeClockMs: verificationClockMs,
    expectation: "accept",
    cacheState: "warm-expired",
    expectedRequests: 2,
  },
] as const;
