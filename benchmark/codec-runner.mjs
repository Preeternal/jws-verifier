import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import process, { cpuUsage } from "node:process";

import {
  buildOcspRequest,
  parseAppReceiptTransactionId,
  parseOcspResponse,
} from "../dist/index.js";
import { CertificatePreparation } from "../dist/x509/prepared-certificates.js";
import { benchmarkVectors } from "../test/fixtures/benchmark-vectors.ts";
import { summarizeSamples } from "./runner.mjs";

const warmup = 100;
const samples = 10;
const batch = 100;
const bytes = (value) => Buffer.from(value, "base64");
const root = bytes(benchmarkVectors.rootDerBase64);
const header = Buffer.from(benchmarkVectors.validJws.split(".")[0], "base64url");
const [leaf, intermediate] = JSON.parse(header.toString("utf8")).x5c.map(bytes);
const preparation = new CertificatePreparation([root]);
const preparedChain = preparation.prepareChain(leaf, intermediate);
const ocspResponse = bytes(benchmarkVectors.leafGood);
// Synthetic CMS envelope with indefinite lengths and nested OCTET STRING fragments.
const receipt =
  // biome-ignore lint/security/noSecrets: Synthetic fixture without keys, signatures, or user data.
  "MIAGCSqGSIb3DQEHAqCAMIACAQExADBABgkqhkiG9w0BBwGgMySABAsxJTAjAgERAgEBBCSABBwbMRkwFwICBqcCAQEEDgwMYmVuY2htYXJrLWlkAAAAADEAAAAAAAAA";

const operations = {
  "x509-prepare-chain": () => preparation.prepareChain(leaf, intermediate),
  "ocsp-request": () => buildOcspRequest(preparedChain.leaf, preparedChain.intermediate),
  "ocsp-response": () => parseOcspResponse(ocspResponse),
  receipt: () => parseAppReceiptTransactionId(receipt),
};

assert.deepEqual(operations["x509-prepare-chain"]().leaf.der, new Uint8Array(leaf));
assert.equal(
  Buffer.from(operations["ocsp-request"]()).toString("base64"),
  benchmarkVectors.leafRequest,
);
assert.equal(operations["ocsp-response"]().basic?.responses[0]?.status, "good");
assert.deepEqual(operations.receipt(), { kind: "found", transactionId: "benchmark-id" });

const cpuMicros = (before, after) => after.user + after.system - before.user - before.system;

const measure = (operation) => {
  const cpuBefore = cpuUsage();
  const wallBefore = performance.now();
  for (let index = 0; index < batch; index += 1) operation();
  return {
    cpuMicros: cpuMicros(cpuBefore, cpuUsage()) / batch,
    wallMicros: ((performance.now() - wallBefore) * 1000) / batch,
  };
};

const result = {};
for (const [name, operation] of Object.entries(operations)) {
  for (let index = 0; index < warmup; index += 1) operation();
  const measurements = Array.from({ length: samples }, () => measure(operation));
  result[name] = {
    batch,
    summary: summarizeSamples(measurements),
    samples: measurements,
  };
}

process.stdout.write(`${JSON.stringify({ node: process.version, result }, null, 2)}\n`);
