import { verify, X509Certificate } from "node:crypto";

import { describe, expect, it } from "vitest";
import { z } from "zod/mini";

import { benchmarkFixtures, benchmarkPolicy, verificationClockMs } from "./benchmark-fixtures.js";

const protectedHeader = z.object({
  alg: z.string(),
  x5c: z.tuple([z.string(), z.string(), z.string()]),
});

describe("public benchmark fixture catalog", () => {
  it("has unique IDs and synthetic provenance", () => {
    const ids = benchmarkFixtures.map(({ id }) => id);

    expect(new Set(ids).size).toBe(ids.length);
    for (const fixture of benchmarkFixtures) {
      expect(fixture.provenance).toBe("synthetic-v1");
      expect(fixture.clockMs).toBeGreaterThanOrEqual(verificationClockMs);
    }
  });

  it("covers JWS, OCSP, cache states, and all outcomes", () => {
    expect(new Set(benchmarkFixtures.map(({ kind }) => kind))).toEqual(new Set(["jws", "ocsp"]));
    expect(new Set(benchmarkFixtures.map(({ cacheState }) => cacheState))).toEqual(
      new Set(["cold", "warm-hit", "warm-miss", "warm-expired"]),
    );
    expect(new Set(benchmarkFixtures.map(({ expectation }) => expectation))).toEqual(
      new Set(["accept", "reject", "transport-error"]),
    );
  });

  it("contains no provider-specific or secret material", () => {
    const serialized = JSON.stringify(benchmarkFixtures);

    expect(serialized).not.toMatch(/apple|app-store|dayily|private key|token|secret/i);
    expect(serialized).not.toMatch(/\/Users\/|[A-Za-z]:\\/);
  });

  it("binds the signed inputs to the configured trust anchor and fixed time", () => {
    const [rootDer] = benchmarkPolicy.trustedRootsBase64;
    const root = new X509Certificate(Buffer.from(rootDer, "base64"));

    for (const fixture of benchmarkFixtures) {
      const [header = "", payload = "", signature = ""] = fixture.jws.split(".");
      const { alg, x5c } = protectedHeader.parse(
        JSON.parse(Buffer.from(header, "base64url").toString("utf8")),
      );
      const leaf = new X509Certificate(Buffer.from(x5c[0], "base64"));
      const intermediate = new X509Certificate(Buffer.from(x5c[1], "base64"));
      expect(x5c[2]).toBe(rootDer);
      expect(leaf.verify(intermediate.publicKey)).toBe(true);
      expect(intermediate.verify(root.publicKey)).toBe(true);
      for (const certificate of [leaf, intermediate, root]) {
        expect(fixture.clockMs).toBeGreaterThanOrEqual(certificate.validFromDate.getTime());
        expect(fixture.clockMs).toBeLessThan(certificate.validToDate.getTime());
      }

      const reason = "reason" in fixture ? fixture.reason : undefined;
      expect(alg === benchmarkPolicy.algorithm).toBe(reason !== "unsupported-algorithm");
      if (alg === benchmarkPolicy.algorithm) {
        const valid = verify(
          "sha256",
          Buffer.from(`${header}.${payload}`),
          { key: leaf.publicKey, dsaEncoding: "ieee-p1363" },
          Buffer.from(signature, "base64url"),
        );
        expect(valid).toBe(reason !== "invalid-signature");
      }
      if (reason === "invalid-signature" || reason === "unsupported-algorithm") {
        expect("expectedRequests" in fixture && fixture.expectedRequests).toBe(0);
      }
    }
  });
});
