import { describe, expect, it, vi } from "vitest";

import { createVerifier, VerificationError } from "../../source/index.js";
import { CertificatePreparation } from "../../source/x509/prepared-certificates.js";
import { benchmarkPolicy, verificationClockMs } from "../fixtures/benchmark-fixtures.js";
import { benchmarkVectors } from "../fixtures/benchmark-vectors.js";
import {
  makeSignedFixture,
  signedFixtureTime,
  signedOcspEndpoints,
} from "../fixtures/signed-jws.js";

const bytes = (value: string): Uint8Array => Buffer.from(value, "base64");
const allowedEndpoints = ["http://leaf.example.test/", "http://intermediate.example.test/"];

const onlineVerifier = (
  leafResponse: string = benchmarkVectors.leafGood,
  intermediateResponse: string = benchmarkVectors.intermediateGood,
  clock = verificationClockMs,
) =>
  createVerifier({
    trustedRoots: [bytes(benchmarkPolicy.trustedRootsBase64[0])],
    clock: () => clock,
    policy: {
      mode: "online",
      ocsp: { allowedEndpoints },
      application: benchmarkPolicy.application,
      environment: benchmarkPolicy.environment,
      claimPaths: { application: ["application"], environment: ["environment"] },
    },
    ocspTransport: async ({ body }) => {
      const key = Buffer.from(body).toString("base64");
      if (key === benchmarkVectors.leafRequest) return bytes(leafResponse);
      if (key === benchmarkVectors.intermediateRequest) return bytes(intermediateResponse);
      throw new Error("replay-mismatch");
    },
  });

const verifierWithTransport = (
  transport: NonNullable<Parameters<typeof createVerifier>[0]>["ocspTransport"],
  policy: NonNullable<Parameters<typeof createVerifier>[0]>["policy"] = { mode: "online" },
  clock: () => number = () => verificationClockMs,
) =>
  createVerifier({
    trustedRoots: [bytes(benchmarkPolicy.trustedRootsBase64[0])],
    clock,
    policy: { mode: "online", ...policy, ocsp: { allowedEndpoints, ...policy.ocsp } },
    ocspTransport: transport,
  });

const expectCode = async (promise: Promise<unknown>, code: VerificationError["code"]) => {
  try {
    await promise;
    throw new Error("Expected verification to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(VerificationError);
    expect((error as VerificationError).code).toBe(code);
  }
};

describe("online OCSP verification", () => {
  it("reuses the verified chain without skipping a new JWS signature", async () => {
    const transport = vi.fn(async ({ body }: { body: Uint8Array }) => {
      const key = Buffer.from(body).toString("base64");
      if (key === benchmarkVectors.leafRequest) return bytes(benchmarkVectors.leafGood);
      if (key === benchmarkVectors.intermediateRequest)
        return bytes(benchmarkVectors.intermediateGood);
      throw new Error("replay-mismatch");
    });
    const verifier = createVerifier({
      trustedRoots: [bytes(benchmarkPolicy.trustedRootsBase64[0])],
      clock: () => verificationClockMs,
      policy: {
        mode: "online",
        ocsp: { allowedEndpoints },
        application: benchmarkPolicy.application,
        environment: benchmarkPolicy.environment,
        claimPaths: { application: ["application"], environment: ["environment"] },
      },
      ocspTransport: transport,
    });

    const signatureStart = benchmarkVectors.nextJws.lastIndexOf(".") + 1;
    const invalid =
      benchmarkVectors.nextJws.slice(0, signatureStart) +
      (benchmarkVectors.nextJws[signatureStart] === "A" ? "B" : "A") +
      benchmarkVectors.nextJws.slice(signatureStart + 1);
    const prepareChain = vi.spyOn(CertificatePreparation.prototype, "prepareChain");
    try {
      await expect(verifier.verify(benchmarkVectors.validJws)).resolves.toBeTruthy();
      await expect(verifier.verify(benchmarkVectors.nextJws)).resolves.toBeTruthy();
      await expectCode(verifier.verify(invalid), "invalid-signature");
      expect(transport).toHaveBeenCalledTimes(2);
      expect(prepareChain).toHaveBeenCalledTimes(1);
    } finally {
      prepareChain.mockRestore();
    }
  });

  it("refreshes OCSP after the configured online cache TTL", async () => {
    let now = verificationClockMs;
    const transport = vi.fn(async ({ body }: { body: Uint8Array }) => {
      const key = Buffer.from(body).toString("base64");
      if (key === benchmarkVectors.leafRequest) return bytes(benchmarkVectors.leafGood);
      if (key === benchmarkVectors.intermediateRequest)
        return bytes(benchmarkVectors.intermediateGood);
      throw new Error("replay-mismatch");
    });
    const verifier = createVerifier({
      trustedRoots: [bytes(benchmarkPolicy.trustedRootsBase64[0])],
      clock: () => now,
      limits: { cacheTtlMs: 1_000 },
      policy: { mode: "online", ocsp: { allowedEndpoints } },
      ocspTransport: transport,
    });

    await verifier.verify(benchmarkVectors.validJws);
    now += 1_001;
    await verifier.verify(benchmarkVectors.nextJws);
    expect(transport).toHaveBeenCalledTimes(4);
  });

  it("evicts old prepared chains when the cache entry limit is reached", async () => {
    const first = makeSignedFixture();
    const second = makeSignedFixture();
    const responses = [
      first.ocspResponse(signedOcspEndpoints[0], "issuer-name"),
      first.ocspResponse(signedOcspEndpoints[1], "issuer-name"),
      second.ocspResponse(signedOcspEndpoints[0], "issuer-name"),
      second.ocspResponse(signedOcspEndpoints[1], "issuer-name"),
      first.ocspResponse(signedOcspEndpoints[0], "issuer-name"),
      first.ocspResponse(signedOcspEndpoints[1], "issuer-name"),
    ];
    let responseIndex = 0;
    const transport = vi.fn(async () => {
      const response = responses[responseIndex++];
      if (response === undefined) throw new Error("unexpected OCSP request");
      return new Uint8Array(response);
    });
    const verifier = createVerifier({
      trustedRoots: [first.rootDer, second.rootDer],
      clock: () => signedFixtureTime,
      limits: { maxCacheEntries: 1 },
      policy: { mode: "online", ocsp: { allowedEndpoints: signedOcspEndpoints } },
      ocspTransport: transport,
    });

    await verifier.verify(first.signJws({ sequence: 1 }));
    await verifier.verify(second.signJws({ sequence: 2 }));
    await verifier.verify(first.signJws({ sequence: 3 }));
    expect(transport).toHaveBeenCalledTimes(6);
  });

  it("rechecks OCSP freshness after the clock moves backward", async () => {
    const fixture = makeSignedFixture();
    let now = signedFixtureTime;
    const transport = vi.fn(async ({ url }: { url: string }) => fixture.ocspResponse(url, "byKey"));
    const verifier = createVerifier({
      trustedRoots: [fixture.rootDer],
      clock: () => now,
      policy: { mode: "online", ocsp: { allowedEndpoints: signedOcspEndpoints } },
      ocspTransport: transport,
    });
    await verifier.verify(fixture.signJws({}));
    now -= 61_000;
    await expectCode(verifier.verify(fixture.signJws({})), "ocsp-stale");
    expect(transport).toHaveBeenCalledTimes(3);
  });

  it("reselects a trusted root when the cached anchor expires", async () => {
    const fixture = makeSignedFixture();
    let now = signedFixtureTime;
    const transport = vi.fn(async ({ url }: { url: string }) => fixture.ocspResponse(url, "byKey"));
    const verifier = createVerifier({
      trustedRoots: [fixture.shortLivedRootDer, fixture.rootDer],
      clock: () => now,
      policy: { mode: "online", ocsp: { allowedEndpoints: signedOcspEndpoints } },
      ocspTransport: transport,
    });
    await verifier.verify(fixture.signJws({}));
    now += 2_000;
    await verifier.verify(fixture.signJws({}));
    await verifier.verify(fixture.signJws({}));
    expect(transport).toHaveBeenCalledTimes(4);
  });

  it("checks both leaf and intermediate certificates", async () => {
    await expect(onlineVerifier().verify(benchmarkVectors.validJws)).resolves.toMatchObject({
      payload: {
        application: benchmarkPolicy.application,
        environment: benchmarkPolicy.environment,
      },
    });
  });

  it("rejects revoked, stale, mismatched and incorrectly signed responses", async () => {
    await expectCode(
      onlineVerifier(benchmarkVectors.leafRevoked).verify(benchmarkVectors.validJws),
      "ocsp-revoked",
    );

    await expectCode(
      onlineVerifier(
        benchmarkVectors.leafGood,
        benchmarkVectors.intermediateGood,
        Date.parse("2026-11-20T18:26:00Z"),
      ).verify(benchmarkVectors.validJws),
      "ocsp-stale",
    );
    await expectCode(
      onlineVerifier(benchmarkVectors.intermediateGood, benchmarkVectors.intermediateGood).verify(
        benchmarkVectors.validJws,
      ),
      "ocsp-policy",
    );
    const invalid = bytes(benchmarkVectors.leafGood);
    invalid[invalid.length - 1] = (invalid[invalid.length - 1] ?? 0) ^ 1;
    await expectCode(
      onlineVerifier(Buffer.from(invalid).toString("base64")).verify(benchmarkVectors.validJws),
      "ocsp-signature",
    );
  });

  it("maps transport failures and keeps synchronous online use explicit", async () => {
    const verifier = createVerifier({
      trustedRoots: [bytes(benchmarkPolicy.trustedRootsBase64[0])],
      clock: () => verificationClockMs,
      policy: { mode: "online", ocsp: { allowedEndpoints } },
      ocspTransport: async () => {
        throw new Error("timeout");
      },
    });
    await expectCode(verifier.verify(benchmarkVectors.validJws), "transport-error");
    expect(() => verifier.verifySync(benchmarkVectors.validJws)).toThrow(
      expect.objectContaining({ code: "online-unavailable" }),
    );
    await expectCode(
      verifierWithTransport(async () => {
        throw new VerificationError("ocsp-policy", "blocked");
      }).verify(benchmarkVectors.validJws),
      "ocsp-policy",
    );
    const synchronousThrow = (() => {
      throw new Error("synchronous transport failure");
    }) as unknown as NonNullable<Parameters<typeof createVerifier>[0]>["ocspTransport"];
    await expectCode(
      verifierWithTransport(synchronousThrow).verify(benchmarkVectors.validJws),
      "transport-error",
    );
  });

  it("rejects malformed, unsuccessful and unsupported OCSP responses before trust decisions", async () => {
    await expectCode(
      verifierWithTransport(async () => Uint8Array.of(1)).verify(benchmarkVectors.validJws),
      "ocsp-format",
    );
    await expectCode(
      verifierWithTransport(async () => Uint8Array.of(0x30, 0x03, 0x0a, 0x01, 0x02)).verify(
        benchmarkVectors.validJws,
      ),
      "ocsp-status",
    );
    await expectCode(
      verifierWithTransport(async () => Uint8Array.of(0x30, 0x03, 0x0a, 0x01, 0x00)).verify(
        benchmarkVectors.validJws,
      ),
      "ocsp-format",
    );
    await expectCode(
      verifierWithTransport(async () => "not-bytes" as unknown as Uint8Array).verify(
        benchmarkVectors.validJws,
      ),
      "transport-error",
    );
  });

  it("enforces endpoint allowlists and validates the online clock", async () => {
    await expectCode(
      verifierWithTransport(async () => bytes(benchmarkVectors.leafGood), {
        ocsp: { allowedEndpoints: ["https://different.example.test"] },
      }).verify(benchmarkVectors.validJws),
      "ocsp-policy",
    );
    await expectCode(
      verifierWithTransport(
        async () => bytes(benchmarkVectors.leafGood),
        { mode: "online" },
        () => NaN,
      ).verify(benchmarkVectors.validJws),
      "invalid-effective-time",
    );
    await expectCode(
      verifierWithTransport(async () => bytes(benchmarkVectors.leafGood), {
        ocsp: { allowedSignatureAlgorithms: [] },
      }).verify(benchmarkVectors.validJws),
      "ocsp-policy",
    );
  });

  it("preflights both endpoints and checks claims and time before transport", async () => {
    const transport = vi.fn(async () => bytes(benchmarkVectors.leafGood));
    const noAllowlist = createVerifier({
      trustedRoots: [bytes(benchmarkPolicy.trustedRootsBase64[0])],
      clock: () => verificationClockMs,
      policy: { mode: "online" },
      ocspTransport: transport,
    });
    await expectCode(noAllowlist.verify(benchmarkVectors.validJws), "ocsp-policy");
    await expectCode(
      verifierWithTransport(transport, {
        ocsp: { allowedEndpoints: allowedEndpoints.slice(0, 1) },
      }).verify(benchmarkVectors.validJws),
      "ocsp-policy",
    );
    await expectCode(
      verifierWithTransport(transport, {
        application: "different",
        claimPaths: { application: ["application"] },
      }).verify(benchmarkVectors.validJws),
      "claim-policy",
    );
    await expectCode(
      verifierWithTransport(transport).verify(benchmarkVectors.validJws, {
        effectiveTime: verificationClockMs,
      }),
      "invalid-effective-time",
    );
    expect(transport).not.toHaveBeenCalled();
  });

  it.each(["byKey", "issuer-name", "delegate-name", "unauthorized"] as const)(
    "verifies signed responses with responder %s",
    async (scenario) => {
      const fixture = makeSignedFixture();
      const verifier = createVerifier({
        trustedRoots: [fixture.rootDer],
        clock: () => signedFixtureTime,
        policy: { mode: "online", ocsp: { allowedEndpoints: signedOcspEndpoints } },
        ocspTransport: async ({ url }) => fixture.ocspResponse(url, scenario),
      });
      const verification = verifier.verify(fixture.signJws({}));
      if (scenario === "unauthorized") {
        await expectCode(verification, "ocsp-policy");
      } else {
        await expect(verification).resolves.toMatchObject({ payload: {} });
      }
    },
  );
});
