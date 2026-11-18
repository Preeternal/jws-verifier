import { describe, expect, it, vi } from "vitest";

import { createVerifier, VerificationError, type VerifierOptions } from "../../source/index.js";
import { benchmarkPolicy, verificationClockMs } from "../fixtures/benchmark-fixtures.js";
import { benchmarkVectors } from "../fixtures/benchmark-vectors.js";
import { fixtureMarkerOid, makeSignedFixture, signedFixtureTime } from "../fixtures/signed-jws.js";

const bytes = (base64: string): Uint8Array => Buffer.from(base64, "base64");
const effectiveTime = { effectiveTime: verificationClockMs };
const claimPaths = { application: ["application"], environment: ["environment"] };

const options = (overrides: Partial<VerifierOptions> = {}): VerifierOptions => ({
  trustedRoots: [{ id: "benchmark-root", der: bytes(benchmarkPolicy.trustedRootsBase64[0]) }],
  policy: {
    mode: "offline",
    application: benchmarkPolicy.application,
    environment: benchmarkPolicy.environment,
    claimPaths,
  },
  ...overrides,
});

const expectCode = (callback: () => unknown, code: VerificationError["code"]): void => {
  try {
    callback();
    throw new Error("Expected verification to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(VerificationError);
    expect((error as VerificationError).code).toBe(code);
  }
};

describe("JWS verifier", () => {
  it("verifies an ES256 JWS and its X.509 chain", () => {
    const result = createVerifier(options()).verifySync<{
      application: string;
      environment: string;
    }>(benchmarkVectors.validJws, effectiveTime);

    expect(result.payload).toMatchObject({
      application: benchmarkPolicy.application,
      environment: benchmarkPolicy.environment,
    });
    expect(result.protectedHeader.alg).toBe("ES256");
    expect(result.compactJws).toBe(benchmarkVectors.validJws);
  });

  it("checks the exact signed input and rejects a bad signature before claims", () => {
    const start = benchmarkVectors.validJws.lastIndexOf(".") + 1;
    const replacement = benchmarkVectors.validJws[start] === "A" ? "B" : "A";
    const invalid =
      benchmarkVectors.validJws.slice(0, start) +
      replacement +
      benchmarkVectors.validJws.slice(start + 1);

    const verifier = createVerifier(options({ policy: { signedTimePath: ["missingTime"] } }));
    expectCode(() => verifier.verifySync(invalid), "invalid-signature");
  });

  it("rejects unsupported algorithms without touching the certificate chain", () => {
    expectCode(
      () =>
        createVerifier(options()).verifySync(
          benchmarkVectors.unsupportedAlgorithmJws,
          effectiveTime,
        ),
      "unsupported-algorithm",
    );
  });

  it("rejects a mismatched application claim", () => {
    expectCode(
      () =>
        createVerifier(
          options({
            policy: {
              mode: "offline",
              application: "com.example.other",
              environment: benchmarkPolicy.environment,
              claimPaths,
            },
          }),
        ).verifySync(benchmarkVectors.validJws, effectiveTime),
      "claim-policy",
    );
  });

  it("checks required certificate extensions by role and OID", () => {
    const { rootDer, signJws } = makeSignedFixture();
    const jws = signJws({ issuedAt: signedFixtureTime });
    const verifierFor = (policy: VerifierOptions["policy"]) =>
      createVerifier({
        trustedRoots: [rootDer],
        policy: { signedTimePath: ["issuedAt"], ...policy },
      });

    expect(
      verifierFor({ requiredExtensions: { leaf: [fixtureMarkerOid] } }).verifySync(jws).payload,
    ).toEqual({ issuedAt: signedFixtureTime });
    expectCode(
      () =>
        verifierFor({ requiredExtensions: { intermediate: [fixtureMarkerOid] } }).verifySync(jws),
      "certificate-policy",
    );
  });

  it("checks signed claims only at the configured paths", async () => {
    const { rootDer, signJws } = makeSignedFixture();
    const verifier = createVerifier({
      trustedRoots: [rootDer],
      policy: {
        application: "com.example.app",
        environment: "sandbox",
        claimPaths: { application: ["data", "id"], environment: ["data", "environment"] },
        signedTimePath: ["issuedAt"],
      },
    });
    const payload = {
      issuedAt: signedFixtureTime,
      application: "outer",
      environment: "other",
      data: { id: "com.example.app", environment: "sandbox" },
    };
    await expect(verifier.verify(signJws(payload))).resolves.toMatchObject({ payload });
    for (const data of [
      undefined,
      { id: "other", environment: "sandbox" },
      { id: "com.example.app", environment: "other" },
      { id: 42, environment: "sandbox" },
    ]) {
      expectCode(
        () =>
          verifier.verifySync(
            signJws({ ...payload, application: "com.example.app", environment: "sandbox", data }),
          ),
        "claim-policy",
      );
    }
    expect(() =>
      createVerifier({ trustedRoots: [rootDer], policy: { application: "com.example.app" } }),
    ).toThrow(TypeError);
    expect(() =>
      createVerifier({ trustedRoots: [rootDer], policy: { environment: "sandbox" } }),
    ).toThrow(TypeError);
  });

  it("requires an explicit or signed historical time without reading the host clock", () => {
    const { rootDer, signJws } = makeSignedFixture();
    const clock = vi.fn(() => signedFixtureTime);
    const verifier = createVerifier({
      trustedRoots: [rootDer],
      clock,
      policy: { signedTimePath: ["issuedAt"] },
    });
    for (const issuedAt of [undefined, "2025-01-01", null, 1.5, 9e15]) {
      const jws = signJws({ issuedAt });
      expectCode(() => verifier.verifySync(jws), "invalid-effective-time");
      expect(verifier.verifySync(jws, { effectiveTime: signedFixtureTime }).compactJws).toBe(jws);
    }
    const jws = signJws({ issuedAt: Date.UTC(2010, 0, 1) });
    expectCode(() => verifier.verifySync(jws), "certificate-policy");
    expectCode(() => verifier.verifySync(jws, { effectiveTime: NaN }), "invalid-effective-time");
    expectCode(
      () =>
        createVerifier({ trustedRoots: [rootDer], policy: {} }).verifySync(
          signJws({ issuedAt: signedFixtureTime }),
        ),
      "invalid-effective-time",
    );
    expect(clock).not.toHaveBeenCalled();
  });

  it.each(["leaf", "intermediate"] as const)(
    "rejects unsupported critical extensions on the %s certificate",
    (role) => {
      const { rootDer, signJws } = makeSignedFixture(role);
      const verifier = createVerifier({
        trustedRoots: [rootDer],
        policy: { requiredExtensions: { leaf: [fixtureMarkerOid] } },
      });
      expectCode(
        () => verifier.verifySync(signJws({}), { effectiveTime: signedFixtureTime }),
        "certificate-policy",
      );
    },
  );

  it("rejects unsupported JOSE parameters on signed JWS inputs", () => {
    const { rootDer, signJws } = makeSignedFixture();
    const verifier = createVerifier({ trustedRoots: [rootDer], policy: {} });
    for (const header of [{ crit: ["custom"], custom: true }, { crit: [] }, { b64: false }]) {
      expectCode(
        () => verifier.verifySync(signJws({}, header), { effectiveTime: signedFixtureTime }),
        "invalid-header",
      );
    }
  });

  it("keeps online mode unavailable until the OCSP task", () => {
    expectCode(
      () =>
        createVerifier(options({ policy: { mode: "online" } })).verifySync(
          benchmarkVectors.validJws,
        ),
      "online-unavailable",
    );
  });

  it("considers same-subject anchors with different keys or validity periods", () => {
    const { rootDer, rotatedRootDer, expiredRootDer, signJws } = makeSignedFixture();
    const jws = signJws({ issuedAt: signedFixtureTime });
    const verifierFor = (...trustedRoots: Uint8Array[]) =>
      createVerifier({ trustedRoots, policy: { signedTimePath: ["issuedAt"] } });
    const verifier = verifierFor(rotatedRootDer, expiredRootDer, rootDer);
    expect(verifier.verifySync(jws).compactJws).toBe(jws);
    expectCode(() => verifierFor(rotatedRootDer).verifySync(jws), "certificate-chain");
    expectCode(
      () => verifierFor(expiredRootDer, rotatedRootDer).verifySync(jws),
      "certificate-policy",
    );
  });

  it("rejects a presented root outside the configured trust store", () => {
    const { rootDer, rotatedRootDer, signJws } = makeSignedFixture();
    const verifier = createVerifier({ trustedRoots: [rootDer], policy: {} });
    expectCode(
      () =>
        verifier.verifySync(signJws({}, {}, rotatedRootDer), { effectiveTime: signedFixtureTime }),
      "certificate-chain",
    );
  });
});
