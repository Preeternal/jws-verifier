import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { buildOcspRequest, ocspCertIdFor, parseOcspResponse } from "../../source/index.js";
import { CertificatePreparation } from "../../source/x509/prepared-certificates.js";
import { benchmarkPolicy } from "../fixtures/benchmark-fixtures.js";
import { benchmarkVectors } from "../fixtures/benchmark-vectors.js";

const bytes = (value: string): Uint8Array => Buffer.from(value, "base64");

const preparedChain = () => {
  const header = JSON.parse(
    Buffer.from(benchmarkVectors.validJws.split(".")[0] ?? "", "base64url").toString("utf8"),
  ) as { x5c: [string, string, string] };
  return new CertificatePreparation([bytes(benchmarkPolicy.trustedRootsBase64[0])]).prepareChain(
    bytes(header.x5c[0]),
    bytes(header.x5c[1]),
  );
};

describe("OCSP codec", () => {
  it("uses the target certificate's issuer Name independently of the supplied signing key", () => {
    const { leaf, roots } = preparedChain();
    const root = roots[0];
    if (root === undefined) throw new Error("Missing synthetic root");
    const { offset, length } = leaf.metadata.issuer;
    expect(ocspCertIdFor(leaf, root).issuerNameHash).toEqual(
      createHash("sha256")
        .update(leaf.der.subarray(offset, offset + length))
        .digest(),
    );
  });
  it("builds the canonical SHA-256 requests and parses BasicOCSPResponse", () => {
    const chain = preparedChain();
    const cases = [
      [chain.leaf, chain.intermediate, benchmarkVectors.leafRequest, benchmarkVectors.leafGood],
      [
        chain.intermediate,
        chain.roots[0],
        benchmarkVectors.intermediateRequest,
        benchmarkVectors.intermediateGood,
      ],
    ] as const;

    for (const [certificate, issuer, request, response] of cases) {
      expect(Buffer.from(buildOcspRequest(certificate, issuer))).toEqual(bytes(request));
      const parsed = parseOcspResponse(bytes(response));
      expect(parsed).toMatchObject({ responseStatus: 0, responseType: "1.3.6.1.5.5.7.48.1.1" });
      expect(parsed.basic?.responses).toHaveLength(1);
      expect(parsed.basic?.responses[0]?.status).toBe("good");
      expect(parsed.basic?.signatureAlgorithm.oid).toBe("1.2.840.10045.4.3.2");
    }
  });

  it("preserves revoked status as data for the policy layer", () => {
    const parsed = parseOcspResponse(bytes(benchmarkVectors.leafRevoked));
    expect(parsed.basic?.responses[0]?.status).toBe("revoked");
  });
});
