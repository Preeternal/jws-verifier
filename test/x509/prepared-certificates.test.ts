import { describe, expect, it } from "vitest";

import { DEFAULT_DER_LIMITS } from "../../source/asn1/der-reader.js";
import { CertificatePreparation } from "../../source/x509/prepared-certificates.js";
import { benchmarkVectors } from "../fixtures/benchmark-vectors.js";

describe("certificate preparation", () => {
  it("reuses prepared roots within one configuration and snapshots caller bytes", () => {
    const original = Buffer.from(benchmarkVectors.rootDerBase64, "base64");
    const rootInput = Buffer.from(original);
    const configuration = new CertificatePreparation([rootInput]);
    rootInput.fill(0);

    const header = JSON.parse(
      Buffer.from(benchmarkVectors.validJws.split(".")[0] ?? "", "base64url").toString("utf8"),
    ) as { x5c: [string, string, string] };
    const leaf = Buffer.from(header.x5c[0], "base64");
    const intermediate = Buffer.from(header.x5c[1], "base64");
    const first = configuration.prepareChain(leaf, intermediate);
    const second = configuration.prepareChain(leaf, intermediate);
    leaf.fill(0);

    expect(first.roots).toBe(second.roots);
    expect(first.roots).toBe(configuration.roots);
    expect(first.roots).not.toBe(new CertificatePreparation([original]).roots);
    expect(first.roots[0]?.der).toEqual(new Uint8Array(original));
    expect(first.leaf.der).not.toEqual(new Uint8Array(leaf));
    expect(first.leaf.certificate.verify(first.intermediate.certificate.publicKey)).toBe(true);
    expect(first.leaf.metadata.authorityInfoAccess?.ocspUrls).toHaveLength(1);
  });

  it("checks the input size before preparing roots", () => {
    expect(
      () => new CertificatePreparation([new Uint8Array(DEFAULT_DER_LIMITS.maxInputBytes + 1)]),
    ).toThrow(expect.objectContaining({ code: "input-too-large" }));
  });
});
