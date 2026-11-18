import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { createVerifier, parseAppReceiptTransactionId } from "../../source/index.js";
import { parseX509CertificateMetadata } from "../../source/x509/certificate-metadata.js";

const fixture = (name: string): string =>
  readFileSync(new URL(`../fixtures/apple-compat/${name}`, import.meta.url), "utf8").trim();

const decodeJson = (value: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as Record<string, unknown>;

describe("Apple compatibility fixture smoke test", () => {
  it("extracts certificate markers and exact subject bytes from the snapshot", () => {
    const header = decodeJson(fixture("test-notification.jws").split(".")[0] ?? "");
    const [leaf, intermediate, root] = (header.x5c as string[]).map((value) =>
      Buffer.from(value, "base64"),
    );
    const metadata = parseX509CertificateMetadata(leaf);
    expect(metadata.apple).toEqual({ leaf: true, intermediate: false });
    expect(parseX509CertificateMetadata(intermediate).apple).toEqual({
      leaf: false,
      intermediate: true,
    });
    expect(parseX509CertificateMetadata(root).version).toBe(0);
    const { offset, length } = metadata.subject;
    expect(leaf.subarray(offset, offset + length)).toEqual(leaf.subarray(139, 210));
  });
  it("verifies the signed notification with the fixture trust anchor and profile", async () => {
    const compactJws = fixture("test-notification.jws");
    const parts = compactJws.split(".");
    const header = decodeJson(parts[0] ?? "");
    const root = Buffer.from((header.x5c as string[])[2], "base64");
    const verifier = createVerifier({
      trustedRoots: [root],
      policy: {
        application: "com.example",
        environment: "Sandbox",
        claimPaths: { application: ["data", "bundleId"], environment: ["data", "environment"] },
        signedTimePath: ["signedDate"],
        requiredExtensions: {
          leaf: ["1.2.840.113635.100.6.11.1"],
          intermediate: ["1.2.840.113635.100.6.2.1"],
        },
      },
    });

    await expect(verifier.verify(compactJws)).resolves.toMatchObject({
      protectedHeader: { alg: "ES256", typ: "JWT" },
      payload: {
        signedDate: 1681314324000,
        data: { bundleId: "com.example", environment: "Sandbox" },
      },
    });
  });

  it("preserves rejection preconditions for malformed or mismatched notifications", () => {
    const missingX5c = decodeJson(fixture("missing-x5c-header-claim.jws").split(".")[0] ?? "");
    const wrongBundle = decodeJson(fixture("wrong-bundle-id.jws").split(".")[1] ?? "");

    expect(missingX5c.x5c).toBeUndefined();
    expect(missingX5c.x5cwrong).toBeInstanceOf(Array);
    expect(wrongBundle).toMatchObject({ data: { bundleId: "com.example.wrong" } });
  });

  it("extracts the expected outcomes from the Xcode BER receipt snapshots", () => {
    expect(parseAppReceiptTransactionId(fixture("xcode-app-receipt-empty.base64"))).toEqual({
      kind: "missing",
    });
    expect(
      parseAppReceiptTransactionId(fixture("xcode-app-receipt-with-transaction.base64")),
    ).toEqual({ kind: "found", transactionId: "0" });
  });
});
