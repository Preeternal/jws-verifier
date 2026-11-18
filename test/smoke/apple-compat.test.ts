import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const fixture = (name: string): string =>
  readFileSync(new URL(`../fixtures/apple-compat/${name}`, import.meta.url), "utf8").trim();

const decodeJson = (value: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as Record<string, unknown>;

describe("Apple compatibility fixture smoke test", () => {
  it("loads the accepted notification snapshot", () => {
    const parts = fixture("test-notification.jws").split(".");
    const header = decodeJson(parts[0] ?? "");
    const payload = decodeJson(parts[1] ?? "");

    expect(parts).toHaveLength(3);
    expect(header).toMatchObject({ alg: "ES256", typ: "JWT" });
    expect(header.x5c).toBeInstanceOf(Array);
    expect(payload).toMatchObject({ data: { environment: "Sandbox" } });
  });

  it("preserves rejection preconditions for malformed or mismatched notifications", () => {
    const missingX5c = decodeJson(fixture("missing-x5c-header-claim.jws").split(".")[0] ?? "");
    const wrongBundle = decodeJson(fixture("wrong-bundle-id.jws").split(".")[1] ?? "");

    expect(missingX5c.x5c).toBeUndefined();
    expect(missingX5c.x5cwrong).toBeInstanceOf(Array);
    expect(wrongBundle).toMatchObject({ data: { bundleId: "com.example.wrong" } });
  });

  it("loads both Xcode receipt snapshots as indefinite-length BER sequences", () => {
    for (const name of [
      "xcode-app-receipt-empty.base64",
      "xcode-app-receipt-with-transaction.base64",
    ]) {
      const bytes = Buffer.from(fixture(name), "base64");

      expect([...bytes.subarray(0, 2)]).toEqual([0x30, 0x80]);
      expect(bytes.length).toBeGreaterThan(256);
    }
  });
});
