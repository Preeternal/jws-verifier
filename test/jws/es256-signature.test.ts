import { describe, expect, it } from "vitest";

import { es256SignatureToDer } from "../../source/jws/es256-signature.js";

describe("ES256 signature encoding for native verification", () => {
  it("removes redundant zeros and adds a sign byte when needed", () => {
    const signature = new Uint8Array(64);
    signature[31] = 127;
    signature[63] = 128;
    expect(es256SignatureToDer(signature)).toEqual(Uint8Array.of(0x30, 7, 2, 1, 127, 2, 2, 0, 128));
  });

  it("encodes a zero scalar as one byte for the native verifier to reject", () => {
    expect(es256SignatureToDer(new Uint8Array(64))).toEqual(
      Uint8Array.of(0x30, 6, 2, 1, 0, 2, 1, 0),
    );
  });
});
