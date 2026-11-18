import { describe, expect, it } from "vitest";

import { parseOcspResponse } from "../../source/index.js";

const concat = (...parts: readonly Uint8Array[]): Uint8Array => {
  const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
};

const encodeLength = (length: number): Uint8Array => {
  if (length < 128) return Uint8Array.of(length);
  const high = length > 255 ? 0x82 : 0x81;
  return high === 0x81
    ? Uint8Array.of(high, length)
    : Uint8Array.of(high, length >> 8, length & 0xff);
};
const tlv = (tag: number, value: Uint8Array): Uint8Array =>
  concat(Uint8Array.of(tag), encodeLength(value.length), value);
const sequence = (...parts: readonly Uint8Array[]): Uint8Array => tlv(0x30, concat(...parts));
const oid = (hex: string): Uint8Array => tlv(0x06, Uint8Array.from(Buffer.from(hex, "hex")));
const integer = (value: number): Uint8Array => tlv(0x02, Uint8Array.of(value));
const octets = (value: Uint8Array): Uint8Array => tlv(0x04, value);
const time = (value = "20261118182600Z"): Uint8Array => tlv(0x18, new TextEncoder().encode(value));
const algorithm = (): Uint8Array =>
  sequence(oid("608648016503040201"), tlv(0x05, new Uint8Array()));
const certId = (): Uint8Array =>
  sequence(algorithm(), octets(new Uint8Array(32)), octets(new Uint8Array(32)), integer(1));
const extension = (critical: boolean): Uint8Array =>
  sequence(
    oid("2a0304"),
    ...(critical ? [tlv(0x01, Uint8Array.of(0xff))] : []),
    octets(sequence()),
  );

const single = (status: "good" | "revoked" | "unknown", withNextUpdate = true): Uint8Array =>
  sequence(
    certId(),
    status === "good"
      ? tlv(0x80, new Uint8Array())
      : status === "unknown"
        ? tlv(0x82, new Uint8Array())
        : tlv(0xa1, concat(time(), tlv(0x80, new Uint8Array()))),
    time(),
    ...(withNextUpdate ? [tlv(0xa0, sequence(time("20261119182600Z")))] : []),
    ...(!withNextUpdate ? [tlv(0xa1, sequence(extension(true), extension(false)))] : []),
  );

const response = (
  status: "good" | "revoked" | "unknown",
  implicitName = false,
  byKey = false,
  withCertificates = false,
  signatureUnusedBits = 0,
): Uint8Array => {
  const responderName = sequence(
    tlv(0x31, sequence(oid("550403"), tlv(0x0c, new TextEncoder().encode("Responder")))),
  );
  const responder = byKey
    ? tlv(0xa2, octets(new Uint8Array(20)))
    : tlv(0xa1, implicitName ? responderName.subarray(2) : responderName);
  const responseData = sequence(
    tlv(0xa0, integer(0)),
    responder,
    time(),
    sequence(single(status, false)),
    tlv(0xa1, sequence(extension(false))),
  );
  const basic = sequence(
    responseData,
    sequence(oid("2a8648ce3d040302")),
    tlv(0x03, Uint8Array.of(signatureUnusedBits)),
    ...(withCertificates ? [tlv(0xa0, sequence(sequence()))] : []),
  );
  return sequence(
    tlv(0x0a, Uint8Array.of(0)),
    tlv(0xa0, sequence(oid("2b0601050507300101"), octets(basic))),
  );
};

describe("OCSP parser edge cases", () => {
  it("parses version, byName variants, revoked and unknown statuses", () => {
    expect(parseOcspResponse(response("revoked")).basic?.responses[0]?.status).toBe("revoked");
    expect(parseOcspResponse(response("unknown", true)).basic?.responses[0]?.status).toBe(
      "unknown",
    );
    expect(parseOcspResponse(response("good", false, true, true)).basic?.responderId.kind).toBe(
      "key",
    );
    expect(parseOcspResponse(response("good")).basic?.criticalExtensionOids).toEqual([]);
  });

  it("returns non-success status and ignores non-basic response types at the codec boundary", () => {
    expect(parseOcspResponse(tlv(0x30, tlv(0x0a, Uint8Array.of(6))))).toEqual({
      responseStatus: 6,
    });
    const nonBasic = sequence(
      tlv(0x0a, Uint8Array.of(0)),
      tlv(0xa0, sequence(oid("2a03"), octets(new Uint8Array()))),
    );
    expect(parseOcspResponse(nonBasic)).toMatchObject({ responseStatus: 0, responseType: "1.2.3" });
  });

  it("rejects malformed response status, responder and signature fields", () => {
    expect(() => parseOcspResponse(tlv(0x30, tlv(0x0a, Uint8Array.of(0, 0))))).toThrow();
    const invalidResponder = response("good");
    const responderTag = invalidResponder.indexOf(0xa1);
    if (responderTag >= 0) invalidResponder[responderTag] = 0x80;
    expect(() => parseOcspResponse(invalidResponder)).toThrow();
    const invalidSignature = response("good", false, false, false, 1);
    expect(() => parseOcspResponse(invalidSignature)).toThrow();
    const invalidGoodStatus = response("good");
    const goodStatus = invalidGoodStatus.indexOf(0x80);
    if (goodStatus >= 0 && invalidGoodStatus[goodStatus + 1] === 0)
      invalidGoodStatus[goodStatus + 1] = 1;
    expect(() => parseOcspResponse(invalidGoodStatus)).toThrow();
    const unsupportedStatus = response("good");
    const unsupported = unsupportedStatus.indexOf(0x80);
    if (unsupported >= 0) unsupportedStatus[unsupported] = 0x83;
    expect(() => parseOcspResponse(unsupportedStatus)).toThrow();
  });
});
