import { describe, expect, it } from "vitest";

import { BerCursor, BerParseError, DEFAULT_BER_LIMITS } from "../../source/asn1/ber-reader.js";
import {
  extractTransactionIdFromAppReceipt,
  extractTransactionIdFromTransactionReceipt,
  parseAppReceiptTransactionId,
  parseTransactionReceiptTransactionId,
  ReceiptFormatError,
  ReceiptUtility,
} from "../../source/index.js";

const concat = (...parts: readonly Uint8Array[]): Uint8Array => {
  const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
};

const length = (value: number): Uint8Array =>
  value < 128 ? Uint8Array.of(value) : Uint8Array.of(0x81, value);
const tlv = (tag: number, value: Uint8Array): Uint8Array =>
  concat(Uint8Array.of(tag), length(value.length), value);
const sequence = (...parts: readonly Uint8Array[]): Uint8Array => tlv(0x30, concat(...parts));
const set = (...parts: readonly Uint8Array[]): Uint8Array => tlv(0x31, concat(...parts));
const oid = (hex: string): Uint8Array => tlv(0x06, Uint8Array.from(Buffer.from(hex, "hex")));
const integer = (value: number): Uint8Array => {
  const bytes: number[] = [];
  let remaining = value;
  do {
    bytes.unshift(remaining & 0xff);
    remaining >>>= 8;
  } while (remaining > 0);
  if ((bytes[0] ?? 0) >= 0x80) bytes.unshift(0);
  return tlv(0x02, Uint8Array.from(bytes));
};
const octets = (value: Uint8Array): Uint8Array => tlv(0x04, value);
const utf8 = (value: string): Uint8Array => tlv(0x0c, new TextEncoder().encode(value));
const indefinite = (tag: number, ...parts: readonly Uint8Array[]): Uint8Array =>
  concat(Uint8Array.of(tag, 0x80), concat(...parts), Uint8Array.of(0, 0));

const transaction = (id = "fragmented-id"): Uint8Array =>
  sequence(integer(1703), integer(1), octets(utf8(id)));
const purchase = (...fields: Uint8Array[]): Uint8Array =>
  sequence(integer(17), integer(1), octets(set(...fields)));

const syntheticAppReceipt = (
  receiptSet = set(purchase(transaction())),
  { version = integer(1), algorithms = set(), tail = [set()] } = {},
): Uint8Array => {
  const split = Math.max(1, Math.floor(receiptSet.length / 2));
  const payload = indefinite(
    0x24,
    octets(receiptSet.subarray(0, split)),
    indefinite(0x24, octets(receiptSet.subarray(split))),
  );
  const encapsulated = sequence(oid("2a864886f70d010701"), tlv(0xa0, payload));
  const signedData = indefinite(0x30, version, algorithms, encapsulated, ...tail);
  return indefinite(0x30, oid("2a864886f70d010702"), indefinite(0xa0, signedData));
};

const base64 = (value: string | Uint8Array): string => Buffer.from(value).toString("base64");

describe("legacy receipt extraction", () => {
  it("supports BER indefinite lengths and fragmented OCTET STRINGs", () => {
    const receipt = syntheticAppReceipt();

    expect(extractTransactionIdFromAppReceipt(receipt)).toBe("fragmented-id");
    expect(parseAppReceiptTransactionId(receipt)).toEqual({
      kind: "found",
      transactionId: "fragmented-id",
    });
  });

  it("returns a distinct missing result for a valid receipt without an ID", () => {
    expect(parseAppReceiptTransactionId(syntheticAppReceipt(set(purchase())))).toEqual({
      kind: "missing",
    });
    expect(extractTransactionIdFromAppReceipt(syntheticAppReceipt(set()))).toBeNull();
  });

  it("returns a distinct format error without hiding compatibility exceptions", () => {
    const result = parseAppReceiptTransactionId("!!!!");

    expect(result.kind).toBe("error");
    if (result.kind === "error") expect(result.error).toBeInstanceOf(ReceiptFormatError);
    expect(() => extractTransactionIdFromAppReceipt("!!!!")).toThrow(ReceiptFormatError);
    expect(() => extractTransactionIdFromAppReceipt(syntheticAppReceipt().subarray(0, -2))).toThrow(
      ReceiptFormatError,
    );
  });

  it("validates required and optional SignedData fields", () => {
    const certificates = tlv(0xa0, new Uint8Array());
    const crls = tlv(0xa1, new Uint8Array());
    for (const options of [
      { version: octets(Uint8Array.of(1)) },
      { version: integer(2) },
      { algorithms: sequence() },
      { tail: [] },
      { tail: [sequence()] },
      { tail: [crls, certificates, set()] },
      { tail: [certificates, certificates, set()] },
      { tail: [set(), set()] },
    ]) {
      expect(parseAppReceiptTransactionId(syntheticAppReceipt(undefined, options))).toMatchObject({
        kind: "error",
        error: { code: "invalid-structure" },
      });
    }
    expect(
      extractTransactionIdFromAppReceipt(
        syntheticAppReceipt(undefined, { tail: [certificates, crls, set()] }),
      ),
    ).toBe("fragmented-id");
  });

  it("validates attributes after finding an ID and preserves the first valid ID", () => {
    const invalidVersion = sequence(integer(1), utf8("wrong"), octets(utf8("value")));
    const invalidValue = sequence(integer(1), integer(1), utf8("wrong"));
    const invalidFragment = sequence(integer(1), integer(1), indefinite(0x24, utf8("wrong")));
    const invalidId = sequence(integer(1705), integer(1), octets(integer(1)));
    for (const receiptSet of [
      set(purchase(transaction()), invalidVersion),
      set(purchase(transaction()), invalidValue),
      set(purchase(transaction(), invalidFragment)),
      set(purchase(transaction(), invalidId)),
      set(purchase(transaction()), purchase(invalidVersion)),
    ]) {
      expect(parseAppReceiptTransactionId(syntheticAppReceipt(receiptSet))).toMatchObject({
        kind: "error",
        error: { code: "invalid-structure" },
      });
    }
    const withMultipleIds = set(
      purchase(transaction("first"), transaction("second")),
      purchase(transaction("third")),
    );
    expect(extractTransactionIdFromAppReceipt(syntheticAppReceipt(withMultipleIds))).toBe("first");
  });

  it("applies the input size limit to bytes and both base64 APIs", () => {
    const limit = DEFAULT_BER_LIMITS.maxInputBytes;
    const overLimit = new Uint8Array(limit + 1);
    const encoded = base64(overLimit);
    const atLimit = base64(overLimit.subarray(0, limit));
    expect(encoded.length).toBe(atLimit.length);
    for (const outcome of [
      parseAppReceiptTransactionId(overLimit),
      parseAppReceiptTransactionId(encoded),
      parseTransactionReceiptTransactionId(encoded),
    ]) {
      expect(outcome).toMatchObject({ kind: "error", error: { code: "limit-exceeded" } });
    }
    expect(parseAppReceiptTransactionId(atLimit)).toMatchObject({
      kind: "error",
      error: { code: "invalid-structure" },
    });
  });

  it("preserves the text transaction receipt behavior", () => {
    const purchaseInfo = base64(
      '{\n\t"transaction-id" = "33993399";\n\t"product-id" = "café ☕";\n}',
    );
    const receipt = base64(`{\n\t"purchase-info" = "${purchaseInfo}";\n}`);
    const withoutId = base64(
      `{\n\t"purchase-info" = "${base64('{\n\t"original-transaction-id" = "33993399";\n}')}";\n}`,
    );

    expect(extractTransactionIdFromTransactionReceipt(receipt)).toBe("33993399");
    expect(parseTransactionReceiptTransactionId(withoutId)).toEqual({ kind: "missing" });
    expect(() => extractTransactionIdFromTransactionReceipt(base64("{}"))).toThrow(
      ReceiptFormatError,
    );
  });

  it("exposes the compatibility facade separately from the JWS verifier", () => {
    const utility = new ReceiptUtility();
    expect(utility.extractTransactionIdFromAppReceipt(base64(syntheticAppReceipt()))).toBe(
      "fragmented-id",
    );
  });
});

describe("BER cursor safety boundaries", () => {
  const parse = (bytes: number[], options = {}) =>
    new BerCursor(Uint8Array.from(bytes), options).readElement();

  it("rejects truncated, non-canonical, and overflowing BER elements", () => {
    for (const bytes of [
      [],
      [0x04],
      [0x1f],
      [0x1f, 0x80, 0x00],
      [0x1f, 0x81, 0x80, 0x80, 0x80, 0x00],
      [0x04, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00],
      [0x04, 0x82, 0x01],
      [0x04, 0x81, 0x00],
      [0x04, 0x01],
      [0x30, 0x02, 0x04, 0x01],
      [0x30, 0x80, 0x04, 0x00],
      [0x30, 0x02, 0x00, 0x00],
      [0x04, 0x80, 0x00, 0x00],
    ]) {
      expect(() => parse(bytes)).toThrow(BerParseError);
    }
  });

  it("enforces cursor limits and accepts a canonical high tag", () => {
    expect(() => parse([0x04, 0x00], { maxElements: 0 })).toThrow(BerParseError);
    expect(() => parse([0x04, 0x01, 0x00], { maxWorkBytes: 1 })).toThrow(BerParseError);
    expect(() => parse([0x30, 0x00], { maxDepth: 0 })).not.toThrow();
    expect(parse([0x1f, 0x1f, 0x00]).tagNumber).toBe(31);
    expect(() => new BerCursor(new Uint8Array([0]), {}, 2)).toThrow(RangeError);
    expect(() => new BerCursor(new Uint8Array([0]), {}, 0, 2)).toThrow(RangeError);
  });

  it("reports malformed text receipts", () => {
    const invalidUtf8 = base64(`{\n\t"purchase-info" = "${base64(new Uint8Array([0xff]))}";\n}`);

    expect(parseTransactionReceiptTransactionId(base64("{}"))).toMatchObject({ kind: "error" });
    expect(parseTransactionReceiptTransactionId(invalidUtf8)).toMatchObject({ kind: "error" });
  });
});
