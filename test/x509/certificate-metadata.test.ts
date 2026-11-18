import { describe, expect, it } from "vitest";

import { DerParseError, DerReader } from "../../source/asn1/der-reader.js";
import {
  parseX509CertificateMetadata,
  X509_EXTENSION_OIDS,
} from "../../source/x509/certificate-metadata.js";

const bytes = (...values: number[]): Uint8Array => Uint8Array.from(values);

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
};

const encodeLength = (length: number): Uint8Array => {
  if (length < 0x80) {
    return bytes(length);
  }
  const octets: number[] = [];
  let value = length;
  while (value > 0) {
    octets.unshift(value & 0xff);
    value >>>= 8;
  }
  return bytes(0x80 | octets.length, ...octets);
};

const tlv = (tag: number, value: Uint8Array): Uint8Array =>
  concat(bytes(tag), encodeLength(value.length), value);
const sequence = (...values: Uint8Array[]): Uint8Array => tlv(0x30, concat(...values));
const set = (...values: Uint8Array[]): Uint8Array => tlv(0x31, concat(...values));
const octetString = (value: Uint8Array): Uint8Array => tlv(0x04, value);
const boolean = (value: boolean): Uint8Array => tlv(0x01, bytes(value ? 0xff : 0));
const integer = (value: number): Uint8Array => tlv(0x02, bytes(value));
const bitString = (value: Uint8Array): Uint8Array => tlv(0x03, value);
const context = (tag: number, value: Uint8Array): Uint8Array => tlv(0xa0 | tag, value);
const contextPrimitive = (tag: number, value: Uint8Array): Uint8Array => tlv(0x80 | tag, value);

const encodeOid = (value: string): Uint8Array => {
  const arcs = value.split(".").map((arc) => BigInt(arc));
  const first = (arcs[0] ?? 0n) * 40n + (arcs[1] ?? 0n);
  const output: number[] = [];
  const encodeArc = (arc: bigint): void => {
    const octets = [Number(arc & 0x7fn)];
    let remaining = arc >> 7n;
    while (remaining > 0n) {
      octets.unshift(Number(remaining & 0x7fn) | 0x80);
      remaining >>= 7n;
    }
    output.push(...octets);
  };
  encodeArc(first);
  for (const arc of arcs.slice(2)) {
    encodeArc(arc);
  }
  return tlv(0x06, bytes(...output));
};

const ascii = (value: string): Uint8Array =>
  bytes(...value.split("").map((character) => character.charCodeAt(0)));

const findBytes = (input: Uint8Array, needle: Uint8Array): number => {
  for (let offset = 0; offset <= input.length - needle.length; offset += 1) {
    if (needle.every((value, index) => input[offset + index] === value)) {
      return offset;
    }
  }
  return -1;
};

const algorithm = sequence(encodeOid("1.2.840.10045.2.1"), encodeOid("1.2.840.10045.3.1.7"));
const name = (commonName: string): Uint8Array =>
  sequence(set(sequence(encodeOid("2.5.4.3"), tlv(0x0c, ascii(commonName)))));
const validity = sequence(tlv(0x17, ascii("261118182600Z")), tlv(0x17, ascii("361118182600Z")));
const subjectPublicKeyInfo = sequence(
  algorithm,
  bitString(bytes(0, 4, ...Array.from({ length: 64 }, () => 0x01))),
);

const extension = (oid: string, value: Uint8Array, critical = false): Uint8Array =>
  sequence(encodeOid(oid), ...(critical ? [boolean(true)] : []), octetString(value));

const defaultExtensions = (): Uint8Array[] => [
  extension(
    X509_EXTENSION_OIDS.authorityInfoAccess,
    sequence(
      sequence(
        encodeOid(X509_EXTENSION_OIDS.ocsp),
        contextPrimitive(6, ascii("http://ocsp.example.test")),
      ),
    ),
  ),
  extension(X509_EXTENSION_OIDS.basicConstraints, sequence(boolean(true), integer(0)), true),
  extension(X509_EXTENSION_OIDS.keyUsage, bitString(bytes(7, 0x80)), true),
  extension(
    X509_EXTENSION_OIDS.extendedKeyUsage,
    sequence(encodeOid(X509_EXTENSION_OIDS.ocspSigning)),
  ),
  extension(X509_EXTENSION_OIDS.appleLeaf, sequence()),
  extension(X509_EXTENSION_OIDS.appleIntermediate, sequence()),
];

interface SyntheticCertificateOptions {
  readonly version?: Uint8Array;
  readonly serial?: Uint8Array;
  readonly algorithm?: Uint8Array;
  readonly issuer?: Uint8Array;
  readonly validity?: Uint8Array;
  readonly subject?: Uint8Array;
  readonly subjectPublicKeyInfo?: Uint8Array;
  readonly extensions?: readonly Uint8Array[];
  readonly optionalFields?: readonly Uint8Array[];
}

const syntheticCertificate = (options: SyntheticCertificateOptions = {}): Uint8Array => {
  const tbs = sequence(
    ...(options.version === undefined ? [context(0, integer(2))] : [options.version]),
    options.serial ?? integer(1),
    options.algorithm ?? algorithm,
    options.issuer ?? name("Issuer"),
    options.validity ?? validity,
    options.subject ?? name("Subject"),
    options.subjectPublicKeyInfo ?? subjectPublicKeyInfo,
    ...(options.optionalFields ?? [
      context(3, sequence(...(options.extensions ?? defaultExtensions()))),
    ]),
  );
  return sequence(tbs, options.algorithm ?? algorithm, bitString(bytes(0, 0x01)));
};

const expectDerError = (callback: () => unknown, code: DerParseError["code"]): void => {
  try {
    callback();
    throw new Error("Expected a DER parse error");
  } catch (error) {
    expect(error).toBeInstanceOf(DerParseError);
    expect((error as DerParseError).code).toBe(code);
  }
};

describe("DER reader", () => {
  it("keeps parent bounds and rejects trailing data and indefinite lengths", () => {
    const overrun = new DerReader(bytes(0x30, 0x02, 0x02, 0x02, 0x00));
    const container = overrun.readElement();
    expectDerError(
      () => overrun.readChildren(container, (reader) => reader.readElement()),
      "container-overrun",
    );

    expectDerError(() => {
      const reader = new DerReader(bytes(0x30, 0x00, 0x00));
      reader.readElement();
      reader.assertEnd();
    }, "trailing-data");
    expectDerError(() => new DerReader(bytes(0x30, 0x80)).readElement(), "indefinite-length");
  });

  it("enforces element, depth, and work limits", () => {
    expectDerError(
      () => new DerReader(bytes(0x05, 0x00), { maxElements: 0 }).readElement(),
      "limit-exceeded",
    );
    expectDerError(
      () =>
        new DerReader(bytes(0x30, 0x02, 0x30, 0x00), { maxDepth: 0 }).readChildren(
          new DerReader(bytes(0x30, 0x02, 0x30, 0x00)).readElement(),
          () => undefined,
        ),
      "limit-exceeded",
    );
    expectDerError(
      () => new DerReader(bytes(0x04, 0x01, 0x00), { maxWorkBytes: 2 }).readElement(),
      "limit-exceeded",
    );
    expectDerError(() => new DerReader(bytes(0x1f, 0x80)).readElement(), "invalid-tag");
    expectDerError(() => new DerReader(bytes(0x1f, 0x1e)).readElement(), "invalid-tag");
    expectDerError(
      () => new DerReader(bytes(0x1f, 0x81, 0x80, 0x80, 0x80, 0x01)).readElement(),
      "limit-exceeded",
    );
    expectDerError(() => new DerReader(bytes(0x05)).readElement(), "invalid-length");
    expectDerError(
      () => new DerReader(bytes(0x05, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00)).readElement(),
      "invalid-length",
    );
    expectDerError(
      () => new DerReader(bytes(0x05, 0x82, 0x00, 0x80)).readElement(),
      "invalid-length",
    );
    expectDerError(() => new DerReader(bytes(0x05, 0x81, 0x7f)).readElement(), "invalid-length");
    expectDerError(() => new DerReader(bytes(0x1f)).readElement(), "unexpected-end");
    expect(() => new DerReader(bytes(0x05, 0x00), {}, -1)).toThrow(RangeError);
    expect(() => new DerReader(bytes(0x05, 0x00), {}, 0, 3)).toThrow(RangeError);
    expect(() => new DerReader({} as Uint8Array)).toThrow(TypeError);
    expectDerError(
      () =>
        new DerReader(bytes(0x05, 0x00), { maxDepth: 0 }, 0, 2, 1, { elements: 0, workBytes: 0 }),
      "limit-exceeded",
    );
    expectDerError(
      () =>
        new DerReader(bytes(0x05, 0x00)).readChildren(
          new DerReader(bytes(0x05, 0x00)).readElement(),
          () => undefined,
        ),
      "invalid-tag",
    );
  });
});

describe("X.509 certificate metadata", () => {
  it("returns exact Name ranges relative to the supplied view", () => {
    const root = concat(
      bytes(255),
      syntheticCertificate({ version: bytes(), optionalFields: [] }),
    ).subarray(1);
    const rootMetadata = parseX509CertificateMetadata(root);
    expect(rootMetadata.version).toBe(0);
    expect(rootMetadata.extensions).toHaveLength(0);
    for (const [range, expected] of [
      [rootMetadata.issuer, name("Issuer")],
      [rootMetadata.subject, name("Subject")],
    ] as const) {
      expect(root.subarray(range.offset, range.offset + range.length)).toEqual(expected);
    }
  });

  it("accepts the ninth Key Usage bit and rejects undefined bits", () => {
    const withUsage = (last: number, unused: number) =>
      syntheticCertificate({
        extensions: [extension(X509_EXTENSION_OIDS.keyUsage, bitString(bytes(unused, 0x08, last)))],
      });
    expect(parseX509CertificateMetadata(withUsage(0x80, 7)).keyUsage?.names).toEqual([
      "keyAgreement",
      "decipherOnly",
    ]);
    expectDerError(() => parseX509CertificateMetadata(withUsage(0x40, 6)), "invalid-tag");
  });

  it("enforces version, ordering and uniqueness of optional fields", () => {
    const issuerId = contextPrimitive(1, bytes(0, 0x80));
    const subjectId = contextPrimitive(2, bytes(0, 0x80));
    const extensions = context(3, sequence(...defaultExtensions()));
    expect(
      parseX509CertificateMetadata(
        syntheticCertificate({
          version: context(0, integer(1)),
          optionalFields: [issuerId, subjectId],
        }),
      ).version,
    ).toBe(1);
    for (const options of [
      { optionalFields: [subjectId, issuerId] },
      { optionalFields: [issuerId, issuerId] },
      { optionalFields: [extensions, extensions] },
      { optionalFields: [context(3, sequence())] },
      { version: bytes(), optionalFields: [issuerId] },
      { version: context(0, integer(1)), optionalFields: [extensions] },
      { version: context(0, integer(0)), optionalFields: [] },
    ]) {
      expectDerError(
        () => parseX509CertificateMetadata(syntheticCertificate(options)),
        "invalid-tag",
      );
    }
  });

  it("bounds numeric conversions and handles long input values", () => {
    const long = new Uint8Array(150_000).fill(0x61);
    const serial = parseX509CertificateMetadata(
      syntheticCertificate({ serial: tlv(0x02, long) }),
    ).serial;
    expect(serial.value.length).toBe(long.length);
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({ version: context(0, tlv(0x02, long)) }),
        ),
      "invalid-tag",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({ version: context(0, tlv(0x02, bytes(0x20, 0, 0, 0, 0, 0, 0))) }),
        ),
      "invalid-tag",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({
            validity: sequence(tlv(0x17, long), tlv(0x17, ascii("361118182600Z"))),
          }),
        ),
      "invalid-tag",
    );
    const input = syntheticCertificate({
      extensions: [
        extension(
          X509_EXTENSION_OIDS.authorityInfoAccess,
          sequence(sequence(encodeOid(X509_EXTENSION_OIDS.ocsp), contextPrimitive(6, long))),
        ),
      ],
    });
    expect(
      parseX509CertificateMetadata(input).authorityInfoAccess?.ocspUrls[0]?.value,
    ).toHaveLength(long.length);
  });

  it("parses policy metadata without building a general ASN.1 tree", () => {
    const input = syntheticCertificate();
    const metadata = parseX509CertificateMetadata(input);

    expectDerError(
      () => parseX509CertificateMetadata(input, { maxAiaEntries: 0 }),
      "limit-exceeded",
    );

    expect(metadata.version).toBe(2);
    expect(metadata.authorityInfoAccess?.ocspUrls).toEqual([
      {
        value: "http://ocsp.example.test",
        range: {
          offset: findBytes(input, ascii("http://ocsp.example.test")),
          length: "http://ocsp.example.test".length,
        },
      },
    ]);
    expect(metadata.basicConstraints).toEqual({ ca: true, pathLenConstraint: 0 });
    expect(metadata.keyUsage).toEqual({ names: ["digitalSignature"] });
    expect(metadata.extendedKeyUsage).toEqual({
      oids: [X509_EXTENSION_OIDS.ocspSigning],
      ocspSigning: true,
    });
    expect(metadata.apple).toEqual({ leaf: true, intermediate: true });

    const subject = metadata.subject;
    expect(input.subarray(subject.offset, subject.offset + subject.length)[0]).toBe(0x30);
    expect(
      input.subarray(
        metadata.serial.value.offset,
        metadata.serial.value.offset + metadata.serial.value.length,
      ),
    ).toEqual(bytes(1));
    expect(
      input.subarray(
        metadata.subjectPublicKey.value.offset,
        metadata.subjectPublicKey.value.offset + 4,
      ),
    ).toEqual(bytes(4, 1, 1, 1));
  });

  it("rejects duplicate fields, duplicate extensions, malformed lengths, and non-canonical OIDs", () => {
    const extensions = defaultExtensions();
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({ extensions: [...extensions, extensions[1] ?? bytes()] }),
        ),
      "invalid-tag",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({ extensions: [context(0, integer(2)), ...extensions] }),
        ),
      "invalid-tag",
    );

    const invalidLength = syntheticCertificate().slice();
    invalidLength[3] = (invalidLength[3] ?? 0) + 1;
    expectDerError(() => parseX509CertificateMetadata(invalidLength), "container-overrun");

    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({
            extensions: [sequence(tlv(0x06, bytes(0x80)), octetString(sequence()))],
          }),
        ),
      "invalid-tag",
    );
  });

  it("rejects malformed certificate fields and extension payloads", () => {
    expectDerError(
      () => parseX509CertificateMetadata(syntheticCertificate({ version: context(0, integer(3)) })),
      "invalid-tag",
    );
    expectDerError(
      () => parseX509CertificateMetadata(syntheticCertificate({ serial: tlv(0x02, bytes()) })),
      "invalid-tag",
    );
    expectDerError(
      () => parseX509CertificateMetadata(syntheticCertificate({ serial: tlv(0x02, bytes(0, 1)) })),
      "invalid-tag",
    );
    expectDerError(
      () => parseX509CertificateMetadata(syntheticCertificate({ serial: tlv(0x02, bytes(0x80)) })),
      "invalid-tag",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({
            algorithm: sequence(encodeOid("1.2.3"), tlv(0x05, bytes()), tlv(0x05, bytes())),
          }),
        ),
      "trailing-data",
    );
    expectDerError(
      () => parseX509CertificateMetadata(syntheticCertificate({ issuer: integer(1) })),
      "invalid-tag",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({ validity: sequence(tlv(0x17, ascii("261118182600Z"))) }),
        ),
      "unexpected-end",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({
            validity: sequence(
              tlv(0x17, ascii("361118182600Z")),
              tlv(0x17, ascii("261118182600Z")),
            ),
          }),
        ),
      "invalid-tag",
    );
    expectDerError(
      () => parseX509CertificateMetadata(syntheticCertificate({ subject: integer(1) })),
      "invalid-tag",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({ subjectPublicKeyInfo: sequence(algorithm) }),
        ),
      "unexpected-end",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({ subjectPublicKeyInfo: sequence(algorithm, bitString(bytes())) }),
        ),
      "invalid-tag",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({
            subjectPublicKeyInfo: sequence(algorithm, bitString(bytes(8, 0))),
          }),
        ),
      "invalid-tag",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({
            subjectPublicKeyInfo: sequence(algorithm, bitString(bytes(7, 1))),
          }),
        ),
      "invalid-tag",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({
            extensions: [extension(X509_EXTENSION_OIDS.basicConstraints, sequence(integer(0)))],
          }),
        ),
      "invalid-tag",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({
            extensions: [
              extension(X509_EXTENSION_OIDS.basicConstraints, sequence(boolean(false), integer(0))),
            ],
          }),
        ),
      "invalid-tag",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({
            extensions: [extension(X509_EXTENSION_OIDS.keyUsage, bitString(bytes(0, 0, 1)))],
          }),
        ),
      "invalid-tag",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({
            extensions: [
              extension(
                X509_EXTENSION_OIDS.extendedKeyUsage,
                sequence(
                  encodeOid(X509_EXTENSION_OIDS.ocspSigning),
                  encodeOid(X509_EXTENSION_OIDS.ocspSigning),
                ),
              ),
            ],
          }),
        ),
      "invalid-tag",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({ extensions: [sequence(encodeOid("1.2.3"))] }),
        ),
      "unexpected-end",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({
            extensions: [sequence(encodeOid("1.2.3"), integer(1), octetString(sequence()))],
          }),
        ),
      "trailing-data",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({
            extensions: [extension(X509_EXTENSION_OIDS.basicConstraints, bytes())],
          }),
        ),
      "unexpected-end",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({
            validity: sequence(
              tlv(0x17, ascii("261118A82600Z")),
              tlv(0x17, ascii("361118182600Z")),
            ),
          }),
        ),
      "invalid-tag",
    );
    expectDerError(
      () =>
        parseX509CertificateMetadata(
          syntheticCertificate({
            validity: sequence(
              tlv(0x17, ascii("261132182600Z")),
              tlv(0x17, ascii("361118182600Z")),
            ),
          }),
        ),
      "invalid-tag",
    );
  });
});
