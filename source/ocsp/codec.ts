// biome-ignore lint/correctness/noNodejsModules: Hashing is deliberately delegated to native crypto.
import { createHash } from "node:crypto";

import { type DerElement, DerParseError, DerReader, derRange } from "../asn1/der-reader.js";
import type { PreparedCertificate } from "../x509/prepared-certificates.js";

const universal = 0;
const contextSpecific = 2;
const sha1Oid = "1.3.14.3.2.26";
const sha256Oid = "2.16.840.1.101.3.4.2.1";
const sha384Oid = "2.16.840.1.101.3.4.2.2";
const sha512Oid = "2.16.840.1.101.3.4.2.3";
const basicResponseOid = "1.3.6.1.5.5.7.48.1.1";
const generalizedTimePattern = /^\d{14}Z$/u;

export type OcspHashAlgorithm = "sha1" | "sha256" | "sha384" | "sha512";
export type OcspCertificateStatus = "good" | "revoked" | "unknown";

export interface OcspCertId {
  readonly hashAlgorithm: OcspHashAlgorithm;
  readonly issuerNameHash: Uint8Array;
  readonly issuerKeyHash: Uint8Array;
  /** Canonical INTEGER contents, including a required sign-protection zero when present. */
  readonly serialNumber: Uint8Array;
}

export interface ParsedOcspSingleResponse {
  readonly certId: OcspCertId;
  readonly status: OcspCertificateStatus;
  readonly thisUpdateMs: number;
  readonly nextUpdateMs?: number;
  readonly criticalExtensionOids: readonly string[];
}

export type OcspResponderId =
  | { readonly kind: "name"; readonly value: Uint8Array; readonly implicit: boolean }
  | { readonly kind: "key"; readonly value: Uint8Array };

export interface OcspSignatureAlgorithm {
  readonly hash: OcspHashAlgorithm;
  readonly key: "ec" | "rsa";
  readonly oid: string;
}

export interface ParsedBasicOcspResponse {
  readonly tbsResponseData: Uint8Array;
  readonly signatureAlgorithm: OcspSignatureAlgorithm;
  readonly signature: Uint8Array;
  readonly responderId: OcspResponderId;
  readonly producedAtMs: number;
  readonly responses: readonly ParsedOcspSingleResponse[];
  readonly certificates: readonly Uint8Array[];
  readonly criticalExtensionOids: readonly string[];
}

export interface ParsedOcspResponse {
  readonly responseStatus: number;
  readonly responseType?: string;
  readonly basic?: ParsedBasicOcspResponse;
}

const oidBytes = (oid: string): Uint8Array => {
  const arcs = oid.split(".").map((arc) => BigInt(arc));
  const first = arcs.shift();
  const second = arcs.shift();
  if (first === undefined || second === undefined || first > 2n || (second > 39n && first < 2n)) {
    throw new TypeError(`Invalid OID: ${oid}`);
  }
  const values = [first * 40n + second, ...arcs];
  const output: number[] = [];
  for (const value of values) {
    const encoded = [Number(value & 0x7fn)];
    let rest = value >> 7n;
    while (rest > 0n) {
      encoded.unshift(Number(rest & 0x7fn) | 0x80);
      rest >>= 7n;
    }
    output.push(...encoded);
  }
  return Uint8Array.from(output);
};

const encodeLength = (length: number): Uint8Array => {
  if (!Number.isSafeInteger(length) || length < 0) throw new RangeError("Invalid DER length");
  if (length < 128) return Uint8Array.of(length);
  const bytes: number[] = [];
  let value = length;
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value >>>= 8;
  }
  return Uint8Array.from([0x80 | bytes.length, ...bytes]);
};

const concat = (...parts: readonly Uint8Array[]): Uint8Array => {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
};

const tlv = (tag: number, value: Uint8Array): Uint8Array =>
  concat(Uint8Array.of(tag), encodeLength(value.length), value);

const sequence = (...values: readonly Uint8Array[]): Uint8Array => tlv(0x30, concat(...values));
const octetString = (value: Uint8Array): Uint8Array => tlv(0x04, value);
const nullValue = (): Uint8Array => Uint8Array.of(0x05, 0x00);
const objectIdentifier = (oid: string): Uint8Array => tlv(0x06, oidBytes(oid));

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
};

const rangeBytes = (certificate: PreparedCertificate, range: { offset: number; length: number }) =>
  certificate.der.subarray(range.offset, range.offset + range.length);

export const ocspCertIdFor = (
  certificate: PreparedCertificate,
  issuer: PreparedCertificate,
): OcspCertId =>
  Object.freeze({
    hashAlgorithm: "sha256",
    issuerNameHash: createHash("sha256")
      .update(rangeBytes(certificate, certificate.metadata.issuer))
      .digest(),
    issuerKeyHash: createHash("sha256")
      .update(rangeBytes(issuer, issuer.metadata.subjectPublicKey.value))
      .digest(),
    serialNumber: new Uint8Array(rangeBytes(certificate, certificate.metadata.serial.value)),
  });

/** Encode the SHA-256 OCSP request used by the verifier. */
export const buildOcspRequest = (
  certificate: PreparedCertificate,
  issuer: PreparedCertificate,
): Uint8Array => {
  const { issuerNameHash, issuerKeyHash, serialNumber } = ocspCertIdFor(certificate, issuer);
  const certId = sequence(
    sequence(objectIdentifier(sha256Oid), nullValue()),
    octetString(issuerNameHash),
    octetString(issuerKeyHash),
    tlv(0x02, serialNumber),
  );
  return sequence(sequence(sequence(sequence(certId))));
};

const readOne = (reader: DerReader, name: string): DerElement => {
  const element = reader.readOptionalElement();
  if (element === undefined) {
    throw new DerParseError("unexpected-end", `Missing ${name}`, reader.end);
  }
  return element;
};

const isTag = (element: DerElement, tagClass: number, tagNumber: number, constructed?: boolean) =>
  element.tagClass === tagClass &&
  element.tagNumber === tagNumber &&
  (constructed === undefined || element.constructed === constructed);

const requireTag = (
  element: DerElement,
  tagClass: number,
  tagNumber: number,
  name: string,
  constructed?: boolean,
): void => {
  if (!isTag(element, tagClass, tagNumber, constructed)) {
    throw new DerParseError("invalid-tag", `${name} has an unexpected DER tag`, element.start);
  }
};

const withChildren = (element: DerElement, callback: (reader: DerReader) => void): void => {
  requireTag(element, universal, 16, "SEQUENCE", true);
  const reader = new DerReader(
    element.context.input,
    element.context.limits,
    element.valueStart,
    element.end,
    element.context.depth + 1,
    element.context.state,
  );
  callback(reader);
  reader.assertEnd();
};

// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: This bounded loop decodes one base-128 OID value without allocating an ASN.1 tree.
const readOid = (element: DerElement, name: string): string => {
  requireTag(element, universal, 6, name, false);
  if (element.value.length === 0)
    throw new DerParseError("invalid-tag", `${name} is empty`, element.start);
  const arcs: bigint[] = [];
  let offset = 0;
  while (offset < element.value.length) {
    let value = 0n;
    let first = true;
    for (;;) {
      if (offset >= element.value.length)
        throw new DerParseError("unexpected-end", `${name} is truncated`, element.end);
      const byte = element.value[offset++] ?? 0;
      if (first && byte === 0x80)
        throw new DerParseError("invalid-tag", `${name} is non-canonical`, element.start);
      first = false;
      value = value * 128n + BigInt(byte & 0x7f);
      if (value > 0xffffffffffffffffn)
        throw new DerParseError("limit-exceeded", `${name} is too large`, element.start);
      if ((byte & 0x80) === 0) break;
    }
    arcs.push(value);
  }
  const first = arcs.shift();
  if (first === undefined)
    throw new DerParseError("invalid-tag", `${name} is empty`, element.start);
  const firstArc = first < 40n ? 0n : first < 80n ? 1n : 2n;
  return [firstArc, firstArc === 2n ? first - 80n : first % 40n, ...arcs].map(String).join(".");
};

const readAlgorithmIdentifier = (
  element: DerElement,
  name: string,
): { readonly oid: string; readonly params?: DerElement } => {
  let oid = "";
  let params: DerElement | undefined;
  withChildren(element, (reader) => {
    oid = readOid(readOne(reader, `${name} OID`), `${name} OID`);
    params = reader.readOptionalElement();
  });
  if (params !== undefined && !isTag(params, universal, 5, false)) {
    throw new DerParseError("invalid-tag", `${name} parameters are unsupported`, params.start);
  }
  return params === undefined ? { oid } : { oid, params };
};

const hashForOid = (oid: string): OcspHashAlgorithm | undefined =>
  oid === sha1Oid
    ? "sha1"
    : oid === sha256Oid
      ? "sha256"
      : oid === sha384Oid
        ? "sha384"
        : oid === sha512Oid
          ? "sha512"
          : undefined;

const signatureAlgorithm = (element: DerElement): OcspSignatureAlgorithm => {
  const { oid } = readAlgorithmIdentifier(element, "signature algorithm");
  const table: Readonly<Record<string, OcspSignatureAlgorithm>> = {
    "1.2.840.10045.4.3.2": { oid, hash: "sha256", key: "ec" },
    "1.2.840.10045.4.3.3": { oid, hash: "sha384", key: "ec" },
    "1.2.840.10045.4.3.4": { oid, hash: "sha512", key: "ec" },
    "1.2.840.113549.1.1.5": { oid, hash: "sha1", key: "rsa" },
    "1.2.840.113549.1.1.11": { oid, hash: "sha256", key: "rsa" },
    "1.2.840.113549.1.1.12": { oid, hash: "sha384", key: "rsa" },
    "1.2.840.113549.1.1.13": { oid, hash: "sha512", key: "rsa" },
  };
  const value = table[oid];
  if (value === undefined)
    throw new DerParseError("invalid-tag", `Unsupported signature algorithm ${oid}`, element.start);
  return value;
};

const readOctets = (element: DerElement, name: string): Uint8Array => {
  requireTag(element, universal, 4, name, false);
  return new Uint8Array(element.value);
};

const readInteger = (element: DerElement, name: string): Uint8Array => {
  requireTag(element, universal, 2, name, false);
  if (
    element.value.length === 0 ||
    (element.value.length > 1 && element.value[0] === 0 && (element.value[1] ?? 0) < 0x80) ||
    (element.value[0] ?? 0) >= 0x80
  ) {
    throw new DerParseError(
      "invalid-tag",
      `${name} is not a canonical non-negative INTEGER`,
      element.start,
    );
  }
  return new Uint8Array(element.value);
};

const parseCertId = (element: DerElement): OcspCertId => {
  let hashAlgorithm: OcspHashAlgorithm | undefined;
  let issuerNameHash: Uint8Array | undefined;
  let issuerKeyHash: Uint8Array | undefined;
  let serialNumber: Uint8Array | undefined;
  withChildren(element, (reader) => {
    const algorithm = readAlgorithmIdentifier(
      readOne(reader, "CertID hash algorithm"),
      "CertID hash algorithm",
    );
    hashAlgorithm = hashForOid(algorithm.oid);
    if (hashAlgorithm === undefined)
      throw new DerParseError("invalid-tag", "Unsupported CertID hash algorithm", element.start);
    issuerNameHash = readOctets(readOne(reader, "CertID issuerNameHash"), "CertID issuerNameHash");
    issuerKeyHash = readOctets(readOne(reader, "CertID issuerKeyHash"), "CertID issuerKeyHash");
    serialNumber = readInteger(readOne(reader, "CertID serialNumber"), "CertID serialNumber");
  });
  if (
    hashAlgorithm === undefined ||
    issuerNameHash === undefined ||
    issuerKeyHash === undefined ||
    serialNumber === undefined
  ) {
    throw new DerParseError("unexpected-end", "CertID is incomplete", element.start);
  }
  return Object.freeze({ hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber });
};

const parseGeneralizedTime = (element: DerElement, name: string): number => {
  requireTag(element, universal, 24, name, false);
  if (element.value.length !== 15 || element.value[14] !== 0x5a) {
    throw new DerParseError("invalid-tag", `${name} must be YYYYMMDDHHMMSSZ`, element.start);
  }
  const text = new TextDecoder("ascii", { fatal: true }).decode(element.value);
  if (!generalizedTimePattern.test(text))
    throw new DerParseError("invalid-tag", `${name} has invalid digits`, element.start);
  const date = new Date(
    Date.UTC(
      Number(text.slice(0, 4)),
      Number(text.slice(4, 6)) - 1,
      Number(text.slice(6, 8)),
      Number(text.slice(8, 10)),
      Number(text.slice(10, 12)),
      Number(text.slice(12, 14)),
    ),
  );
  if (
    date.getUTCFullYear() !== Number(text.slice(0, 4)) ||
    date.getUTCMonth() !== Number(text.slice(4, 6)) - 1 ||
    date.getUTCDate() !== Number(text.slice(6, 8)) ||
    date.getUTCHours() !== Number(text.slice(8, 10)) ||
    date.getUTCMinutes() !== Number(text.slice(10, 12)) ||
    date.getUTCSeconds() !== Number(text.slice(12, 14))
  ) {
    throw new DerParseError("invalid-tag", `${name} has an invalid date`, element.start);
  }
  return date.getTime();
};

const parseExtensions = (element: DerElement, name: string): readonly string[] => {
  requireTag(element, contextSpecific, element.tagNumber, name, true);
  const critical: string[] = [];
  const outer = new DerReader(
    element.context.input,
    element.context.limits,
    element.valueStart,
    element.end,
    element.context.depth + 1,
    element.context.state,
  );
  const sequenceElement = readOne(outer, `${name} sequence`);
  withChildren(sequenceElement, (reader) => {
    while (reader.remaining > 0) {
      const extension = reader.readElement();
      withChildren(extension, (fields) => {
        const oid = readOid(readOne(fields, "extension OID"), "extension OID");
        const maybeCritical = fields.readOptionalElement();
        if (maybeCritical !== undefined && isTag(maybeCritical, universal, 1, false)) {
          if (maybeCritical.value[0] !== 0) critical.push(oid);
          readOctets(readOne(fields, "extension value"), "extension value");
        } else if (maybeCritical !== undefined) {
          readOctets(maybeCritical, "extension value");
        }
      });
    }
  });
  outer.assertEnd();
  return Object.freeze(critical);
};

const parseSingleResponse = (element: DerElement): ParsedOcspSingleResponse => {
  let certId: OcspCertId | undefined;
  let status: OcspCertificateStatus | undefined;
  let thisUpdateMs: number | undefined;
  let nextUpdateMs: number | undefined;
  let criticalExtensionOids: readonly string[] = [];
  // biome-ignore lint/complexity/noExcessiveCognitiveComplexity: The branches mirror the bounded SingleResponse ASN.1 choice and optional fields.
  withChildren(element, (reader) => {
    certId = parseCertId(readOne(reader, "SingleResponse certID"));
    const statusElement = readOne(reader, "SingleResponse certStatus");
    if (isTag(statusElement, contextSpecific, 0, false)) {
      if (statusElement.value.length !== 0)
        throw new DerParseError("invalid-tag", "OCSP good status is not NULL", statusElement.start);
      status = "good";
    } else if (isTag(statusElement, contextSpecific, 1, true)) {
      status = "revoked";
      const revokedReader = new DerReader(
        statusElement.context.input,
        statusElement.context.limits,
        statusElement.valueStart,
        statusElement.end,
        statusElement.context.depth + 1,
        statusElement.context.state,
      );
      parseGeneralizedTime(readOne(revokedReader, "revocationTime"), "revocationTime");
      if (revokedReader.remaining > 0) revokedReader.readElement();
      revokedReader.assertEnd();
    } else if (isTag(statusElement, contextSpecific, 2)) {
      status = "unknown";
    } else {
      throw new DerParseError("invalid-tag", "Unsupported OCSP certStatus", statusElement.start);
    }
    thisUpdateMs = parseGeneralizedTime(
      readOne(reader, "SingleResponse thisUpdate"),
      "SingleResponse thisUpdate",
    );
    const optional = reader.readOptionalElement();
    if (optional !== undefined && isTag(optional, contextSpecific, 0, true)) {
      const nextReader = new DerReader(
        optional.context.input,
        optional.context.limits,
        optional.valueStart,
        optional.end,
        optional.context.depth + 1,
        optional.context.state,
      );
      nextUpdateMs = parseGeneralizedTime(readOne(nextReader, "nextUpdate"), "nextUpdate");
      nextReader.assertEnd();
      const extensions = reader.readOptionalElement();
      if (extensions !== undefined)
        criticalExtensionOids = parseExtensions(extensions, "singleExtensions");
    } else if (optional !== undefined) {
      criticalExtensionOids = parseExtensions(optional, "singleExtensions");
    }
  });
  if (certId === undefined || status === undefined || thisUpdateMs === undefined)
    throw new DerParseError("unexpected-end", "SingleResponse is incomplete", element.start);
  return Object.freeze({
    certId,
    status,
    thisUpdateMs,
    ...(nextUpdateMs === undefined ? {} : { nextUpdateMs }),
    criticalExtensionOids,
  });
};

const parseBasicResponse = (input: Uint8Array): ParsedBasicOcspResponse => {
  const reader = new DerReader(input);
  const root = reader.readElement();
  reader.assertEnd();
  let tbsResponseData: Uint8Array | undefined;
  let algorithm: OcspSignatureAlgorithm | undefined;
  let signature: Uint8Array | undefined;
  let responderId: OcspResponderId | undefined;
  let producedAtMs: number | undefined;
  let responses: readonly ParsedOcspSingleResponse[] = [];
  let certificates: readonly Uint8Array[] = [];
  let criticalExtensionOids: readonly string[] = [];
  withChildren(root, (fields) => {
    const tbs = readOne(fields, "tbsResponseData");
    tbsResponseData = new Uint8Array(input.subarray(tbs.start, tbs.end));
    withChildren(tbs, (data) => {
      const first = data.readElement();
      let responder: DerElement;
      if (isTag(first, contextSpecific, 0, true)) {
        const versionReader = new DerReader(
          first.context.input,
          first.context.limits,
          first.valueStart,
          first.end,
          first.context.depth + 1,
          first.context.state,
        );
        readInteger(readOne(versionReader, "ResponseData version"), "ResponseData version");
        versionReader.assertEnd();
        responder = data.readElement();
      } else {
        responder = first;
      }
      if (isTag(responder, contextSpecific, 1, true)) {
        const nested = new DerReader(
          input,
          responder.context.limits,
          responder.valueStart,
          responder.end,
          responder.context.depth + 1,
          responder.context.state,
        );
        const candidate = nested.readOptionalElement();
        if (
          candidate !== undefined &&
          isTag(candidate, universal, 16, true) &&
          nested.remaining === 0
        ) {
          responderId = {
            kind: "name",
            value: new Uint8Array(input.subarray(candidate.start, candidate.end)),
            implicit: false,
          };
        } else {
          responderId = {
            kind: "name",
            value: new Uint8Array(input.subarray(responder.valueStart, responder.end)),
            implicit: true,
          };
        }
      } else if (isTag(responder, contextSpecific, 2, true)) {
        responderId = { kind: "key", value: readResponderKeyHash(responder) };
      } else {
        throw new DerParseError("invalid-tag", "Invalid OCSP responderID", responder.start);
      }
      producedAtMs = parseGeneralizedTime(data.readElement(), "producedAt");
      const responseList = data.readElement();
      withChildren(responseList, (list) => {
        const parsed: ParsedOcspSingleResponse[] = [];
        while (list.remaining > 0) parsed.push(parseSingleResponse(list.readElement()));
        responses = Object.freeze(parsed);
      });
      const extensions = data.readOptionalElement();
      if (extensions !== undefined)
        criticalExtensionOids = parseExtensions(extensions, "responseExtensions");
    });
    algorithm = signatureAlgorithm(readOne(fields, "signatureAlgorithm"));
    const signatureElement = readOne(fields, "signature");
    requireTag(signatureElement, universal, 3, "signature", false);
    if (signatureElement.value.length === 0 || signatureElement.value[0] !== 0)
      throw new DerParseError(
        "invalid-tag",
        "OCSP signature must have zero unused bits",
        signatureElement.start,
      );
    signature = new Uint8Array(signatureElement.value.subarray(1));
    const certs = fields.readOptionalElement();
    if (certs !== undefined) {
      requireTag(certs, contextSpecific, 0, "certs", true);
      const certReader = new DerReader(
        input,
        certs.context.limits,
        certs.valueStart,
        certs.end,
        certs.context.depth + 1,
        certs.context.state,
      );
      const certSequence = readOne(certReader, "certs sequence");
      withChildren(certSequence, (list) => {
        const parsed: Uint8Array[] = [];
        while (list.remaining > 0) {
          const certificate = list.readElement();
          parsed.push(new Uint8Array(input.subarray(certificate.start, certificate.end)));
        }
        certificates = Object.freeze(parsed);
      });
      certReader.assertEnd();
    }
  });
  if (
    tbsResponseData === undefined ||
    algorithm === undefined ||
    signature === undefined ||
    responderId === undefined ||
    producedAtMs === undefined
  )
    throw new DerParseError("unexpected-end", "BasicOCSPResponse is incomplete", 0);
  return Object.freeze({
    tbsResponseData,
    signatureAlgorithm: algorithm,
    signature,
    responderId,
    producedAtMs,
    responses,
    certificates,
    criticalExtensionOids,
  });
};

const readResponderKeyHash = (element: DerElement): Uint8Array => {
  const reader = new DerReader(
    element.context.input,
    element.context.limits,
    element.valueStart,
    element.end,
    element.context.depth + 1,
    element.context.state,
  );
  const hash = readOctets(reader.readElement(), "ResponderID KeyHash");
  reader.assertEnd();
  if (hash.length !== 20) {
    throw new DerParseError(
      "invalid-length",
      "ResponderID KeyHash must be 20 bytes",
      element.start,
    );
  }
  return hash;
};

/** Parse an OCSPResponse without making a trust decision. */
export const parseOcspResponse = (input: Uint8Array): ParsedOcspResponse => {
  const reader = new DerReader(input);
  const root = reader.readElement();
  reader.assertEnd();
  let responseStatus: number | undefined;
  let responseType: string | undefined;
  let basic: ParsedBasicOcspResponse | undefined;
  withChildren(root, (fields) => {
    const status = readOne(fields, "OCSP responseStatus");
    requireTag(status, universal, 10, "OCSP responseStatus", false);
    if (status.value.length !== 1)
      throw new DerParseError("invalid-tag", "OCSP responseStatus must be one byte", status.start);
    responseStatus = status.value[0];
    const responseBytes = fields.readOptionalElement();
    if (responseBytes === undefined) return;
    requireTag(responseBytes, contextSpecific, 0, "responseBytes", true);
    const explicit = new DerReader(
      input,
      responseBytes.context.limits,
      responseBytes.valueStart,
      responseBytes.end,
      responseBytes.context.depth + 1,
      responseBytes.context.state,
    );
    const sequenceElement = readOne(explicit, "responseBytes sequence");
    withChildren(sequenceElement, (responseFields) => {
      responseType = readOid(readOne(responseFields, "responseType"), "responseType");
      const octets = readOctets(readOne(responseFields, "response"), "response");
      if (responseType === basicResponseOid) basic = parseBasicResponse(octets);
    });
    explicit.assertEnd();
  });
  if (responseStatus === undefined)
    throw new DerParseError("unexpected-end", "OCSP response is incomplete", 0);
  return Object.freeze({
    responseStatus,
    ...(responseType === undefined ? {} : { responseType }),
    ...(basic === undefined ? {} : { basic }),
  });
};

export const ocspNameValue = (certificate: PreparedCertificate): Uint8Array => {
  const range = certificate.metadata.subject;
  return new Uint8Array(certificate.der.subarray(range.offset, range.offset + range.length));
};

export const ocspKeyHash = (certificate: PreparedCertificate): Uint8Array =>
  // nosemgrep: no-weak-crypto-hash -- RFC 6960 responderID byKey is defined as SHA-1.
  createHash("sha1")
    .update(rangeBytes(certificate, certificate.metadata.subjectPublicKey.value))
    .digest();

export const ocspBytesEqual = bytesEqual;
export const ocspDerRange = derRange;
