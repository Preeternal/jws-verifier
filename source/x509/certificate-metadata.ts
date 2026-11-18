import {
  type ByteRange,
  DEFAULT_DER_LIMITS,
  type DerElement,
  type DerLimits,
  DerParseError,
  DerReader,
  derRange,
} from "../asn1/der-reader.js";

const OIDS = Object.freeze({
  authorityInfoAccess: "1.3.6.1.5.5.7.1.1",
  basicConstraints: "2.5.29.19",
  extendedKeyUsage: "2.5.29.37",
  keyUsage: "2.5.29.15",
  ocsp: "1.3.6.1.5.5.7.48.1",
  ocspSigning: "1.3.6.1.5.5.7.3.9",
  appleLeaf: "1.2.840.113635.100.6.11.1",
  appleIntermediate: "1.2.840.113635.100.6.2.1",
});

export interface X509MetadataLimits extends DerLimits {
  readonly maxExtensions?: number;
  readonly maxAiaEntries?: number;
  readonly maxOidArcs?: number;
}

export interface X509SerialNumber {
  readonly tlv: ByteRange;
  readonly value: ByteRange;
}

export interface X509SubjectPublicKey {
  readonly bitString: ByteRange;
  readonly value: ByteRange;
  readonly unusedBits: number;
}

export interface X509Validity {
  readonly notBefore: ByteRange;
  readonly notBeforeMs: number;
  readonly notAfter: ByteRange;
  readonly notAfterMs: number;
}

export interface X509AuthorityInfoAccess {
  readonly ocspUrls: readonly X509Uri[];
}

export interface X509Uri {
  readonly value: string;
  readonly range: ByteRange;
}

export interface X509BasicConstraints {
  readonly ca: boolean;
  readonly pathLenConstraint?: number;
}

export type X509KeyUsageName =
  | "digitalSignature"
  | "contentCommitment"
  | "keyEncipherment"
  | "dataEncipherment"
  | "keyAgreement"
  | "keyCertSign"
  | "cRLSign"
  | "encipherOnly"
  | "decipherOnly";

export interface X509KeyUsage {
  readonly names: readonly X509KeyUsageName[];
}

export interface X509ExtendedKeyUsage {
  readonly oids: readonly string[];
  readonly ocspSigning: boolean;
}

export type X509ParsedExtension =
  | { readonly kind: "authorityInfoAccess"; readonly value: X509AuthorityInfoAccess }
  | { readonly kind: "basicConstraints"; readonly value: X509BasicConstraints }
  | { readonly kind: "extendedKeyUsage"; readonly value: X509ExtendedKeyUsage }
  | { readonly kind: "keyUsage"; readonly value: X509KeyUsage };

export interface X509ExtensionMetadata {
  readonly oid: string;
  readonly oidValue: ByteRange;
  readonly critical: boolean;
  readonly tlv: ByteRange;
  readonly value: ByteRange;
  readonly parsed?: X509ParsedExtension;
}

export interface X509CertificateMetadata {
  readonly version: 0 | 1 | 2;
  readonly issuer: ByteRange;
  readonly subject: ByteRange;
  readonly serial: X509SerialNumber;
  readonly validity: X509Validity;
  readonly subjectPublicKey: X509SubjectPublicKey;
  readonly extensions: readonly X509ExtensionMetadata[];
  readonly authorityInfoAccess?: X509AuthorityInfoAccess;
  readonly basicConstraints?: X509BasicConstraints;
  readonly keyUsage?: X509KeyUsage;
  readonly extendedKeyUsage?: X509ExtendedKeyUsage;
  readonly apple: {
    readonly leaf: boolean;
    readonly intermediate: boolean;
  };
}

const defaults = Object.freeze({
  maxAiaEntries: 32,
  maxExtensions: 64,
  maxOidArcs: 64,
});

const universal = 0;
const contextSpecific = 2;
const decimalDigits = /^\d+$/;
const asciiDecoder = new TextDecoder();

const isTag = (
  element: DerElement,
  tagClass: number,
  tagNumber: number,
  constructed?: boolean,
): boolean =>
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

const requireSequence = (element: DerElement, name: string): void => {
  requireTag(element, universal, 16, name, true);
};

const requireSet = (element: DerElement, name: string): void => {
  requireTag(element, universal, 17, name, true);
};

const readOne = (reader: DerReader, name: string): DerElement => {
  const element = reader.readOptionalElement();
  if (element === undefined) {
    throw new DerParseError("unexpected-end", `Missing ${name}`, reader.end);
  }
  return element;
};

const parseOid = (
  element: DerElement,
  name: string,
  maxOidArcs: number,
): { readonly oid: string; readonly value: ByteRange } => {
  requireTag(element, universal, 6, name, false);
  if (element.value.length === 0) {
    throw new DerParseError("invalid-tag", `${name} cannot be empty`, element.start);
  }

  const components: bigint[] = [];
  let index = 0;
  while (index < element.value.length) {
    const component = readOidComponent(element, index, name);
    components.push(component.value);
    index = component.next;
    if (components.length > maxOidArcs) {
      throw new DerParseError("limit-exceeded", `${name} has too many components`, element.start);
    }
  }

  const first = components[0];
  if (first === undefined) {
    throw new DerParseError("invalid-tag", `${name} cannot be empty`, element.start);
  }
  const firstArc = first < 40n ? first : first < 80n ? 1n : 2n;
  const secondArc = firstArc === 2n ? first - 80n : first % 40n;
  const oid = [firstArc, secondArc, ...components.slice(1)].map(String).join(".");
  return { oid, value: derRange(element.valueStart, element.value.length) };
};

const readOidComponent = (
  element: DerElement,
  start: number,
  name: string,
): { readonly value: bigint; readonly next: number } => {
  let component = 0n;
  let index = start;
  let firstByte = true;
  while (index < element.value.length) {
    const byte = element.value[index] ?? 0;
    index += 1;
    if (firstByte && byte === 0x80) {
      throw new DerParseError("invalid-tag", `${name} contains a non-canonical OID`, element.start);
    }
    firstByte = false;
    component = component * 128n + BigInt(byte & 0x7f);
    if (component > 0xffffffffffffffffn) {
      throw new DerParseError("limit-exceeded", `${name} component is too large`, element.start);
    }
    if ((byte & 0x80) === 0) {
      return { value: component, next: index };
    }
  }
  throw new DerParseError("unexpected-end", `${name} is truncated`, element.end);
};

const parseBoolean = (element: DerElement, name: string): boolean => {
  requireTag(element, universal, 1, name, false);
  if (element.value.length !== 1 || (element.value[0] !== 0x00 && element.value[0] !== 0xff)) {
    throw new DerParseError("invalid-tag", `${name} is not a canonical DER BOOLEAN`, element.start);
  }
  return element.value[0] === 0xff;
};

const requireNonNegativeInteger = (element: DerElement, name: string): void => {
  requireTag(element, universal, 2, name, false);
  if (
    element.value.length === 0 ||
    (element.value.length > 1 && element.value[0] === 0x00 && (element.value[1] ?? 0) < 0x80)
  ) {
    throw new DerParseError("invalid-tag", `${name} is not a canonical DER INTEGER`, element.start);
  }
  if ((element.value[0] ?? 0) >= 0x80) {
    throw new DerParseError("invalid-tag", `${name} must be non-negative`, element.start);
  }
};

const parseNonNegativeInteger = (element: DerElement, name: string): number => {
  requireNonNegativeInteger(element, name);
  if (element.value.length > 7) {
    throw new DerParseError(
      "invalid-tag",
      `${name} exceeds the supported integer range`,
      element.start,
    );
  }
  let value = 0;
  for (const byte of element.value) {
    value = value * 256 + byte;
  }
  if (!Number.isSafeInteger(value)) {
    throw new DerParseError(
      "invalid-tag",
      `${name} exceeds the supported integer range`,
      element.start,
    );
  }
  return value;
};

const parseVersion = (element: DerElement, limits: Required<X509MetadataLimits>): 0 | 1 | 2 => {
  requireTag(element, contextSpecific, 0, "certificate version", true);
  let version = 0;
  elementReader(element, limits, (reader) => {
    const integer = readOne(reader, "certificate version value");
    version = parseNonNegativeInteger(integer, "certificate version");
  });
  if (version === 0 || version > 2) {
    throw new DerParseError("invalid-tag", "Unsupported X.509 certificate version", element.start);
  }
  return version as 1 | 2;
};

const parseAlgorithmIdentifier = (
  element: DerElement,
  limits: Required<X509MetadataLimits>,
  name: string,
): void => {
  requireSequence(element, name);
  elementReader(element, limits, (reader) => {
    parseOid(readOne(reader, `${name} OID`), `${name} OID`, limits.maxOidArcs);
    reader.readOptionalElement();
    if (reader.remaining !== 0) {
      throw new DerParseError("trailing-data", `${name} has too many fields`, reader.start);
    }
  });
};

const parseName = (
  element: DerElement,
  limits: Required<X509MetadataLimits>,
  name: string,
): void => {
  requireSequence(element, name);
  elementReader(element, limits, (reader) => {
    while (reader.remaining > 0) {
      const relativeName = reader.readElement();
      requireSet(relativeName, `${name} relative distinguished name`);
      elementReader(relativeName, limits, (setReader) => {
        while (setReader.remaining > 0) {
          const attribute = setReader.readElement();
          requireSequence(attribute, `${name} attribute`);
          elementReader(attribute, limits, (attributeReader) => {
            parseOid(
              readOne(attributeReader, `${name} attribute OID`),
              `${name} attribute OID`,
              limits.maxOidArcs,
            );
            readOne(attributeReader, `${name} attribute value`);
          });
        }
      });
    }
  });
};

const parseTime = (element: DerElement, name: string): number => {
  requireTag(element, universal, element.tagNumber, name, false);
  const generalized = element.tagNumber === 24;
  const expectedLength = generalized ? 15 : 13;
  if (
    (!generalized && element.tagNumber !== 23) ||
    element.value.length !== expectedLength ||
    element.value[expectedLength - 1] !== 0x5a
  ) {
    throw new DerParseError("invalid-tag", `${name} is not a canonical UTC time`, element.start);
  }
  const text = asciiDecoder.decode(element.value);

  const digit = (offset: number, length: number): number => {
    const value = Number.parseInt(text.slice(offset, offset + length), 10);
    if (!Number.isInteger(value) || !decimalDigits.test(text.slice(offset, offset + length))) {
      throw new DerParseError("invalid-tag", `${name} contains invalid time digits`, element.start);
    }
    return value;
  };

  const year = generalized
    ? digit(0, 4)
    : (() => {
        const shortYear = digit(0, 2);
        return shortYear >= 50 ? 1900 + shortYear : 2000 + shortYear;
      })();
  const monthOffset = generalized ? 4 : 2;
  const month = digit(monthOffset, 2);
  const day = digit(monthOffset + 2, 2);
  const hour = digit(monthOffset + 4, 2);
  const minute = digit(monthOffset + 6, 2);
  const second = digit(monthOffset + 8, 2);
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day ||
    date.getUTCHours() !== hour ||
    date.getUTCMinutes() !== minute ||
    date.getUTCSeconds() !== second
  ) {
    throw new DerParseError("invalid-tag", `${name} contains an invalid date`, element.start);
  }
  return date.getTime();
};

const parseValidity = (element: DerElement, limits: Required<X509MetadataLimits>): X509Validity => {
  requireSequence(element, "certificate validity");
  let notBefore: DerElement | undefined;
  let notAfter: DerElement | undefined;
  elementReader(element, limits, (reader) => {
    notBefore = readOne(reader, "notBefore");
    notAfter = readOne(reader, "notAfter");
  });
  if (notBefore === undefined || notAfter === undefined) {
    throw new DerParseError("unexpected-end", "Certificate validity is incomplete", element.start);
  }
  const notBeforeMs = parseTime(notBefore, "notBefore");
  const notAfterMs = parseTime(notAfter, "notAfter");
  if (notBeforeMs > notAfterMs) {
    throw new DerParseError("invalid-tag", "Certificate validity is reversed", element.start);
  }
  return Object.freeze({
    notBefore: derRange(notBefore.start, notBefore.end - notBefore.start),
    notBeforeMs,
    notAfter: derRange(notAfter.start, notAfter.end - notAfter.start),
    notAfterMs,
  });
};

const parseBitString = (
  element: DerElement,
  name: string,
): { readonly bitString: ByteRange; readonly value: ByteRange; readonly unusedBits: number } => {
  requireTag(element, universal, 3, name, false);
  if (element.value.length === 0) {
    throw new DerParseError(
      "invalid-tag",
      `${name} is missing the unused-bits count`,
      element.start,
    );
  }
  const unusedBits = element.value[0] ?? 0;
  if (unusedBits > 7 || (element.value.length === 1 && unusedBits !== 0)) {
    throw new DerParseError(
      "invalid-tag",
      `${name} has an invalid unused-bits count`,
      element.start,
    );
  }
  const last = element.value[element.value.length - 1] ?? 0;
  if (unusedBits > 0 && (last & ((1 << unusedBits) - 1)) !== 0) {
    throw new DerParseError("invalid-tag", `${name} has non-zero unused bits`, element.start);
  }
  return Object.freeze({
    bitString: derRange(element.start, element.end - element.start),
    value: derRange(element.valueStart + 1, element.value.length - 1),
    unusedBits,
  });
};

const parseSubjectPublicKeyInfo = (
  element: DerElement,
  limits: Required<X509MetadataLimits>,
): X509SubjectPublicKey => {
  requireSequence(element, "SPKI");
  let bitString: DerElement | undefined;
  elementReader(element, limits, (reader) => {
    parseAlgorithmIdentifier(readOne(reader, "SPKI algorithm"), limits, "SPKI algorithm");
    bitString = readOne(reader, "SPKI key");
  });
  if (bitString === undefined) {
    throw new DerParseError("unexpected-end", "SPKI is missing its key", element.end);
  }
  return parseBitString(bitString, "SPKI key");
};

const parseImplicitBitString = (element: DerElement, name: string): void => {
  requireTag(element, contextSpecific, element.tagNumber, name, false);
  if (element.value.length === 0 || (element.value[0] ?? 0) > 7) {
    throw new DerParseError("invalid-tag", `${name} has an invalid bit string`, element.start);
  }
  const unusedBits = element.value[0] ?? 0;
  const last = element.value[element.value.length - 1] ?? 0;
  if (unusedBits > 0 && (last & ((1 << unusedBits) - 1)) !== 0) {
    throw new DerParseError("invalid-tag", `${name} has non-zero unused bits`, element.start);
  }
};

const parseBasicConstraints = (
  element: DerElement,
  limits: Required<X509MetadataLimits>,
): X509BasicConstraints => {
  requireSequence(element, "basicConstraints");
  let ca = false;
  let pathLenConstraint: number | undefined;
  elementReader(element, limits, (reader) => {
    const first = reader.readOptionalElement();
    if (first === undefined) {
      return;
    }
    if (isTag(first, universal, 1, false)) {
      ca = parseBoolean(first, "basicConstraints cA");
      const path = reader.readOptionalElement();
      if (path !== undefined) {
        const value = parseNonNegativeInteger(path, "basicConstraints pathLenConstraint");
        if (!ca) {
          throw new DerParseError(
            "invalid-tag",
            "Invalid basicConstraints pathLenConstraint",
            path.start,
          );
        }
        pathLenConstraint = value;
      }
      return;
    }
    throw new DerParseError(
      "invalid-tag",
      "Invalid basicConstraints pathLenConstraint",
      first.start,
    );
  });
  return Object.freeze({ ca, ...(pathLenConstraint === undefined ? {} : { pathLenConstraint }) });
};

const keyUsageNames: readonly X509KeyUsageName[] = [
  "digitalSignature",
  "contentCommitment",
  "keyEncipherment",
  "dataEncipherment",
  "keyAgreement",
  "keyCertSign",
  "cRLSign",
  "encipherOnly",
  "decipherOnly",
];

const parseKeyUsage = (element: DerElement): X509KeyUsage => {
  parseBitString(element, "keyUsage");
  const value = element.value;
  const names = keyUsageNames.filter((_, index) => {
    const byte = value[1 + Math.floor(index / 8)] ?? 0;
    return (byte & (0x80 >>> (index % 8))) !== 0;
  });
  if (value.length > 3 || (value.length === 3 && value[2] !== 0x80)) {
    throw new DerParseError("invalid-tag", "keyUsage contains unsupported bits", element.start);
  }
  return Object.freeze({ names: Object.freeze(names) });
};

const parseExtendedKeyUsage = (
  element: DerElement,
  limits: Required<X509MetadataLimits>,
): X509ExtendedKeyUsage => {
  requireSequence(element, "extendedKeyUsage");
  const oids: string[] = [];
  elementReader(element, limits, (reader) => {
    while (reader.remaining > 0) {
      const oid = parseOid(reader.readElement(), "extendedKeyUsage OID", limits.maxOidArcs).oid;
      if (oids.includes(oid)) {
        throw new DerParseError("invalid-tag", "Duplicate extendedKeyUsage OID", reader.start);
      }
      oids.push(oid);
    }
  });
  return Object.freeze({ oids: Object.freeze(oids), ocspSigning: oids.includes(OIDS.ocspSigning) });
};

const parseAuthorityInfoAccess = (
  element: DerElement,
  limits: Required<X509MetadataLimits>,
): X509AuthorityInfoAccess => {
  requireSequence(element, "authorityInfoAccess");
  const ocspUrls: X509Uri[] = [];
  let entries = 0;
  elementReader(element, limits, (reader) => {
    while (reader.remaining > 0) {
      entries += 1;
      if (entries > limits.maxAiaEntries) {
        throw new DerParseError(
          "limit-exceeded",
          "Too many authorityInfoAccess entries",
          reader.start,
        );
      }
      const accessDescription = reader.readElement();
      requireSequence(accessDescription, "authorityInfoAccess entry");
      elementReader(accessDescription, limits, (entryReader) => {
        const method = parseOid(
          readOne(entryReader, "authorityInfoAccess method"),
          "authorityInfoAccess method",
          limits.maxOidArcs,
        ).oid;
        const location = readOne(entryReader, "authorityInfoAccess location");
        if (method === OIDS.ocsp) {
          requireTag(location, contextSpecific, 6, "authorityInfoAccess OCSP URI", false);
          if (location.value.length === 0 || location.value.some((byte) => byte > 0x7f)) {
            throw new DerParseError(
              "invalid-tag",
              "authorityInfoAccess OCSP URI is not IA5",
              location.start,
            );
          }
          ocspUrls.push(
            Object.freeze({
              value: asciiDecoder.decode(location.value),
              range: derRange(location.valueStart, location.value.length),
            }),
          );
        } else if (location.tagClass !== contextSpecific) {
          throw new DerParseError(
            "invalid-tag",
            "authorityInfoAccess location is not a GeneralName",
            location.start,
          );
        }
      });
    }
  });
  return Object.freeze({ ocspUrls: Object.freeze(ocspUrls) });
};

const parseExtensionValue = (
  oid: string,
  element: DerElement,
  limits: Required<X509MetadataLimits>,
): X509ParsedExtension | undefined => {
  let parsed: X509ParsedExtension | undefined;
  const inner = new DerReader(
    element.context.input,
    limits,
    element.valueStart,
    element.end,
    element.context.depth + 1,
    element.context.state,
  );
  const value = inner.readElement();
  inner.assertEnd();
  if (oid === OIDS.authorityInfoAccess) {
    parsed = Object.freeze({
      kind: "authorityInfoAccess",
      value: parseAuthorityInfoAccess(value, limits),
    });
  } else if (oid === OIDS.basicConstraints) {
    parsed = Object.freeze({
      kind: "basicConstraints",
      value: parseBasicConstraints(value, limits),
    });
  } else if (oid === OIDS.extendedKeyUsage) {
    parsed = Object.freeze({
      kind: "extendedKeyUsage",
      value: parseExtendedKeyUsage(value, limits),
    });
  } else if (oid === OIDS.keyUsage) {
    parsed = Object.freeze({ kind: "keyUsage", value: parseKeyUsage(value) });
  }
  return parsed;
};

const parseExtensions = (
  element: DerElement,
  limits: Required<X509MetadataLimits>,
): readonly X509ExtensionMetadata[] => {
  requireTag(element, contextSpecific, 3, "certificate extensions", true);
  const extensions: X509ExtensionMetadata[] = [];
  const seen = new Set<string>();
  elementReader(element, limits, (explicitReader) => {
    const sequence = readOne(explicitReader, "certificate extensions sequence");
    requireSequence(sequence, "certificate extensions sequence");
    if (sequence.value.length === 0) {
      throw new DerParseError(
        "invalid-tag",
        "Certificate extensions cannot be empty",
        sequence.start,
      );
    }
    elementReader(sequence, limits, (extensionReader) => {
      while (extensionReader.remaining > 0) {
        if (extensions.length >= limits.maxExtensions) {
          throw new DerParseError(
            "limit-exceeded",
            "Too many certificate extensions",
            extensionReader.start,
          );
        }
        extensions.push(parseExtension(extensionReader.readElement(), limits, seen));
      }
    });
  });
  return Object.freeze(extensions);
};

const parseExtension = (
  extension: DerElement,
  limits: Required<X509MetadataLimits>,
  seen: Set<string>,
): X509ExtensionMetadata => {
  requireSequence(extension, "certificate extension");
  let oid = "";
  let oidValue: ByteRange | undefined;
  let critical = false;
  let value: DerElement | undefined;
  elementReader(extension, limits, (fields) => {
    const parsedOid = parseOid(
      readOne(fields, "certificate extension OID"),
      "certificate extension OID",
      limits.maxOidArcs,
    );
    oid = parsedOid.oid;
    oidValue = parsedOid.value;
    const maybeCritical = fields.readOptionalElement();
    if (maybeCritical !== undefined && isTag(maybeCritical, universal, 1, false)) {
      critical = parseBoolean(maybeCritical, "certificate extension critical");
    } else if (maybeCritical !== undefined) {
      value = maybeCritical;
    }
    value ??= readOne(fields, "certificate extension value");
  });
  if (seen.has(oid)) {
    throw new DerParseError(
      "invalid-tag",
      `Duplicate certificate extension ${oid}`,
      extension.start,
    );
  }
  seen.add(oid);
  if (oidValue === undefined || value === undefined) {
    throw new DerParseError(
      "unexpected-end",
      "Certificate extension is incomplete",
      extension.start,
    );
  }
  requireTag(value, universal, 4, "certificate extension value", false);
  const parsed = parseExtensionValue(oid, value, limits);
  return Object.freeze({
    oid,
    oidValue,
    critical,
    tlv: derRange(extension.start, extension.end - extension.start),
    value: derRange(value.valueStart, value.value.length),
    ...(parsed === undefined ? {} : { parsed }),
  });
};

const elementReader = (
  element: DerElement,
  limits: Required<X509MetadataLimits>,
  callback: (reader: DerReader) => void,
): void => {
  const reader = new DerReader(
    element.context.input,
    limits,
    element.valueStart,
    element.end,
    element.context.depth + 1,
    element.context.state,
  );
  callback(reader);
  reader.assertEnd();
};

const parseTbsCertificate = (
  element: DerElement,
  limits: Required<X509MetadataLimits>,
): Omit<X509CertificateMetadata, "apple"> & { readonly extensionOids: readonly string[] } => {
  requireSequence(element, "tbsCertificate");
  let version: 0 | 1 | 2 = 0;
  let serialElement: DerElement | undefined;
  let issuer: DerElement | undefined;
  let subject: DerElement | undefined;
  let validity: X509Validity | undefined;
  let subjectPublicKey: X509SubjectPublicKey | undefined;
  let extensions: readonly X509ExtensionMetadata[] = [];

  elementReader(element, limits, (reader) => {
    const core = parseTbsCore(reader, limits);
    version = core.version;
    serialElement = core.serialElement;
    issuer = core.issuer;
    subject = core.subject;
    validity = core.validity;
    subjectPublicKey = core.subjectPublicKey;
    extensions = parseTbsOptionalFields(reader, limits, version);
  });

  if (
    serialElement === undefined ||
    issuer === undefined ||
    subject === undefined ||
    validity === undefined ||
    subjectPublicKey === undefined
  ) {
    throw new DerParseError("unexpected-end", "tbsCertificate is incomplete", element.start);
  }
  const serial = Object.freeze({
    tlv: derRange(serialElement.start, serialElement.end - serialElement.start),
    value: derRange(serialElement.valueStart, serialElement.value.length),
  });
  const extensionOids = Object.freeze(extensions.map(({ oid }) => oid));
  let authorityInfoAccess: X509AuthorityInfoAccess | undefined;
  let basicConstraints: X509BasicConstraints | undefined;
  let keyUsage: X509KeyUsage | undefined;
  let extendedKeyUsage: X509ExtendedKeyUsage | undefined;
  for (const extension of extensions) {
    const parsed = extension.parsed;
    if (parsed?.kind === "authorityInfoAccess") {
      authorityInfoAccess = parsed.value;
    } else if (parsed?.kind === "basicConstraints") {
      basicConstraints = parsed.value;
    } else if (parsed?.kind === "keyUsage") {
      keyUsage = parsed.value;
    } else if (parsed?.kind === "extendedKeyUsage") {
      extendedKeyUsage = parsed.value;
    }
  }
  return {
    version,
    issuer: derRange(issuer.start, issuer.end - issuer.start),
    subject: derRange(subject.start, subject.end - subject.start),
    serial,
    validity,
    subjectPublicKey,
    extensions,
    extensionOids,
    ...(authorityInfoAccess === undefined ? {} : { authorityInfoAccess }),
    ...(basicConstraints === undefined ? {} : { basicConstraints }),
    ...(keyUsage === undefined ? {} : { keyUsage }),
    ...(extendedKeyUsage === undefined ? {} : { extendedKeyUsage }),
  };
};

const parseTbsOptionalFields = (
  reader: DerReader,
  limits: Required<X509MetadataLimits>,
  version: 0 | 1 | 2,
): readonly X509ExtensionMetadata[] => {
  let extensions: readonly X509ExtensionMetadata[] = Object.freeze([]);
  let previousTag = 0;
  while (reader.remaining > 0) {
    const field = reader.readElement();
    const tag = field.tagNumber;
    if (field.tagClass !== contextSpecific || tag <= previousTag || tag > 3) {
      throw new DerParseError(
        "invalid-tag",
        "Unexpected or out-of-order tbsCertificate field",
        field.start,
      );
    }
    if (version === 0 || (tag === 3 && version !== 2)) {
      throw new DerParseError(
        "invalid-tag",
        "Field is not allowed in this certificate version",
        field.start,
      );
    }
    previousTag = tag;
    if (tag === 3) {
      extensions = parseExtensions(field, limits);
    } else {
      parseImplicitBitString(field, tag === 1 ? "issuerUniqueID" : "subjectUniqueID");
    }
  }
  return extensions;
};

const parseTbsCore = (
  reader: DerReader,
  limits: Required<X509MetadataLimits>,
): {
  readonly version: 0 | 1 | 2;
  readonly serialElement: DerElement;
  readonly issuer: DerElement;
  readonly subject: DerElement;
  readonly validity: X509Validity;
  readonly subjectPublicKey: X509SubjectPublicKey;
} => {
  let version: 0 | 1 | 2 = 0;
  let serialElement = readOne(reader, "certificate serial number or version");
  if (isTag(serialElement, contextSpecific, 0, true)) {
    version = parseVersion(serialElement, limits);
    serialElement = readOne(reader, "certificate serial number");
  }
  requireNonNegativeInteger(serialElement, "certificate serial number");
  parseAlgorithmIdentifier(
    readOne(reader, "certificate signature algorithm"),
    limits,
    "certificate signature algorithm",
  );
  const issuer = readOne(reader, "certificate issuer");
  parseName(issuer, limits, "certificate issuer");
  const validity = parseValidity(readOne(reader, "certificate validity"), limits);
  const subject = readOne(reader, "certificate subject");
  parseName(subject, limits, "certificate subject");
  const subjectPublicKey = parseSubjectPublicKeyInfo(readOne(reader, "SPKI"), limits);
  return { version, serialElement, issuer, subject, validity, subjectPublicKey };
};

export const parseX509CertificateMetadata = (
  input: Uint8Array,
  options: X509MetadataLimits = {},
): X509CertificateMetadata => {
  const limits = {
    ...defaults,
    ...options,
    maxDepth: options.maxDepth ?? DEFAULT_DER_LIMITS.maxDepth,
    maxElements: options.maxElements ?? DEFAULT_DER_LIMITS.maxElements,
    maxInputBytes: options.maxInputBytes ?? DEFAULT_DER_LIMITS.maxInputBytes,
    maxWorkBytes: options.maxWorkBytes ?? DEFAULT_DER_LIMITS.maxWorkBytes,
  };
  const reader = new DerReader(input, limits);
  const certificate = reader.readElement();
  reader.assertEnd();
  requireSequence(certificate, "certificate");
  let tbsCertificate: DerElement | undefined;
  elementReader(certificate, limits, (certificateReader) => {
    tbsCertificate = readOne(certificateReader, "tbsCertificate");
    parseAlgorithmIdentifier(
      readOne(certificateReader, "certificate signature algorithm"),
      limits,
      "certificate signature algorithm",
    );
    parseBitString(readOne(certificateReader, "certificate signature"), "certificate signature");
  });
  if (tbsCertificate === undefined) {
    throw new DerParseError(
      "unexpected-end",
      "Certificate is missing tbsCertificate",
      certificate.start,
    );
  }
  const parsed = parseTbsCertificate(tbsCertificate, limits);
  const extensionOids = new Set(parsed.extensionOids);
  return Object.freeze({
    ...parsed,
    apple: Object.freeze({
      leaf: extensionOids.has(OIDS.appleLeaf),
      intermediate: extensionOids.has(OIDS.appleIntermediate),
    }),
  });
};

export { OIDS as X509_EXTENSION_OIDS };
