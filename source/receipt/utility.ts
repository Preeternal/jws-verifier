import {
  BerCursor,
  type BerElement,
  BerParseError,
  DEFAULT_BER_LIMITS,
} from "../asn1/ber-reader.js";

const IN_APP_TYPE_ID = 17;
const TRANSACTION_IDENTIFIER_TYPE_ID = 1703;
const ORIGINAL_TRANSACTION_IDENTIFIER_TYPE_ID = 1705;
// biome-ignore lint/security/noSecrets: This is a public ASN.1 object identifier, not a secret.
const PKCS7_SIGNED_DATA_OID = "2a864886f70d010702";
// biome-ignore lint/security/noSecrets: This is a public ASN.1 object identifier, not a secret.
const PKCS7_DATA_OID = "2a864886f70d010701";
const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/u;
const PURCHASE_INFO_PATTERN = /"purchase-info"\s+=\s+"([A-Za-z0-9+/=]+)";/u;
const TRANSACTION_ID_PATTERN = /"transaction-id"\s+=\s+"([A-Za-z0-9+/=]+)";/u;
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

const universal = 0;
const contextSpecific = 2;

export type ReceiptErrorCode =
  | "invalid-base64"
  | "invalid-utf8"
  | "invalid-structure"
  | "limit-exceeded";

export class ReceiptFormatError extends Error {
  readonly code: ReceiptErrorCode;
  readonly offset?: number;

  constructor(code: ReceiptErrorCode, message: string, offset?: number, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "ReceiptFormatError";
    this.code = code;
    this.offset = offset;
  }
}

export type ReceiptExtractionResult =
  | { readonly kind: "found"; readonly transactionId: string }
  | { readonly kind: "missing" };

export type ReceiptExtractionOutcome =
  | ReceiptExtractionResult
  | { readonly kind: "error"; readonly error: ReceiptFormatError };

export type AppReceiptInput = string | Uint8Array;

const found = (transactionId: string): ReceiptExtractionResult =>
  Object.freeze({ kind: "found", transactionId });
const missing = (): ReceiptExtractionResult => Object.freeze({ kind: "missing" });

const fail = (message: string, offset?: number): never => {
  throw new ReceiptFormatError("invalid-structure", message, offset);
};

const checkReceiptSize = (byteLength: number): void => {
  if (byteLength > DEFAULT_BER_LIMITS.maxInputBytes) {
    throw new ReceiptFormatError("limit-exceeded", "Receipt exceeds the configured size limit");
  }
};

const decodeBase64 = (value: string): Uint8Array => {
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  checkReceiptSize(Math.floor(value.length / 4) * 3 - padding);
  if (value.length % 4 !== 0 || !BASE64_PATTERN.test(value)) {
    throw new ReceiptFormatError("invalid-base64", "Receipt is not valid canonical base64");
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) {
    throw new ReceiptFormatError("invalid-base64", "Receipt is not valid canonical base64");
  }
  return bytes;
};

const appReceiptBytes = (input: AppReceiptInput): Uint8Array => {
  if (typeof input === "string") return decodeBase64(input);
  checkReceiptSize(input.byteLength);
  return new Uint8Array(input);
};

const decodeUtf8 = (bytes: Uint8Array): string => {
  try {
    return utf8Decoder.decode(bytes);
  } catch (error) {
    throw new ReceiptFormatError(
      "invalid-utf8",
      "Receipt contains invalid UTF-8",
      undefined,
      error,
    );
  }
};

const isTag = (
  element: BerElement,
  tagClass: number,
  tagNumber: number,
  constructed?: boolean,
): boolean =>
  element.tagClass === tagClass &&
  element.tagNumber === tagNumber &&
  (constructed === undefined || element.constructed === constructed);

const requireTag = (
  element: BerElement,
  tagClass: number,
  tagNumber: number,
  name: string,
  constructed?: boolean,
): void => {
  if (!isTag(element, tagClass, tagNumber, constructed)) {
    fail(`${name} has an unexpected BER tag`, element.start);
  }
};

const childrenOf = (input: Uint8Array, element: BerElement, name: string): BerElement[] => {
  if (!element.constructed) fail(`${name} must be constructed`, element.start);
  const cursor = new BerCursor(input, element.limits, element.valueStart, element.contentEnd);
  const children: BerElement[] = [];
  while (cursor.remaining > 0) children.push(cursor.readElement());
  cursor.assertEnd();
  return children;
};

const oneChild = (input: Uint8Array, element: BerElement, name: string): BerElement => {
  const children = childrenOf(input, element, name);
  if (children.length !== 1) fail(`${name} must contain exactly one element`, element.start);
  return children[0] as BerElement;
};

const oneRoot = (input: Uint8Array, name: string): BerElement => {
  const cursor = new BerCursor(input);
  const root = cursor.readElement();
  cursor.assertEnd();
  if (root.start !== 0) fail(`${name} has an invalid root`, root.start);
  return root;
};

const oidHex = (element: BerElement, name: string): string => {
  requireTag(element, universal, 6, name, false);
  return Buffer.from(element.value).toString("hex");
};

const requireOid = (element: BerElement, expected: string, name: string): void => {
  if (oidHex(element, name) !== expected)
    fail(`${name} has an unexpected object identifier`, element.start);
};

const integerValue = (element: BerElement, name: string): number => {
  requireTag(element, universal, 2, name, false);
  if (
    element.value.length === 0 ||
    (element.value.length > 1 && element.value[0] === 0 && (element.value[1] ?? 0) < 0x80) ||
    (element.value[0] ?? 0) >= 0x80 ||
    element.value.length > 6
  ) {
    fail(`${name} is not a supported non-negative INTEGER`, element.start);
  }
  let value = 0;
  for (const byte of element.value) value = value * 256 + byte;
  if (!Number.isSafeInteger(value)) fail(`${name} is outside the supported range`, element.start);
  return value;
};

const concat = (parts: readonly Uint8Array[], maxBytes: number): Uint8Array => {
  const size = parts.reduce((total, part) => total + part.byteLength, 0);
  if (size > maxBytes) {
    throw new ReceiptFormatError(
      "limit-exceeded",
      "Receipt OCTET STRING exceeds the configured size limit",
    );
  }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
};

const visitOctetFragments = (
  input: Uint8Array,
  element: BerElement,
  visit?: (bytes: Uint8Array) => void,
): void => {
  requireTag(element, universal, 4, "OCTET STRING");
  if (!element.constructed) {
    visit?.(element.value);
    return;
  }
  for (const child of childrenOf(input, element, "constructed OCTET STRING")) {
    visitOctetFragments(input, child, visit);
  }
};

const octetStringBytes = (input: Uint8Array, element: BerElement): Uint8Array => {
  requireTag(element, universal, 4, "OCTET STRING");
  if (!element.constructed) return element.value;
  const parts: Uint8Array[] = [];
  visitOctetFragments(input, element, (part) => parts.push(part));
  if (parts.length === 1 && parts[0] !== undefined) return parts[0];
  return concat(parts, DEFAULT_BER_LIMITS.maxInputBytes);
};

const transactionIdFromUtf8Value = (input: Uint8Array, element: BerElement): string => {
  const bytes = octetStringBytes(input, element);
  const value = oneRoot(bytes, "transaction identifier value");
  requireTag(value, universal, 12, "transaction identifier", false);
  return decodeUtf8(value.value);
};

function* receiptAttributes(input: Uint8Array, set: BerElement) {
  requireTag(set, universal, 17, "receipt attribute set", true);
  for (const entry of childrenOf(input, set, "receipt attribute set")) {
    requireTag(entry, universal, 16, "receipt attribute", true);
    const [type, version, value, extra] = childrenOf(input, entry, "receipt attribute");
    if (!type || !version || !value || extra) {
      throw new ReceiptFormatError(
        "invalid-structure",
        "Receipt attribute must contain three fields",
        entry.start,
      );
    }
    integerValue(version, "receipt attribute version");
    yield { type: integerValue(type, "receipt attribute type"), value };
  }
}

const extractFromInAppSet = (input: Uint8Array, set: BerElement): string | undefined => {
  let firstId: string | undefined;
  for (const { type, value } of receiptAttributes(input, set)) {
    if (
      type !== TRANSACTION_IDENTIFIER_TYPE_ID &&
      type !== ORIGINAL_TRANSACTION_IDENTIFIER_TYPE_ID
    ) {
      visitOctetFragments(input, value);
      continue;
    }
    const id = transactionIdFromUtf8Value(input, value);
    firstId ??= id;
  }
  return firstId;
};

const extractFromReceiptSet = (input: Uint8Array, set: BerElement): ReceiptExtractionResult => {
  let firstId: string | undefined;
  for (const { type, value } of receiptAttributes(input, set)) {
    if (type !== IN_APP_TYPE_ID) {
      visitOctetFragments(input, value);
      continue;
    }
    const inAppBytes = octetStringBytes(input, value);
    const inApp = oneRoot(inAppBytes, "in-app purchase payload");
    const transactionId = extractFromInAppSet(inAppBytes, inApp);
    firstId ??= transactionId;
  }
  return firstId === undefined ? missing() : found(firstId);
};

const readSignedDataContent = (input: Uint8Array, signedData: BerElement): BerElement => {
  requireTag(signedData, universal, 16, "CMS SignedData", true);
  const fields = childrenOf(input, signedData, "CMS SignedData");
  const [version, algorithms, content] = fields;
  if (!version || !algorithms || !content) {
    throw new ReceiptFormatError(
      "invalid-structure",
      "CMS SignedData is incomplete",
      signedData.start,
    );
  }
  if (![1, 3, 4, 5].includes(integerValue(version, "CMS version"))) {
    fail("Unsupported CMS version", version.start);
  }
  requireTag(algorithms, universal, 17, "CMS digestAlgorithms", true);
  let index = 3;
  for (const tag of [0, 1]) {
    const field = fields[index];
    if (field && isTag(field, contextSpecific, tag, true)) index += 1;
  }
  const signers = fields[index];
  if (!signers || index !== fields.length - 1) {
    throw new ReceiptFormatError(
      "invalid-structure",
      "CMS SignedData must end with signerInfos",
      signedData.start,
    );
  }
  requireTag(signers, universal, 17, "CMS signerInfos", true);
  return content;
};

const parseAppReceiptOrThrow = (input: AppReceiptInput): ReceiptExtractionResult => {
  const bytes = appReceiptBytes(input);
  try {
    const root = oneRoot(bytes, "CMS receipt");
    requireTag(root, universal, 16, "CMS ContentInfo", true);
    const contentInfo = childrenOf(bytes, root, "CMS ContentInfo");
    if (contentInfo.length !== 2) fail("CMS ContentInfo must contain two fields", root.start);
    requireOid(contentInfo[0] as BerElement, PKCS7_SIGNED_DATA_OID, "CMS content type");
    requireTag(contentInfo[1] as BerElement, contextSpecific, 0, "CMS signed data wrapper", true);

    const signedData = oneChild(bytes, contentInfo[1] as BerElement, "CMS signed data wrapper");
    const encapsulated = readSignedDataContent(bytes, signedData);
    requireTag(encapsulated, universal, 16, "CMS encapsulated content", true);
    const encapsulatedFields = childrenOf(bytes, encapsulated, "CMS encapsulated content");
    if (encapsulatedFields.length !== 2)
      fail("CMS encapsulated content is incomplete", encapsulated.start);
    requireOid(
      encapsulatedFields[0] as BerElement,
      PKCS7_DATA_OID,
      "CMS encapsulated content type",
    );
    requireTag(
      encapsulatedFields[1] as BerElement,
      contextSpecific,
      0,
      "CMS receipt wrapper",
      true,
    );

    const payload = oneChild(bytes, encapsulatedFields[1] as BerElement, "CMS receipt wrapper");
    const receiptBytes = octetStringBytes(bytes, payload);
    const receiptSet = oneRoot(receiptBytes, "receipt payload");
    return extractFromReceiptSet(receiptBytes, receiptSet);
  } catch (error) {
    if (error instanceof ReceiptFormatError) throw error;
    if (error instanceof BerParseError) {
      const code: ReceiptErrorCode =
        error.code === "limit-exceeded" ? "limit-exceeded" : "invalid-structure";
      throw new ReceiptFormatError(code, error.message, error.offset, error);
    }
    throw new ReceiptFormatError(
      "invalid-structure",
      "Receipt has an invalid structure",
      undefined,
      error,
    );
  }
};

export const parseAppReceiptTransactionId = (input: AppReceiptInput): ReceiptExtractionOutcome => {
  try {
    return parseAppReceiptOrThrow(input);
  } catch (error) {
    if (error instanceof ReceiptFormatError) return { kind: "error", error };
    throw error;
  }
};

export const extractTransactionIdFromAppReceipt = (input: AppReceiptInput): string | null => {
  const result = parseAppReceiptOrThrow(input);
  return result.kind === "found" ? result.transactionId : null;
};

const parseTransactionReceiptOrThrow = (transactionReceipt: string): ReceiptExtractionResult => {
  const topLevel = decodeUtf8(decodeBase64(transactionReceipt));
  const topLevelMatch = topLevel.match(PURCHASE_INFO_PATTERN);
  const purchaseInfoBase64: string =
    topLevelMatch?.[1] ?? fail("Transaction receipt does not contain purchase-info");
  const purchaseInfo = decodeUtf8(decodeBase64(purchaseInfoBase64));
  const transactionIdMatch = purchaseInfo.match(TRANSACTION_ID_PATTERN);
  const transactionId = transactionIdMatch?.[1];
  return transactionId === undefined ? missing() : found(transactionId);
};

export const parseTransactionReceiptTransactionId = (
  transactionReceipt: string,
): ReceiptExtractionOutcome => {
  try {
    return parseTransactionReceiptOrThrow(transactionReceipt);
  } catch (error) {
    if (error instanceof ReceiptFormatError) return { kind: "error", error };
    throw error;
  }
};

export const extractTransactionIdFromTransactionReceipt = (
  transactionReceipt: string,
): string | null => {
  const result = parseTransactionReceiptOrThrow(transactionReceipt);
  return result.kind === "found" ? result.transactionId : null;
};

/** Compatibility facade matching Apple's receipt utility method names. */
export class ReceiptUtility {
  extractTransactionIdFromAppReceipt(input: AppReceiptInput): string | null {
    return extractTransactionIdFromAppReceipt(input);
  }

  extractTransactionIdFromTransactionReceipt(transactionReceipt: string): string | null {
    return extractTransactionIdFromTransactionReceipt(transactionReceipt);
  }
}
