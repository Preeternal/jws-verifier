// biome-ignore lint/correctness/noNodejsModules: Native crypto is the intentional verification boundary.
import { type KeyObject, verify as verifySignature } from "node:crypto";

import { z } from "zod";

import { DerReader } from "../asn1/der-reader.js";
import {
  buildOcspRequest,
  type OcspResponderId,
  ocspBytesEqual,
  ocspCertIdFor,
  ocspKeyHash,
  ocspNameValue,
  parseOcspResponse,
} from "../ocsp/codec.js";
import { fetchOcspResponse } from "../ocsp/transport.js";
import {
  CertificatePreparation,
  type PreparedCertificate,
  type PreparedChain,
  prepareCertificate,
} from "../x509/prepared-certificates.js";

const MAX_DEFAULT_COMPACT_JWS_BYTES = 1024 * 1024;
const MAX_DEFAULT_PROTECTED_HEADER_BYTES = 16 * 1024;
const MAX_DEFAULT_PAYLOAD_BYTES = 512 * 1024;
const MAX_DEFAULT_X5C_ENTRIES = 3;
const MAX_DEFAULT_CERTIFICATE_BYTES = 1024 * 1024;

const compactSegmentPattern = /^[A-Za-z0-9_-]+$/;
const standardBase64Pattern = /^[A-Za-z0-9+/]*={0,2}$/;
const base64UrlPaddingPattern = /={0,2}$/u;
const trailingPaddingPattern = /=+$/u;
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const claimPathSchema = z.array(z.string().min(1)).min(1);
const oidSchema = z.string().regex(/^[012](\.(0|[1-9][0-9]*)){1,63}$/u);
const protectedHeaderSchema = z.looseObject({ alg: z.string(), x5c: z.array(z.string()) });
const ocspPolicySchema = z.strictObject({
  allowedEndpoints: z.array(z.string().min(1)).optional(),
  timeoutMs: z.number().int().positive().max(60_000).default(5_000),
  maxResponseBytes: z
    .number()
    .int()
    .positive()
    .max(16 * 1024 * 1024)
    .default(256 * 1024),
  allowMissingNextUpdate: z.boolean().default(false),
  maxAgeMs: z
    .number()
    .int()
    .positive()
    .default(15 * 60 * 1000),
  allowedSignatureAlgorithms: z
    .array(z.string().min(1))
    .default([
      "1.2.840.10045.4.3.2",
      "1.2.840.10045.4.3.3",
      "1.2.840.10045.4.3.4",
      "1.2.840.113549.1.1.11",
      "1.2.840.113549.1.1.12",
      "1.2.840.113549.1.1.13",
    ]),
});

const verifierPolicySchema = z
  .strictObject({
    mode: z.enum(["offline", "online"]).default("offline"),
    algorithm: z.literal("ES256").default("ES256"),
    application: z.string().min(1).optional(),
    environment: z.string().min(1).optional(),
    claimPaths: z
      .strictObject({
        application: claimPathSchema.optional(),
        environment: claimPathSchema.optional(),
      })
      .optional(),
    signedTimePath: claimPathSchema.optional(),
    requiredExtensions: z
      .strictObject({
        leaf: z.array(oidSchema).optional(),
        intermediate: z.array(oidSchema).optional(),
      })
      .optional(),
    ocsp: ocspPolicySchema.optional(),
    validateClaims: z
      .custom<NonNullable<VerifierPolicy["validateClaims"]>>((value) => typeof value === "function")
      .optional(),
  })
  .refine(({ application, claimPaths }) => application === undefined || !!claimPaths?.application, {
    message: "An expected application requires an explicit application claim path",
  })
  .refine(({ environment, claimPaths }) => environment === undefined || !!claimPaths?.environment, {
    message: "An expected environment requires an explicit environment claim path",
  });

const verifierLimitsSchema = z
  .object({
    maxCompactJwsBytes: z.number().int().positive().default(MAX_DEFAULT_COMPACT_JWS_BYTES),
    maxProtectedHeaderBytes: z
      .number()
      .int()
      .positive()
      .default(MAX_DEFAULT_PROTECTED_HEADER_BYTES),
    maxPayloadBytes: z.number().int().positive().default(MAX_DEFAULT_PAYLOAD_BYTES),
    maxX5cEntries: z.number().int().min(2).max(MAX_DEFAULT_X5C_ENTRIES).default(3),
    maxCertificateBytes: z.number().int().positive().default(MAX_DEFAULT_CERTIFICATE_BYTES),
  })
  .passthrough();

const standardBase64 = (value: string, field: string): Uint8Array => {
  const paddingStart = value.indexOf("=");
  const unpadded = value.replace(base64UrlPaddingPattern, "");
  if (
    !standardBase64Pattern.test(value) ||
    unpadded.length % 4 === 1 ||
    (paddingStart >= 0 && value.length % 4 !== 0)
  ) {
    throw new VerificationError("invalid-header", `${field} is not valid base64`);
  }
  const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
  const decoded = Buffer.from(padded, "base64");
  const canonical = decoded.toString("base64");
  if (canonical.replace(trailingPaddingPattern, "") !== unpadded) {
    throw new VerificationError("invalid-header", `${field} is not canonical base64`);
  }
  return new Uint8Array(decoded);
};

const base64Url = (value: string, field: string): Uint8Array => {
  if (!value || !compactSegmentPattern.test(value) || value.length % 4 === 1) {
    throw new VerificationError("invalid-jws", `${field} is not valid base64url`);
  }
  const padded =
    value.replace(/-/gu, "+").replace(/_/gu, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const decoded = new Uint8Array(Buffer.from(padded, "base64"));
  const canonical = Buffer.from(decoded)
    .toString("base64")
    .replace(trailingPaddingPattern, "")
    .replace(/\+/gu, "-")
    .replace(/\//gu, "_");
  if (canonical !== value) {
    throw new VerificationError("invalid-jws", `${field} is not canonical base64url`);
  }
  return decoded;
};

const decodeJson = (
  bytes: Uint8Array,
  field: string,
  code: VerificationErrorCode = "invalid-jws",
): unknown => {
  try {
    return JSON.parse(textDecoder.decode(bytes)) as unknown;
  } catch (error) {
    throw new VerificationError(code, `${field} is not valid UTF-8 JSON`, error);
  }
};

export interface OcspTransportRequest {
  readonly url: string;
  readonly body: Uint8Array;
  readonly signal: AbortSignal;
}

export type OcspTransport = (request: OcspTransportRequest) => Promise<Uint8Array>;

const defaultOcspPolicy = {
  timeoutMs: 5_000,
  maxResponseBytes: 256 * 1024,
  allowMissingNextUpdate: false,
  maxAgeMs: 15 * 60 * 1000,
  allowedSignatureAlgorithms: [
    "1.2.840.10045.4.3.2",
    "1.2.840.10045.4.3.3",
    "1.2.840.10045.4.3.4",
    "1.2.840.113549.1.1.11",
    "1.2.840.113549.1.1.12",
    "1.2.840.113549.1.1.13",
  ],
} as const;

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
};

const rangeBytes = (
  certificate: PreparedCertificate,
  range: { offset: number; length: number },
): Uint8Array => certificate.der.subarray(range.offset, range.offset + range.length);

const issuerMatches = (certificate: PreparedCertificate, issuer: PreparedCertificate): boolean =>
  bytesEqual(
    rangeBytes(certificate, certificate.metadata.issuer),
    rangeBytes(issuer, issuer.metadata.subject),
  );

const claimAt = (payload: unknown, path: readonly string[]): unknown => {
  let current: unknown = payload;
  for (const key of path) {
    if (typeof current !== "object" || current === null || !Object.hasOwn(current, key)) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[key];
  }
  return current;
};

const validateClaims = (payload: unknown, policy: VerifierPolicy): void => {
  const { application, environment, claimPaths } = policy;
  if (
    application !== undefined &&
    claimAt(payload, claimPaths?.application ?? []) !== application
  ) {
    throw new VerificationError("claim-policy", "The application claim does not match policy");
  }
  if (
    environment !== undefined &&
    claimAt(payload, claimPaths?.environment ?? []) !== environment
  ) {
    throw new VerificationError("claim-policy", "The environment claim does not match policy");
  }
  if (policy.validateClaims !== undefined && policy.validateClaims(payload) !== true) {
    throw new VerificationError("claim-policy", "The payload claims were rejected by policy");
  }
};

const isEffectiveTime = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && Math.abs(value) <= 8.64e15;

const getEffectiveTime = (
  explicitTime: number | undefined,
  payload: unknown,
  signedTimePath: readonly string[] | undefined,
): number => {
  if (explicitTime !== undefined) return explicitTime;
  const signedTime = signedTimePath === undefined ? undefined : claimAt(payload, signedTimePath);
  if (!isEffectiveTime(signedTime)) {
    throw new VerificationError(
      "invalid-effective-time",
      "Offline verification requires an explicit effectiveTime or a valid signed time claim",
    );
  }
  return signedTime;
};

const verifyExtensions = (
  certificate: PreparedCertificate,
  requiredOids: readonly string[],
  name: string,
): void => {
  const { extensions } = certificate.metadata;
  for (const { critical, oid, parsed } of extensions) {
    if (critical && parsed?.kind !== "basicConstraints" && parsed?.kind !== "keyUsage") {
      throw new VerificationError(
        "certificate-policy",
        `${name} has unsupported critical extension ${oid}`,
      );
    }
  }
  for (const oid of requiredOids) {
    if (!extensions.some((extension) => extension.oid === oid)) {
      throw new VerificationError("certificate-policy", `${name} lacks required extension ${oid}`);
    }
  }
};

const ensureValidity = (
  certificate: PreparedCertificate,
  effectiveTime: number,
  name: string,
): void => {
  const { notBeforeMs, notAfterMs } = certificate.metadata.validity;
  if (effectiveTime < notBeforeMs || effectiveTime > notAfterMs) {
    throw new VerificationError(
      "certificate-policy",
      `${name} is not valid at the verification time`,
    );
  }
};

const verifyCertificateSignature = (
  certificate: PreparedCertificate,
  issuer: PreparedCertificate,
  name: string,
): void => {
  try {
    if (!certificate.certificate.verify(issuer.certificate.publicKey)) {
      throw new VerificationError("certificate-chain", `${name} signature is invalid`);
    }
  } catch (error) {
    if (error instanceof VerificationError) throw error;
    throw new VerificationError(
      "certificate-chain",
      `${name} signature could not be verified`,
      error,
    );
  }
};

const verifyTrustAnchor = (
  chain: PreparedChain,
  presentedRootDer: Uint8Array | undefined,
  effectiveTime: number,
): PreparedCertificate => {
  const { intermediate, roots } = chain;
  let failure: VerificationError | undefined;
  for (const root of roots) {
    if (presentedRootDer !== undefined && !bytesEqual(root.der, presentedRootDer)) continue;
    if (!issuerMatches(intermediate, root)) continue;
    try {
      verifyCertificateSignature(intermediate, root, "Intermediate certificate");
      ensureValidity(root, effectiveTime, "Trusted root");
      return root;
    } catch (error) {
      if (!(error instanceof VerificationError)) throw error;
      if (failure === undefined || error.code === "certificate-policy") failure = error;
    }
  }
  throw (
    failure ??
    new VerificationError("certificate-chain", "JWS chain does not terminate at a trusted root")
  );
};

const ensurePublicKey = (key: KeyObject): void => {
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw new VerificationError("certificate-policy", "The JWS certificate key is not P-256");
  }
};

export type VerificationMode = "offline" | "online";

export type VerificationErrorCode =
  | "invalid-jws"
  | "invalid-header"
  | "unsupported-algorithm"
  | "invalid-signature"
  | "certificate-chain"
  | "certificate-policy"
  | "claim-policy"
  | "invalid-effective-time"
  | "online-unavailable"
  | "invalid-trust-anchor"
  | "ocsp-format"
  | "ocsp-policy"
  | "ocsp-status"
  | "ocsp-signature"
  | "ocsp-revoked"
  | "ocsp-unknown"
  | "ocsp-stale"
  | "transport-error";

export class VerificationError extends Error {
  readonly code: VerificationErrorCode;

  constructor(code: VerificationErrorCode, message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "VerificationError";
    this.code = code;
  }
}

export interface OcspPolicy {
  /** Exact OCSP URLs allowed by the host. An omitted list permits no endpoints. */
  readonly allowedEndpoints?: readonly string[];
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
  readonly allowMissingNextUpdate?: boolean;
  readonly maxAgeMs?: number;
  /** Signature algorithm OIDs accepted for BasicOCSPResponse. */
  readonly allowedSignatureAlgorithms?: readonly string[];
}

export interface VerifierPolicy {
  readonly mode?: VerificationMode;
  readonly algorithm?: "ES256";
  readonly application?: string;
  readonly environment?: string;
  readonly claimPaths?: {
    readonly application?: readonly string[];
    readonly environment?: readonly string[];
  };
  /** Unix milliseconds at this exact payload path, read after signature verification. */
  readonly signedTimePath?: readonly string[];
  /** Extension OIDs that must be present in the named certificate. */
  readonly requiredExtensions?: {
    readonly leaf?: readonly string[];
    readonly intermediate?: readonly string[];
  };
  readonly ocsp?: OcspPolicy;
  readonly validateClaims?: (payload: unknown) => boolean;
}

export interface VerifierLimits {
  readonly maxCompactJwsBytes?: number;
  readonly maxProtectedHeaderBytes?: number;
  readonly maxPayloadBytes?: number;
  readonly maxX5cEntries?: number;
  readonly maxCertificateBytes?: number;
}

export interface TrustedRoot {
  readonly id?: string;
  readonly der: Uint8Array;
}

export interface VerifierOptions {
  readonly trustedRoots: readonly (Uint8Array | TrustedRoot)[];
  readonly policy: VerifierPolicy;
  /** Host clock for online verification. */
  readonly clock?: () => number;
  readonly limits?: VerifierLimits;
  readonly ocspTransport?: OcspTransport;
}

export interface VerifyOptions {
  /** Explicit Unix milliseconds for offline verification. Overrides signedTimePath. */
  readonly effectiveTime?: number;
}

export interface VerifiedJws<TPayload = unknown> {
  readonly compactJws: string;
  readonly protectedHeader: Readonly<Record<string, unknown>>;
  readonly payload: TPayload;
}

type NormalizedVerifierPolicy = z.output<typeof verifierPolicySchema>;

interface NormalizedOcspPolicy {
  readonly allowedEndpoints?: readonly string[];
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
  readonly allowMissingNextUpdate: boolean;
  readonly maxAgeMs: number;
  readonly allowedSignatureAlgorithms: readonly string[];
}

interface NormalizedVerifierLimits {
  readonly maxCompactJwsBytes: number;
  readonly maxProtectedHeaderBytes: number;
  readonly maxPayloadBytes: number;
  readonly maxX5cEntries: number;
  readonly maxCertificateBytes: number;
}

interface ParsedCompactJws {
  readonly protectedSegment: string;
  readonly payloadSegment: string;
  readonly signature: Uint8Array;
  readonly protectedHeader: Readonly<Record<string, unknown>>;
  readonly payloadBytes: Uint8Array;
  readonly certificates: readonly Uint8Array[];
}

const freezeHeader = (header: {
  readonly alg: string;
  readonly x5c: readonly string[];
}): Readonly<Record<string, unknown>> =>
  Object.freeze({ ...header, x5c: Object.freeze([...header.x5c]) });

const normalizePolicy = (policy: VerifierPolicy): NormalizedVerifierPolicy => {
  const parsed = verifierPolicySchema.safeParse(policy);
  if (!parsed.success) {
    throw new TypeError(`Invalid verifier policy: ${parsed.error.message}`);
  }
  return parsed.data;
};

const normalizeLimits = (limits: VerifierLimits | undefined): NormalizedVerifierLimits => {
  const parsed = verifierLimitsSchema.safeParse(limits ?? {});
  if (!parsed.success) {
    throw new TypeError(`Invalid verifier limits: ${parsed.error.message}`);
  }
  return parsed.data as NormalizedVerifierLimits;
};

const normalizeRoots = (roots: readonly (Uint8Array | TrustedRoot)[]): readonly Uint8Array[] => {
  if (!Array.isArray(roots) || roots.length === 0) {
    throw new TypeError("At least one trusted root is required");
  }
  return Object.freeze(
    roots.map((root) => {
      const der = root instanceof Uint8Array ? root : root?.der;
      if (!(der instanceof Uint8Array)) throw new TypeError("Trusted roots must contain DER bytes");
      return new Uint8Array(der);
    }),
  );
};

const prepareRoots = (roots: readonly Uint8Array[]): CertificatePreparation => {
  try {
    return new CertificatePreparation(roots);
  } catch (error) {
    throw new VerificationError(
      "invalid-trust-anchor",
      "A trusted root is not a valid certificate",
      error,
    );
  }
};

const parseCompactJws = (
  compactJws: string,
  limits: NormalizedVerifierLimits,
  algorithm: "ES256",
): ParsedCompactJws => {
  if (typeof compactJws !== "string" || compactJws.length > limits.maxCompactJwsBytes) {
    throw new VerificationError("invalid-jws", "Compact JWS exceeds the configured limit");
  }
  const parts = compactJws.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new VerificationError("invalid-jws", "Compact JWS must contain three non-empty segments");
  }
  const [protectedSegment, payloadSegment, signatureSegment] = parts as [string, string, string];
  const protectedBytes = base64Url(protectedSegment, "Protected header");
  const payloadBytes = base64Url(payloadSegment, "Payload");
  const signature = base64Url(signatureSegment, "Signature");
  if (protectedBytes.length > limits.maxProtectedHeaderBytes) {
    throw new VerificationError("invalid-jws", "Protected header exceeds the configured limit");
  }
  if (payloadBytes.length > limits.maxPayloadBytes) {
    throw new VerificationError("invalid-jws", "Payload exceeds the configured limit");
  }
  if (signature.length !== 64) {
    throw new VerificationError("invalid-signature", "ES256 JWS signature must be 64 bytes");
  }

  const protectedValue = decodeJson(protectedBytes, "Protected header", "invalid-header");
  const headerResult = protectedHeaderSchema.safeParse(protectedValue);
  if (!headerResult.success) {
    throw new VerificationError(
      "invalid-header",
      "Protected header does not match the JWS contract",
    );
  }
  const header = headerResult.data;
  if (Object.hasOwn(header, "crit") || Object.hasOwn(header, "b64")) {
    throw new VerificationError("invalid-header", "Unsupported critical JWS header parameter");
  }
  if (header.alg !== algorithm) {
    throw new VerificationError("unsupported-algorithm", `Only ${algorithm} is supported`);
  }
  if (header.x5c.length < 2 || header.x5c.length > limits.maxX5cEntries) {
    throw new VerificationError(
      "invalid-header",
      "JWS x5c must contain a leaf and an intermediate certificate",
    );
  }
  const certificates = header.x5c.map((value, index) => {
    const der = standardBase64(value, `x5c[${index}]`);
    if (der.length > limits.maxCertificateBytes) {
      throw new VerificationError(
        "invalid-header",
        `x5c[${index}] exceeds the configured certificate limit`,
      );
    }
    return der;
  });
  return {
    protectedSegment,
    payloadSegment,
    signature,
    protectedHeader: freezeHeader(header),
    payloadBytes,
    certificates,
  };
};

const verifyJwsSignature = (parsed: ParsedCompactJws, leaf: PreparedCertificate): void => {
  const signingInput = Buffer.from(`${parsed.protectedSegment}.${parsed.payloadSegment}`, "ascii");
  try {
    if (
      !verifySignature(
        "sha256",
        signingInput,
        { key: leaf.certificate.publicKey, dsaEncoding: "ieee-p1363" },
        parsed.signature,
      )
    ) {
      throw new VerificationError("invalid-signature", "JWS signature is invalid");
    }
  } catch (error) {
    if (error instanceof VerificationError) throw error;
    throw new VerificationError("invalid-signature", "JWS signature could not be verified", error);
  }
};

const ocspPolicyFor = (policy: NormalizedVerifierPolicy): NormalizedOcspPolicy =>
  policy.ocsp === undefined
    ? defaultOcspPolicy
    : {
        ...defaultOcspPolicy,
        ...policy.ocsp,
        allowedSignatureAlgorithms:
          policy.ocsp.allowedSignatureAlgorithms ?? defaultOcspPolicy.allowedSignatureAlgorithms,
      };

const normalizedHttpUrl = (value: string): string => {
  let url: URL;
  try {
    url = new URL(value);
  } catch (error) {
    throw new VerificationError("ocsp-policy", "OCSP endpoint is not a valid URL", error);
  }
  if (
    (url.protocol !== "http:" && url.protocol !== "https:") ||
    url.username ||
    url.password ||
    url.hash
  ) {
    throw new VerificationError(
      "ocsp-policy",
      "OCSP endpoint must be an HTTP(S) URL without credentials",
    );
  }
  return url.href;
};

const chooseOcspEndpoint = (
  certificate: PreparedCertificate,
  policy: ReturnType<typeof ocspPolicyFor>,
): string => {
  const allowed = (policy.allowedEndpoints ?? []).map(normalizedHttpUrl);
  const candidates =
    certificate.metadata.authorityInfoAccess?.ocspUrls.map(({ value }) => value) ?? [];
  for (const candidate of candidates) {
    const normalized = normalizedHttpUrl(candidate);
    if (allowed.includes(normalized)) return normalized;
  }
  throw new VerificationError("ocsp-policy", "No certificate OCSP endpoint is allowed by policy");
};

const subjectValue = (certificate: PreparedCertificate): Uint8Array => {
  const reader = new DerReader(
    certificate.der,
    {},
    certificate.metadata.subject.offset,
    certificate.metadata.subject.offset + certificate.metadata.subject.length,
  );
  const element = reader.readElement();
  reader.assertEnd();
  return element.value;
};

const responderMatches = (
  responder: OcspResponderId,
  certificate: PreparedCertificate,
): boolean => {
  if (responder.kind === "key") return ocspBytesEqual(responder.value, ocspKeyHash(certificate));
  const expected = responder.implicit ? subjectValue(certificate) : ocspNameValue(certificate);
  return ocspBytesEqual(responder.value, expected);
};

const verifyResponderCertificate = (
  signer: PreparedCertificate,
  issuer: PreparedCertificate,
  effectiveTime: number,
): void => {
  if (!issuerMatches(signer, issuer)) {
    throw new VerificationError("ocsp-policy", "OCSP delegated responder has the wrong issuer");
  }
  verifyCertificateSignature(signer, issuer, "OCSP delegated responder");
  ensureValidity(signer, effectiveTime, "OCSP delegated responder");
  if (signer.metadata.basicConstraints?.ca === true) {
    throw new VerificationError("ocsp-policy", "OCSP delegated responder must not be a CA");
  }
  if (!signer.metadata.extendedKeyUsage?.ocspSigning) {
    throw new VerificationError("ocsp-policy", "OCSP delegated responder lacks OCSPSigning");
  }
  if (
    signer.metadata.keyUsage !== undefined &&
    !signer.metadata.keyUsage.names.includes("digitalSignature")
  ) {
    throw new VerificationError("ocsp-policy", "OCSP delegated responder lacks digitalSignature");
  }
  for (const extension of signer.metadata.extensions) {
    if (
      extension.critical &&
      extension.parsed?.kind !== "basicConstraints" &&
      extension.parsed?.kind !== "keyUsage" &&
      extension.parsed?.kind !== "extendedKeyUsage"
    ) {
      throw new VerificationError(
        "ocsp-policy",
        `OCSP delegated responder has unsupported critical extension ${extension.oid}`,
      );
    }
  }
};

const authorizedDelegate = (
  der: Uint8Array,
  responder: OcspResponderId,
  issuer: PreparedCertificate,
  effectiveTime: number,
): PreparedCertificate | undefined => {
  try {
    const candidate = prepareCertificate(der);
    if (!responderMatches(responder, candidate)) return undefined;
    verifyResponderCertificate(candidate, issuer, effectiveTime);
    return candidate;
  } catch {
    return undefined;
  }
};

type BasicOcspResponse = NonNullable<ReturnType<typeof parseOcspResponse>["basic"]>;

const hasValidOcspSignature = (
  response: BasicOcspResponse,
  signer: PreparedCertificate,
): boolean => {
  try {
    const key = signer.certificate.publicKey;
    if (key.asymmetricKeyType !== response.signatureAlgorithm.key) return false;
    return verifySignature(
      response.signatureAlgorithm.hash,
      response.tbsResponseData,
      key,
      response.signature,
    );
  } catch {
    return false;
  }
};

const verifyOcspSignature = (
  response: BasicOcspResponse,
  issuer: PreparedCertificate,
  effectiveTime: number,
): void => {
  if (response.criticalExtensionOids.length > 0) {
    throw new VerificationError(
      "ocsp-policy",
      "OCSP response contains unsupported critical extensions",
    );
  }
  let authorized = responderMatches(response.responderId, issuer);
  if (authorized && hasValidOcspSignature(response, issuer)) return;
  for (const der of response.certificates) {
    const candidate = authorizedDelegate(der, response.responderId, issuer, effectiveTime);
    if (candidate === undefined) continue;
    authorized = true;
    if (hasValidOcspSignature(response, candidate)) return;
  }
  if (authorized) {
    throw new VerificationError("ocsp-signature", "OCSP response signature is invalid");
  }
  throw new VerificationError(
    "ocsp-policy",
    "OCSP responder is not the issuer or an authorized delegate",
  );
};

const verifyOcspStatus = (
  response: NonNullable<ReturnType<typeof parseOcspResponse>["basic"]>,
  certificate: PreparedCertificate,
  issuer: PreparedCertificate,
  effectiveTime: number,
  policy: ReturnType<typeof ocspPolicyFor>,
): void => {
  if (response.producedAtMs > effectiveTime) {
    throw new VerificationError("ocsp-stale", "OCSP response was produced in the future");
  }
  const expected = ocspCertIdFor(certificate, issuer);
  const matching = response.responses.filter(
    ({ certId }) =>
      certId.hashAlgorithm === expected.hashAlgorithm &&
      ocspBytesEqual(certId.issuerNameHash, expected.issuerNameHash) &&
      ocspBytesEqual(certId.issuerKeyHash, expected.issuerKeyHash) &&
      ocspBytesEqual(certId.serialNumber, expected.serialNumber),
  );
  if (matching.length === 0)
    throw new VerificationError("ocsp-policy", "OCSP response CertID does not match the request");
  if (matching.length !== 1)
    throw new VerificationError(
      "ocsp-policy",
      "OCSP response contains duplicate matching CertID entries",
    );
  const result = matching[0];
  if (result === undefined)
    throw new VerificationError(
      "ocsp-policy",
      "OCSP response is missing its matching SingleResponse",
    );
  if (result.status === "revoked")
    throw new VerificationError("ocsp-revoked", "Certificate is revoked according to OCSP");
  if (result.status === "unknown")
    throw new VerificationError("ocsp-unknown", "OCSP responder returned unknown status");
  if (
    result.thisUpdateMs > effectiveTime ||
    (result.nextUpdateMs !== undefined && result.nextUpdateMs < result.thisUpdateMs)
  ) {
    throw new VerificationError("ocsp-stale", "OCSP response has invalid update times");
  }
  if (result.nextUpdateMs === undefined) {
    if (!policy.allowMissingNextUpdate || effectiveTime - result.thisUpdateMs > policy.maxAgeMs) {
      throw new VerificationError("ocsp-stale", "OCSP response has no acceptable nextUpdate");
    }
  } else if (effectiveTime > result.nextUpdateMs) {
    throw new VerificationError("ocsp-stale", "OCSP response is expired");
  }
  if (result.criticalExtensionOids.length > 0) {
    throw new VerificationError("ocsp-policy", "OCSP SingleResponse contains critical extensions");
  }
};

export class JwsVerifier {
  readonly #policy: NormalizedVerifierPolicy;

  private readonly preparation: CertificatePreparation;
  private readonly limits: NormalizedVerifierLimits;
  private readonly clock: () => number;
  private readonly ocspTransport: OcspTransport | undefined;

  constructor(options: VerifierOptions) {
    if (options === null || typeof options !== "object") {
      throw new TypeError("Verifier options are required");
    }
    this.#policy = normalizePolicy(options.policy);
    this.limits = normalizeLimits(options.limits);
    this.preparation = prepareRoots(normalizeRoots(options.trustedRoots));
    this.clock = options.clock ?? (() => Date.now());
    if (typeof this.clock !== "function") throw new TypeError("clock must be a function");
    if (options.ocspTransport !== undefined && typeof options.ocspTransport !== "function") {
      throw new TypeError("ocspTransport must be a function");
    }
    this.ocspTransport = options.ocspTransport;
  }

  async verify<TPayload = unknown>(
    compactJws: string,
    options: VerifyOptions = {},
  ): Promise<VerifiedJws<TPayload>> {
    if (this.#policy.mode === "online") return this.verifyOnline<TPayload>(compactJws, options);
    return this.verifySync<TPayload>(compactJws, options);
  }

  verifySync<TPayload = unknown>(
    compactJws: string,
    options: VerifyOptions = {},
  ): VerifiedJws<TPayload> {
    if (this.#policy.mode === "online") {
      throw new VerificationError(
        "online-unavailable",
        "Online verification requires the asynchronous verify() method",
      );
    }
    if (options.effectiveTime !== undefined && !isEffectiveTime(options.effectiveTime)) {
      throw new VerificationError(
        "invalid-effective-time",
        "effectiveTime must be Unix milliseconds",
      );
    }
    const parsed = parseCompactJws(compactJws, this.limits, this.#policy.algorithm);
    const [leafDer, intermediateDer, presentedRootDer] = parsed.certificates as [
      Uint8Array,
      Uint8Array,
      Uint8Array?,
    ];
    const prepared = this.prepareChain(leafDer, intermediateDer);
    ensurePublicKey(prepared.leaf.certificate.publicKey);
    verifyJwsSignature(parsed, prepared.leaf);

    const payload = decodeJson(parsed.payloadBytes, "Payload");
    const effectiveTime = getEffectiveTime(
      options.effectiveTime,
      payload,
      this.#policy.signedTimePath,
    );
    this.verifyChain(prepared, effectiveTime);
    verifyTrustAnchor(prepared, presentedRootDer, effectiveTime);
    validateClaims(payload, this.#policy);
    return Object.freeze({
      compactJws,
      protectedHeader: parsed.protectedHeader,
      payload: payload as TPayload,
    });
  }

  private async verifyOnline<TPayload = unknown>(
    compactJws: string,
    options: VerifyOptions,
  ): Promise<VerifiedJws<TPayload>> {
    if (options.effectiveTime !== undefined) {
      throw new VerificationError(
        "invalid-effective-time",
        "effectiveTime is only supported in offline verification",
      );
    }
    const parsed = parseCompactJws(compactJws, this.limits, this.#policy.algorithm);
    const [leafDer, intermediateDer, presentedRootDer] = parsed.certificates as [
      Uint8Array,
      Uint8Array,
      Uint8Array?,
    ];
    const prepared = this.prepareChain(leafDer, intermediateDer);
    ensurePublicKey(prepared.leaf.certificate.publicKey);
    verifyJwsSignature(parsed, prepared.leaf);
    const payload = decodeJson(parsed.payloadBytes, "Payload");
    const effectiveTime = this.clock();
    if (!isEffectiveTime(effectiveTime)) {
      throw new VerificationError("invalid-effective-time", "clock must return Unix milliseconds");
    }
    this.verifyChain(prepared, effectiveTime);
    const root = verifyTrustAnchor(prepared, presentedRootDer, effectiveTime);
    validateClaims(payload, this.#policy);
    const ocspPolicy = ocspPolicyFor(this.#policy);
    const leafEndpoint = chooseOcspEndpoint(prepared.leaf, ocspPolicy);
    const intermediateEndpoint = chooseOcspEndpoint(prepared.intermediate, ocspPolicy);
    await this.verifyOcsp(prepared.leaf, prepared.intermediate, effectiveTime, leafEndpoint);
    await this.verifyOcsp(prepared.intermediate, root, effectiveTime, intermediateEndpoint);
    return Object.freeze({
      compactJws,
      protectedHeader: parsed.protectedHeader,
      payload: payload as TPayload,
    });
  }

  private async requestOcsp(url: string, body: Uint8Array): Promise<Uint8Array> {
    const policy = ocspPolicyFor(this.#policy);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), policy.timeoutMs);
    let raceTimer: ReturnType<typeof setTimeout> | undefined;
    const request =
      this.ocspTransport ??
      ((input: OcspTransportRequest) =>
        fetchOcspResponse(input.url, input.body, input.signal, {
          maxResponseBytes: policy.maxResponseBytes,
        }));
    try {
      const response = await Promise.race([
        request({ url, body, signal: controller.signal }),
        new Promise<Uint8Array>((_, reject) => {
          raceTimer = setTimeout(
            () => reject(new Error("OCSP request timed out")),
            policy.timeoutMs,
          );
        }),
      ]);
      if (!(response instanceof Uint8Array) || response.byteLength > policy.maxResponseBytes) {
        throw new Error("OCSP response exceeds the configured body limit");
      }
      return response;
    } catch (error) {
      if (error instanceof VerificationError) throw error;
      throw new VerificationError("transport-error", "OCSP transport failed", error);
    } finally {
      clearTimeout(timer);
      if (raceTimer !== undefined) clearTimeout(raceTimer);
    }
  }

  private async verifyOcsp(
    certificate: PreparedCertificate,
    issuer: PreparedCertificate,
    effectiveTime: number,
    endpoint: string,
  ): Promise<void> {
    const policy = ocspPolicyFor(this.#policy);
    const request = buildOcspRequest(certificate, issuer);
    const responseBytes = await this.requestOcsp(endpoint, request);
    let response: ReturnType<typeof parseOcspResponse>;
    try {
      response = parseOcspResponse(responseBytes);
    } catch (error) {
      throw new VerificationError("ocsp-format", "OCSP response is malformed", error);
    }
    if (response.responseStatus !== 0) {
      throw new VerificationError(
        "ocsp-status",
        `OCSP responder returned status ${response.responseStatus}`,
      );
    }
    if (response.responseType !== "1.3.6.1.5.5.7.48.1.1" || response.basic === undefined) {
      throw new VerificationError("ocsp-format", "OCSP response is not BasicOCSPResponse");
    }
    if (!policy.allowedSignatureAlgorithms.includes(response.basic.signatureAlgorithm.oid)) {
      throw new VerificationError("ocsp-policy", "OCSP signature algorithm is not allowed");
    }
    verifyOcspSignature(response.basic, issuer, effectiveTime);
    verifyOcspStatus(response.basic, certificate, issuer, effectiveTime, policy);
  }

  private prepareChain(leafDer: Uint8Array, intermediateDer: Uint8Array): PreparedChain {
    try {
      return this.preparation.prepareChain(leafDer, intermediateDer);
    } catch (error) {
      throw new VerificationError("certificate-chain", "JWS certificate chain is malformed", error);
    }
  }

  private verifyChain({ leaf, intermediate }: PreparedChain, effectiveTime: number): void {
    ensureValidity(leaf, effectiveTime, "Leaf certificate");
    ensureValidity(intermediate, effectiveTime, "Intermediate certificate");
    const required = this.#policy.requiredExtensions;
    verifyExtensions(leaf, required?.leaf ?? [], "Leaf certificate");
    verifyExtensions(intermediate, required?.intermediate ?? [], "Intermediate certificate");
    if (leaf.metadata.basicConstraints?.ca === true) {
      throw new VerificationError("certificate-policy", "Leaf certificate must not be a CA");
    }
    if (
      leaf.metadata.keyUsage !== undefined &&
      !leaf.metadata.keyUsage.names.includes("digitalSignature")
    ) {
      throw new VerificationError(
        "certificate-policy",
        "Leaf certificate lacks digitalSignature key usage",
      );
    }
    if (intermediate.metadata.basicConstraints?.ca !== true) {
      throw new VerificationError("certificate-policy", "Intermediate certificate must be a CA");
    }
    if (
      intermediate.metadata.keyUsage !== undefined &&
      !intermediate.metadata.keyUsage.names.includes("keyCertSign")
    ) {
      throw new VerificationError(
        "certificate-policy",
        "Intermediate certificate lacks keyCertSign key usage",
      );
    }
    if (!issuerMatches(leaf, intermediate)) {
      throw new VerificationError(
        "certificate-chain",
        "Leaf issuer does not match intermediate subject",
      );
    }
    verifyCertificateSignature(leaf, intermediate, "Leaf certificate");
  }
}

export const createVerifier = (options: VerifierOptions): JwsVerifier => new JwsVerifier(options);
