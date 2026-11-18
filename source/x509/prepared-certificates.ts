// biome-ignore lint/correctness/noNodejsModules: Native certificate operations belong in this adapter.
import { X509Certificate } from "node:crypto";

import { DEFAULT_DER_LIMITS, DerParseError } from "../asn1/der-reader.js";
import {
  parseX509CertificateMetadata,
  type X509CertificateMetadata,
} from "./certificate-metadata.js";

export interface PreparedCertificate {
  /** Owned DER bytes. Internal consumers must treat these as read-only. */
  readonly der: Uint8Array;
  readonly certificate: X509Certificate;
  readonly metadata: X509CertificateMetadata;
}

export interface PreparedChain {
  readonly leaf: PreparedCertificate;
  readonly intermediate: PreparedCertificate;
  readonly roots: readonly PreparedCertificate[];
}

const prepareCertificate = (input: Uint8Array): PreparedCertificate => {
  if (input.byteLength > DEFAULT_DER_LIMITS.maxInputBytes) {
    throw new DerParseError("input-too-large", "DER input exceeds the configured limit", 0);
  }
  const der = new Uint8Array(input);
  const metadata = parseX509CertificateMetadata(der);
  return Object.freeze({ der, certificate: new X509Certificate(der), metadata });
};

/** Owns the prepared trust anchors for one verifier configuration. */
export class CertificatePreparation {
  readonly roots: readonly PreparedCertificate[];

  constructor(trustedRoots: readonly Uint8Array[]) {
    this.roots = Object.freeze(trustedRoots.map(prepareCertificate));
  }

  /** Prepare once on a cache miss and pass the same result to chain and OCSP checks. */
  prepareChain(leaf: Uint8Array, intermediate: Uint8Array): PreparedChain {
    return Object.freeze({
      leaf: prepareCertificate(leaf),
      intermediate: prepareCertificate(intermediate),
      roots: this.roots,
    });
  }
}
