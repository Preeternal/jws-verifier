import { Buffer } from "node:buffer";
import { verify, X509Certificate } from "node:crypto";

const decodeBase64Url = (value) => Uint8Array.from(Buffer.from(value, "base64url"));
const decodeJson = (value) => JSON.parse(Buffer.from(value, "base64url").toString("utf8"));

const reject = (reason) => ({ outcome: "reject", reason });
const cacheTtlMs = 15 * 60 * 1000;

export const adapter = {
  name: "native-crypto-reference",
  version: "0.1.0",
  capabilities: ["jws"],
  supports: (fixture) => fixture.kind === "jws",
  create: ({ policy, clockMs, transport, ocspRequests }) => {
    const chainCache = new Map();

    return {
      async verify({ jws, clockMs: caseClockMs = clockMs }) {
        const parts = jws.split(".");
        if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
          return reject("malformed-jws");
        }

        let header;
        let payload;
        try {
          header = decodeJson(parts[0]);
          payload = decodeJson(parts[1]);
        } catch {
          return reject("malformed-jws");
        }

        const { alg, x5c } = header;
        if (alg !== policy.algorithm) {
          return reject("unsupported-algorithm");
        }
        if (
          !Array.isArray(x5c) ||
          x5c.length !== 3 ||
          x5c.some((value) => typeof value !== "string")
        ) {
          return reject("invalid-certificate-chain");
        }

        let leaf;
        let intermediate;
        let root;
        try {
          leaf = new X509Certificate(Buffer.from(x5c[0], "base64"));
          intermediate = new X509Certificate(Buffer.from(x5c[1], "base64"));
          root = new X509Certificate(Buffer.from(x5c[2], "base64"));
        } catch {
          return reject("invalid-certificate-chain");
        }

        const signatureValid = verify(
          "sha256",
          Buffer.from(`${parts[0]}.${parts[1]}`),
          { key: leaf.publicKey, dsaEncoding: "ieee-p1363" },
          decodeBase64Url(parts[2]),
        );
        if (!signatureValid) {
          return reject("invalid-signature");
        }

        const cacheKey = x5c.join(".");
        const expiresAt = chainCache.get(cacheKey);
        const cached = expiresAt !== undefined && caseClockMs < expiresAt;
        if (!cached) {
          const validAt = (certificate) =>
            caseClockMs >= certificate.validFromDate.getTime() &&
            caseClockMs < certificate.validToDate.getTime();
          if (
            x5c[2] !== policy.trustedRootsBase64[0] ||
            !validAt(leaf) ||
            !validAt(intermediate) ||
            !validAt(root)
          ) {
            return reject("invalid-certificate-chain");
          }
          if (!leaf.verify(intermediate.publicKey) || !intermediate.verify(root.publicKey)) {
            return reject("invalid-certificate-chain");
          }
        }

        if (
          payload.application !== policy.application ||
          payload.environment !== policy.environment
        ) {
          return reject("claims-mismatch");
        }

        if (!cached) {
          try {
            for (const { url, request } of ocspRequests) {
              await transport.request(url, request);
            }
            chainCache.set(
              cacheKey,
              Math.min(
                caseClockMs + cacheTtlMs,
                ...[leaf, intermediate, root].map((certificate) =>
                  certificate.validToDate.getTime(),
                ),
              ),
            );
          } catch (error) {
            return {
              outcome: "transport-error",
              reason: error instanceof Error ? error.message : "transport-error",
            };
          }
        }

        return { outcome: "accept" };
      },
    };
  },
};
