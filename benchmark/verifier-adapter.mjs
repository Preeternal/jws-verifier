import { createVerifier } from "../dist/index.js";

export const adapter = {
  name: "jws-verifier",
  version: "workspace",
  capabilities: ["jws", "ocsp"],
  create({ policy, clockMs, transport, ocspRequests }) {
    let now = clockMs;
    const verifier = createVerifier({
      trustedRoots: policy.trustedRootsBase64.map((value) => Buffer.from(value, "base64")),
      clock: () => now,
      policy: {
        mode: "online",
        algorithm: policy.algorithm,
        application: policy.application,
        environment: policy.environment,
        claimPaths: { application: ["application"], environment: ["environment"] },
        ocsp: { allowedEndpoints: ocspRequests.map(({ url }) => url) },
      },
      ocspTransport: ({ url, body }) => transport.request(url, body),
    });

    return {
      async verify({ jws, clockMs: time }) {
        now = time;
        try {
          await verifier.verify(jws);
          return { outcome: "accept" };
        } catch (error) {
          const reason =
            error.code === "ocsp-revoked"
              ? "revoked"
              : error.code === "ocsp-stale"
                ? "stale"
                : error.code === "transport-error"
                  ? "timeout"
                  : error.code;
          return {
            outcome: error.code === "transport-error" ? "transport-error" : "reject",
            reason,
          };
        }
      },
    };
  },
};
