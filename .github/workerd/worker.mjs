// biome-ignore lint/correctness/noNodejsModules: This Worker exercises Node.js compatibility.
import { Buffer } from "node:buffer";

import { createVerifier } from "@preeternal/jws-verifier";

import { benchmarkFixtures, benchmarkPolicy } from "../../test/fixtures/benchmark-fixtures.ts";

const fixture = benchmarkFixtures.find(({ id }) => id === "jws.synthetic.valid-cold");
const verifier = createVerifier({
  trustedRoots: benchmarkPolicy.trustedRootsBase64.map((value) => Buffer.from(value, "base64")),
  clock: () => fixture.clockMs,
  policy: {
    mode: "online",
    application: benchmarkPolicy.application,
    environment: benchmarkPolicy.environment,
    claimPaths: { application: ["application"], environment: ["environment"] },
    ocsp: { allowedEndpoints: fixture.transport.map(({ url }) => url) },
  },
});

// biome-ignore lint/style/noDefaultExport: workerd module workers require a default handler export.
export default {
  async fetch() {
    try {
      const { payload } = await verifier.verify(fixture.jws);
      return Response.json(payload);
    } catch (error) {
      return Response.json(
        { code: error.code, message: error.message, cause: String(error.cause) },
        { status: 500 },
      );
    }
  },
};
