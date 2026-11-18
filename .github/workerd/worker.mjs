// biome-ignore lint/correctness/noNodejsModules: This Worker exercises Node.js compatibility.
import { Buffer } from "node:buffer";

import { createVerifier } from "@preeternal/jws-verifier";

import { ocspRequestKey } from "../../benchmark/ocsp-replay.mjs";
import { benchmarkFixtures, benchmarkPolicy } from "../../test/fixtures/benchmark-fixtures.ts";

const fixture = benchmarkFixtures.find(({ id }) => id === "jws.synthetic.valid-cold");
const replay = new Map(
  fixture.transport.map(({ url, requestBase64, responseBase64 }) => [
    url,
    {
      key: ocspRequestKey(Buffer.from(requestBase64, "base64")),
      response: Buffer.from(responseBase64, "base64"),
    },
  ]),
);
const verifier = createVerifier({
  trustedRoots: benchmarkPolicy.trustedRootsBase64.map((value) => Buffer.from(value, "base64")),
  clock: () => fixture.clockMs,
  policy: {
    mode: "online",
    application: benchmarkPolicy.application,
    environment: benchmarkPolicy.environment,
    claimPaths: { application: ["application"], environment: ["environment"] },
    ocsp: { allowedEndpoints: [...replay.keys()] },
  },
  async ocspTransport({ url, body }) {
    const entry = replay.get(url);
    if (entry?.key !== ocspRequestKey(body)) throw new Error("Unexpected OCSP request");
    return entry.response;
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
