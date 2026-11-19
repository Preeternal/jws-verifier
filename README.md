# `@preeternal/jws-verifier`

[![npm version](https://img.shields.io/npm/v/@preeternal/jws-verifier.svg)](https://www.npmjs.com/package/@preeternal/jws-verifier)
[![npm downloads](https://img.shields.io/npm/dm/@preeternal/jws-verifier.svg)](https://www.npmjs.com/package/@preeternal/jws-verifier)
[![Patreon](https://img.shields.io/endpoint?url=https%3A%2F%2Fshieldsio-patreon.vercel.app%2Fapi%2F%3Fusername%3Dpreeternal%26type%3Dpatrons)](https://www.patreon.com/preeternal)

TypeScript library for verifying compact ES256 JWS with X.509 certificate chains
and optional OCSP revocation checks.

## Why this library?

Use it when your application needs to verify signed messages independently of
a provider SDK. You supply trusted roots, claim rules, and an OCSP policy. For
example, a service that receives App Store notifications can use the verifier
independently of its App Store Server API client.

The package is ESM-only and targets Node.js 22+ and Cloudflare Workers with
Node.js compatibility enabled. It uses `node:crypto` for signatures and
hashing, with TypeScript parsers for certificates, OCSP, and legacy receipts.

## Install

```bash
yarn add @preeternal/jws-verifier
```

## Usage

```ts
import { createVerifier } from "@preeternal/jws-verifier";

const verifier = createVerifier({
  trustedRoots: [rootDer], // Uint8Array loaded from your trusted configuration
  policy: {
    mode: "offline",
    application: "com.example.app",
    environment: "sandbox",
    claimPaths: { application: ["data", "id"], environment: ["data", "environment"] },
    signedTimePath: ["issuedAt"],
  },
});

const { payload } = await verifier.verify(compactJws);
```

Obtain DER trust anchors from your provider or your own trust configuration,
independently of the incoming JWS. Set the claim paths and any
`requiredExtensions` to match the signing profile your application accepts.
The example paths are illustrative.

- **Offline** checks certificate validity at a signed Unix millisecond
  timestamp from `signedTimePath` or at an explicit time passed as
  `verify(compactJws, { effectiveTime })`. It performs no OCSP queries.
- **Online** checks certificate validity against the host clock and checks
  revocation through OCSP. Set `mode: "online"` and
  `ocsp: { allowedEndpoints: [...] }` inside `policy`. The built-in transport
  uses the host's `fetch`, rejects redirects, and enforces time and body-size
  limits. To customize it, pass a top-level `ocspTransport` callback that
  takes `{ url, body, signal }` and returns response bytes. Reuse the verifier
  for a stable configuration to take advantage of its validation cache.

For legacy App Receipts, `extractTransactionIdFromAppReceipt` reads the ID
synchronously. The extracted value alone does not establish receipt
authenticity or purchase entitlement.

## Performance

CPU time per verification (median / p95) on Linux GitHub Actions at `164e443`.
The benchmark uses synthetic ES256 JWS and OCSP responses replayed from memory.

| Scenario                       | Node 22 · EPYC 9V74 | Node 24 · EPYC 9V74 |
| ------------------------------ | ------------------: | ------------------: |
| First verification after setup |      5.65 / 5.89 ms |      8.31 / 8.76 ms |
| Warm cache miss                |      1.12 / 1.83 ms |      1.38 / 3.41 ms |
| Warm cache hit                 |      0.12 / 0.84 ms |      0.15 / 0.81 ms |

Run locally with `yarn benchmark:ci`. [Node 22 CI report](https://github.com/Preeternal/jws-verifier/actions/runs/44624487233/attempts/1#summary-135914557381) · [Node 24 CI report](https://github.com/Preeternal/jws-verifier/actions/runs/44624487233/attempts/1#summary-135914557677)

## Contributing

Development setup, checks, benchmarks, Worker startup, and pull-request
guidance are documented in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) © Preeternal.
