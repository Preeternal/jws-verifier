# `@preeternal/jws-verifier`

[![npm version](https://img.shields.io/npm/v/@preeternal/jws-verifier.svg)](https://www.npmjs.com/package/@preeternal/jws-verifier)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

TypeScript library for secure JWS verification, X.509 certificate chain validation, and OCSP revocation checking

## Install

```bash
yarn add @preeternal/jws-verifier
```

## Usage

```ts
import { createVerifier } from "@preeternal/jws-verifier";

const verifier = createVerifier({
  trustedRoots: [rootDer], // DER certificate bytes supplied by the host
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

Configure claim paths for the payload schema you expect. Offline verification
uses a signed Unix millisecond timestamp at `signedTimePath` or an explicit
`effectiveTime` passed as the second argument to `verify()`. Optional
`requiredExtensions` lists required certificate extension OIDs by role.
Online verification and OCSP are pending.

## Development

Lint, format, type-check, dependency and security policy checks, and tests are
wired into a single command:

```bash
yarn run check         # lint + dep/security checks + typecheck + coverage
yarn run test          # run tests
yarn run setup:editor  # generate local Yarn PnP SDKs for VS Code
yarn run build         # build to dist/
yarn run release:check # package validation + publish dry run
```

`yarn run security:lint` prefers `semgrep` on PATH and otherwise runs the pinned `uvx semgrep@1.165.0` scan.

## License

[MIT](LICENSE) © Preeternal.
