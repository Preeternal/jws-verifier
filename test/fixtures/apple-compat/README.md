# Apple compatibility smoke fixtures

These fixtures are an optional compatibility example, not part of the generic
benchmark suite. They are snapshots of synthetic test data from the [Apple App
Store Server Library for Node.js](https://github.com/apple/app-store-server-library-node)
at commit b71d9c70aa4a4a5efea258d530f50733a7916af3, branch `main`.

The source project is distributed under the MIT license and credits Apple Inc.
The fixtures are kept with this attribution so their provenance is visible.
They contain example identifiers and test certificates only; no production
tokens, user data, or private signing keys are included.

The smoke test checks that the snapshots load and that the expected compatibility
preconditions are still visible. It does not claim to perform cryptographic
verification until the verifier implementation exists.
