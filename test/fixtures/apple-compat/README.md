# Apple compatibility smoke fixtures

These fixtures are an optional compatibility example, not part of the generic
benchmark suite. They are snapshots of synthetic test data from the [Apple App
Store Server Library for Node.js](https://github.com/apple/app-store-server-library-node)
at commit b71d9c70aa4a4a5efea258d530f50733a7916af3, branch `main`.

The source project is distributed under the MIT license and credits Apple Inc.
The fixtures are kept with this attribution so their provenance is visible.
They contain example identifiers and test certificates only; no production
tokens, user data, or private signing keys are included.

Run `yarn run test:smoke:apple` to check that the verifier accepts the signed
notification with the fixture trust anchor and policy, that the negative
snapshots contain the expected malformed or mismatched fields, and that the
BER receipts produce the expected extraction results.
