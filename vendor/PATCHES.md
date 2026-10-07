# Vendored sources

Libraries are copied from their upstream GitHub repositories because this project builds
without npm. Licenses are kept next to each copy.

| Folder | Upstream | Version |
| --- | --- | --- |
| noble-curves | github.com/paulmillr/noble-curves | 1.9.7 |
| noble-hashes | github.com/paulmillr/noble-hashes | 1.8.0 |
| scure-bip39 | github.com/paulmillr/scure-bip39 | 1.6.0 |
| scure-base | github.com/paulmillr/scure-base | 1.2.6 |
| tlock-js | github.com/drand/tlock-js | main |
| stablelib/* | github.com/StableLib/stablelib | main |
| buffer, base64-js, ieee754 | github.com/feross/buffer and friends | main |
| qrcodegen | github.com/nayuki/QR-Code-generator (TypeScript) | main |
| slip39 | github.com/trezor/python-shamir-mnemonic (wordlist + test vectors) | main |

## Patches

1. `tlock-js/src/age/utils-crypto.ts`: `random()` always uses `globalThis.crypto.getRandomValues`
   (the original fell back to Node's `require("crypto")`, which cannot be bundled).
2. `qrcodegen/qrcodegen.ts`: appended `export default qrcodegen;` so it can be imported as a module.
3. `drand-client` is not vendored. `src/lib/drand.ts` implements the small part tlock-js uses,
   with drand quicknet chain info pinned.
