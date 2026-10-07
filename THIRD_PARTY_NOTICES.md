# Third-party notices

Alagael's own library code is GPL-3.0-or-later. Each vendored dependency retains its original license in vendor/. Bundled distributions must retain the included sources and notices.

Included source directories: vendor/noble-hashes, vendor/scure-base, vendor/scure-bip39, vendor/qrcodegen, vendor/slip39.

See vendor/PATCHES.md for provenance and local patches. CommonJS vendored JavaScript has explicit package type markers so the ESM distribution does not reinterpret it. Noble BLS documentation examples use generated disposable keys instead of fixed key literals; this is a comment-only edit. Cryptographic algorithms are unchanged. These pinned source snapshots are not automatically updated by a registry audit. Review upstream advisories before each release; a clean dependency audit is not a cryptographic audit.
