# Contributing

```text
$ git checkout -b fix/short-description
$ pnpm install --frozen-lockfile
$ pnpm run build
$ pnpm test
```

Use Node.js 22 or newer and pnpm 10.17.1. Contract contributors also need Foundry v1.1.0 and Solidity 0.8.30. Follow the actual commands in README.md for this repository.

## Pull requests

- Explain the problem, the change, and the test evidence.
- Keep changes focused; add regression coverage for behavior changes.
- Preserve existing license notices and list new third-party code.
- Never commit credentials, live seed phrases, wallet backups, personal data, or environment files.
- Do not use real funds or real secrets in examples or tests.
- Flag format, cryptography, ABI, or compatibility changes explicitly.

Report vulnerabilities privately to support@alagael.xyz; do not open an issue containing an exploit, sensitive logs, or credentials.
