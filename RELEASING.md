# Release procedure

1. Update package.json and CHANGELOG.md together.
2. Install from the committed lockfile, build, test, and run the dependency audit.
3. Inspect the exact package contents with pnpm pack. No environment files, credentials, wallet material, development metadata, or unlicensed dependencies may ship.
4. Create a v-prefixed tag matching package.json. The pinned CI workflow validates and packages it.
5. After CI succeeds, create a GitHub release and attach the locally reviewed .tgz plus SHA256SUMS. State the beta and audit status.

GitHub release packages are downloadable archives. A GitHub release does **not** imply publication to the npm registry. Registry publication, if desired later, needs separate authorization and a verified namespace.
