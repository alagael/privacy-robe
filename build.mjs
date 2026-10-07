// This template becomes build.mjs in the two standalone cryptographic repos.
import { build } from "esbuild";
import { execFileSync } from "node:child_process";
import { mkdirSync, readdirSync, copyFileSync } from "node:fs";
import path from "node:path";
const root = path.dirname(new URL(import.meta.url).pathname);
const v = p => path.join(root, "vendor", p);
const alias = {
  "@noble/curves": v("noble-curves/src"),
  "@noble/hashes": v("noble-hashes/src"),
  "@scure/bip39": v("scure-bip39/src"),
  "@scure/base": v("scure-base/index.ts"),
  "@stablelib/chacha20poly1305": v("stablelib/chacha20poly1305/chacha20poly1305.ts"),
  "@stablelib/chacha": v("stablelib/chacha/chacha.ts"),
  "@stablelib/poly1305": v("stablelib/poly1305/poly1305.ts"),
  "@stablelib/constant-time": v("stablelib/constant-time/constant-time.ts"),
  "@stablelib/wipe": v("stablelib/wipe/wipe.ts"),
  "@stablelib/binary": v("stablelib/binary/binary.ts"),
  "@stablelib/int": v("stablelib/int/int.ts"),
  "@stablelib/aead": v("stablelib/aead/aead.ts"),
  buffer: v("buffer/index.js"), "base64-js": v("base64-js/index.js"), ieee754: v("ieee754/index.js"),
  "drand-client": path.join(root, "src/lib/drand.ts"),
};
if (process.argv[2] === "test") {
  mkdirSync(path.join(root, ".test-build"), { recursive: true });
  for (const file of readdirSync(path.join(root, "test")).filter(f => f.endsWith(".test.ts"))) {
    const outfile = path.join(root, ".test-build", file.replace(/\.ts$/, ".mjs"));
    await build({ entryPoints: [path.join(root, "test", file)], bundle: true, format: "esm", platform: "node", alias, outfile, target: "node22" });
    execFileSync(process.execPath, [outfile], { stdio: "inherit" });
  }
} else {
  mkdirSync(path.join(root, "dist"), { recursive: true });
  await build({ entryPoints: [path.join(root, "src/index.ts")], bundle: true, format: "esm", platform: "neutral", alias,
    outfile: path.join(root, "dist/index.js"), target: "es2022", minify: false, legalComments: "eof" });
  copyFileSync(path.join(root, "src/index.d.ts"), path.join(root, "dist/index.d.ts"));
}
