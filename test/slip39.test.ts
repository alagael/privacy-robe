// Runs Trezor's official SLIP-39 test vectors (vendor/slip39/vectors.json).
// Each vector: [description, mnemonics, masterSecretHex ("" = must fail), xprv]. Passphrase "TREZOR".
import vectors from "../vendor/slip39/vectors.json";
import { combineMnemonics, generateMnemonics, shareFromMnemonic, shareToWords } from "../src/lib/slip39";

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
let pass = 0, fail = 0;

for (const [desc, mnemonics, secretHex] of vectors as [string, string[], string, string][]) {
  let got: string | null = null;
  let err = "";
  try { got = hex(await combineMnemonics(mnemonics, "TREZOR")); }
  catch (e) { err = (e as Error).message; }
  const ok = secretHex ? got === secretHex : got === null;
  if (ok) pass++; else { fail++; console.log(`FAIL ${desc}\n  expected ${secretHex || "error"}, got ${got ?? "error: " + err}`); }
}
console.log(`vectors: ${pass} passed, ${fail} failed of ${(vectors as unknown[]).length}`);

// Round trip: re-encoding a decoded share gives the same words.
for (const [, mnemonics, secretHex] of vectors as [string, string[], string, string][]) {
  if (!secretHex) continue;
  for (const m of mnemonics) {
    const again = shareToWords(shareFromMnemonic(m)).join(" ");
    if (again !== m.trim()) { fail++; console.log("FAIL re-encode", m); }
  }
}

// Generate + combine with random subsets, several thresholds and secret sizes.
for (const [t, n] of [[2, 3], [3, 5], [4, 6], [1, 1]] as const) {
  for (const len of [16, 32]) {
    const secret = crypto.getRandomValues(new Uint8Array(len));
    const [shares] = await generateMnemonics(secret, { groups: [[t, n]], passphrase: "pw", iterationExponent: 0 });
    const subset = [...shares].sort(() => Math.random() - 0.5).slice(0, t);
    const back = await combineMnemonics(subset, "pw");
    if (hex(back) !== hex(secret)) { fail++; console.log(`FAIL roundtrip ${t}-of-${n} ${len}B`); } else pass++;
    if (t > 1) {
      let threw = false;
      try { await combineMnemonics(subset.slice(0, t - 1), "pw"); } catch { threw = true; }
      if (!threw) { fail++; console.log(`FAIL ${t - 1} shares should not recover`); } else pass++;
    }
  }
}
// Lenient mode accepts extra shares.
{
  const secret = crypto.getRandomValues(new Uint8Array(16));
  const [shares] = await generateMnemonics(secret, { groups: [[3, 5]], iterationExponent: 0 });
  const back = await combineMnemonics(shares, "", true);
  if (hex(back) !== hex(secret)) { fail++; console.log("FAIL lenient"); } else pass++;
}

console.log(`total: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
