import { splitSeed, recoverSeed, checkBip39, sampleSeed, qrSvg, parseShares } from "../src/lib/robe";
import { generateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";

let pass = 0, fail = 0;
const ok = (name: string, c: boolean) => { if (c) pass++; else { fail++; console.log("FAIL", name); } };

// BIP-39 test vector (all-zero entropy, 12 and 24 words).
const s12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const s24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
ok("valid 12", checkBip39(s12).ok);
ok("valid 24", checkBip39(s24).ok);
ok("bad checksum", !checkBip39(s12.replace("about", "abandon")).ok);
ok("bad word", !checkBip39(s12.replace("about", "aboutt")).ok);

for (const seed of [s12, s24, sampleSeed()]) {
  const shares = await splitSeed(seed, 3, 5, "");
  ok("5 shares", shares.length === 5);
  ok("share length", shares[0].split(" ").length === (seed.split(" ").length === 12 ? 20 : 33));
  ok("recover 3", (await recoverSeed([shares[1], shares[3], shares[4]], "")) === seed);
  let threw = false;
  try { await recoverSeed(shares.slice(0, 2), ""); } catch { threw = true; }
  ok("2 not enough", threw);
}
const withPass = await splitSeed(s12, 2, 3, "correct horse");
ok("passphrase recovers", (await recoverSeed(withPass.slice(0, 2), "correct horse")) === s12);
ok("wrong passphrase gives a different seed", (await recoverSeed(withPass.slice(0, 2), "wrong")) !== s12);
ok("qr svg", qrSvg("hello").startsWith("<svg"));

// parseShares: every input format a real user will paste.
{
  const sh = await splitSeed(s12, 2, 3, "");
  const file = sh.map((x, i) => `Share ${i + 1} of 3 (any 2 recover)\n${x}\n`).join("\n"); // the app's own download
  ok("parse downloaded file", JSON.stringify(parseShares(file)) === JSON.stringify(sh));
  ok("recover from downloaded file", (await recoverSeed(parseShares(file).slice(1), "")) === s12);
  ok("parse 'Share 1:' labels", JSON.stringify(parseShares(`Share 1: ${sh[0]}\nShare 2: ${sh[1]}`)) === JSON.stringify(sh.slice(0, 2)));
  ok("parse 'Keeper 2 -' labels", JSON.stringify(parseShares(`Keeper 1 - ${sh[0]}\nKeeper 2 - ${sh[1]}`)) === JSON.stringify(sh.slice(0, 2)));
  ok("parse numbered list", JSON.stringify(parseShares(`1. ${sh[0]}\n2) ${sh[2]}`)) === JSON.stringify([sh[0], sh[2]]));
  ok("parse uppercase, CRLF", JSON.stringify(parseShares(`${sh[0].toUpperCase()}\r\n${sh[1]}`)) === JSON.stringify(sh.slice(0, 2)));
}
for (const bits of [128, 160, 192, 224, 256]) {
  const seed = generateMnemonic(wordlist, bits);
  const sh = await splitSeed(seed, 2, 3, "");
  const wrapped = sh.slice(0, 2).map((x) => { const w = x.split(" "); return w.slice(0, 7).join(" ") + "\n" + w.slice(7).join(" "); }).join("\n");
  const parsed = parseShares(wrapped);
  ok(`wrapped ${seed.split(" ").length}-word seed shares parse`, JSON.stringify(parsed) === JSON.stringify(sh.slice(0, 2)));
  ok(`wrapped ${seed.split(" ").length}-word seed recovers`, (await recoverSeed(parsed, "")) === seed);
}
console.log(`robe: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
