// Privacy Robe: BIP-39 seed <-> SLIP-39 shares, plus QR rendering for share cards.
import { mnemonicToEntropy, entropyToMnemonic, validateMnemonic, generateMnemonic } from "@scure/bip39";
import { wordlist as english } from "@scure/bip39/wordlists/english";
import qrcodegen from "../../vendor/qrcodegen/qrcodegen";
import { combineMnemonics, generateMnemonics, describeShare } from "./slip39";

export function normalizeBip39(m: string): string {
  return m.trim().toLowerCase().split(/\s+/).filter(Boolean).join(" ");
}

export function checkBip39(m: string): { ok: true; words: number } | { ok: false; error: string } {
  const n = normalizeBip39(m);
  const count = n ? n.split(" ").length : 0;
  if (![12, 15, 18, 21, 24].includes(count)) return { ok: false, error: `A BIP-39 seed has 12, 15, 18, 21 or 24 words. This has ${count}.` };
  const bad = n.split(" ").find((w) => !english.includes(w));
  if (bad) return { ok: false, error: `"${bad}" is not a BIP-39 English word.` };
  if (!validateMnemonic(n, english)) return { ok: false, error: "The checksum does not match. Check the word order and spelling." };
  return { ok: true, words: count };
}

/** Splits an existing BIP-39 seed: its entropy becomes the SLIP-39 master secret. */
export async function splitSeed(seed: string, threshold: number, count: number, passphrase: string): Promise<string[]> {
  const c = checkBip39(seed);
  if (!c.ok) throw new Error(c.error);
  const entropy = mnemonicToEntropy(normalizeBip39(seed), english);
  try {
    const [shares] = await generateMnemonics(entropy, { groups: [[threshold, count]], passphrase, extendable: true, iterationExponent: 1 });
    return shares;
  } finally {
    entropy.fill(0);
  }
}

/** Recovers the original BIP-39 seed from enough shares. */
export async function recoverSeed(shares: string[], passphrase: string): Promise<string> {
  const clean = shares.map((s) => s.trim()).filter(Boolean);
  if (!clean.length) throw new Error("Paste at least one share.");
  const entropy = await combineMnemonics(clean, passphrase, true);
  try {
    if (![16, 20, 24, 28, 32].includes(entropy.length)) throw new Error("These shares do not hold a BIP-39 seed.");
    return entropyToMnemonic(entropy, english);
  } finally {
    entropy.fill(0);
  }
}

export function sampleSeed(): string {
  return generateMnemonic(english, 128);
}

/** SVG markup for a QR code of `text` (byte mode, medium error correction). */
export function qrSvg(text: string, dark = "#0F0F0F", light = "#FFFFFF"): string {
  const qr = qrcodegen.QrCode.encodeText(text, qrcodegen.QrCode.Ecc.MEDIUM);
  const border = 2;
  const size = qr.size + border * 2;
  let path = "";
  for (let y = 0; y < qr.size; y++)
    for (let x = 0; x < qr.size; x++)
      if (qr.getModule(x, y)) path += `M${x + border},${y + border}h1v1h-1z`;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges" role="img" aria-label="QR code of the share words"><rect width="100%" height="100%" fill="${light}"/><path d="${path}" fill="${dark}"/></svg>`;
}

/** Share lengths in words: 20 (128-bit), 23, 27, 30 and 33 (256-bit) for 12–24 word seeds. */
export const SHARE_LENGTHS = [20, 23, 27, 30, 33];
/** Strips labels such as "Share 1 of 3 (any 2 recover)", "Keeper 2:", "1." or "2)" from the start of a line. */
function stripShareLabel(line: string): string {
  return line
    .replace(/^(?:share|keeper)(?:\s+share)?\s*#?\d+(?:\s*of\s*\d+)?(?:\s*\([^)]*\))?\s*[:.)\-]?\s*/i, "")
    .replace(/^#?\d+\s*[.):\-]\s*/, "");
}
/** Accepts shares one per line (with or without labels), the app's own downloaded file, or shares wrapped across lines. */
export function parseShares(text: string): string[] {
  const lines = text.split(/\r?\n/).map((l) => stripShareLabel(l.trim().toLowerCase()).trim()).filter((l) => /[a-z]/.test(l));
  if (lines.length && lines.every((l) => describeShare(l).ok)) return lines;
  const words = lines.join(" ").split(/\s+/).filter((w) => /^[a-z]+$/.test(w));
  for (const len of SHARE_LENGTHS) {
    if (words.length && words.length % len === 0) {
      const chunks = Array.from({ length: words.length / len }, (_, i) => words.slice(i * len, i * len + len).join(" "));
      if (chunks.every((c) => describeShare(c).ok)) return chunks;
    }
  }
  return lines;
}

