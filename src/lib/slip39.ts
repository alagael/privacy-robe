// SLIP-39: Shamir's Secret-Sharing for Mnemonic Codes.
// A direct TypeScript port of Trezor's reference implementation
// (github.com/trezor/python-shamir-mnemonic, MIT). Verified against its vectors.json.

import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { pbkdf2Async } from "@noble/hashes/pbkdf2";
import WORDLIST_TEXT from "../../vendor/slip39/wordlist.txt";

export const WORDLIST: string[] = WORDLIST_TEXT.trim().split(/\s+/);
if (WORDLIST.length !== 1024) throw new Error("SLIP-39 wordlist must have 1024 words");
const WORD_INDEX = new Map(WORDLIST.map((w, i) => [w, i]));

const RADIX_BITS = 10;
const ID_LENGTH_BITS = 15;
const EXTENDABLE_FLAG_LENGTH_BITS = 1;
const ITERATION_EXP_LENGTH_BITS = 4;
const ID_EXP_LENGTH_WORDS = 2;
const MAX_SHARE_COUNT = 16;
const CHECKSUM_LENGTH_WORDS = 3;
const DIGEST_LENGTH_BYTES = 4;
const CUSTOMIZATION_STRING_ORIG = asciiBytes("shamir");
const CUSTOMIZATION_STRING_EXTENDABLE = asciiBytes("shamir_extendable");
const GROUP_PREFIX_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 1;
const METADATA_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 2 + CHECKSUM_LENGTH_WORDS;
const MIN_STRENGTH_BITS = 128;
const MIN_MNEMONIC_LENGTH_WORDS = METADATA_LENGTH_WORDS + Math.ceil(MIN_STRENGTH_BITS / RADIX_BITS);
const BASE_ITERATION_COUNT = 10000;
const ROUND_COUNT = 4;
const SECRET_INDEX = 255;
const DIGEST_INDEX = 254;

export class MnemonicError extends Error {}

function asciiBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

// ---------- RS1024 checksum ----------
const GEN = [0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009, 0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120];

function polymod(values: ArrayLike<number>): number {
  let chk = 1;
  for (let j = 0; j < values.length; j++) {
    const b = chk >>> 20;
    chk = (((chk & 0xfffff) << 10) ^ values[j]) >>> 0;
    for (let i = 0; i < 10; i++) if ((b >>> i) & 1) chk = (chk ^ GEN[i]) >>> 0;
  }
  return chk;
}

function customizationString(extendable: boolean): Uint8Array {
  return extendable ? CUSTOMIZATION_STRING_EXTENDABLE : CUSTOMIZATION_STRING_ORIG;
}

function createChecksum(data: number[], cs: Uint8Array): number[] {
  const values = [...cs, ...data, 0, 0, 0];
  const pm = polymod(values) ^ 1;
  return [2, 1, 0].map((i) => (pm >>> (10 * i)) & 1023);
}

function verifyChecksum(data: number[], cs: Uint8Array): boolean {
  return polymod([...cs, ...data]) === 1;
}

// ---------- Feistel cipher ----------
async function roundFunction(i: number, passphrase: Uint8Array, e: number, salt: Uint8Array, r: Uint8Array): Promise<Uint8Array> {
  return pbkdf2Async(sha256, concat(new Uint8Array([i]), passphrase), concat(salt, r), {
    c: (BASE_ITERATION_COUNT << e) / ROUND_COUNT,
    dkLen: r.length,
  });
}

function getSalt(identifier: number, extendable: boolean): Uint8Array {
  if (extendable) return new Uint8Array(0);
  return concat(CUSTOMIZATION_STRING_ORIG, new Uint8Array([(identifier >> 8) & 0xff, identifier & 0xff]));
}

async function encryptMS(ms: Uint8Array, passphrase: Uint8Array, e: number, identifier: number, extendable: boolean): Promise<Uint8Array> {
  if (ms.length % 2 !== 0) throw new Error("The length of the master secret in bytes must be an even number.");
  let l: Uint8Array = ms.slice(0, ms.length / 2);
  let r: Uint8Array = ms.slice(ms.length / 2);
  const salt = getSalt(identifier, extendable);
  for (let i = 0; i < ROUND_COUNT; i++) {
    const f = await roundFunction(i, passphrase, e, salt, r);
    [l, r] = [r, xor(l, f)];
  }
  return concat(r, l);
}

async function decryptEMS(ems: Uint8Array, passphrase: Uint8Array, e: number, identifier: number, extendable: boolean): Promise<Uint8Array> {
  if (ems.length % 2 !== 0) throw new Error("The length of the encrypted master secret in bytes must be an even number.");
  let l: Uint8Array = ems.slice(0, ems.length / 2);
  let r: Uint8Array = ems.slice(ems.length / 2);
  const salt = getSalt(identifier, extendable);
  for (let i = ROUND_COUNT - 1; i >= 0; i--) {
    const f = await roundFunction(i, passphrase, e, salt, r);
    [l, r] = [r, xor(l, f)];
  }
  return concat(r, l);
}

// ---------- GF(256) Shamir ----------
const EXP = new Array<number>(255).fill(0);
const LOG = new Array<number>(256).fill(0);
{
  let poly = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = poly;
    LOG[poly] = i;
    poly = (poly << 1) ^ poly;
    if (poly & 0x100) poly ^= 0x11b;
  }
}

interface RawShare { x: number; data: Uint8Array }

function mod255(n: number): number { return ((n % 255) + 255) % 255; }

function interpolate(shares: RawShare[], x: number): Uint8Array {
  const xs = new Set(shares.map((s) => s.x));
  if (xs.size !== shares.length) throw new MnemonicError("Invalid set of shares. Share indices must be unique.");
  const lens = new Set(shares.map((s) => s.data.length));
  if (lens.size !== 1) throw new MnemonicError("Invalid set of shares. All share values must have the same length.");
  if (xs.has(x)) return shares.find((s) => s.x === x)!.data;

  let logProd = 0;
  for (const s of shares) logProd += LOG[s.x ^ x];
  const result = new Uint8Array(shares[0].data.length);
  for (const s of shares) {
    let sumOthers = 0;
    for (const o of shares) sumOthers += LOG[s.x ^ o.x];
    const logBasisEval = mod255(logProd - LOG[s.x ^ x] - sumOthers);
    for (let k = 0; k < result.length; k++) {
      const v = s.data[k];
      result[k] ^= v !== 0 ? EXP[(LOG[v] + logBasisEval) % 255] : 0;
    }
  }
  return result;
}

function createDigest(randomData: Uint8Array, sharedSecret: Uint8Array): Uint8Array {
  return hmac(sha256, randomData, sharedSecret).slice(0, DIGEST_LENGTH_BYTES);
}

function splitSecret(threshold: number, shareCount: number, sharedSecret: Uint8Array): RawShare[] {
  if (threshold < 1) throw new Error("The requested threshold must be a positive integer.");
  if (threshold > shareCount) throw new Error("The requested threshold must not exceed the number of shares.");
  if (shareCount > MAX_SHARE_COUNT) throw new Error(`The requested number of shares must not exceed ${MAX_SHARE_COUNT}.`);
  if (threshold === 1) return Array.from({ length: shareCount }, (_, i) => ({ x: i, data: sharedSecret }));

  const randomShareCount = threshold - 2;
  const shares: RawShare[] = Array.from({ length: randomShareCount }, (_, i) => ({ x: i, data: randomBytes(sharedSecret.length) }));
  const randomPart = randomBytes(sharedSecret.length - DIGEST_LENGTH_BYTES);
  const digest = createDigest(randomPart, sharedSecret);
  const baseShares = [...shares, { x: DIGEST_INDEX, data: concat(digest, randomPart) }, { x: SECRET_INDEX, data: sharedSecret }];
  for (let i = randomShareCount; i < shareCount; i++) shares.push({ x: i, data: interpolate(baseShares, i) });
  return shares;
}

function recoverSecret(threshold: number, shares: RawShare[]): Uint8Array {
  if (threshold === 1) return shares[0].data;
  const sharedSecret = interpolate(shares, SECRET_INDEX);
  const digestShare = interpolate(shares, DIGEST_INDEX);
  const digest = digestShare.slice(0, DIGEST_LENGTH_BYTES);
  const randomPart = digestShare.slice(DIGEST_LENGTH_BYTES);
  if (!bytesEqual(digest, createDigest(randomPart, sharedSecret))) throw new MnemonicError("Invalid digest of the shared secret.");
  return sharedSecret;
}

// ---------- Share encoding ----------
export interface Share {
  identifier: number;
  extendable: boolean;
  iterationExponent: number;
  groupIndex: number;
  groupThreshold: number;
  groupCount: number;
  index: number;
  memberThreshold: number;
  value: Uint8Array;
}

function intToIndices(value: bigint, length: number, radixBits: number): number[] {
  const mask = (1n << BigInt(radixBits)) - 1n;
  const out: number[] = [];
  for (let i = length - 1; i >= 0; i--) out.push(Number((value >> BigInt(i * radixBits)) & mask));
  return out;
}

function intFromIndices(indices: number[]): bigint {
  let v = 0n;
  for (const i of indices) v = v * 1024n + BigInt(i);
  return v;
}

function bytesToBigInt(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

function bigIntToBytes(v: bigint, len: number): Uint8Array | null {
  if (v >= 1n << BigInt(8 * len)) return null;
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

export function shareToWords(s: Share): string[] {
  let idExp = BigInt(s.identifier) << BigInt(ITERATION_EXP_LENGTH_BITS + EXTENDABLE_FLAG_LENGTH_BITS);
  idExp += BigInt(s.extendable ? 1 : 0) << BigInt(ITERATION_EXP_LENGTH_BITS);
  idExp += BigInt(s.iterationExponent);
  let p = BigInt(s.groupIndex);
  p = (p << 4n) + BigInt(s.groupThreshold - 1);
  p = (p << 4n) + BigInt(s.groupCount - 1);
  p = (p << 4n) + BigInt(s.index);
  p = (p << 4n) + BigInt(s.memberThreshold - 1);
  const valueWordCount = Math.ceil((s.value.length * 8) / RADIX_BITS);
  const data = [
    ...intToIndices(idExp, ID_EXP_LENGTH_WORDS, RADIX_BITS),
    ...intToIndices(p, 2, RADIX_BITS),
    ...intToIndices(bytesToBigInt(s.value), valueWordCount, RADIX_BITS),
  ];
  const checksum = createChecksum(data, customizationString(s.extendable));
  return [...data, ...checksum].map((i) => WORDLIST[i]);
}

export function normalizeMnemonic(m: string): string[] {
  return m.trim().toLowerCase().split(/\s+/).filter(Boolean);
}

export function shareFromMnemonic(mnemonic: string): Share {
  const words = normalizeMnemonic(mnemonic);
  const data = words.map((w) => {
    const i = WORD_INDEX.get(w);
    if (i === undefined) throw new MnemonicError(`Invalid mnemonic word "${w}".`);
    return i;
  });
  if (data.length < MIN_MNEMONIC_LENGTH_WORDS)
    throw new MnemonicError(`Invalid mnemonic length. The length of each mnemonic must be at least ${MIN_MNEMONIC_LENGTH_WORDS} words.`);
  const paddingLen = (RADIX_BITS * (data.length - METADATA_LENGTH_WORDS)) % 16;
  if (paddingLen > 8) throw new MnemonicError("Invalid mnemonic length.");

  const idExpInt = Number(intFromIndices(data.slice(0, ID_EXP_LENGTH_WORDS)));
  const identifier = idExpInt >> (EXTENDABLE_FLAG_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS);
  const extendable = ((idExpInt >> ITERATION_EXP_LENGTH_BITS) & 1) === 1;
  const iterationExponent = idExpInt & ((1 << ITERATION_EXP_LENGTH_BITS) - 1);
  const prefix = words.slice(0, ID_EXP_LENGTH_WORDS + 2).join(" ");

  if (!verifyChecksum(data, customizationString(extendable))) throw new MnemonicError(`Invalid mnemonic checksum for "${prefix} ...".`);

  const params = intToIndices(intFromIndices(data.slice(ID_EXP_LENGTH_WORDS, ID_EXP_LENGTH_WORDS + 2)), 5, 4);
  const [groupIndex, groupThreshold, groupCount, index, memberThreshold] = params;
  if (groupCount < groupThreshold)
    throw new MnemonicError(`Invalid mnemonic "${prefix} ...". Group threshold cannot be greater than group count.`);

  const valueData = data.slice(ID_EXP_LENGTH_WORDS + 2, data.length - CHECKSUM_LENGTH_WORDS);
  const valueByteCount = Math.ceil((RADIX_BITS * valueData.length - paddingLen) / 8);
  const value = bigIntToBytes(intFromIndices(valueData), valueByteCount);
  if (!value) throw new MnemonicError(`Invalid mnemonic padding for "${prefix} ...".`);

  return {
    identifier, extendable, iterationExponent, groupIndex,
    groupThreshold: groupThreshold + 1, groupCount: groupCount + 1,
    index, memberThreshold: memberThreshold + 1, value,
  };
}

// ---------- Public API ----------
function checkPassphrase(passphrase: string): Uint8Array {
  for (let i = 0; i < passphrase.length; i++) {
    const c = passphrase.charCodeAt(i);
    if (c < 32 || c > 126) throw new Error("The passphrase must contain only printable ASCII characters (code points 32-126).");
  }
  return asciiBytes(passphrase);
}

export interface GenerateOptions {
  groupThreshold?: number;
  groups: Array<[memberThreshold: number, memberCount: number]>;
  passphrase?: string;
  extendable?: boolean;
  iterationExponent?: number;
}

/** Split a master secret (16–32 bytes, even length) into SLIP-39 mnemonics, grouped. */
export async function generateMnemonics(masterSecret: Uint8Array, opts: GenerateOptions): Promise<string[][]> {
  const groupThreshold = opts.groupThreshold ?? 1;
  const extendable = opts.extendable ?? true;
  const e = opts.iterationExponent ?? 1;
  const pass = checkPassphrase(opts.passphrase ?? "");
  if (masterSecret.length * 8 < MIN_STRENGTH_BITS) throw new Error("The master secret must be at least 16 bytes.");
  if (groupThreshold > opts.groups.length) throw new Error("The requested group threshold must not exceed the number of groups.");
  if (opts.groups.some(([t, c]) => t === 1 && c > 1)) throw new Error("Creating multiple member shares with member threshold 1 is not allowed. Use 1-of-1 member sharing instead.");

  const idBytes = randomBytes(2);
  const identifier = ((idBytes[0] << 8) | idBytes[1]) & ((1 << ID_LENGTH_BITS) - 1);
  const ems = await encryptMS(masterSecret, pass, e, identifier, extendable);
  const groupShares = splitSecret(groupThreshold, opts.groups.length, ems);
  return opts.groups.map(([memberThreshold, memberCount], gi) =>
    splitSecret(memberThreshold, memberCount, groupShares[gi].data).map((raw) =>
      shareToWords({
        identifier, extendable, iterationExponent: e,
        groupIndex: groupShares[gi].x, groupThreshold, groupCount: opts.groups.length,
        index: raw.x, memberThreshold, value: raw.data,
      }).join(" "),
    ),
  );
}

/**
 * Combine mnemonics into the master secret. Strict, as the reference: each group must
 * contain exactly its member threshold, and exactly groupThreshold groups. Set `lenient`
 * to automatically use the first threshold shares when extra shares are supplied.
 */
export async function combineMnemonics(mnemonics: string[], passphrase = "", lenient = false): Promise<Uint8Array> {
  if (!mnemonics.length) throw new MnemonicError("The list of mnemonics is empty.");
  const shares = mnemonics.map(shareFromMnemonic);

  const commonKey = (s: Share) => [s.identifier, s.extendable, s.iterationExponent, s.groupThreshold, s.groupCount].join(",");
  const groupKey = (s: Share) => [commonKey(s), s.groupIndex, s.memberThreshold].join(",");
  if (new Set(shares.map(commonKey)).size !== 1)
    throw new MnemonicError(`Invalid set of mnemonics. All mnemonics must begin with the same ${ID_EXP_LENGTH_WORDS} words, must have the same group threshold and the same group count.`);

  const groups = new Map<number, Share[]>();
  for (const s of shares) {
    const g = groups.get(s.groupIndex) ?? [];
    if (g.length && groupKey(g[0]) !== groupKey(s)) throw new MnemonicError("Invalid set of mnemonics. The group parameters don't match.");
    if (!g.some((o) => o.index === s.index && bytesEqual(o.value, s.value))) g.push(s);
    groups.set(s.groupIndex, g);
  }

  const p = shares[0];
  let groupEntries = [...groups.entries()];
  if (lenient) {
    groupEntries = groupEntries
      .filter(([, g]) => g.length >= g[0].memberThreshold)
      .map(([gi, g]) => [gi, g.slice(0, g[0].memberThreshold)] as [number, Share[]])
      .slice(0, p.groupThreshold);
  }
  if (groupEntries.length < p.groupThreshold)
    throw new MnemonicError(`Insufficient number of mnemonic groups. The required number of groups is ${p.groupThreshold}.`);
  if (groupEntries.length !== p.groupThreshold)
    throw new MnemonicError(`Wrong number of mnemonic groups. Expected ${p.groupThreshold} groups, but ${groupEntries.length} were provided.`);
  for (const [, g] of groupEntries) {
    if (g.length !== g[0].memberThreshold) {
      const pre = shareToWords(g[0]).slice(0, GROUP_PREFIX_LENGTH_WORDS).join(" ");
      throw new MnemonicError(`Wrong number of mnemonics. Expected ${g[0].memberThreshold} mnemonics starting with "${pre} ...", but ${g.length} were provided.`);
    }
  }

  const groupShares: RawShare[] = groupEntries.map(([gi, g]) => ({
    x: gi,
    data: recoverSecret(g[0].memberThreshold, g.map((s) => ({ x: s.index, data: s.value }))),
  }));
  const ems = recoverSecret(p.groupThreshold, groupShares);
  return decryptEMS(ems, checkPassphrase(passphrase), p.iterationExponent, p.identifier, p.extendable);
}

/** Describe a share without combining, for UI. */
export function describeShare(m: string): { ok: true; share: Share } | { ok: false; error: string } {
  try { return { ok: true, share: shareFromMnemonic(m) }; }
  catch (e) { return { ok: false, error: (e as Error).message }; }
}
