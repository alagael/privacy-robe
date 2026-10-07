// vendor/noble-hashes/src/crypto.ts
var crypto2 = typeof globalThis === "object" && "crypto" in globalThis ? globalThis.crypto : void 0;

// vendor/noble-hashes/src/utils.ts
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function anumber(n) {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("positive integer expected, got " + n);
}
function abytes(b, ...lengths) {
  if (!isBytes(b)) throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
}
function ahash(h) {
  if (typeof h !== "function" || typeof h.create !== "function")
    throw new Error("Hash should be wrapped by utils.createHasher");
  anumber(h.outputLen);
  anumber(h.blockLen);
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed) throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished) throw new Error("Hash#digest() has already been called");
}
function aoutput(out, instance) {
  abytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error("digestInto() expects output buffer of length at least " + min);
  }
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
var nextTick = async () => {
};
async function asyncLoop(iters, tick, cb) {
  let ts = Date.now();
  for (let i = 0; i < iters; i++) {
    cb(i);
    const diff = Date.now() - ts;
    if (diff >= 0 && diff < tick) continue;
    await nextTick();
    ts += diff;
  }
}
function utf8ToBytes(str) {
  if (typeof str !== "string") throw new Error("string expected");
  return new Uint8Array(new TextEncoder().encode(str));
}
function toBytes(data) {
  if (typeof data === "string") data = utf8ToBytes(data);
  abytes(data);
  return data;
}
function kdfInputToBytes(data) {
  if (typeof data === "string") data = utf8ToBytes(data);
  abytes(data);
  return data;
}
function checkOpts(defaults, opts) {
  if (opts !== void 0 && {}.toString.call(opts) !== "[object Object]")
    throw new Error("options should be object or undefined");
  const merged = Object.assign(defaults, opts);
  return merged;
}
var Hash = class {
};
function createHasher(hashCons) {
  const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}
function randomBytes(bytesLength = 32) {
  if (crypto2 && typeof crypto2.getRandomValues === "function") {
    return crypto2.getRandomValues(new Uint8Array(bytesLength));
  }
  if (crypto2 && typeof crypto2.randomBytes === "function") {
    return Uint8Array.from(crypto2.randomBytes(bytesLength));
  }
  throw new Error("crypto.getRandomValues must be defined");
}

// vendor/noble-hashes/src/hmac.ts
var HMAC = class extends Hash {
  oHash;
  iHash;
  blockLen;
  outputLen;
  finished = false;
  destroyed = false;
  constructor(hash, _key) {
    super();
    ahash(hash);
    const key = toBytes(_key);
    this.iHash = hash.create();
    if (typeof this.iHash.update !== "function")
      throw new Error("Expected instance of class which extends utils.Hash");
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad = new Uint8Array(blockLen);
    pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
    for (let i = 0; i < pad.length; i++) pad[i] ^= 54;
    this.iHash.update(pad);
    this.oHash = hash.create();
    for (let i = 0; i < pad.length; i++) pad[i] ^= 54 ^ 92;
    this.oHash.update(pad);
    clean(pad);
  }
  update(buf) {
    aexists(this);
    this.iHash.update(buf);
    return this;
  }
  digestInto(out) {
    aexists(this);
    abytes(out, this.outputLen);
    this.finished = true;
    this.iHash.digestInto(out);
    this.oHash.update(out);
    this.oHash.digestInto(out);
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to) {
    to ||= Object.create(Object.getPrototypeOf(this), {});
    const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
    to = to;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
  destroy() {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
};
var hmac = (hash, key, message) => new HMAC(hash, key).update(message).digest();
hmac.create = (hash, key) => new HMAC(hash, key);

// vendor/noble-hashes/src/pbkdf2.ts
function pbkdf2Init(hash, _password, _salt, _opts) {
  ahash(hash);
  const opts = checkOpts({ dkLen: 32, asyncTick: 10 }, _opts);
  const { c, dkLen, asyncTick } = opts;
  anumber(c);
  anumber(dkLen);
  anumber(asyncTick);
  if (c < 1) throw new Error("iterations (c) should be >= 1");
  const password = kdfInputToBytes(_password);
  const salt = kdfInputToBytes(_salt);
  const DK = new Uint8Array(dkLen);
  const PRF = hmac.create(hash, password);
  const PRFSalt = PRF._cloneInto().update(salt);
  return { c, dkLen, asyncTick, DK, PRF, PRFSalt };
}
function pbkdf2Output(PRF, PRFSalt, DK, prfW, u) {
  PRF.destroy();
  PRFSalt.destroy();
  if (prfW) prfW.destroy();
  clean(u);
  return DK;
}
async function pbkdf2Async(hash, password, salt, opts) {
  const { c, dkLen, asyncTick, DK, PRF, PRFSalt } = pbkdf2Init(hash, password, salt, opts);
  let prfW;
  const arr = new Uint8Array(4);
  const view = createView(arr);
  const u = new Uint8Array(PRF.outputLen);
  for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += PRF.outputLen) {
    const Ti = DK.subarray(pos, pos + PRF.outputLen);
    view.setInt32(0, ti, false);
    (prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u);
    Ti.set(u.subarray(0, Ti.length));
    await asyncLoop(c - 1, asyncTick, () => {
      PRF._cloneInto(prfW).update(u).digestInto(u);
      for (let i = 0; i < Ti.length; i++) Ti[i] ^= u[i];
    });
  }
  return pbkdf2Output(PRF, PRFSalt, DK, prfW, u);
}

// vendor/noble-hashes/src/_md.ts
function setBigUint64(view, byteOffset, value, isLE) {
  if (typeof view.setBigUint64 === "function") return view.setBigUint64(byteOffset, value, isLE);
  const _32n = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE ? 4 : 0;
  const l = isLE ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE);
  view.setUint32(byteOffset + l, wl, isLE);
}
function Chi(a, b, c) {
  return a & b ^ ~a & c;
}
function Maj(a, b, c) {
  return a & b ^ a & c ^ b & c;
}
var HashMD = class extends Hash {
  blockLen;
  outputLen;
  padOffset;
  isLE;
  // For partial updates less than block size
  buffer;
  view;
  finished = false;
  length = 0;
  pos = 0;
  destroyed = false;
  constructor(blockLen, outputLen, padOffset, isLE) {
    super();
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    aexists(this);
    data = toBytes(data);
    abytes(data);
    const { view, buffer, blockLen } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen) this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    clean(this.buffer.subarray(pos));
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    for (let i = pos; i < blockLen; i++) buffer[i] = 0;
    setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
    this.process(view, 0);
    const oview = createView(out);
    const len = this.outputLen;
    if (len % 4) throw new Error("_sha2: outputLen should be aligned to 32bit");
    const outLen = len / 4;
    const state = this.get();
    if (outLen > state.length) throw new Error("_sha2: outputLen bigger than state");
    for (let i = 0; i < outLen; i++) oview.setUint32(4 * i, state[i], isLE);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to) {
    to ||= new this.constructor();
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    if (length % blockLen) to.buffer.set(buffer);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
};
var SHA256_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);

// vendor/noble-hashes/src/_u64.ts
var U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);

// vendor/noble-hashes/src/sha2.ts
var SHA256_K = /* @__PURE__ */ Uint32Array.from([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
var SHA256 = class extends HashMD {
  // We cannot use array here since array allows indexing by variable
  // which means optimizer/compiler cannot use registers.
  A = SHA256_IV[0] | 0;
  B = SHA256_IV[1] | 0;
  C = SHA256_IV[2] | 0;
  D = SHA256_IV[3] | 0;
  E = SHA256_IV[4] | 0;
  F = SHA256_IV[5] | 0;
  G = SHA256_IV[6] | 0;
  H = SHA256_IV[7] | 0;
  constructor(outputLen = 32) {
    super(64, outputLen, 8, false);
  }
  get() {
    const { A, B, C, D, E, F, G, H } = this;
    return [A, B, C, D, E, F, G, H];
  }
  // prettier-ignore
  set(A, B, C, D, E, F, G, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4) SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16; i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W2 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B, C, D, E, F, G, H } = this;
    for (let i = 0; i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G;
      G = F;
      F = E;
      E = D + T1 | 0;
      D = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D = D + this.D | 0;
    E = E + this.E | 0;
    F = F + this.F | 0;
    G = G + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D, E, F, G, H);
  }
  roundClean() {
    clean(SHA256_W);
  }
  destroy() {
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    clean(this.buffer);
  }
};
var sha256 = /* @__PURE__ */ createHasher(() => new SHA256());

// vendor/scure-base/index.ts
function isBytes2(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function isArrayOf(isString, arr) {
  if (!Array.isArray(arr)) return false;
  if (arr.length === 0) return true;
  if (isString) {
    return arr.every((item) => typeof item === "string");
  } else {
    return arr.every((item) => Number.isSafeInteger(item));
  }
}
function afn(input) {
  if (typeof input !== "function") throw new Error("function expected");
  return true;
}
function astr(label, input) {
  if (typeof input !== "string") throw new Error(`${label}: string expected`);
  return true;
}
function anumber2(n) {
  if (!Number.isSafeInteger(n)) throw new Error(`invalid integer: ${n}`);
}
function aArr(input) {
  if (!Array.isArray(input)) throw new Error("array expected");
}
function astrArr(label, input) {
  if (!isArrayOf(true, input)) throw new Error(`${label}: array of strings expected`);
}
function anumArr(label, input) {
  if (!isArrayOf(false, input)) throw new Error(`${label}: array of numbers expected`);
}
// @__NO_SIDE_EFFECTS__
function chain(...args) {
  const id = (a) => a;
  const wrap = (a, b) => (c) => a(b(c));
  const encode = args.map((x) => x.encode).reduceRight(wrap, id);
  const decode = args.map((x) => x.decode).reduce(wrap, id);
  return { encode, decode };
}
// @__NO_SIDE_EFFECTS__
function alphabet(letters) {
  const lettersA = typeof letters === "string" ? letters.split("") : letters;
  const len = lettersA.length;
  astrArr("alphabet", lettersA);
  const indexes = new Map(lettersA.map((l, i) => [l, i]));
  return {
    encode: (digits) => {
      aArr(digits);
      return digits.map((i) => {
        if (!Number.isSafeInteger(i) || i < 0 || i >= len)
          throw new Error(
            `alphabet.encode: digit index outside alphabet "${i}". Allowed: ${letters}`
          );
        return lettersA[i];
      });
    },
    decode: (input) => {
      aArr(input);
      return input.map((letter) => {
        astr("alphabet.decode", letter);
        const i = indexes.get(letter);
        if (i === void 0) throw new Error(`Unknown letter: "${letter}". Allowed: ${letters}`);
        return i;
      });
    }
  };
}
// @__NO_SIDE_EFFECTS__
function join(separator = "") {
  astr("join", separator);
  return {
    encode: (from) => {
      astrArr("join.decode", from);
      return from.join(separator);
    },
    decode: (to) => {
      astr("join.decode", to);
      return to.split(separator);
    }
  };
}
// @__NO_SIDE_EFFECTS__
function padding(bits, chr = "=") {
  anumber2(bits);
  astr("padding", chr);
  return {
    encode(data) {
      astrArr("padding.encode", data);
      while (data.length * bits % 8) data.push(chr);
      return data;
    },
    decode(input) {
      astrArr("padding.decode", input);
      let end = input.length;
      if (end * bits % 8)
        throw new Error("padding: invalid, string should have whole number of bytes");
      for (; end > 0 && input[end - 1] === chr; end--) {
        const last = end - 1;
        const byte = last * bits;
        if (byte % 8 === 0) throw new Error("padding: invalid, string has too much padding");
      }
      return input.slice(0, end);
    }
  };
}
function convertRadix(data, from, to) {
  if (from < 2) throw new Error(`convertRadix: invalid from=${from}, base cannot be less than 2`);
  if (to < 2) throw new Error(`convertRadix: invalid to=${to}, base cannot be less than 2`);
  aArr(data);
  if (!data.length) return [];
  let pos = 0;
  const res = [];
  const digits = Array.from(data, (d) => {
    anumber2(d);
    if (d < 0 || d >= from) throw new Error(`invalid integer: ${d}`);
    return d;
  });
  const dlen = digits.length;
  while (true) {
    let carry = 0;
    let done = true;
    for (let i = pos; i < dlen; i++) {
      const digit = digits[i];
      const fromCarry = from * carry;
      const digitBase = fromCarry + digit;
      if (!Number.isSafeInteger(digitBase) || fromCarry / from !== carry || digitBase - digit !== fromCarry) {
        throw new Error("convertRadix: carry overflow");
      }
      const div = digitBase / to;
      carry = digitBase % to;
      const rounded = Math.floor(div);
      digits[i] = rounded;
      if (!Number.isSafeInteger(rounded) || rounded * to + carry !== digitBase)
        throw new Error("convertRadix: carry overflow");
      if (!done) continue;
      else if (!rounded) pos = i;
      else done = false;
    }
    res.push(carry);
    if (done) break;
  }
  for (let i = 0; i < data.length - 1 && data[i] === 0; i++) res.push(0);
  return res.reverse();
}
var gcd = (a, b) => b === 0 ? a : gcd(b, a % b);
var radix2carry = /* @__NO_SIDE_EFFECTS__ */ (from, to) => from + (to - gcd(from, to));
var powers = /* @__PURE__ */ (() => {
  let res = [];
  for (let i = 0; i < 40; i++) res.push(2 ** i);
  return res;
})();
function convertRadix2(data, from, to, padding2) {
  aArr(data);
  if (from <= 0 || from > 32) throw new Error(`convertRadix2: wrong from=${from}`);
  if (to <= 0 || to > 32) throw new Error(`convertRadix2: wrong to=${to}`);
  if (/* @__PURE__ */ radix2carry(from, to) > 32) {
    throw new Error(
      `convertRadix2: carry overflow from=${from} to=${to} carryBits=${/* @__PURE__ */ radix2carry(from, to)}`
    );
  }
  let carry = 0;
  let pos = 0;
  const max = powers[from];
  const mask = powers[to] - 1;
  const res = [];
  for (const n of data) {
    anumber2(n);
    if (n >= max) throw new Error(`convertRadix2: invalid data word=${n} from=${from}`);
    carry = carry << from | n;
    if (pos + from > 32) throw new Error(`convertRadix2: carry overflow pos=${pos} from=${from}`);
    pos += from;
    for (; pos >= to; pos -= to) res.push((carry >> pos - to & mask) >>> 0);
    const pow = powers[pos];
    if (pow === void 0) throw new Error("invalid carry");
    carry &= pow - 1;
  }
  carry = carry << to - pos & mask;
  if (!padding2 && pos >= from) throw new Error("Excess padding");
  if (!padding2 && carry > 0) throw new Error(`Non-zero padding: ${carry}`);
  if (padding2 && pos > 0) res.push(carry >>> 0);
  return res;
}
// @__NO_SIDE_EFFECTS__
function radix(num) {
  anumber2(num);
  const _256 = 2 ** 8;
  return {
    encode: (bytes) => {
      if (!isBytes2(bytes)) throw new Error("radix.encode input should be Uint8Array");
      return convertRadix(Array.from(bytes), _256, num);
    },
    decode: (digits) => {
      anumArr("radix.decode", digits);
      return Uint8Array.from(convertRadix(digits, num, _256));
    }
  };
}
// @__NO_SIDE_EFFECTS__
function radix2(bits, revPadding = false) {
  anumber2(bits);
  if (bits <= 0 || bits > 32) throw new Error("radix2: bits should be in (0..32]");
  if (/* @__PURE__ */ radix2carry(8, bits) > 32 || /* @__PURE__ */ radix2carry(bits, 8) > 32)
    throw new Error("radix2: carry overflow");
  return {
    encode: (bytes) => {
      if (!isBytes2(bytes)) throw new Error("radix2.encode input should be Uint8Array");
      return convertRadix2(Array.from(bytes), 8, bits, !revPadding);
    },
    decode: (digits) => {
      anumArr("radix2.decode", digits);
      return Uint8Array.from(convertRadix2(digits, bits, 8, revPadding));
    }
  };
}
function checksum(len, fn) {
  anumber2(len);
  afn(fn);
  return {
    encode(data) {
      if (!isBytes2(data)) throw new Error("checksum.encode: input should be Uint8Array");
      const sum = fn(data).slice(0, len);
      const res = new Uint8Array(data.length + len);
      res.set(data);
      res.set(sum, data.length);
      return res;
    },
    decode(data) {
      if (!isBytes2(data)) throw new Error("checksum.decode: input should be Uint8Array");
      const payload = data.slice(0, -len);
      const oldChecksum = data.slice(-len);
      const newChecksum = fn(payload).slice(0, len);
      for (let i = 0; i < len; i++)
        if (newChecksum[i] !== oldChecksum[i]) throw new Error("Invalid checksum");
      return payload;
    }
  };
}
var utils = {
  alphabet,
  chain,
  checksum,
  convertRadix,
  convertRadix2,
  radix,
  radix2,
  join,
  padding
};

// vendor/scure-bip39/src/index.ts
var isJapanese = (wordlist2) => wordlist2[0] === "\u3042\u3044\u3053\u304F\u3057\u3093";
function nfkd(str) {
  if (typeof str !== "string") throw new TypeError("invalid mnemonic type: " + typeof str);
  return str.normalize("NFKD");
}
function normalize(str) {
  const norm = nfkd(str);
  const words = norm.split(" ");
  if (![12, 15, 18, 21, 24].includes(words.length)) throw new Error("Invalid mnemonic");
  return { nfkd: norm, words };
}
function aentropy(ent) {
  abytes(ent, 16, 20, 24, 28, 32);
}
function generateMnemonic(wordlist2, strength = 128) {
  anumber(strength);
  if (strength % 32 !== 0 || strength > 256) throw new TypeError("Invalid entropy");
  return entropyToMnemonic(randomBytes(strength / 8), wordlist2);
}
var calcChecksum = (entropy) => {
  const bitsLeft = 8 - entropy.length / 4;
  return new Uint8Array([sha256(entropy)[0] >> bitsLeft << bitsLeft]);
};
function getCoder(wordlist2) {
  if (!Array.isArray(wordlist2) || wordlist2.length !== 2048 || typeof wordlist2[0] !== "string")
    throw new Error("Wordlist: expected array of 2048 strings");
  wordlist2.forEach((i) => {
    if (typeof i !== "string") throw new Error("wordlist: non-string element: " + i);
  });
  return utils.chain(
    utils.checksum(1, calcChecksum),
    utils.radix2(11, true),
    utils.alphabet(wordlist2)
  );
}
function mnemonicToEntropy(mnemonic, wordlist2) {
  const { words } = normalize(mnemonic);
  const entropy = getCoder(wordlist2).decode(words);
  aentropy(entropy);
  return entropy;
}
function entropyToMnemonic(entropy, wordlist2) {
  aentropy(entropy);
  const words = getCoder(wordlist2).encode(entropy);
  return words.join(isJapanese(wordlist2) ? "\u3000" : " ");
}
function validateMnemonic(mnemonic, wordlist2) {
  try {
    mnemonicToEntropy(mnemonic, wordlist2);
  } catch (e) {
    return false;
  }
  return true;
}

// vendor/scure-bip39/src/wordlists/english.ts
var wordlist = `abandon
ability
able
about
above
absent
absorb
abstract
absurd
abuse
access
accident
account
accuse
achieve
acid
acoustic
acquire
across
act
action
actor
actress
actual
adapt
add
addict
address
adjust
admit
adult
advance
advice
aerobic
affair
afford
afraid
again
age
agent
agree
ahead
aim
air
airport
aisle
alarm
album
alcohol
alert
alien
all
alley
allow
almost
alone
alpha
already
also
alter
always
amateur
amazing
among
amount
amused
analyst
anchor
ancient
anger
angle
angry
animal
ankle
announce
annual
another
answer
antenna
antique
anxiety
any
apart
apology
appear
apple
approve
april
arch
arctic
area
arena
argue
arm
armed
armor
army
around
arrange
arrest
arrive
arrow
art
artefact
artist
artwork
ask
aspect
assault
asset
assist
assume
asthma
athlete
atom
attack
attend
attitude
attract
auction
audit
august
aunt
author
auto
autumn
average
avocado
avoid
awake
aware
away
awesome
awful
awkward
axis
baby
bachelor
bacon
badge
bag
balance
balcony
ball
bamboo
banana
banner
bar
barely
bargain
barrel
base
basic
basket
battle
beach
bean
beauty
because
become
beef
before
begin
behave
behind
believe
below
belt
bench
benefit
best
betray
better
between
beyond
bicycle
bid
bike
bind
biology
bird
birth
bitter
black
blade
blame
blanket
blast
bleak
bless
blind
blood
blossom
blouse
blue
blur
blush
board
boat
body
boil
bomb
bone
bonus
book
boost
border
boring
borrow
boss
bottom
bounce
box
boy
bracket
brain
brand
brass
brave
bread
breeze
brick
bridge
brief
bright
bring
brisk
broccoli
broken
bronze
broom
brother
brown
brush
bubble
buddy
budget
buffalo
build
bulb
bulk
bullet
bundle
bunker
burden
burger
burst
bus
business
busy
butter
buyer
buzz
cabbage
cabin
cable
cactus
cage
cake
call
calm
camera
camp
can
canal
cancel
candy
cannon
canoe
canvas
canyon
capable
capital
captain
car
carbon
card
cargo
carpet
carry
cart
case
cash
casino
castle
casual
cat
catalog
catch
category
cattle
caught
cause
caution
cave
ceiling
celery
cement
census
century
cereal
certain
chair
chalk
champion
change
chaos
chapter
charge
chase
chat
cheap
check
cheese
chef
cherry
chest
chicken
chief
child
chimney
choice
choose
chronic
chuckle
chunk
churn
cigar
cinnamon
circle
citizen
city
civil
claim
clap
clarify
claw
clay
clean
clerk
clever
click
client
cliff
climb
clinic
clip
clock
clog
close
cloth
cloud
clown
club
clump
cluster
clutch
coach
coast
coconut
code
coffee
coil
coin
collect
color
column
combine
come
comfort
comic
common
company
concert
conduct
confirm
congress
connect
consider
control
convince
cook
cool
copper
copy
coral
core
corn
correct
cost
cotton
couch
country
couple
course
cousin
cover
coyote
crack
cradle
craft
cram
crane
crash
crater
crawl
crazy
cream
credit
creek
crew
cricket
crime
crisp
critic
crop
cross
crouch
crowd
crucial
cruel
cruise
crumble
crunch
crush
cry
crystal
cube
culture
cup
cupboard
curious
current
curtain
curve
cushion
custom
cute
cycle
dad
damage
damp
dance
danger
daring
dash
daughter
dawn
day
deal
debate
debris
decade
december
decide
decline
decorate
decrease
deer
defense
define
defy
degree
delay
deliver
demand
demise
denial
dentist
deny
depart
depend
deposit
depth
deputy
derive
describe
desert
design
desk
despair
destroy
detail
detect
develop
device
devote
diagram
dial
diamond
diary
dice
diesel
diet
differ
digital
dignity
dilemma
dinner
dinosaur
direct
dirt
disagree
discover
disease
dish
dismiss
disorder
display
distance
divert
divide
divorce
dizzy
doctor
document
dog
doll
dolphin
domain
donate
donkey
donor
door
dose
double
dove
draft
dragon
drama
drastic
draw
dream
dress
drift
drill
drink
drip
drive
drop
drum
dry
duck
dumb
dune
during
dust
dutch
duty
dwarf
dynamic
eager
eagle
early
earn
earth
easily
east
easy
echo
ecology
economy
edge
edit
educate
effort
egg
eight
either
elbow
elder
electric
elegant
element
elephant
elevator
elite
else
embark
embody
embrace
emerge
emotion
employ
empower
empty
enable
enact
end
endless
endorse
enemy
energy
enforce
engage
engine
enhance
enjoy
enlist
enough
enrich
enroll
ensure
enter
entire
entry
envelope
episode
equal
equip
era
erase
erode
erosion
error
erupt
escape
essay
essence
estate
eternal
ethics
evidence
evil
evoke
evolve
exact
example
excess
exchange
excite
exclude
excuse
execute
exercise
exhaust
exhibit
exile
exist
exit
exotic
expand
expect
expire
explain
expose
express
extend
extra
eye
eyebrow
fabric
face
faculty
fade
faint
faith
fall
false
fame
family
famous
fan
fancy
fantasy
farm
fashion
fat
fatal
father
fatigue
fault
favorite
feature
february
federal
fee
feed
feel
female
fence
festival
fetch
fever
few
fiber
fiction
field
figure
file
film
filter
final
find
fine
finger
finish
fire
firm
first
fiscal
fish
fit
fitness
fix
flag
flame
flash
flat
flavor
flee
flight
flip
float
flock
floor
flower
fluid
flush
fly
foam
focus
fog
foil
fold
follow
food
foot
force
forest
forget
fork
fortune
forum
forward
fossil
foster
found
fox
fragile
frame
frequent
fresh
friend
fringe
frog
front
frost
frown
frozen
fruit
fuel
fun
funny
furnace
fury
future
gadget
gain
galaxy
gallery
game
gap
garage
garbage
garden
garlic
garment
gas
gasp
gate
gather
gauge
gaze
general
genius
genre
gentle
genuine
gesture
ghost
giant
gift
giggle
ginger
giraffe
girl
give
glad
glance
glare
glass
glide
glimpse
globe
gloom
glory
glove
glow
glue
goat
goddess
gold
good
goose
gorilla
gospel
gossip
govern
gown
grab
grace
grain
grant
grape
grass
gravity
great
green
grid
grief
grit
grocery
group
grow
grunt
guard
guess
guide
guilt
guitar
gun
gym
habit
hair
half
hammer
hamster
hand
happy
harbor
hard
harsh
harvest
hat
have
hawk
hazard
head
health
heart
heavy
hedgehog
height
hello
helmet
help
hen
hero
hidden
high
hill
hint
hip
hire
history
hobby
hockey
hold
hole
holiday
hollow
home
honey
hood
hope
horn
horror
horse
hospital
host
hotel
hour
hover
hub
huge
human
humble
humor
hundred
hungry
hunt
hurdle
hurry
hurt
husband
hybrid
ice
icon
idea
identify
idle
ignore
ill
illegal
illness
image
imitate
immense
immune
impact
impose
improve
impulse
inch
include
income
increase
index
indicate
indoor
industry
infant
inflict
inform
inhale
inherit
initial
inject
injury
inmate
inner
innocent
input
inquiry
insane
insect
inside
inspire
install
intact
interest
into
invest
invite
involve
iron
island
isolate
issue
item
ivory
jacket
jaguar
jar
jazz
jealous
jeans
jelly
jewel
job
join
joke
journey
joy
judge
juice
jump
jungle
junior
junk
just
kangaroo
keen
keep
ketchup
key
kick
kid
kidney
kind
kingdom
kiss
kit
kitchen
kite
kitten
kiwi
knee
knife
knock
know
lab
label
labor
ladder
lady
lake
lamp
language
laptop
large
later
latin
laugh
laundry
lava
law
lawn
lawsuit
layer
lazy
leader
leaf
learn
leave
lecture
left
leg
legal
legend
leisure
lemon
lend
length
lens
leopard
lesson
letter
level
liar
liberty
library
license
life
lift
light
like
limb
limit
link
lion
liquid
list
little
live
lizard
load
loan
lobster
local
lock
logic
lonely
long
loop
lottery
loud
lounge
love
loyal
lucky
luggage
lumber
lunar
lunch
luxury
lyrics
machine
mad
magic
magnet
maid
mail
main
major
make
mammal
man
manage
mandate
mango
mansion
manual
maple
marble
march
margin
marine
market
marriage
mask
mass
master
match
material
math
matrix
matter
maximum
maze
meadow
mean
measure
meat
mechanic
medal
media
melody
melt
member
memory
mention
menu
mercy
merge
merit
merry
mesh
message
metal
method
middle
midnight
milk
million
mimic
mind
minimum
minor
minute
miracle
mirror
misery
miss
mistake
mix
mixed
mixture
mobile
model
modify
mom
moment
monitor
monkey
monster
month
moon
moral
more
morning
mosquito
mother
motion
motor
mountain
mouse
move
movie
much
muffin
mule
multiply
muscle
museum
mushroom
music
must
mutual
myself
mystery
myth
naive
name
napkin
narrow
nasty
nation
nature
near
neck
need
negative
neglect
neither
nephew
nerve
nest
net
network
neutral
never
news
next
nice
night
noble
noise
nominee
noodle
normal
north
nose
notable
note
nothing
notice
novel
now
nuclear
number
nurse
nut
oak
obey
object
oblige
obscure
observe
obtain
obvious
occur
ocean
october
odor
off
offer
office
often
oil
okay
old
olive
olympic
omit
once
one
onion
online
only
open
opera
opinion
oppose
option
orange
orbit
orchard
order
ordinary
organ
orient
original
orphan
ostrich
other
outdoor
outer
output
outside
oval
oven
over
own
owner
oxygen
oyster
ozone
pact
paddle
page
pair
palace
palm
panda
panel
panic
panther
paper
parade
parent
park
parrot
party
pass
patch
path
patient
patrol
pattern
pause
pave
payment
peace
peanut
pear
peasant
pelican
pen
penalty
pencil
people
pepper
perfect
permit
person
pet
phone
photo
phrase
physical
piano
picnic
picture
piece
pig
pigeon
pill
pilot
pink
pioneer
pipe
pistol
pitch
pizza
place
planet
plastic
plate
play
please
pledge
pluck
plug
plunge
poem
poet
point
polar
pole
police
pond
pony
pool
popular
portion
position
possible
post
potato
pottery
poverty
powder
power
practice
praise
predict
prefer
prepare
present
pretty
prevent
price
pride
primary
print
priority
prison
private
prize
problem
process
produce
profit
program
project
promote
proof
property
prosper
protect
proud
provide
public
pudding
pull
pulp
pulse
pumpkin
punch
pupil
puppy
purchase
purity
purpose
purse
push
put
puzzle
pyramid
quality
quantum
quarter
question
quick
quit
quiz
quote
rabbit
raccoon
race
rack
radar
radio
rail
rain
raise
rally
ramp
ranch
random
range
rapid
rare
rate
rather
raven
raw
razor
ready
real
reason
rebel
rebuild
recall
receive
recipe
record
recycle
reduce
reflect
reform
refuse
region
regret
regular
reject
relax
release
relief
rely
remain
remember
remind
remove
render
renew
rent
reopen
repair
repeat
replace
report
require
rescue
resemble
resist
resource
response
result
retire
retreat
return
reunion
reveal
review
reward
rhythm
rib
ribbon
rice
rich
ride
ridge
rifle
right
rigid
ring
riot
ripple
risk
ritual
rival
river
road
roast
robot
robust
rocket
romance
roof
rookie
room
rose
rotate
rough
round
route
royal
rubber
rude
rug
rule
run
runway
rural
sad
saddle
sadness
safe
sail
salad
salmon
salon
salt
salute
same
sample
sand
satisfy
satoshi
sauce
sausage
save
say
scale
scan
scare
scatter
scene
scheme
school
science
scissors
scorpion
scout
scrap
screen
script
scrub
sea
search
season
seat
second
secret
section
security
seed
seek
segment
select
sell
seminar
senior
sense
sentence
series
service
session
settle
setup
seven
shadow
shaft
shallow
share
shed
shell
sheriff
shield
shift
shine
ship
shiver
shock
shoe
shoot
shop
short
shoulder
shove
shrimp
shrug
shuffle
shy
sibling
sick
side
siege
sight
sign
silent
silk
silly
silver
similar
simple
since
sing
siren
sister
situate
six
size
skate
sketch
ski
skill
skin
skirt
skull
slab
slam
sleep
slender
slice
slide
slight
slim
slogan
slot
slow
slush
small
smart
smile
smoke
smooth
snack
snake
snap
sniff
snow
soap
soccer
social
sock
soda
soft
solar
soldier
solid
solution
solve
someone
song
soon
sorry
sort
soul
sound
soup
source
south
space
spare
spatial
spawn
speak
special
speed
spell
spend
sphere
spice
spider
spike
spin
spirit
split
spoil
sponsor
spoon
sport
spot
spray
spread
spring
spy
square
squeeze
squirrel
stable
stadium
staff
stage
stairs
stamp
stand
start
state
stay
steak
steel
stem
step
stereo
stick
still
sting
stock
stomach
stone
stool
story
stove
strategy
street
strike
strong
struggle
student
stuff
stumble
style
subject
submit
subway
success
such
sudden
suffer
sugar
suggest
suit
summer
sun
sunny
sunset
super
supply
supreme
sure
surface
surge
surprise
surround
survey
suspect
sustain
swallow
swamp
swap
swarm
swear
sweet
swift
swim
swing
switch
sword
symbol
symptom
syrup
system
table
tackle
tag
tail
talent
talk
tank
tape
target
task
taste
tattoo
taxi
teach
team
tell
ten
tenant
tennis
tent
term
test
text
thank
that
theme
then
theory
there
they
thing
this
thought
three
thrive
throw
thumb
thunder
ticket
tide
tiger
tilt
timber
time
tiny
tip
tired
tissue
title
toast
tobacco
today
toddler
toe
together
toilet
token
tomato
tomorrow
tone
tongue
tonight
tool
tooth
top
topic
topple
torch
tornado
tortoise
toss
total
tourist
toward
tower
town
toy
track
trade
traffic
tragic
train
transfer
trap
trash
travel
tray
treat
tree
trend
trial
tribe
trick
trigger
trim
trip
trophy
trouble
truck
true
truly
trumpet
trust
truth
try
tube
tuition
tumble
tuna
tunnel
turkey
turn
turtle
twelve
twenty
twice
twin
twist
two
type
typical
ugly
umbrella
unable
unaware
uncle
uncover
under
undo
unfair
unfold
unhappy
uniform
unique
unit
universe
unknown
unlock
until
unusual
unveil
update
upgrade
uphold
upon
upper
upset
urban
urge
usage
use
used
useful
useless
usual
utility
vacant
vacuum
vague
valid
valley
valve
van
vanish
vapor
various
vast
vault
vehicle
velvet
vendor
venture
venue
verb
verify
version
very
vessel
veteran
viable
vibrant
vicious
victory
video
view
village
vintage
violin
virtual
virus
visa
visit
visual
vital
vivid
vocal
voice
void
volcano
volume
vote
voyage
wage
wagon
wait
walk
wall
walnut
want
warfare
warm
warrior
wash
wasp
waste
water
wave
way
wealth
weapon
wear
weasel
weather
web
wedding
weekend
weird
welcome
west
wet
whale
what
wheat
wheel
when
where
whip
whisper
wide
width
wife
wild
will
win
window
wine
wing
wink
winner
winter
wire
wisdom
wise
wish
witness
wolf
woman
wonder
wood
wool
word
work
world
worry
worth
wrap
wreck
wrestle
wrist
write
wrong
yard
year
yellow
you
young
youth
zebra
zero
zone
zoo`.split("\n");

// vendor/qrcodegen/qrcodegen.ts
var qrcodegen;
((qrcodegen2) => {
  class QrCode {
    /*-- Constructor (low level) and fields --*/
    // Creates a new QR Code with the given version number,
    // error correction level, data codeword bytes, and mask number.
    // This is a low-level API that most users should not use directly.
    // A mid-level API is the encodeSegments() function.
    constructor(version, errorCorrectionLevel, dataCodewords, msk) {
      this.version = version;
      this.errorCorrectionLevel = errorCorrectionLevel;
      if (version < QrCode.MIN_VERSION || version > QrCode.MAX_VERSION)
        throw new RangeError("Version value out of range");
      if (msk < -1 || msk > 7)
        throw new RangeError("Mask value out of range");
      this.size = version * 4 + 17;
      let row = [];
      for (let i = 0; i < this.size; i++)
        row.push(false);
      for (let i = 0; i < this.size; i++) {
        this.modules.push(row.slice());
        this.isFunction.push(row.slice());
      }
      this.drawFunctionPatterns();
      const allCodewords = this.addEccAndInterleave(dataCodewords);
      this.drawCodewords(allCodewords);
      if (msk == -1) {
        let minPenalty = 1e9;
        for (let i = 0; i < 8; i++) {
          this.applyMask(i);
          this.drawFormatBits(i);
          const penalty = this.getPenaltyScore();
          if (penalty < minPenalty) {
            msk = i;
            minPenalty = penalty;
          }
          this.applyMask(i);
        }
      }
      assert(0 <= msk && msk <= 7);
      this.mask = msk;
      this.applyMask(msk);
      this.drawFormatBits(msk);
      this.isFunction = [];
    }
    /*-- Static factory functions (high level) --*/
    // Returns a QR Code representing the given Unicode text string at the given error correction level.
    // As a conservative upper bound, this function is guaranteed to succeed for strings that have 738 or fewer
    // Unicode code points (not UTF-16 code units) if the low error correction level is used. The smallest possible
    // QR Code version is automatically chosen for the output. The ECC level of the result may be higher than the
    // ecl argument if it can be done without increasing the version.
    static encodeText(text, ecl) {
      const segs = qrcodegen2.QrSegment.makeSegments(text);
      return QrCode.encodeSegments(segs, ecl);
    }
    // Returns a QR Code representing the given binary data at the given error correction level.
    // This function always encodes using the binary segment mode, not any text mode. The maximum number of
    // bytes allowed is 2953. The smallest possible QR Code version is automatically chosen for the output.
    // The ECC level of the result may be higher than the ecl argument if it can be done without increasing the version.
    static encodeBinary(data, ecl) {
      const seg = qrcodegen2.QrSegment.makeBytes(data);
      return QrCode.encodeSegments([seg], ecl);
    }
    /*-- Static factory functions (mid level) --*/
    // Returns a QR Code representing the given segments with the given encoding parameters.
    // The smallest possible QR Code version within the given range is automatically
    // chosen for the output. Iff boostEcl is true, then the ECC level of the result
    // may be higher than the ecl argument if it can be done without increasing the
    // version. The mask number is either between 0 to 7 (inclusive) to force that
    // mask, or -1 to automatically choose an appropriate mask (which may be slow).
    // This function allows the user to create a custom sequence of segments that switches
    // between modes (such as alphanumeric and byte) to encode text in less space.
    // This is a mid-level API; the high-level API is encodeText() and encodeBinary().
    static encodeSegments(segs, ecl, minVersion = 1, maxVersion = 40, mask = -1, boostEcl = true) {
      if (!(QrCode.MIN_VERSION <= minVersion && minVersion <= maxVersion && maxVersion <= QrCode.MAX_VERSION) || mask < -1 || mask > 7)
        throw new RangeError("Invalid value");
      let version;
      let dataUsedBits;
      for (version = minVersion; ; version++) {
        const dataCapacityBits2 = QrCode.getNumDataCodewords(version, ecl) * 8;
        const usedBits = QrSegment.getTotalBits(segs, version);
        if (usedBits <= dataCapacityBits2) {
          dataUsedBits = usedBits;
          break;
        }
        if (version >= maxVersion)
          throw new RangeError("Data too long");
      }
      for (const newEcl of [QrCode.Ecc.MEDIUM, QrCode.Ecc.QUARTILE, QrCode.Ecc.HIGH]) {
        if (boostEcl && dataUsedBits <= QrCode.getNumDataCodewords(version, newEcl) * 8)
          ecl = newEcl;
      }
      let bb = [];
      for (const seg of segs) {
        appendBits(seg.mode.modeBits, 4, bb);
        appendBits(seg.numChars, seg.mode.numCharCountBits(version), bb);
        for (const b of seg.getData())
          bb.push(b);
      }
      assert(bb.length == dataUsedBits);
      const dataCapacityBits = QrCode.getNumDataCodewords(version, ecl) * 8;
      assert(bb.length <= dataCapacityBits);
      appendBits(0, Math.min(4, dataCapacityBits - bb.length), bb);
      appendBits(0, (8 - bb.length % 8) % 8, bb);
      assert(bb.length % 8 == 0);
      for (let padByte = 236; bb.length < dataCapacityBits; padByte ^= 236 ^ 17)
        appendBits(padByte, 8, bb);
      let dataCodewords = [];
      while (dataCodewords.length * 8 < bb.length)
        dataCodewords.push(0);
      bb.forEach((b, i) => dataCodewords[i >>> 3] |= b << 7 - (i & 7));
      return new QrCode(version, ecl, dataCodewords, mask);
    }
    /*-- Fields --*/
    // The width and height of this QR Code, measured in modules, between
    // 21 and 177 (inclusive). This is equal to version * 4 + 17.
    size;
    // The index of the mask pattern used in this QR Code, which is between 0 and 7 (inclusive).
    // Even if a QR Code is created with automatic masking requested (mask = -1),
    // the resulting object still has a mask value between 0 and 7.
    mask;
    // The modules of this QR Code (false = light, true = dark).
    // Immutable after constructor finishes. Accessed through getModule().
    modules = [];
    // Indicates function modules that are not subjected to masking. Discarded when constructor finishes.
    isFunction = [];
    /*-- Accessor methods --*/
    // Returns the color of the module (pixel) at the given coordinates, which is false
    // for light or true for dark. The top left corner has the coordinates (x=0, y=0).
    // If the given coordinates are out of bounds, then false (light) is returned.
    getModule(x, y) {
      return 0 <= x && x < this.size && 0 <= y && y < this.size && this.modules[y][x];
    }
    /*-- Private helper methods for constructor: Drawing function modules --*/
    // Reads this object's version field, and draws and marks all function modules.
    drawFunctionPatterns() {
      for (let i = 0; i < this.size; i++) {
        this.setFunctionModule(6, i, i % 2 == 0);
        this.setFunctionModule(i, 6, i % 2 == 0);
      }
      this.drawFinderPattern(3, 3);
      this.drawFinderPattern(this.size - 4, 3);
      this.drawFinderPattern(3, this.size - 4);
      const alignPatPos = this.getAlignmentPatternPositions();
      const numAlign = alignPatPos.length;
      for (let i = 0; i < numAlign; i++) {
        for (let j = 0; j < numAlign; j++) {
          if (!(i == 0 && j == 0 || i == 0 && j == numAlign - 1 || i == numAlign - 1 && j == 0))
            this.drawAlignmentPattern(alignPatPos[i], alignPatPos[j]);
        }
      }
      this.drawFormatBits(0);
      this.drawVersion();
    }
    // Draws two copies of the format bits (with its own error correction code)
    // based on the given mask and this object's error correction level field.
    drawFormatBits(mask) {
      const data = this.errorCorrectionLevel.formatBits << 3 | mask;
      let rem = data;
      for (let i = 0; i < 10; i++)
        rem = rem << 1 ^ (rem >>> 9) * 1335;
      const bits = (data << 10 | rem) ^ 21522;
      assert(bits >>> 15 == 0);
      for (let i = 0; i <= 5; i++)
        this.setFunctionModule(8, i, getBit(bits, i));
      this.setFunctionModule(8, 7, getBit(bits, 6));
      this.setFunctionModule(8, 8, getBit(bits, 7));
      this.setFunctionModule(7, 8, getBit(bits, 8));
      for (let i = 9; i < 15; i++)
        this.setFunctionModule(14 - i, 8, getBit(bits, i));
      for (let i = 0; i < 8; i++)
        this.setFunctionModule(this.size - 1 - i, 8, getBit(bits, i));
      for (let i = 8; i < 15; i++)
        this.setFunctionModule(8, this.size - 15 + i, getBit(bits, i));
      this.setFunctionModule(8, this.size - 8, true);
    }
    // Draws two copies of the version bits (with its own error correction code),
    // based on this object's version field, iff 7 <= version <= 40.
    drawVersion() {
      if (this.version < 7)
        return;
      let rem = this.version;
      for (let i = 0; i < 12; i++)
        rem = rem << 1 ^ (rem >>> 11) * 7973;
      const bits = this.version << 12 | rem;
      assert(bits >>> 18 == 0);
      for (let i = 0; i < 18; i++) {
        const color = getBit(bits, i);
        const a = this.size - 11 + i % 3;
        const b = Math.floor(i / 3);
        this.setFunctionModule(a, b, color);
        this.setFunctionModule(b, a, color);
      }
    }
    // Draws a 9*9 finder pattern including the border separator,
    // with the center module at (x, y). Modules can be out of bounds.
    drawFinderPattern(x, y) {
      for (let dy = -4; dy <= 4; dy++) {
        for (let dx = -4; dx <= 4; dx++) {
          const dist = Math.max(Math.abs(dx), Math.abs(dy));
          const xx = x + dx;
          const yy = y + dy;
          if (0 <= xx && xx < this.size && 0 <= yy && yy < this.size)
            this.setFunctionModule(xx, yy, dist != 2 && dist != 4);
        }
      }
    }
    // Draws a 5*5 alignment pattern, with the center module
    // at (x, y). All modules must be in bounds.
    drawAlignmentPattern(x, y) {
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++)
          this.setFunctionModule(x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) != 1);
      }
    }
    // Sets the color of a module and marks it as a function module.
    // Only used by the constructor. Coordinates must be in bounds.
    setFunctionModule(x, y, isDark) {
      this.modules[y][x] = isDark;
      this.isFunction[y][x] = true;
    }
    /*-- Private helper methods for constructor: Codewords and masking --*/
    // Returns a new byte string representing the given data with the appropriate error correction
    // codewords appended to it, based on this object's version and error correction level.
    addEccAndInterleave(data) {
      const ver = this.version;
      const ecl = this.errorCorrectionLevel;
      if (data.length != QrCode.getNumDataCodewords(ver, ecl))
        throw new RangeError("Invalid argument");
      const numBlocks = QrCode.NUM_ERROR_CORRECTION_BLOCKS[ecl.ordinal][ver];
      const blockEccLen = QrCode.ECC_CODEWORDS_PER_BLOCK[ecl.ordinal][ver];
      const rawCodewords = Math.floor(QrCode.getNumRawDataModules(ver) / 8);
      const numShortBlocks = numBlocks - rawCodewords % numBlocks;
      const shortBlockLen = Math.floor(rawCodewords / numBlocks);
      let blocks = [];
      const rsDiv = QrCode.reedSolomonComputeDivisor(blockEccLen);
      for (let i = 0, k = 0; i < numBlocks; i++) {
        let dat = data.slice(k, k + shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1));
        k += dat.length;
        const ecc = QrCode.reedSolomonComputeRemainder(dat, rsDiv);
        if (i < numShortBlocks)
          dat.push(0);
        blocks.push(dat.concat(ecc));
      }
      let result = [];
      for (let i = 0; i < blocks[0].length; i++) {
        blocks.forEach((block, j) => {
          if (i != shortBlockLen - blockEccLen || j >= numShortBlocks)
            result.push(block[i]);
        });
      }
      assert(result.length == rawCodewords);
      return result;
    }
    // Draws the given sequence of 8-bit codewords (data and error correction) onto the entire
    // data area of this QR Code. Function modules need to be marked off before this is called.
    drawCodewords(data) {
      if (data.length != Math.floor(QrCode.getNumRawDataModules(this.version) / 8))
        throw new RangeError("Invalid argument");
      let i = 0;
      for (let right = this.size - 1; right >= 1; right -= 2) {
        if (right == 6)
          right = 5;
        for (let vert = 0; vert < this.size; vert++) {
          for (let j = 0; j < 2; j++) {
            const x = right - j;
            const upward = (right + 1 & 2) == 0;
            const y = upward ? this.size - 1 - vert : vert;
            if (!this.isFunction[y][x] && i < data.length * 8) {
              this.modules[y][x] = getBit(data[i >>> 3], 7 - (i & 7));
              i++;
            }
          }
        }
      }
      assert(i == data.length * 8);
    }
    // XORs the codeword modules in this QR Code with the given mask pattern.
    // The function modules must be marked and the codeword bits must be drawn
    // before masking. Due to the arithmetic of XOR, calling applyMask() with
    // the same mask value a second time will undo the mask. A final well-formed
    // QR Code needs exactly one (not zero, two, etc.) mask applied.
    applyMask(mask) {
      if (mask < 0 || mask > 7)
        throw new RangeError("Mask value out of range");
      for (let y = 0; y < this.size; y++) {
        for (let x = 0; x < this.size; x++) {
          let invert;
          switch (mask) {
            case 0:
              invert = (x + y) % 2 == 0;
              break;
            case 1:
              invert = y % 2 == 0;
              break;
            case 2:
              invert = x % 3 == 0;
              break;
            case 3:
              invert = (x + y) % 3 == 0;
              break;
            case 4:
              invert = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 == 0;
              break;
            case 5:
              invert = x * y % 2 + x * y % 3 == 0;
              break;
            case 6:
              invert = (x * y % 2 + x * y % 3) % 2 == 0;
              break;
            case 7:
              invert = ((x + y) % 2 + x * y % 3) % 2 == 0;
              break;
            default:
              throw new Error("Unreachable");
          }
          if (!this.isFunction[y][x] && invert)
            this.modules[y][x] = !this.modules[y][x];
        }
      }
    }
    // Calculates and returns the penalty score based on state of this QR Code's current modules.
    // This is used by the automatic mask choice algorithm to find the mask pattern that yields the lowest score.
    getPenaltyScore() {
      let result = 0;
      for (let y = 0; y < this.size; y++) {
        let runColor = false;
        let runX = 0;
        let runHistory = [0, 0, 0, 0, 0, 0, 0];
        for (let x = 0; x < this.size; x++) {
          if (this.modules[y][x] == runColor) {
            runX++;
            if (runX == 5)
              result += QrCode.PENALTY_N1;
            else if (runX > 5)
              result++;
          } else {
            this.finderPenaltyAddHistory(runX, runHistory);
            if (!runColor)
              result += this.finderPenaltyCountPatterns(runHistory) * QrCode.PENALTY_N3;
            runColor = this.modules[y][x];
            runX = 1;
          }
        }
        result += this.finderPenaltyTerminateAndCount(runColor, runX, runHistory) * QrCode.PENALTY_N3;
      }
      for (let x = 0; x < this.size; x++) {
        let runColor = false;
        let runY = 0;
        let runHistory = [0, 0, 0, 0, 0, 0, 0];
        for (let y = 0; y < this.size; y++) {
          if (this.modules[y][x] == runColor) {
            runY++;
            if (runY == 5)
              result += QrCode.PENALTY_N1;
            else if (runY > 5)
              result++;
          } else {
            this.finderPenaltyAddHistory(runY, runHistory);
            if (!runColor)
              result += this.finderPenaltyCountPatterns(runHistory) * QrCode.PENALTY_N3;
            runColor = this.modules[y][x];
            runY = 1;
          }
        }
        result += this.finderPenaltyTerminateAndCount(runColor, runY, runHistory) * QrCode.PENALTY_N3;
      }
      for (let y = 0; y < this.size - 1; y++) {
        for (let x = 0; x < this.size - 1; x++) {
          const color = this.modules[y][x];
          if (color == this.modules[y][x + 1] && color == this.modules[y + 1][x] && color == this.modules[y + 1][x + 1])
            result += QrCode.PENALTY_N2;
        }
      }
      let dark = 0;
      for (const row of this.modules)
        dark = row.reduce((sum, color) => sum + (color ? 1 : 0), dark);
      const total = this.size * this.size;
      const k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
      assert(0 <= k && k <= 9);
      result += k * QrCode.PENALTY_N4;
      assert(0 <= result && result <= 2568888);
      return result;
    }
    /*-- Private helper functions --*/
    // Returns an ascending list of positions of alignment patterns for this version number.
    // Each position is in the range [0,177), and are used on both the x and y axes.
    // This could be implemented as lookup table of 40 variable-length lists of integers.
    getAlignmentPatternPositions() {
      if (this.version == 1)
        return [];
      else {
        const numAlign = Math.floor(this.version / 7) + 2;
        const step = Math.floor((this.version * 8 + numAlign * 3 + 5) / (numAlign * 4 - 4)) * 2;
        let result = [6];
        for (let pos = this.size - 7; result.length < numAlign; pos -= step)
          result.splice(1, 0, pos);
        return result;
      }
    }
    // Returns the number of data bits that can be stored in a QR Code of the given version number, after
    // all function modules are excluded. This includes remainder bits, so it might not be a multiple of 8.
    // The result is in the range [208, 29648]. This could be implemented as a 40-entry lookup table.
    static getNumRawDataModules(ver) {
      if (ver < QrCode.MIN_VERSION || ver > QrCode.MAX_VERSION)
        throw new RangeError("Version number out of range");
      let result = (16 * ver + 128) * ver + 64;
      if (ver >= 2) {
        const numAlign = Math.floor(ver / 7) + 2;
        result -= (25 * numAlign - 10) * numAlign - 55;
        if (ver >= 7)
          result -= 36;
      }
      assert(208 <= result && result <= 29648);
      return result;
    }
    // Returns the number of 8-bit data (i.e. not error correction) codewords contained in any
    // QR Code of the given version number and error correction level, with remainder bits discarded.
    // This stateless pure function could be implemented as a (40*4)-cell lookup table.
    static getNumDataCodewords(ver, ecl) {
      return Math.floor(QrCode.getNumRawDataModules(ver) / 8) - QrCode.ECC_CODEWORDS_PER_BLOCK[ecl.ordinal][ver] * QrCode.NUM_ERROR_CORRECTION_BLOCKS[ecl.ordinal][ver];
    }
    // Returns a Reed-Solomon ECC generator polynomial for the given degree. This could be
    // implemented as a lookup table over all possible parameter values, instead of as an algorithm.
    static reedSolomonComputeDivisor(degree) {
      if (degree < 1 || degree > 255)
        throw new RangeError("Degree out of range");
      let result = [];
      for (let i = 0; i < degree - 1; i++)
        result.push(0);
      result.push(1);
      let root = 1;
      for (let i = 0; i < degree; i++) {
        for (let j = 0; j < result.length; j++) {
          result[j] = QrCode.reedSolomonMultiply(result[j], root);
          if (j + 1 < result.length)
            result[j] ^= result[j + 1];
        }
        root = QrCode.reedSolomonMultiply(root, 2);
      }
      return result;
    }
    // Returns the Reed-Solomon error correction codeword for the given data and divisor polynomials.
    static reedSolomonComputeRemainder(data, divisor) {
      let result = divisor.map((_) => 0);
      for (const b of data) {
        const factor = b ^ result.shift();
        result.push(0);
        divisor.forEach((coef, i) => result[i] ^= QrCode.reedSolomonMultiply(coef, factor));
      }
      return result;
    }
    // Returns the product of the two given field elements modulo GF(2^8/0x11D). The arguments and result
    // are unsigned 8-bit integers. This could be implemented as a lookup table of 256*256 entries of uint8.
    static reedSolomonMultiply(x, y) {
      if (x >>> 8 != 0 || y >>> 8 != 0)
        throw new RangeError("Byte out of range");
      let z = 0;
      for (let i = 7; i >= 0; i--) {
        z = z << 1 ^ (z >>> 7) * 285;
        z ^= (y >>> i & 1) * x;
      }
      assert(z >>> 8 == 0);
      return z;
    }
    // Can only be called immediately after a light run is added, and
    // returns either 0, 1, or 2. A helper function for getPenaltyScore().
    finderPenaltyCountPatterns(runHistory) {
      const n = runHistory[1];
      assert(n <= this.size * 3);
      const core = n > 0 && runHistory[2] == n && runHistory[3] == n * 3 && runHistory[4] == n && runHistory[5] == n;
      return (core && runHistory[0] >= n * 4 && runHistory[6] >= n ? 1 : 0) + (core && runHistory[6] >= n * 4 && runHistory[0] >= n ? 1 : 0);
    }
    // Must be called at the end of a line (row or column) of modules. A helper function for getPenaltyScore().
    finderPenaltyTerminateAndCount(currentRunColor, currentRunLength, runHistory) {
      if (currentRunColor) {
        this.finderPenaltyAddHistory(currentRunLength, runHistory);
        currentRunLength = 0;
      }
      currentRunLength += this.size;
      this.finderPenaltyAddHistory(currentRunLength, runHistory);
      return this.finderPenaltyCountPatterns(runHistory);
    }
    // Pushes the given value to the front and drops the last value. A helper function for getPenaltyScore().
    finderPenaltyAddHistory(currentRunLength, runHistory) {
      if (runHistory[0] == 0)
        currentRunLength += this.size;
      runHistory.pop();
      runHistory.unshift(currentRunLength);
    }
    /*-- Constants and tables --*/
    // The minimum version number supported in the QR Code Model 2 standard.
    static MIN_VERSION = 1;
    // The maximum version number supported in the QR Code Model 2 standard.
    static MAX_VERSION = 40;
    // For use in getPenaltyScore(), when evaluating which mask is best.
    static PENALTY_N1 = 3;
    static PENALTY_N2 = 3;
    static PENALTY_N3 = 40;
    static PENALTY_N4 = 10;
    static ECC_CODEWORDS_PER_BLOCK = [
      // Version: (note that index 0 is for padding, and is set to an illegal value)
      //0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40    Error correction level
      [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
      // Low
      [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
      // Medium
      [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
      // Quartile
      [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30]
      // High
    ];
    static NUM_ERROR_CORRECTION_BLOCKS = [
      // Version: (note that index 0 is for padding, and is set to an illegal value)
      //0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40    Error correction level
      [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
      // Low
      [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
      // Medium
      [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
      // Quartile
      [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81]
      // High
    ];
  }
  qrcodegen2.QrCode = QrCode;
  function appendBits(val, len, bb) {
    if (len < 0 || len > 31 || val >>> len != 0)
      throw new RangeError("Value out of range");
    for (let i = len - 1; i >= 0; i--)
      bb.push(val >>> i & 1);
  }
  function getBit(x, i) {
    return (x >>> i & 1) != 0;
  }
  function assert(cond) {
    if (!cond)
      throw new Error("Assertion error");
  }
  class QrSegment {
    /*-- Constructor (low level) and fields --*/
    // Creates a new QR Code segment with the given attributes and data.
    // The character count (numChars) must agree with the mode and the bit buffer length,
    // but the constraint isn't checked. The given bit buffer is cloned and stored.
    constructor(mode, numChars, bitData) {
      this.mode = mode;
      this.numChars = numChars;
      this.bitData = bitData;
      if (numChars < 0)
        throw new RangeError("Invalid argument");
      this.bitData = bitData.slice();
    }
    /*-- Static factory functions (mid level) --*/
    // Returns a segment representing the given binary data encoded in
    // byte mode. All input byte arrays are acceptable. Any text string
    // can be converted to UTF-8 bytes and encoded as a byte mode segment.
    static makeBytes(data) {
      let bb = [];
      for (const b of data)
        appendBits(b, 8, bb);
      return new QrSegment(QrSegment.Mode.BYTE, data.length, bb);
    }
    // Returns a segment representing the given string of decimal digits encoded in numeric mode.
    static makeNumeric(digits) {
      if (!QrSegment.isNumeric(digits))
        throw new RangeError("String contains non-numeric characters");
      let bb = [];
      for (let i = 0; i < digits.length; ) {
        const n = Math.min(digits.length - i, 3);
        appendBits(parseInt(digits.substring(i, i + n), 10), n * 3 + 1, bb);
        i += n;
      }
      return new QrSegment(QrSegment.Mode.NUMERIC, digits.length, bb);
    }
    // Returns a segment representing the given text string encoded in alphanumeric mode.
    // The characters allowed are: 0 to 9, A to Z (uppercase only), space,
    // dollar, percent, asterisk, plus, hyphen, period, slash, colon.
    static makeAlphanumeric(text) {
      if (!QrSegment.isAlphanumeric(text))
        throw new RangeError("String contains unencodable characters in alphanumeric mode");
      let bb = [];
      let i;
      for (i = 0; i + 2 <= text.length; i += 2) {
        let temp = QrSegment.ALPHANUMERIC_CHARSET.indexOf(text.charAt(i)) * 45;
        temp += QrSegment.ALPHANUMERIC_CHARSET.indexOf(text.charAt(i + 1));
        appendBits(temp, 11, bb);
      }
      if (i < text.length)
        appendBits(QrSegment.ALPHANUMERIC_CHARSET.indexOf(text.charAt(i)), 6, bb);
      return new QrSegment(QrSegment.Mode.ALPHANUMERIC, text.length, bb);
    }
    // Returns a new mutable list of zero or more segments to represent the given Unicode text string.
    // The result may use various segment modes and switch modes to optimize the length of the bit stream.
    static makeSegments(text) {
      if (text == "")
        return [];
      else if (QrSegment.isNumeric(text))
        return [QrSegment.makeNumeric(text)];
      else if (QrSegment.isAlphanumeric(text))
        return [QrSegment.makeAlphanumeric(text)];
      else
        return [QrSegment.makeBytes(QrSegment.toUtf8ByteArray(text))];
    }
    // Returns a segment representing an Extended Channel Interpretation
    // (ECI) designator with the given assignment value.
    static makeEci(assignVal) {
      let bb = [];
      if (assignVal < 0)
        throw new RangeError("ECI assignment value out of range");
      else if (assignVal < 1 << 7)
        appendBits(assignVal, 8, bb);
      else if (assignVal < 1 << 14) {
        appendBits(2, 2, bb);
        appendBits(assignVal, 14, bb);
      } else if (assignVal < 1e6) {
        appendBits(6, 3, bb);
        appendBits(assignVal, 21, bb);
      } else
        throw new RangeError("ECI assignment value out of range");
      return new QrSegment(QrSegment.Mode.ECI, 0, bb);
    }
    // Tests whether the given string can be encoded as a segment in numeric mode.
    // A string is encodable iff each character is in the range 0 to 9.
    static isNumeric(text) {
      return QrSegment.NUMERIC_REGEX.test(text);
    }
    // Tests whether the given string can be encoded as a segment in alphanumeric mode.
    // A string is encodable iff each character is in the following set: 0 to 9, A to Z
    // (uppercase only), space, dollar, percent, asterisk, plus, hyphen, period, slash, colon.
    static isAlphanumeric(text) {
      return QrSegment.ALPHANUMERIC_REGEX.test(text);
    }
    /*-- Methods --*/
    // Returns a new copy of the data bits of this segment.
    getData() {
      return this.bitData.slice();
    }
    // (Package-private) Calculates and returns the number of bits needed to encode the given segments at
    // the given version. The result is infinity if a segment has too many characters to fit its length field.
    static getTotalBits(segs, version) {
      let result = 0;
      for (const seg of segs) {
        const ccbits = seg.mode.numCharCountBits(version);
        if (seg.numChars >= 1 << ccbits)
          return Infinity;
        result += 4 + ccbits + seg.bitData.length;
      }
      return result;
    }
    // Returns a new array of bytes representing the given string encoded in UTF-8.
    static toUtf8ByteArray(str) {
      str = encodeURI(str);
      let result = [];
      for (let i = 0; i < str.length; i++) {
        if (str.charAt(i) != "%")
          result.push(str.charCodeAt(i));
        else {
          result.push(parseInt(str.substring(i + 1, i + 3), 16));
          i += 2;
        }
      }
      return result;
    }
    /*-- Constants --*/
    // Describes precisely all strings that are encodable in numeric mode.
    static NUMERIC_REGEX = /^[0-9]*$/;
    // Describes precisely all strings that are encodable in alphanumeric mode.
    static ALPHANUMERIC_REGEX = /^[A-Z0-9 $%*+.\/:-]*$/;
    // The set of all legal characters in alphanumeric mode,
    // where each character value maps to the index in the string.
    static ALPHANUMERIC_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
  }
  qrcodegen2.QrSegment = QrSegment;
})(qrcodegen || (qrcodegen = {}));
((qrcodegen2) => {
  let QrCode;
  ((QrCode2) => {
    class Ecc {
      // The QR Code can tolerate about 30% erroneous codewords
      /*-- Constructor and fields --*/
      constructor(ordinal, formatBits) {
        this.ordinal = ordinal;
        this.formatBits = formatBits;
      }
      /*-- Constants --*/
      static LOW = new Ecc(0, 1);
      // The QR Code can tolerate about  7% erroneous codewords
      static MEDIUM = new Ecc(1, 0);
      // The QR Code can tolerate about 15% erroneous codewords
      static QUARTILE = new Ecc(2, 3);
      // The QR Code can tolerate about 25% erroneous codewords
      static HIGH = new Ecc(3, 2);
    }
    QrCode2.Ecc = Ecc;
  })(QrCode = qrcodegen2.QrCode || (qrcodegen2.QrCode = {}));
})(qrcodegen || (qrcodegen = {}));
((qrcodegen2) => {
  let QrSegment;
  ((QrSegment2) => {
    class Mode {
      /*-- Constructor and fields --*/
      constructor(modeBits, numBitsCharCount) {
        this.modeBits = modeBits;
        this.numBitsCharCount = numBitsCharCount;
      }
      /*-- Constants --*/
      static NUMERIC = new Mode(1, [10, 12, 14]);
      static ALPHANUMERIC = new Mode(2, [9, 11, 13]);
      static BYTE = new Mode(4, [8, 16, 16]);
      static KANJI = new Mode(8, [8, 10, 12]);
      static ECI = new Mode(7, [0, 0, 0]);
      /*-- Method --*/
      // (Package-private) Returns the bit width of the character count field for a segment in
      // this mode in a QR Code at the given version number. The result is in the range [0, 16].
      numCharCountBits(ver) {
        return this.numBitsCharCount[Math.floor((ver + 7) / 17)];
      }
    }
    QrSegment2.Mode = Mode;
  })(QrSegment = qrcodegen2.QrSegment || (qrcodegen2.QrSegment = {}));
})(qrcodegen || (qrcodegen = {}));
var qrcodegen_default = qrcodegen;

// vendor/slip39/wordlist.txt
var wordlist_default = "academic\nacid\nacne\nacquire\nacrobat\nactivity\nactress\nadapt\nadequate\nadjust\nadmit\nadorn\nadult\nadvance\nadvocate\nafraid\nagain\nagency\nagree\naide\naircraft\nairline\nairport\najar\nalarm\nalbum\nalcohol\nalien\nalive\nalpha\nalready\nalto\naluminum\nalways\namazing\nambition\namount\namuse\nanalysis\nanatomy\nancestor\nancient\nangel\nangry\nanimal\nanswer\nantenna\nanxiety\napart\naquatic\narcade\narena\nargue\narmed\nartist\nartwork\naspect\nauction\naugust\naunt\naverage\naviation\navoid\naward\naway\naxis\naxle\nbeam\nbeard\nbeaver\nbecome\nbedroom\nbehavior\nbeing\nbelieve\nbelong\nbenefit\nbest\nbeyond\nbike\nbiology\nbirthday\nbishop\nblack\nblanket\nblessing\nblimp\nblind\nblue\nbody\nbolt\nboring\nborn\nboth\nboundary\nbracelet\nbranch\nbrave\nbreathe\nbriefing\nbroken\nbrother\nbrowser\nbucket\nbudget\nbuilding\nbulb\nbulge\nbumpy\nbundle\nburden\nburning\nbusy\nbuyer\ncage\ncalcium\ncamera\ncampus\ncanyon\ncapacity\ncapital\ncapture\ncarbon\ncards\ncareful\ncargo\ncarpet\ncarve\ncategory\ncause\nceiling\ncenter\nceramic\nchampion\nchange\ncharity\ncheck\nchemical\nchest\nchew\nchubby\ncinema\ncivil\nclass\nclay\ncleanup\nclient\nclimate\nclinic\nclock\nclogs\ncloset\nclothes\nclub\ncluster\ncoal\ncoastal\ncoding\ncolumn\ncompany\ncorner\ncostume\ncounter\ncourse\ncover\ncowboy\ncradle\ncraft\ncrazy\ncredit\ncricket\ncriminal\ncrisis\ncritical\ncrowd\ncrucial\ncrunch\ncrush\ncrystal\ncubic\ncultural\ncurious\ncurly\ncustody\ncylinder\ndaisy\ndamage\ndance\ndarkness\ndatabase\ndaughter\ndeadline\ndeal\ndebris\ndebut\ndecent\ndecision\ndeclare\ndecorate\ndecrease\ndeliver\ndemand\ndensity\ndeny\ndepart\ndepend\ndepict\ndeploy\ndescribe\ndesert\ndesire\ndesktop\ndestroy\ndetailed\ndetect\ndevice\ndevote\ndiagnose\ndictate\ndiet\ndilemma\ndiminish\ndining\ndiploma\ndisaster\ndiscuss\ndisease\ndish\ndismiss\ndisplay\ndistance\ndive\ndivorce\ndocument\ndomain\ndomestic\ndominant\ndough\ndowntown\ndragon\ndramatic\ndream\ndress\ndrift\ndrink\ndrove\ndrug\ndryer\nduckling\nduke\nduration\ndwarf\ndynamic\nearly\nearth\neasel\neasy\necho\neclipse\necology\nedge\neditor\neducate\neither\nelbow\nelder\nelection\nelegant\nelement\nelephant\nelevator\nelite\nelse\nemail\nemerald\nemission\nemperor\nemphasis\nemployer\nempty\nending\nendless\nendorse\nenemy\nenergy\nenforce\nengage\nenjoy\nenlarge\nentrance\nenvelope\nenvy\nepidemic\nepisode\nequation\nequip\neraser\nerode\nescape\nestate\nestimate\nevaluate\nevening\nevidence\nevil\nevoke\nexact\nexample\nexceed\nexchange\nexclude\nexcuse\nexecute\nexercise\nexhaust\nexotic\nexpand\nexpect\nexplain\nexpress\nextend\nextra\neyebrow\nfacility\nfact\nfailure\nfaint\nfake\nfalse\nfamily\nfamous\nfancy\nfangs\nfantasy\nfatal\nfatigue\nfavorite\nfawn\nfiber\nfiction\nfilter\nfinance\nfindings\nfinger\nfirefly\nfirm\nfiscal\nfishing\nfitness\nflame\nflash\nflavor\nflea\nflexible\nflip\nfloat\nfloral\nfluff\nfocus\nforbid\nforce\nforecast\nforget\nformal\nfortune\nforward\nfounder\nfraction\nfragment\nfrequent\nfreshman\nfriar\nfridge\nfriendly\nfrost\nfroth\nfrozen\nfumes\nfunding\nfurl\nfused\ngalaxy\ngame\ngarbage\ngarden\ngarlic\ngasoline\ngather\ngeneral\ngenius\ngenre\ngenuine\ngeology\ngesture\nglad\nglance\nglasses\nglen\nglimpse\ngoat\ngolden\ngraduate\ngrant\ngrasp\ngravity\ngray\ngreatest\ngrief\ngrill\ngrin\ngrocery\ngross\ngroup\ngrownup\ngrumpy\nguard\nguest\nguilt\nguitar\ngums\nhairy\nhamster\nhand\nhanger\nharvest\nhave\nhavoc\nhawk\nhazard\nheadset\nhealth\nhearing\nheat\nhelpful\nherald\nherd\nhesitate\nhobo\nholiday\nholy\nhome\nhormone\nhospital\nhour\nhuge\nhuman\nhumidity\nhunting\nhusband\nhush\nhusky\nhybrid\nidea\nidentify\nidle\nimage\nimpact\nimply\nimprove\nimpulse\ninclude\nincome\nincrease\nindex\nindicate\nindustry\ninfant\ninform\ninherit\ninjury\ninmate\ninsect\ninside\ninstall\nintend\nintimate\ninvasion\ninvolve\niris\nisland\nisolate\nitem\nivory\njacket\njerky\njewelry\njoin\njudicial\njuice\njump\njunction\njunior\njunk\njury\njustice\nkernel\nkeyboard\nkidney\nkind\nkitchen\nknife\nknit\nladen\nladle\nladybug\nlair\nlamp\nlanguage\nlarge\nlaser\nlaundry\nlawsuit\nleader\nleaf\nlearn\nleaves\nlecture\nlegal\nlegend\nlegs\nlend\nlength\nlevel\nliberty\nlibrary\nlicense\nlift\nlikely\nlilac\nlily\nlips\nliquid\nlisten\nliterary\nliving\nlizard\nloan\nlobe\nlocation\nlosing\nloud\nloyalty\nluck\nlunar\nlunch\nlungs\nluxury\nlying\nlyrics\nmachine\nmagazine\nmaiden\nmailman\nmain\nmakeup\nmaking\nmama\nmanager\nmandate\nmansion\nmanual\nmarathon\nmarch\nmarket\nmarvel\nmason\nmaterial\nmath\nmaximum\nmayor\nmeaning\nmedal\nmedical\nmember\nmemory\nmental\nmerchant\nmerit\nmethod\nmetric\nmidst\nmild\nmilitary\nmineral\nminister\nmiracle\nmixed\nmixture\nmobile\nmodern\nmodify\nmoisture\nmoment\nmorning\nmortgage\nmother\nmountain\nmouse\nmove\nmuch\nmule\nmultiple\nmuscle\nmuseum\nmusic\nmustang\nnail\nnational\nnecklace\nnegative\nnervous\nnetwork\nnews\nnuclear\nnumb\nnumerous\nnylon\noasis\nobesity\nobject\nobserve\nobtain\nocean\noften\nolympic\nomit\noral\norange\norbit\norder\nordinary\norganize\nounce\noven\noverall\nowner\npaces\npacific\npackage\npaid\npainting\npajamas\npancake\npants\npapa\npaper\nparcel\nparking\nparty\npatent\npatrol\npayment\npayroll\npeaceful\npeanut\npeasant\npecan\npenalty\npencil\npercent\nperfect\npermit\npetition\nphantom\npharmacy\nphoto\nphrase\nphysics\npickup\npicture\npiece\npile\npink\npipeline\npistol\npitch\nplains\nplan\nplastic\nplatform\nplayoff\npleasure\nplot\nplunge\npractice\nprayer\npreach\npredator\npregnant\npremium\nprepare\npresence\nprevent\npriest\nprimary\npriority\nprisoner\nprivacy\nprize\nproblem\nprocess\nprofile\nprogram\npromise\nprospect\nprovide\nprune\npublic\npulse\npumps\npunish\npuny\npupal\npurchase\npurple\npython\nquantity\nquarter\nquick\nquiet\nrace\nracism\nradar\nrailroad\nrainbow\nraisin\nrandom\nranked\nrapids\nraspy\nreaction\nrealize\nrebound\nrebuild\nrecall\nreceiver\nrecover\nregret\nregular\nreject\nrelate\nremember\nremind\nremove\nrender\nrepair\nrepeat\nreplace\nrequire\nrescue\nresearch\nresident\nresponse\nresult\nretailer\nretreat\nreunion\nrevenue\nreview\nreward\nrhyme\nrhythm\nrich\nrival\nriver\nrobin\nrocky\nromantic\nromp\nroster\nround\nroyal\nruin\nruler\nrumor\nsack\nsafari\nsalary\nsalon\nsalt\nsatisfy\nsatoshi\nsaver\nsays\nscandal\nscared\nscatter\nscene\nscholar\nscience\nscout\nscramble\nscrew\nscript\nscroll\nseafood\nseason\nsecret\nsecurity\nsegment\nsenior\nshadow\nshaft\nshame\nshaped\nsharp\nshelter\nsheriff\nshort\nshould\nshrimp\nsidewalk\nsilent\nsilver\nsimilar\nsimple\nsingle\nsister\nskin\nskunk\nslap\nslavery\nsled\nslice\nslim\nslow\nslush\nsmart\nsmear\nsmell\nsmirk\nsmith\nsmoking\nsmug\nsnake\nsnapshot\nsniff\nsociety\nsoftware\nsoldier\nsolution\nsoul\nsource\nspace\nspark\nspeak\nspecies\nspelling\nspend\nspew\nspider\nspill\nspine\nspirit\nspit\nspray\nsprinkle\nsquare\nsqueeze\nstadium\nstaff\nstandard\nstarting\nstation\nstay\nsteady\nstep\nstick\nstilt\nstory\nstrategy\nstrike\nstyle\nsubject\nsubmit\nsugar\nsuitable\nsunlight\nsuperior\nsurface\nsurprise\nsurvive\nsweater\nswimming\nswing\nswitch\nsymbolic\nsympathy\nsyndrome\nsystem\ntackle\ntactics\ntadpole\ntalent\ntask\ntaste\ntaught\ntaxi\nteacher\nteammate\nteaspoon\ntemple\ntenant\ntendency\ntension\nterminal\ntestify\ntexture\nthank\nthat\ntheater\ntheory\ntherapy\nthorn\nthreaten\nthumb\nthunder\nticket\ntidy\ntimber\ntimely\nting\ntofu\ntogether\ntolerate\ntotal\ntoxic\ntracks\ntraffic\ntraining\ntransfer\ntrash\ntraveler\ntreat\ntrend\ntrial\ntricycle\ntrip\ntriumph\ntrouble\ntrue\ntrust\ntwice\ntwin\ntype\ntypical\nugly\nultimate\numbrella\nuncover\nundergo\nunfair\nunfold\nunhappy\nunion\nuniverse\nunkind\nunknown\nunusual\nunwrap\nupgrade\nupstairs\nusername\nusher\nusual\nvalid\nvaluable\nvampire\nvanish\nvarious\nvegan\nvelvet\nventure\nverdict\nverify\nvery\nveteran\nvexed\nvictim\nvideo\nview\nvintage\nviolence\nviral\nvisitor\nvisual\nvitamins\nvocal\nvoice\nvolume\nvoter\nvoting\nwalnut\nwarmth\nwarn\nwatch\nwavy\nwealthy\nweapon\nwebcam\nwelcome\nwelfare\nwestern\nwidth\nwildlife\nwindow\nwine\nwireless\nwisdom\nwithdraw\nwits\nwolf\nwoman\nwork\nworthy\nwrap\nwrist\nwriting\nwrote\nyear\nyelp\nyield\nyoga\nzero\n";

// src/lib/slip39.ts
var WORDLIST = wordlist_default.trim().split(/\s+/);
if (WORDLIST.length !== 1024) throw new Error("SLIP-39 wordlist must have 1024 words");
var WORD_INDEX = new Map(WORDLIST.map((w, i) => [w, i]));
var RADIX_BITS = 10;
var ID_LENGTH_BITS = 15;
var EXTENDABLE_FLAG_LENGTH_BITS = 1;
var ITERATION_EXP_LENGTH_BITS = 4;
var ID_EXP_LENGTH_WORDS = 2;
var MAX_SHARE_COUNT = 16;
var CHECKSUM_LENGTH_WORDS = 3;
var DIGEST_LENGTH_BYTES = 4;
var CUSTOMIZATION_STRING_ORIG = asciiBytes("shamir");
var CUSTOMIZATION_STRING_EXTENDABLE = asciiBytes("shamir_extendable");
var GROUP_PREFIX_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 1;
var METADATA_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 2 + CHECKSUM_LENGTH_WORDS;
var MIN_STRENGTH_BITS = 128;
var MIN_MNEMONIC_LENGTH_WORDS = METADATA_LENGTH_WORDS + Math.ceil(MIN_STRENGTH_BITS / RADIX_BITS);
var BASE_ITERATION_COUNT = 1e4;
var ROUND_COUNT = 4;
var SECRET_INDEX = 255;
var DIGEST_INDEX = 254;
var MnemonicError = class extends Error {
};
function asciiBytes(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
function xor(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
function randomBytes2(n) {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}
var GEN = [14737472, 29474944, 58949888, 117899776, 235798537, 470557714, 940076068, 814808136, 565311632, 66318624];
function polymod(values) {
  let chk = 1;
  for (let j = 0; j < values.length; j++) {
    const b = chk >>> 20;
    chk = ((chk & 1048575) << 10 ^ values[j]) >>> 0;
    for (let i = 0; i < 10; i++) if (b >>> i & 1) chk = (chk ^ GEN[i]) >>> 0;
  }
  return chk;
}
function customizationString(extendable) {
  return extendable ? CUSTOMIZATION_STRING_EXTENDABLE : CUSTOMIZATION_STRING_ORIG;
}
function createChecksum(data, cs) {
  const values = [...cs, ...data, 0, 0, 0];
  const pm = polymod(values) ^ 1;
  return [2, 1, 0].map((i) => pm >>> 10 * i & 1023);
}
function verifyChecksum(data, cs) {
  return polymod([...cs, ...data]) === 1;
}
async function roundFunction(i, passphrase, e, salt, r) {
  return pbkdf2Async(sha256, concat(new Uint8Array([i]), passphrase), concat(salt, r), {
    c: (BASE_ITERATION_COUNT << e) / ROUND_COUNT,
    dkLen: r.length
  });
}
function getSalt(identifier, extendable) {
  if (extendable) return new Uint8Array(0);
  return concat(CUSTOMIZATION_STRING_ORIG, new Uint8Array([identifier >> 8 & 255, identifier & 255]));
}
async function encryptMS(ms, passphrase, e, identifier, extendable) {
  if (ms.length % 2 !== 0) throw new Error("The length of the master secret in bytes must be an even number.");
  let l = ms.slice(0, ms.length / 2);
  let r = ms.slice(ms.length / 2);
  const salt = getSalt(identifier, extendable);
  for (let i = 0; i < ROUND_COUNT; i++) {
    const f = await roundFunction(i, passphrase, e, salt, r);
    [l, r] = [r, xor(l, f)];
  }
  return concat(r, l);
}
async function decryptEMS(ems, passphrase, e, identifier, extendable) {
  if (ems.length % 2 !== 0) throw new Error("The length of the encrypted master secret in bytes must be an even number.");
  let l = ems.slice(0, ems.length / 2);
  let r = ems.slice(ems.length / 2);
  const salt = getSalt(identifier, extendable);
  for (let i = ROUND_COUNT - 1; i >= 0; i--) {
    const f = await roundFunction(i, passphrase, e, salt, r);
    [l, r] = [r, xor(l, f)];
  }
  return concat(r, l);
}
var EXP = new Array(255).fill(0);
var LOG = new Array(256).fill(0);
{
  let poly = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = poly;
    LOG[poly] = i;
    poly = poly << 1 ^ poly;
    if (poly & 256) poly ^= 283;
  }
}
function mod255(n) {
  return (n % 255 + 255) % 255;
}
function interpolate(shares, x) {
  const xs = new Set(shares.map((s) => s.x));
  if (xs.size !== shares.length) throw new MnemonicError("Invalid set of shares. Share indices must be unique.");
  const lens = new Set(shares.map((s) => s.data.length));
  if (lens.size !== 1) throw new MnemonicError("Invalid set of shares. All share values must have the same length.");
  if (xs.has(x)) return shares.find((s) => s.x === x).data;
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
function createDigest(randomData, sharedSecret) {
  return hmac(sha256, randomData, sharedSecret).slice(0, DIGEST_LENGTH_BYTES);
}
function splitSecret(threshold, shareCount, sharedSecret) {
  if (threshold < 1) throw new Error("The requested threshold must be a positive integer.");
  if (threshold > shareCount) throw new Error("The requested threshold must not exceed the number of shares.");
  if (shareCount > MAX_SHARE_COUNT) throw new Error(`The requested number of shares must not exceed ${MAX_SHARE_COUNT}.`);
  if (threshold === 1) return Array.from({ length: shareCount }, (_, i) => ({ x: i, data: sharedSecret }));
  const randomShareCount = threshold - 2;
  const shares = Array.from({ length: randomShareCount }, (_, i) => ({ x: i, data: randomBytes2(sharedSecret.length) }));
  const randomPart = randomBytes2(sharedSecret.length - DIGEST_LENGTH_BYTES);
  const digest = createDigest(randomPart, sharedSecret);
  const baseShares = [...shares, { x: DIGEST_INDEX, data: concat(digest, randomPart) }, { x: SECRET_INDEX, data: sharedSecret }];
  for (let i = randomShareCount; i < shareCount; i++) shares.push({ x: i, data: interpolate(baseShares, i) });
  return shares;
}
function recoverSecret(threshold, shares) {
  if (threshold === 1) return shares[0].data;
  const sharedSecret = interpolate(shares, SECRET_INDEX);
  const digestShare = interpolate(shares, DIGEST_INDEX);
  const digest = digestShare.slice(0, DIGEST_LENGTH_BYTES);
  const randomPart = digestShare.slice(DIGEST_LENGTH_BYTES);
  if (!bytesEqual(digest, createDigest(randomPart, sharedSecret))) throw new MnemonicError("Invalid digest of the shared secret.");
  return sharedSecret;
}
function intToIndices(value, length, radixBits) {
  const mask = (1n << BigInt(radixBits)) - 1n;
  const out = [];
  for (let i = length - 1; i >= 0; i--) out.push(Number(value >> BigInt(i * radixBits) & mask));
  return out;
}
function intFromIndices(indices) {
  let v = 0n;
  for (const i of indices) v = v * 1024n + BigInt(i);
  return v;
}
function bytesToBigInt(b) {
  let v = 0n;
  for (const x of b) v = v << 8n | BigInt(x);
  return v;
}
function bigIntToBytes(v, len) {
  if (v >= 1n << BigInt(8 * len)) return null;
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}
function shareToWords(s) {
  let idExp = BigInt(s.identifier) << BigInt(ITERATION_EXP_LENGTH_BITS + EXTENDABLE_FLAG_LENGTH_BITS);
  idExp += BigInt(s.extendable ? 1 : 0) << BigInt(ITERATION_EXP_LENGTH_BITS);
  idExp += BigInt(s.iterationExponent);
  let p = BigInt(s.groupIndex);
  p = (p << 4n) + BigInt(s.groupThreshold - 1);
  p = (p << 4n) + BigInt(s.groupCount - 1);
  p = (p << 4n) + BigInt(s.index);
  p = (p << 4n) + BigInt(s.memberThreshold - 1);
  const valueWordCount = Math.ceil(s.value.length * 8 / RADIX_BITS);
  const data = [
    ...intToIndices(idExp, ID_EXP_LENGTH_WORDS, RADIX_BITS),
    ...intToIndices(p, 2, RADIX_BITS),
    ...intToIndices(bytesToBigInt(s.value), valueWordCount, RADIX_BITS)
  ];
  const checksum2 = createChecksum(data, customizationString(s.extendable));
  return [...data, ...checksum2].map((i) => WORDLIST[i]);
}
function normalizeMnemonic(m) {
  return m.trim().toLowerCase().split(/\s+/).filter(Boolean);
}
function shareFromMnemonic(mnemonic) {
  const words = normalizeMnemonic(mnemonic);
  const data = words.map((w) => {
    const i = WORD_INDEX.get(w);
    if (i === void 0) throw new MnemonicError(`Invalid mnemonic word "${w}".`);
    return i;
  });
  if (data.length < MIN_MNEMONIC_LENGTH_WORDS)
    throw new MnemonicError(`Invalid mnemonic length. The length of each mnemonic must be at least ${MIN_MNEMONIC_LENGTH_WORDS} words.`);
  const paddingLen = RADIX_BITS * (data.length - METADATA_LENGTH_WORDS) % 16;
  if (paddingLen > 8) throw new MnemonicError("Invalid mnemonic length.");
  const idExpInt = Number(intFromIndices(data.slice(0, ID_EXP_LENGTH_WORDS)));
  const identifier = idExpInt >> EXTENDABLE_FLAG_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS;
  const extendable = (idExpInt >> ITERATION_EXP_LENGTH_BITS & 1) === 1;
  const iterationExponent = idExpInt & (1 << ITERATION_EXP_LENGTH_BITS) - 1;
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
    identifier,
    extendable,
    iterationExponent,
    groupIndex,
    groupThreshold: groupThreshold + 1,
    groupCount: groupCount + 1,
    index,
    memberThreshold: memberThreshold + 1,
    value
  };
}
function checkPassphrase(passphrase) {
  for (let i = 0; i < passphrase.length; i++) {
    const c = passphrase.charCodeAt(i);
    if (c < 32 || c > 126) throw new Error("The passphrase must contain only printable ASCII characters (code points 32-126).");
  }
  return asciiBytes(passphrase);
}
async function generateMnemonics(masterSecret, opts) {
  const groupThreshold = opts.groupThreshold ?? 1;
  const extendable = opts.extendable ?? true;
  const e = opts.iterationExponent ?? 1;
  const pass = checkPassphrase(opts.passphrase ?? "");
  if (masterSecret.length * 8 < MIN_STRENGTH_BITS) throw new Error("The master secret must be at least 16 bytes.");
  if (groupThreshold > opts.groups.length) throw new Error("The requested group threshold must not exceed the number of groups.");
  if (opts.groups.some(([t, c]) => t === 1 && c > 1)) throw new Error("Creating multiple member shares with member threshold 1 is not allowed. Use 1-of-1 member sharing instead.");
  const idBytes = randomBytes2(2);
  const identifier = (idBytes[0] << 8 | idBytes[1]) & (1 << ID_LENGTH_BITS) - 1;
  const ems = await encryptMS(masterSecret, pass, e, identifier, extendable);
  const groupShares = splitSecret(groupThreshold, opts.groups.length, ems);
  return opts.groups.map(
    ([memberThreshold, memberCount], gi) => splitSecret(memberThreshold, memberCount, groupShares[gi].data).map(
      (raw) => shareToWords({
        identifier,
        extendable,
        iterationExponent: e,
        groupIndex: groupShares[gi].x,
        groupThreshold,
        groupCount: opts.groups.length,
        index: raw.x,
        memberThreshold,
        value: raw.data
      }).join(" ")
    )
  );
}
async function combineMnemonics(mnemonics, passphrase = "", lenient = false) {
  if (!mnemonics.length) throw new MnemonicError("The list of mnemonics is empty.");
  const shares = mnemonics.map(shareFromMnemonic);
  const commonKey = (s) => [s.identifier, s.extendable, s.iterationExponent, s.groupThreshold, s.groupCount].join(",");
  const groupKey = (s) => [commonKey(s), s.groupIndex, s.memberThreshold].join(",");
  if (new Set(shares.map(commonKey)).size !== 1)
    throw new MnemonicError(`Invalid set of mnemonics. All mnemonics must begin with the same ${ID_EXP_LENGTH_WORDS} words, must have the same group threshold and the same group count.`);
  const groups = /* @__PURE__ */ new Map();
  for (const s of shares) {
    const g = groups.get(s.groupIndex) ?? [];
    if (g.length && groupKey(g[0]) !== groupKey(s)) throw new MnemonicError("Invalid set of mnemonics. The group parameters don't match.");
    if (!g.some((o) => o.index === s.index && bytesEqual(o.value, s.value))) g.push(s);
    groups.set(s.groupIndex, g);
  }
  const p = shares[0];
  let groupEntries = [...groups.entries()];
  if (lenient) {
    groupEntries = groupEntries.filter(([, g]) => g.length >= g[0].memberThreshold).map(([gi, g]) => [gi, g.slice(0, g[0].memberThreshold)]).slice(0, p.groupThreshold);
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
  const groupShares = groupEntries.map(([gi, g]) => ({
    x: gi,
    data: recoverSecret(g[0].memberThreshold, g.map((s) => ({ x: s.index, data: s.value })))
  }));
  const ems = recoverSecret(p.groupThreshold, groupShares);
  return decryptEMS(ems, checkPassphrase(passphrase), p.iterationExponent, p.identifier, p.extendable);
}
function describeShare(m) {
  try {
    return { ok: true, share: shareFromMnemonic(m) };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// src/lib/robe.ts
function normalizeBip39(m) {
  return m.trim().toLowerCase().split(/\s+/).filter(Boolean).join(" ");
}
function checkBip39(m) {
  const n = normalizeBip39(m);
  const count = n ? n.split(" ").length : 0;
  if (![12, 15, 18, 21, 24].includes(count)) return { ok: false, error: `A BIP-39 seed has 12, 15, 18, 21 or 24 words. This has ${count}.` };
  const bad = n.split(" ").find((w) => !wordlist.includes(w));
  if (bad) return { ok: false, error: `"${bad}" is not a BIP-39 English word.` };
  if (!validateMnemonic(n, wordlist)) return { ok: false, error: "The checksum does not match. Check the word order and spelling." };
  return { ok: true, words: count };
}
async function splitSeed(seed, threshold, count, passphrase) {
  const c = checkBip39(seed);
  if (!c.ok) throw new Error(c.error);
  const entropy = mnemonicToEntropy(normalizeBip39(seed), wordlist);
  try {
    const [shares] = await generateMnemonics(entropy, { groups: [[threshold, count]], passphrase, extendable: true, iterationExponent: 1 });
    return shares;
  } finally {
    entropy.fill(0);
  }
}
async function recoverSeed(shares, passphrase) {
  const clean2 = shares.map((s) => s.trim()).filter(Boolean);
  if (!clean2.length) throw new Error("Paste at least one share.");
  const entropy = await combineMnemonics(clean2, passphrase, true);
  try {
    if (![16, 20, 24, 28, 32].includes(entropy.length)) throw new Error("These shares do not hold a BIP-39 seed.");
    return entropyToMnemonic(entropy, wordlist);
  } finally {
    entropy.fill(0);
  }
}
function sampleSeed() {
  return generateMnemonic(wordlist, 128);
}
function qrSvg(text, dark = "#0F0F0F", light = "#FFFFFF") {
  const qr = qrcodegen_default.QrCode.encodeText(text, qrcodegen_default.QrCode.Ecc.MEDIUM);
  const border = 2;
  const size = qr.size + border * 2;
  let path = "";
  for (let y = 0; y < qr.size; y++)
    for (let x = 0; x < qr.size; x++)
      if (qr.getModule(x, y)) path += `M${x + border},${y + border}h1v1h-1z`;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges" role="img" aria-label="QR code of the share words"><rect width="100%" height="100%" fill="${light}"/><path d="${path}" fill="${dark}"/></svg>`;
}
var SHARE_LENGTHS = [20, 23, 27, 30, 33];
function stripShareLabel(line) {
  return line.replace(/^(?:share|keeper)(?:\s+share)?\s*#?\d+(?:\s*of\s*\d+)?(?:\s*\([^)]*\))?\s*[:.)\-]?\s*/i, "").replace(/^#?\d+\s*[.):\-]\s*/, "");
}
function parseShares(text) {
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
export {
  checkBip39,
  normalizeBip39,
  parseShares,
  qrSvg,
  recoverSeed,
  sampleSeed,
  splitSeed
};
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
/*! scure-base - MIT License (c) 2022 Paul Miller (paulmillr.com) */
/*! scure-bip39 - MIT License (c) 2022 Patricio Palladino, Paul Miller (paulmillr.com) */
