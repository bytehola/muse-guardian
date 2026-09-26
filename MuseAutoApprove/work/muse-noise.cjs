'use strict';
/*
 * muse.ai Noise 传输层 Node 复刻（依据 scripts/muse-noise-transport.js 逆向）
 * - Noise_XX_25519_AESGCM_SHA256（标准 XX，msg1=66B, msg2=166B, msg3=64B）
 * - AES-256-GCM nonce = [0,0,0,0][hi BE u32][lo BE u32]（非标准小端，按原实现逐字节复刻）
 * - 帧: NoiseFrame protobuf 分块 → encryptWithAd(空AD) → WS binary
 * - RPC: ServiceRequest{service,payload=ServiceFrame{streamId,request{verb,path,headers,body,end_body}}}
 */
const crypto = require('crypto');

const te = new TextEncoder();
const bin = (b) => Buffer.from(b);

function sha256(...parts) { const h = crypto.createHash('sha256'); for (const p of parts) h.update(bin(p)); return new Uint8Array(h.digest()); }
function hmac(key, data) { const h = crypto.createHmac('sha256', bin(key)); h.update(bin(data)); return new Uint8Array(h.digest()); }
function concat(...arrs) { return new Uint8Array(Buffer.concat(arrs.map(a => bin(a)))); }
function eq(a, b) { return a.length === b.length && crypto.timingSafeEqual(bin(a), bin(b)); }

// HKDF per Noise: temp=HMAC(ck, ikm); k1=HMAC(temp,0x01); k2=HMAC(temp,k1||0x02); k3=HMAC(temp,k2||0x03)
function hkdf(ck, ikm, n) {
  const t = hmac(ck, ikm);
  const o1 = hmac(t, Uint8Array.of(1));
  const o2 = hmac(t, concat(o1, Uint8Array.of(2)));
  if (n === 2) return [o1, o2];
  const o3 = hmac(t, concat(o2, Uint8Array.of(3)));
  return [o1, o2, o3];
}

// X25519 通过 Node crypto ECDH
// x25519 via EVP (Node 22: createECDH('x25519') 不支持)
const SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
function x25519Generate() {
  const kp = crypto.generateKeyPairSync('x25519');
  return { priv: kp.privateKey, pub: new Uint8Array(kp.publicKey.export({ type: 'spki', format: 'der' }).slice(-32)) };
}
function x25519Dh(privKey, pubBytes) {
  const pk = crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(pubBytes)]), format: 'der', type: 'spki' });
  return new Uint8Array(crypto.diffieHellman({ privateKey: privKey, publicKey: pk }));
}

function nonce12(n) {
  const out = new Uint8Array(12);
  const dv = new DataView(out.buffer);
  dv.setUint32(4, Math.floor(n / 0x100000000), false);
  dv.setUint32(8, n >>> 0, false);
  return out;
}

class CipherState {
  constructor() { this.key = null; this.n = 0; }
  initKey(k) { this.key = bin(k); this.n = 0; }
  hasKey() { return !!this.key; }
  encryptWithAd(ad, pt) {
    if (!this.key) return new Uint8Array(pt);
    const iv = nonce12(this.n++);
    const c = crypto.createCipheriv('aes-256-gcm', this.key, bin(iv));
    c.setAAD(bin(ad));
    const out = Buffer.concat([c.update(bin(pt)), c.final(), c.getAuthTag()]);
    return new Uint8Array(out);
  }
  decryptWithAd(ad, ct) {
    if (!this.key) return new Uint8Array(ct);
    const iv = nonce12(this.n++);
    const tag = ct.slice(ct.length - 16);
    const body = ct.slice(0, ct.length - 16);
    const d = crypto.createDecipheriv('aes-256-gcm', this.key, bin(iv));
    d.setAAD(bin(ad)); d.setAuthTag(bin(tag));
    return new Uint8Array(Buffer.concat([d.update(bin(body)), d.final()]));
  }
}

class SymmetricState {
  constructor() { this.ck = null; this.h = null; this.cipher = new CipherState(); }
  init(protocolName) {
    const t = new Uint8Array(32); t.set(te.encode(protocolName));
    this.ck = t;
    this.h = new Uint8Array(this.ck);
    this.mixHash(new Uint8Array(0));
  }
  mixHash(data) { this.h = sha256(this.h, data); }
  mixKey(ikm) {
    // [修复] Noise 规范：ck'=HKDF(ck, ikm) 的 chaining key；h 只在 mixHash 更新。
    // 旧版误用 this.h 当 HKDF key 且覆盖 h → 与服务器密钥链分叉。
    const [ck, k] = hkdf(this.ck, ikm, 2);
    this.ck = ck; this.cipher = new CipherState(); this.cipher.initKey(k);
  }
  encryptAndHash(pt) { const c = this.cipher.encryptWithAd(this.h, pt); this.mixHash(c); return c; }
  decryptAndHash(ct) { const p = this.cipher.decryptWithAd(this.h, ct); this.mixHash(ct); return p; }
  split() { const [k1, k2] = hkdf(this.ck, new Uint8Array(0), 2); const a = new CipherState(); a.initKey(k1); const b = new CipherState(); b.initKey(k2); return [a, b]; }
}

class NoiseXXInitiator {
  constructor() { this.s = new SymmetricState(); }
  initialize() { this.s.init('Noise_XX_25519_AESGCM_SHA256'); }
  // 返回 { message: Uint8Array, localEphPub }
  writeMessage1(payload = new Uint8Array(0)) {
    this.eph = x25519Generate();
    this.s.mixHash(this.eph.pub);
    const n = this.s.encryptAndHash(payload);
    return concat(this.eph.pub, n);
  }
  readMessage2(msg) {
    if (msg.length < 96) throw new Error('message 2 too short: ' + msg.length);
    let t = 0;
    this.re = msg.slice(t, t + 32); t += 32;
    this.s.mixHash(this.re);
    let dh = x25519Dh(this.eph.priv, this.re); this.s.mixKey(dh);
    this.rs = this.s.decryptAndHash(msg.slice(t, t + 48)); t += 48;
    dh = x25519Dh(this.eph.priv, this.rs); this.s.mixKey(dh);
    const payload = this.s.decryptAndHash(msg.slice(t));
    return payload; // msg2 payload (可能含 rv challenge / attestation)
  }
  writeMessage3(payload = new Uint8Array(0)) {
    const e2 = x25519Generate(); this.eph2 = e2;
    const n = this.s.encryptAndHash(e2.pub);
    const dh = x25519Dh(e2.priv, this.re); this.s.mixKey(dh);
    const a = this.s.encryptAndHash(payload);
    return concat(n, a);
  }
  // 交换得到的传输 cipher：initiator -> [send, recv]
  split() {
    const [k1, k2] = hkdf(this.s.ck, new Uint8Array(0), 2);
    const send = new CipherState(); send.initKey(k1);
    const recv = new CipherState(); recv.initKey(k2);
    return { send, recv };
  }
  handshakeHash() { return new Uint8Array(this.s.h); }
}

/* ---------------- protobuf 极简编解码 ---------------- */
const WT = { VARINT: 0, F64: 1, LEN: 2, F32: 5 };
function varintBytes(n) {
  n = typeof n === 'bigint' ? n : BigInt(n);
  const out = [];
  while (n > 127n) { out.push(Number(n & 127n) | 128); n >>= 7n; }
  out.push(Number(n)); return Uint8Array.from(out);
}
function tag(fieldNo, wt) { return varintBytes((BigInt(fieldNo) << 3n) | BigInt(wt)); }
function pbVarint(fieldNo, n) { return concat(tag(fieldNo, WT.VARINT), varintBytes(n)); }
function pbBytes(fieldNo, b) { return concat(tag(fieldNo, WT.LEN), varintBytes(b.length), b); }
function pbString(fieldNo, s) { return pbBytes(fieldNo, te.encode(s)); }
function pbFixed64(fieldNo, n) { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt.asUintN(64, BigInt(n))); return concat(tag(fieldNo, WT.F64), new Uint8Array(b)); }

function pbRead(buf) {
  // 返回 {fieldNo: {wt, v}} 或数组；对 oneof/多值返回数组
  const out = []; let p = 0; const u = bin(buf);
  const readVarint = () => { let r = 0n, s = 0n; while (true) { const b = u[p++]; r |= BigInt(b & 127) << s; if (!(b & 128)) break; s += 7n; } return r; };
  while (p < u.length) {
    const key = readVarint(); const fieldNo = Number(key >> 3n); const wt = Number(key & 7n);
    let v;
    if (wt === 0) v = readVarint();
    else if (wt === 1) { v = u.slice(p, p + 8); p += 8; }
    else if (wt === 2) { const len = Number(readVarint()); v = new Uint8Array(u.slice(p, p + len)); p += len; }
    else if (wt === 5) { v = u.slice(p, p + 4); p += 4; }
    else throw new Error('bad wiretype ' + wt);
    out.push({ no: fieldNo, wt, v });
  }
  return out;
}
function pbGet(fields, no) { return fields.filter(f => f.no === no); }

/* ---------------- 帧编解码（chunk_id/chunk_index/total_chunks/payload） ---------------- */
const MAX_CHUNK = 65489;
function encodeFrames(chunkId, payload) {
  const frames = [];
  const total = Math.max(1, Math.ceil(payload.length / MAX_CHUNK));
  if (payload.length === 0) {
    frames.push(pbConcatFields([pbVarint(1, chunkId), pbVarint(2, 0), pbVarint(3, 1), pbBytes(4, new Uint8Array(0))]));
    return frames;
  }
  for (let i = 0; i < total; i++) {
    const part = payload.slice(i * MAX_CHUNK, Math.min((i + 1) * MAX_CHUNK, payload.length));
    frames.push(pbConcatFields([pbVarint(1, chunkId), pbVarint(2, i), pbVarint(3, total), pbBytes(4, part)]));
  }
  return frames;
}
function pbConcatFields(arr) { return new Uint8Array(Buffer.concat(arr.map(a => bin(a)))); }
class FrameDecoder {
  constructor() { this.pending = new Map(); }
  decode(buf) {
    const f = pbRead(buf);
    const chunkId = BigInt((pbGet(f, 1)[0] || { v: 0n }).v || 0n);
    const idx = Number((pbGet(f, 2)[0] || { v: 0n }).v || 0n);
    const total = Number((pbGet(f, 3)[0] || { v: 1n }).v || 1n);
    const payload = (pbGet(f, 4)[0] || { v: new Uint8Array(0) }).v;
    const key = chunkId.toString();
    if (!this.pending.has(key)) this.pending.set(key, { chunks: new Map(), total });
    const asm = this.pending.get(key);
    asm.chunks.set(idx, payload);
    if (asm.chunks.size < asm.total) return null;
    this.pending.delete(key);
    const parts = [];
    for (let i = 0; i < asm.total; i++) parts.push(asm.chunks.get(i));
    return concat(...parts);
  }
}

/* ---------------- NoiseTransport 复刻 ---------------- */
const SVC = { daemon: 0, sentinel: 1, vault: 2, authd: 3 };
class NoiseTransport {
  constructor(send, recv) { this.send = send; this.recv = recv; this.streamId = 1n; this.dec = new FrameDecoder(); this.buf = new Uint8Array(0); }

  // 完整请求（endBody=true），返回 {streamId, frames:[Uint8Array]}
  async encryptHttpRequest({ httpMethod, path, body = new Uint8Array(0), service = 'daemon', headers = [] }) {
    const sid = this.streamId++;
    const hdrs = headers.map(h => pbConcatFields([pbString(1, h.key), pbString(2, h.value)]));
    const req = pbConcatFields([
      pbString(1, httpMethod),
      pbString(2, path),
      ...hdrs.map(h => pbBytes(3, h)),
      pbBytes(4, body),
      pbVarint(5, 1),
    ]);
    const frame = pbConcatFields([pbVarint(1, sid), pbBytes(2, req)]);
    const payload = pbConcatFields([pbVarint(1, SVC[service]), pbBytes(2, frame)]);
    const chunkId = (BigInt(crypto.randomBytes(4).readUInt32BE(0)) << 32n) | BigInt(crypto.randomBytes(4).readUInt32BE(0));
    const frames = encodeFrames(chunkId, payload).map(f => this.send.encryptWithAd(new Uint8Array(0), f));
    return { streamId: sid, frames };
  }

  // 解密一条 WS 消息 → {streamId, type:'response'|'bodyChunk'|'reset', status?, headers?, body?, endBody?} 或 null
  decryptFrame(msg) {
    const plain = this.recv.decryptWithAd(new Uint8Array(0), new Uint8Array(msg));
    const assembled = this.dec.decode(plain);
    if (assembled == null) return null;
    // ServiceResponse{payload}
    const sr = pbRead(assembled);
    const payloadField = pbGet(sr, 1)[0];
    if (!payloadField || payloadField.v.length === 0) throw new Error('empty ServiceResponse payload');
    const sf = pbRead(payloadField.v);
    const streamId = (pbGet(sf, 1)[0] || { v: 0n }).v;
    const kind = (pbGet(sf, 2)[0] || pbGet(sf, 3)[0] || pbGet(sf, 4)[0] || pbGet(sf, 5)[0]);
    if (!kind) return null;
    if (kind.no === 3) { // response
      const rf = pbRead(kind.v);
      const status = Number((pbGet(rf, 1)[0] || { v: 0n }).v);
      const headers = pbGet(rf, 2).map(h => { const hf = pbRead(h.v); return { key: new TextDecoder().decode((pbGet(hf, 1)[0] || { v: new Uint8Array() }).v), value: new TextDecoder().decode((pbGet(hf, 2)[0] || { v: new Uint8Array() }).v) }; });
      const body = (pbGet(rf, 3)[0] || { v: new Uint8Array(0) }).v;
      const endBody = Number((pbGet(rf, 4)[0] || { v: 0n }).v) === 1;
      return { streamId, type: 'response', status, headers, body, endBody };
    }
    if (kind.no === 4) { // bodyChunk
      const bf = pbRead(kind.v);
      const data = (pbGet(bf, 1)[0] || { v: new Uint8Array(0) }).v;
      const endBody = Number((pbGet(bf, 2)[0] || { v: 0n }).v) === 1;
      return { streamId, type: 'bodyChunk', data, endBody };
    }
    if (kind.no === 5) return { streamId, type: 'reset' };
    return null;
  }
}

module.exports = { NoiseXXInitiator, NoiseTransport, x25519Generate, x25519Dh, SVC, pbVarint, pbBytes, pbString, pbFixed64, pbRead, pbGet, pbConcatFields, te };