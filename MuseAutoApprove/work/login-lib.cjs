'use strict';
/*
 * muse.ai 全自动登录库 (v2)
 *
 * 凭据来源优先级（resolveCredentials）：
 *   1) 环境变量 MUSE_USER / MUSE_PASSWORD（MUSE_EMAIL 也可当邮箱用）
 *   2) data/credentials.json  { "email": "...", "password": "..." }
 *   两处都没有时抛 code=NO_CREDENTIALS 的友好错误（调用方负责提示用户）。
 *
 * 链路（网络默认直连；设置 MUSE_PROXY 后全部经该代理）：
 *   POST /api/auth/native/restart                     -> csrf_token + password_encryption(公钥/keyId) + cookie 组
 *   POST /api/auth/native/send-otp {contact_point}    -> otp_sent（必须步骤，会发一封验证码邮件；无需读码）
 *   POST /api/auth/native/confirm-password {password} -> 200 {redirect_to, auth_meta_session} + Set-Cookie hatch_sess(30天)
 *
 * 密码信封（复刻 chunk-auth-native.js cG()）：
 *   h = [1, keyId, u16le sealLen] + seal + aesTag(16) + aesCt
 *   seal  = crypto_box_seal(AESkey32, serverPk)                  (libsodium sealed box)
 *   aesCt = AES-256-GCM(key=AESkey32, iv=12*0x00, aad=String(ts), pt=password)
 *   形如: #PWD_BROWSER:5:<ts>:<b64>
 */
const fs = require('fs');
const { installProxy } = require('./proxy.cjs');
installProxy();
let sodi = null;
try { sodi = require('sodium-native'); } catch { /* 缺失时在 buildBlob 里给出明确错误 */ }
const { webcrypto, randomBytes } = require('crypto');

const paths = require('./paths.cjs');
const CRED_PATH = paths.CRED_PATH;
const COOKIE_PATH = paths.COOKIE_PATH;
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0';

/* 凭据解析：env 优先 -> credentials.json；都缺失时抛 NO_CREDENTIALS */
function resolveCredentials(opts = {}) {
  const envE = process.env.MUSE_USER || process.env.MUSE_EMAIL || '';
  const envP = process.env.MUSE_PASSWORD || '';
  let fileE = '', fileP = '', fileFound = false;
  if (fs.existsSync(CRED_PATH)) {
    try {
      const j = JSON.parse(fs.readFileSync(CRED_PATH, 'utf8'));
      fileE = j.email || j.username || '';
      fileP = j.password || '';
      fileFound = true;
    } catch { /* 损坏的 credentials.json 视为不存在，由下方统一提示 */ }
  }
  const email = opts.email || envE || fileE;
  const password = opts.password || envP || fileP;
  let source;
  if (opts.email || opts.password) source = 'argument';
  else if (envE && envP) source = 'env';
  else if (fileE && fileP) source = 'file';
  else source = 'mixed';
  if (!email || !password) {
    const e = new Error(
      '缺少登录凭据，无法自动登录。请任选其一配置后重试：\n' +
      '  [A] 设置环境变量（推荐）:  MUSE_USER=你的邮箱   MUSE_PASSWORD=你的密码\n' +
      '  [B] 创建文件 ' + CRED_PATH + '\n' +
      '      内容: {"email":"你的邮箱","password":"你的密码"}\n' +
      (fileFound ? '  ⚠ 检测到 credentials.json 但 email/password 字段不完整\n' : '') +
      (envE || envP ? '  ⚠ 检测到环境变量但 MUSE_USER / MUSE_PASSWORD 不完整\n' : '')
    );
    e.code = 'NO_CREDENTIALS';
    throw e;
  }
  return { email, password, source };
}

async function buildBlob(password, pk, keyId, ts) {
  if (!sodi) throw new Error('sodium-native 未安装（npm i sodium-native），无法构造密码信封');
  const t = String(pk).trim();
  const pkBytes = Buffer.from(t, /^[0-9a-fA-F]{64}$/.test(t) ? 'hex' : 'base64');
  if (pkBytes.length !== 32) throw new Error('bad server pubkey len ' + pkBytes.length);
  const aesKey = randomBytes(32);
  const seal = Buffer.alloc(32 + sodi.crypto_box_SEALBYTES);
  sodi.crypto_box_seal(seal, aesKey, pkBytes);
  const key = await webcrypto.subtle.importKey('raw', aesKey, 'AES-GCM', false, ['encrypt']);
  const ct = Buffer.from(await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: new Uint8Array(12), additionalData: Buffer.from(String(ts), 'utf8'), tagLength: 128 },
    key, Buffer.from(password, 'utf8')));
  const tag = ct.subarray(ct.length - 16), body = ct.subarray(0, ct.length - 16);
  const h = Buffer.alloc(4 + seal.length + 16 + body.length);
  h[0] = 1; h[1] = keyId & 0xff; h[2] = seal.length & 0xff; h[3] = (seal.length >> 8) & 0xff;
  seal.copy(h, 4); tag.copy(h, 4 + seal.length); body.copy(h, 4 + seal.length + 16);
  return `#PWD_BROWSER:5:${ts}:${Buffer.from(h).toString('base64')}`;
}

async function login(opts = {}) {
  const cred = resolveCredentials(opts);
  const EMAIL = cred.email;
  const PASSWORD = cred.password;
  const log = opts.log || (() => {});
  const jar = new Map();
  const jarHeader = () => [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  const jarUpdate = (sets) => {
    for (const sc of sets) {
      const m = /^([^=]+)=([^;]*)/.exec(sc); if (!m) continue;
      const n = m[1].trim(), v = m[2];
      if (/expires=Thu, 01 Jan 1970/i.test(sc)) jar.delete(n); else jar.set(n, v);
    }
  };
  async function call(p, body, extra = {}) {
    let res, lastErr;
    for (let i = 1; i <= 6; i++) {
      try {
        res = await fetch('https://muse.ai' + p, {
          method: 'POST', redirect: 'manual',
          headers: {
            'Content-Type': 'application/json', Accept: '*/*',
            Origin: 'https://muse.ai', Referer: 'https://muse.ai/login',
            'Sec-Fetch-Dest': 'empty', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Site': 'same-origin',
            'User-Agent': UA, ...(jar.size ? { Cookie: jarHeader() } : {}), ...extra,
          },
          body: typeof body === 'string' ? body : JSON.stringify(body ?? {}),
        });
        break;
      } catch (e) { lastErr = e; await new Promise(r => setTimeout(r, 2000)); }
    }
    if (!res) throw lastErr;
    const setCookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    jarUpdate(setCookies);
    const text = await res.text();
    let json = null; try { json = JSON.parse(text); } catch {}
    return { status: res.status, location: res.headers.get('location'), setCookies, json, text: json ? undefined : text.slice(0, 400) };
  }

  // 1) restart
  let r = await call('/api/auth/native/restart', {});
  if (r.status !== 201) throw new Error(`restart ${r.status}: ${JSON.stringify(r.json ?? r.text).slice(0, 200)}`);
  const csrf = r.json.csrf_token, pe = r.json.password_encryption;
  if (!csrf || !pe) throw new Error('restart missing csrf/password_encryption');
  log('login: restart ok, keyId=' + pe.key_id);

  // 2) send-otp（服务端要求的前置步骤；邮件验证码无需读取）
  r = await call('/api/auth/native/send-otp', { contact_point: EMAIL }, { 'X-Hatch-Csrf-Token': csrf });
  if (r.status !== 201 && r.status !== 200) throw new Error(`send-otp ${r.status}: ${JSON.stringify(r.json ?? r.text).slice(0, 200)}`);
  log('login: send-otp ok ' + JSON.stringify(r.json).slice(0, 120));

  // 3) confirm-password
  const ts = Math.floor(Date.now() / 1000);
  const blob = await buildBlob(PASSWORD, pe.public_key, pe.key_id, ts);
  const cp = await call('/api/auth/native/confirm-password', { password: blob }, { 'X-Hatch-Csrf-Token': csrf });
  if (cp.status !== 200) throw new Error(`confirm-password ${cp.status}: ${JSON.stringify(cp.json ?? cp.text).slice(0, 200)}`);
  let sess = null;
  for (const sc of cp.setCookies) { const m = /^hatch_sess=([^;]+)/.exec(sc); if (m && m[1]) sess = m[1]; }
  if (!sess) throw new Error('confirm-password ok but no hatch_sess returned');
  log('login: confirm-password ok, got session (' + sess.slice(0, 36) + '...)');

  // 写入 cookies.json（文件不存在时自动创建；存在时备份旧值）
  let list = [];
  if (fs.existsSync(COOKIE_PATH)) {
    try {
      const cj = fs.readFileSync(COOKIE_PATH, 'utf8');
      try { fs.writeFileSync(COOKIE_PATH + '.bak.' + Date.now(), cj); } catch {}
      const parsed = JSON.parse(cj);
      if (Array.isArray(parsed)) list = parsed;
    } catch {}
  }
  let found = false;
  for (const c of list) if (c.name === 'hatch_sess') { c.value = sess; found = true; }
  if (!found) list.push({ name: 'hatch_sess', value: sess, domain: '.muse.ai', path: '/' });
  fs.writeFileSync(COOKIE_PATH, JSON.stringify(list, null, 1));

  return { sess, frlAccountId: cp.json && cp.json.auth_meta_session && cp.json.auth_meta_session.frl_account_id, redirectTo: cp.json && cp.json.redirect_to, source: cred.source };
}

module.exports = { login, buildBlob, resolveCredentials };

if (require.main === module) {
  login({ log: console.log }).then(r => {
    console.log('LOGIN OK. source=' + r.source + ' frl_account_id =', r.frlAccountId, 'redirect_to =', r.redirectTo);
  }).catch(e => {
    if (e.code === 'NO_CREDENTIALS') { console.error('\n' + e.message + '\n'); process.exit(2); }
    console.error('LOGIN FAIL:', e.message); process.exit(1);
  });
}