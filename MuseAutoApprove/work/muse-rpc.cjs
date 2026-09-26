'use strict';
/*
 * muse.ai RPC over Noise WebSocket — Node 复刻 CLI
 *
 * 用法:
 *   node work/muse-rpc.cjs list                       # 拉审批列表 egress.approvals
 *   node work/muse-rpc.cjs detail <approval_id>
 *   node work/muse-rpc.cjs decide <approval_id> <decision> [reason]
 *   node work/muse-rpc.cjs call <method> <json-params> # 任意 RPC（路径需在其路由表中）
 *   node work/muse-rpc.cjs raw <json-spec>             # 发自定义请求（排障用）
 *
 * 数据文件: data/cookies.json      (必填: 至少含 hatch_sess；由 login-lib 自动维护)
 *          data/muse-config.json (可选缓存: {vmId,vmName}；缺失时自动从 /api/session 发现，或设 MUSE_VM_ID)
 * 两者均位于项目根目录下的 data/（首次运行自动创建）。
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { installProxy, createWS } = require('./proxy.cjs');
installProxy();
const { NoiseXXInitiator, NoiseTransport, te, pbVarint, pbBytes, pbString, pbRead, pbGet, pbConcatFields } = require('./muse-noise.cjs');

const paths = require('./paths.cjs');
const COOKIE_PATH = paths.COOKIE_PATH;
const CONFIG_PATH = paths.VM_CONFIG_PATH;
const TOKEN_PATH = paths.TOKEN_PATH;
const APP_ID = 'hatch-web';
let VM_ID = process.env.MUSE_VM_ID || null;   // 支持环境变量直接指定
let VM_NAME = null;

/* vmId 解析（懒加载）: ① MUSE_VM_ID 环境变量 ② data/muse-config.json 缓存 ③ GET /api/session 自动发现（发现后写入缓存） */
async function discoverVmId() {
  if (VM_ID) return;
  try {
    const c = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    if (c && c.vmId) { VM_ID = c.vmId; VM_NAME = c.vmName || VM_ID; return; }
  } catch { /* 无缓存 -> 自动发现 */ }
  const res = await fetch('https://muse.ai/api/session', { headers: { ...BROWSER_HDR, Cookie: cookiesHeader() } });
  if (!res.ok) throw new Error('vmId auto-discovery failed: /api/session http ' + res.status + ' (unauthorized / invalid session?)');
  const j = await res.json();
  const vms = Array.isArray(j.vms) ? j.vms : [];
  const pick = vms.find(v => v && v.is_preferred) || vms[0] || (j.vm_id ? { vm_id: j.vm_id, name: j.vm_name } : null);
  if (!pick || !pick.vm_id) throw new Error('vmId auto-discovery: no VM in /api/session (fallback: create data/muse-config.json with {"vmId":"..."})');
  VM_ID = pick.vm_id; VM_NAME = pick.name || pick.vm_name || VM_ID;
  try { fs.writeFileSync(CONFIG_PATH, JSON.stringify({ vmId: VM_ID, vmName: VM_NAME }, null, 2)); } catch {}
  console.error('vmId auto-discovered: ' + VM_ID);
}
const LB = 'hatch.metaaivm.com';

// 简易路由表（从 scripts/deps/muse-dep-2ksz.js 摘取常用项）
const ROUTES = {
  'egress.approvals': { m: 'GET', path: '/approvals', svc: 'sentinel' },
  'egress.permissions': { m: 'GET', path: '/permissions', svc: 'sentinel' },
  'egress.permissions.scoped': { m: 'GET', path: '/permissions/scopes/{scope_type}/{scope_id}', svc: 'sentinel' },
  'permissions.settings': { m: 'GET', path: '/permissions/settings', svc: 'sentinel' },
  'egress.permissions.active': { m: 'GET', path: '/permissions/active', svc: 'sentinel' },
  'egress.permissions.network_rules': { m: 'PATCH', path: '/permissions/network-rules', svc: 'sentinel' },
  'egress.approval': { m: 'GET', path: '/approvals/{approval_id}', svc: 'sentinel' },
  'egress.approval.decide': { m: 'POST', path: '/approvals/{approval_id}/decide', svc: 'sentinel' },
  'egress.approval.history': { m: 'GET', path: '/approvals/history', svc: 'sentinel' },
  'chat.history': { m: 'GET', path: '/chat/history', svc: 'daemon' },
  'sessions.list': { m: 'GET', path: '/sessions', svc: 'daemon' },
};

const BROWSER_HDR = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0',
  'Accept': '*/*',
  'Accept-Language': 'zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5',
  'Referer': 'https://muse.ai/',
  'Origin': 'https://muse.ai',
  'Sec-Fetch-Dest': 'empty', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Site': 'same-origin',
  'Content-Type': 'application/json',
};

function cookiesHeader() {
  const list = JSON.parse(fs.readFileSync(COOKIE_PATH, 'utf8'));
  // 只发 hatch_sess：全量 cookie（陈旧 hatch_gw 等）会让 token 端点 403
  return list.filter(c => c.name === 'hatch_sess').map(c => `${c.name}=${c.value}`).join('; ');
}

function rollCookiesFromToken(res) {
  try {
    const scs = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    const vals = scs.map(sc => /^hatch_sess=([^;]+)/.exec(sc)).filter(Boolean).map(m => m[1]).filter(v => v && v.length > 10);
    if (!vals.length) return;
    const list = JSON.parse(fs.readFileSync(COOKIE_PATH, 'utf8'));
    let found = false;
    for (const c of list) if (c.name === 'hatch_sess') { c.value = vals[vals.length - 1]; found = true; }
    if (!found) list.push({ name: 'hatch_sess', value: vals[vals.length - 1], domain: '.muse.ai', path: '/' });
    fs.writeFileSync(COOKIE_PATH, JSON.stringify(list, null, 1));
    console.error('hatch_sess rotated by token endpoint -> cookies.json updated');
  } catch (e) { console.error('rollCookiesFromToken failed:', e.message); }
}

async function mintToken() {
  const vmAddress = `https://${VM_ID}.metaaivm.com/`;
  // 403 retry: token 端偶发 opaquely Forbidden（瞬时），重试即可
  let res, txt;
  for (let i = 1; i <= 5; i++) {
    res = await fetch('https://muse.ai/api/hatch/token', {
      method: 'POST',
      headers: { ...BROWSER_HDR, 'Cookie': cookiesHeader() },
      body: JSON.stringify({ vmAddress, vmName: VM_NAME }),
    });
    txt = await res.text();
    if (res.ok) break;
    if (res.status === 403 && i < 5) { console.error(`token 403 retry ${i}/5...`); await new Promise(r => setTimeout(r, 1200)); continue; }
    break;
  }
  if (!res.ok) throw new Error(`token ${res.status}: ${txt.slice(0, 300)}`);
  const j = JSON.parse(txt);
  rollCookiesFromToken(res);
  fs.writeFileSync(TOKEN_PATH, JSON.stringify({ mintedAt: Date.now(), body: JSON.parse(txt) && j }, null, 2));
  return j; // {token, notary_token?, ...}
}

function buildWsUrl(token, notaryToken) {
  const q = new URLSearchParams();
  q.set('vm_id', VM_ID);
  q.set('auth_token', token);
  if (notaryToken) q.set('notary_token', notaryToken);
  q.set('app_id', APP_ID);
  q.set('request_id', crypto.randomUUID());
  return `wss://${LB}/v1/noise?${q.toString()}`;
}

// 连接 + Noise 握手 → NoiseTransport
async function connect() {
  await discoverVmId();
  const cred = await mintToken();
  const url = buildWsUrl(cred.token, cred.notary_token || null);
  const ws = createWS(url);
  ws.binaryType = 'arraybuffer';
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = (e) => rej(new Error('ws error')); ws.onclose = () => rej(new Error('ws closed before open')); });

  const next = () => new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('handshake timeout')), 10000);
    ws.onmessage = (ev) => { clearTimeout(t); ws.onmessage = null; resolve(new Uint8Array(ev.data)); };
    ws.onclose = () => { clearTimeout(t); reject(new Error('ws closed during handshake')); };
  });

  const xx = new NoiseXXInitiator();
  xx.initialize();
  // msg1 payload = protobuf field1 bytes(32 随机 nonce)：[0x0a,0x20,nonce...]
  const nonce = crypto.randomBytes(32);
  const p1 = pbConcatFields([pbBytes(1, nonce)]);
  const m1 = xx.writeMessage1(p1);
  ws.send(m1);
  const m2 = await next();
  const _p2 = xx.readMessage2(m2); // 服务器证据载荷（可选校验，跳过 SNP 验证）
  // msg3: 本项目不需要 RV 挑战时 payload 为空（浏览器实测 msg3=64B）
  const m3 = xx.writeMessage3(new Uint8Array(0));
  ws.send(m3);
  const { send, recv } = xx.split();
  const transport = new NoiseTransport(send, recv);
  return { ws, transport };
}

// 发送 RPC 并等响应（JSON 解析 {ok, result}）
async function rpcCall(conn, method, params = {}) {
  const route = ROUTES[method];
  if (!route) throw new Error('no route for ' + method);
  let p = route.path; const bodyParams = { ...params };
  p = p.replace(/\{([^}]+)\}/g, (_, k) => { const v = bodyParams[k]; if (v === undefined) throw new Error('missing param ' + k); delete bodyParams[k]; return encodeURIComponent(String(v)); });
  const isGet = route.m === 'GET';
  const headers = [
    { key: 'x-request-id', value: crypto.randomUUID() },
    { key: 'x-app-id', value: APP_ID },
    { key: 'Accept-Language', value: 'zh-CN' },
  ];
  const reqPath = isGet ? appendQuery(p, bodyParams) : p;
  const body = isGet ? new Uint8Array(0) : te.encode(JSON.stringify(bodyParams));
  if (!isGet) headers.unshift({ key: 'Content-Type', value: 'application/json' });
  const { streamId, frames } = await conn.transport.encryptHttpRequest({ httpMethod: route.m, path: reqPath, body, service: route.svc || 'daemon', headers });

  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('rpc timeout for ' + method)), 20000);
    let acc = [];
    conn.ws.onmessage = async (ev) => {
      if (!(ev.data instanceof ArrayBuffer)) return;
      try {
        const msg = conn.transport.decryptFrame(new Uint8Array(ev.data));
        if (!msg || msg.streamId.toString() !== streamId.toString()) return;
        if (msg.type === 'response') {
          if (msg.body && msg.body.length) acc.push(Buffer.from(msg.body));
          if (msg.endBody) { clearTimeout(timer); finish(); }
        } else if (msg.type === 'bodyChunk') {
          acc.push(Buffer.from(msg.data));
          if (msg.endBody) { clearTimeout(timer); finish(); }
        } else if (msg.type === 'reset') { clearTimeout(timer); reject(new Error('stream reset')); }
      } catch (e) { clearTimeout(timer); reject(e); }
    };
    conn.ws.onclose = () => { clearTimeout(timer); reject(new Error('ws closed')); };
    function finish() {
      const raw = Buffer.concat(acc).toString('utf8');
      let parsed; try { parsed = JSON.parse(raw); } catch { parsed = raw; }
      if (parsed && typeof parsed === 'object' && parsed.ok === true && 'result' in parsed) resolve(parsed.result);
      else if (parsed && typeof parsed === 'object' && parsed.error) reject(new Error('rpc error: ' + JSON.stringify(parsed.error).slice(0, 400)));
      else resolve(parsed);
    }
    for (const f of frames) conn.ws.send(f);
  });
}

function appendQuery(p, params) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) { if (v === undefined || v === null) continue; q.set(k, typeof v === 'object' ? JSON.stringify(v) : String(v)); }
  const s = q.toString();
  return s ? p + '?' + s : p;
}

async function main() {
  const [cmd, a1, a2, a3, ...rest] = process.argv.slice(2);
  const conn = await connect();
  try {
    if (cmd === 'raw') {
      // 直接发自定义 {httpMethod,path,body,service,headers} — 排障用
      const spec = JSON.parse(a1);
      spec.body = spec.body ? new Uint8Array(Buffer.from(spec.body, 'base64')) : new Uint8Array(0);
      const { streamId, frames } = await conn.transport.encryptHttpRequest(spec);
      console.log('sent streamId', streamId.toString(), 'frames', frames.length);
      const out = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('timeout')), 15000);
        let acc = [];
        conn.ws.onmessage = (ev) => {
          if (!(ev.data instanceof ArrayBuffer)) return;
          const msg = conn.transport.decryptFrame(new Uint8Array(ev.data));
          if (!msg) return;
          if (msg.type === 'response' || msg.type === 'bodyChunk') {
            acc.push(Buffer.from(msg.body || msg.data));
            if (msg.endBody) { clearTimeout(timer); resolve(Buffer.concat(acc)); }
          }
        };
      });
      console.log(out.toString('utf8').slice(0, 4000));
      return;
    }
    if (cmd === 'list') {
      const r = await rpcCall(conn, 'egress.approvals', {});
      console.log(JSON.stringify(r, null, 2).slice(0, 6000));
      return;
    }
    if (cmd === 'detail') {
      const r = await rpcCall(conn, 'egress.approval', { approval_id: a1 });
      console.log(JSON.stringify(r, null, 2).slice(0, 6000));
      return;
    }
    if (cmd === 'history') {
      const r = await rpcCall(conn, 'egress.approval.history', a1 ? { cursor: a1 } : {});
      console.log(JSON.stringify(r, null, 2).slice(0, 6000));
      return;
    }
    if (cmd === 'decide') {
      // decide <approval_id> <decision> [reason]
      const params = { approval_id: a1, decision: a2 };
      if (a3) params.reason = a3;
      const r = await rpcCall(conn, 'egress.approval.decide', params);
      console.log(JSON.stringify(r, null, 2).slice(0, 6000));
      return;
    }
    if (cmd === 'call') {
      const r = await rpcCall(conn, a1, JSON.parse(a2 || '{}'));
      console.log(JSON.stringify(r, null, 2).slice(0, 6000));
      return;
    }
    console.log('usage: list | detail <id> | history [cursor] | decide <id> <decision> [reason] | call <method> <json> | raw <json>');
  } finally {
    try { conn.ws.close(); } catch {}
  }
}

if (require.main === module) { main().catch(e => { console.error('ERR:', e.message); process.exit(1); }); }
module.exports = { connect, rpcCall, ROUTES, mintToken, COOKIE_PATH, DATA_DIR: paths.DATA_DIR, LOG_DIR: paths.LOG_DIR };