'use strict';
/*
 * muse.ai 一体化守护进程 v2：自动登录 + 全自动审批（allow_always 永久允许）
 *
 * 用法:
 *   node muse-daemon.cjs                 # 常驻（默认 --loop 10000 --always --fallback-once）
 *   node muse-daemon.cjs --once          # 一次巡检
 *   node muse-daemon.cjs --check         # 体检：凭据来源 + 会话状态（本地读取、不出网）
 *   node muse-daemon.cjs --smoke         # 真测一次全自动登录链路（会发一封验证码邮件），然后退出
 *   可选: --loop <ms> / --decision xxx / --scope xxx / --fallback-once / --no-fallback / --dry
 *
 * 凭据: 环境变量 MUSE_USER / MUSE_PASSWORD 优先；其次 data/credentials.json；
 *       两者都没有且无会话 -> 打印友好提示后退出（退出码 2），不会崩溃。
 * 行为:
 *   1) 会话保活: 每 5 分钟 token touch（轮换 hatch_sess 写回 cookies.json => 30 天窗口永续）
 *   2) 审批轮询: 每 interval 扫 egress.approvals -> 对 pending 单发 allow_always(destination_domain)
 *   3) 自愈: cookie 文件丢失 / 会话失效 -> 自动全链登录（发 1 封邮件，无需读码）-> 重连继续
 *
 * 日志: log/daemon-log.ndjson + log/auto-approve-log.ndjson（decide 记录同格式）
 * 停止: 写 data/muse-daemon.stop 或 Ctrl+C
 */
const fs = require('fs');
const paths = require('./work/paths.cjs');
const { installProxy, PROXY } = require('./work/proxy.cjs');
installProxy();
const { login, resolveCredentials } = require('./work/login-lib.cjs');

const DLOG = paths.DAEMON_LOG_PATH;
const ALOG = paths.AUTO_APPROVE_LOG_PATH;
const STOP = paths.DAEMON_STOP_PATH;
const PIDF = paths.DAEMON_PID_PATH;
const COOKIE_PATH = paths.COOKIE_PATH;
const CONSOLE_LOG = paths.LOG_DIR + '/muse-console.log';
const TOUCH_MS = 5 * 60 * 1000;
const LOG_TRIM_MS  = 60 * 60 * 1000;      // 每小时检查一次日志体积
const LOG_MAX_BYTES = 10 * 1024 * 1024;   // 单文件超过 10MB 触发裁剪，裁剪后保留末尾 ≤ 10MB

function log(obj, toAlog) {
  const line = JSON.stringify({ ts: Date.now(), ...obj });
  try { fs.appendFileSync(DLOG, line + '\n'); } catch {}
  if (toAlog) { try { fs.appendFileSync(ALOG, line + '\n'); } catch {} }
  console.log(line);
}

/* 日志裁剪：单文件超过 LOG_MAX_BYTES 时保留末尾若干整行、总量压回上限内（追加写入，mv 替换安全） */
function trimLog(file) {
  try {
    const st = fs.statSync(file);
    if (st.size <= LOG_MAX_BYTES) return;
    const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
    // 从末尾向前累加，直到再加一行就超过上限为止（保证裁剪后 ≤ 10MB，而不是固定行数）
    const kept = [];
    let bytes = 0;
    for (let i = lines.length - 1; i >= 0; i--) {
      const lineBytes = Buffer.byteLength(lines[i], 'utf8') + 1;
      if (bytes + lineBytes > LOG_MAX_BYTES) break;
      kept.push(lines[i]);
      bytes += lineBytes;
    }
    kept.reverse();
    fs.writeFileSync(file, kept.join('\n') + '\n');
    console.error(`[log-trim] ${file} 已裁剪（保留末 ${kept.length} 行，约 ${Math.round(bytes / 1024 / 1024 * 10) / 10}MB）`);
  } catch {}
}

/* 会话体检（本地读取，不出网） */
function daysText(st) { return st.expiresInDays != null ? ('hatch_sess 约剩 ' + st.expiresInDays + ' 天') : 'hatch_sess 有效（过期时间未能从 token 解析，按 30 天计）'; }
function sessionStatus() {
  const out = { cookieFile: false, session: false, expiresInDays: null, expired: null };
  let list;
  try { list = JSON.parse(fs.readFileSync(COOKIE_PATH, 'utf8')); } catch { return out; }
  out.cookieFile = true;
  const c = Array.isArray(list) ? list.find(x => x && x.name === 'hatch_sess') : null;
  if (c && typeof c.value === 'string' && c.value.length > 10) {
    out.session = true;
    try {
      const b64 = String(c.value).split('.')[0].replace(/-/g, '+').replace(/_/g, '/');
      const payload = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
      if (payload && payload.exp) {
        const secs = payload.exp - Math.floor(Date.now() / 1000);
        out.expiresInDays = Math.round(secs / 8640) / 10;
        out.expired = secs <= 0;
      }
    } catch {}
  }
  return out;
}

function parseArgs(argv) {
  const a = { mode: 'loop', interval: 10000, decision: 'allow_always', scope: 'destination_domain', fallbackOnce: true, dry: false, check: false, smoke: false };
  for (let i = 0; i < argv.length; i++) {
    const v = argv[i];
    if (v === '--once') a.mode = 'once';
    else if (v === '--check') a.check = true;
    else if (v === '--smoke') a.smoke = true;
    else if (v === '--loop') { a.mode = 'loop'; if (argv[i + 1] && /^\d+$/.test(argv[i + 1])) a.interval = parseInt(argv[++i], 10); }
    else if (v === '--decision') a.decision = argv[++i];
    else if (v === '--always') { a.decision = 'allow_always'; if (!a.scope) a.scope = 'destination_domain'; }
    else if (v === '--scope') a.scope = argv[++i];
    else if (v === '--fallback-once') a.fallbackOnce = true;
    else if (v === '--no-fallback') a.fallbackOnce = false;
    else if (v === '--dry') a.dry = true;
  }
  if ((a.decision === 'allow_always' || a.decision === 'deny_always') && !a.scope) a.scope = 'destination_domain';
  return a;
}

function buildDecideParams(id, opts) {
  const p = { approval_id: id, decision: opts.decision };
  if ((opts.decision === 'allow_always' || opts.decision === 'deny_always') && opts.scope) {
    p.always_scope = opts.scope;
    if (opts.decision === 'allow_always') p.allow_always_scope = opts.scope;
  }
  return p;
}

/* 需要重新登录的错误判定：cookie 文件丢失 / 会话失效 / token 拒绝 */
function needsLogin(e) {
  const s = String((e && e.message) || e);
  return /ENOENT|token (401|403)|unauthor|forbidden|invalid session/i.test(s);
}

async function sweep(conn, opts, rpc) {
  let list;
  try { list = await rpc.rpcCall(conn, 'egress.approvals', {}); }
  catch (e) { log({ event: 'list_error', error: e.message }, true); throw e; }
  const pending = (list && list.pending) || [];
  const pa = (list && list.pending_approvals) || [];
  const ids = new Set([...pending.map(p => p.approval_id), ...pa.map(p => p.approval_id)].filter(Boolean));
  if (ids.size === 0) { log({ event: 'heartbeat', pending: 0 }, true); return 0; }
  log({ event: 'pending_found', count: ids.size, ids: [...ids] }, true);
  let done = 0;
  for (const id of ids) {
    if (opts.dry) { log({ event: 'dry_skip', approval_id: id }, true); continue; }
    try {
      const r = await rpc.rpcCall(conn, 'egress.approval.decide', buildDecideParams(id, opts));
      const a = (r && r.approval) || {};
      log({ event: 'decided', approval_id: id, decision: opts.decision, scope: opts.scope, status: a.status, applied_rules: Array.isArray(a.applied_rule_entries) ? a.applied_rule_entries.length : null }, true);
      done++;
    } catch (e) {
      log({ event: 'decide_error', approval_id: id, error: e.message }, true);
      if (opts.fallbackOnce && opts.decision !== 'allow_once') {
        try {
          const r2 = await rpc.rpcCall(conn, 'egress.approval.decide', { approval_id: id, decision: 'allow_once' });
          log({ event: 'decided_fallback', approval_id: id, status: (r2.approval || {}).status }, true);
          done++;
        } catch (e2) { log({ event: 'fallback_error', approval_id: id, error: e2.message }, true); }
      }
    }
  }
  return done;
}

/* 带自愈的连接：会话类错误（ENOENT/401/403）自动登录（最多 4 轮）；网络抖动直接重试 */
async function connectWithHeal(rpc) {
  let lastErr = null;
  for (let i = 1; i <= 4; i++) {
    try { return await rpc.connect(); }
    catch (e) {
      lastErr = e;
      log({ event: 'connect_retry', attempt: i, error: e.message });
      if (needsLogin(e)) {
        try {
          const r = await login({ log: m => log({ event: 'login', msg: m }) });
          log({ event: 'auto_login_ok', frlAccountId: r.frlAccountId, credentialSource: r.source });
        } catch (e2) {
          log({ event: 'auto_login_error', error: e2.message, code: e2.code || null });
          if (e2.code === 'NO_CREDENTIALS') throw e2;
        }
      }
      await new Promise(r => setTimeout(r, 2000));
    }
  }
  throw lastErr;
}

(async () => {
  const opts = parseArgs(process.argv.slice(2));

  /* ---- 体检模式：只本地读，不出网，不写 pid ---- */
  if (opts.check) {
    let credInfo = null, credErr = null;
    try { const c = resolveCredentials({}); credInfo = { email: c.email, source: c.source }; }
    catch (e) { credErr = e; }
    const st = sessionStatus();
    const srcMap = { env: '环境变量 MUSE_USER/MUSE_PASSWORD', file: 'data/credentials.json', mixed: '环境变量+文件混合（可能不完整）', argument: '命令行参数' };
    console.log('--- muse-daemon 体检（本地，不出网） ---');
    console.log('网络: ' + (PROXY ? '经代理 ' + PROXY : '直连（未设置 MUSE_PROXY）'));
    if (credInfo) console.log('凭据: OK (' + credInfo.email + '，来源: ' + (srcMap[credInfo.source] || credInfo.source) + ')');
    else console.log('凭据: 缺失 (' + (credErr && credErr.code === 'NO_CREDENTIALS' ? '无环境变量且无 credentials.json' : credErr.message) + ')');
    console.log('会话: ' + (!st.cookieFile ? '无 cookies.json（需要自动登录）'
      : !st.session ? 'cookies.json 存在但无 hatch_sess（需要自动登录）'
      : st.expired ? 'hatch_sess 已过期（需要自动登录）'
      : 'OK（' + daysText(st) + '）'));
    const ok = !!credInfo || (st.session && !st.expired);
    console.log('结论: ' + (ok
      ? '可以启动（node muse-daemon.cjs）' + (!credInfo ? ' —— 注意：当前仅靠现有会话运行，建议尽快配置凭据' : '')
      : '无法全自动启动 —— 请配置凭据（见上）或先运行 node work/login-lib.cjs'));
    process.exit(ok ? 0 : 2);
  }

  /* ---- smoke：真跑一次全自动登录链路（会发一封邮件），然后退出 ---- */
  if (opts.smoke) {
    log({ event: 'smoke_start' });
    try {
      const r = await login({ log: m => log({ event: 'login', msg: m }) });
      log({ event: 'smoke_ok', frlAccountId: r.frlAccountId, credentialSource: r.source });
      console.log('SMOKE OK: 登录链路全通（凭据来源: ' + r.source + '）。');
      process.exit(0);
    } catch (e) {
      log({ event: 'smoke_error', error: e.message, code: e.code || null });
      if (e.code === 'NO_CREDENTIALS') { console.error('\n' + e.message + '\n'); process.exit(2); }
      console.error('SMOKE FAIL:', e.message); process.exit(1);
    }
  }

  /* ---- pid-guard：已有守护在跑则退出 ---- */
  try {
    const old = parseInt(fs.readFileSync(PIDF, 'utf8'), 10);
    if (old && old !== process.pid) {
      try { process.kill(old, 0); console.error('another muse-daemon is already running: pid ' + old + ' -> exit'); process.exit(0); }
      catch {}
    }
  } catch {}

  /* ---- 启动体检：无凭据且无会话 -> 友好提示退出（而不是崩溃） ---- */
  {
    let credOk = false, credEmail = '', credSource = '';
    try { const c = resolveCredentials({}); credOk = true; credEmail = c.email; credSource = c.source; }
    catch (e) {
      if (e.code !== 'NO_CREDENTIALS') throw e;
      const st = sessionStatus();
      if (st.session && !st.expired) {
        console.log('提示: 未配置登录凭据，但检测到有效会话（' + daysText(st) + '），仍可直接运行。');
      } else {
        console.error('\n==================== 无法启动 ====================');
        console.error('没有可用的登录凭据，也没有有效会话 cookie（' + (st.cookieFile ? 'hatch_sess 缺失或已过期' : 'cookies.json 不存在') + '）。');
        console.error('请任选其一配置后重试：');
        console.error('  [A] 环境变量:  MUSE_USER=你的邮箱   MUSE_PASSWORD=你的密码');
        console.error('  [B] 文件:      ' + paths.CRED_PATH);
        console.error('                内容: {"email":"你的邮箱","password":"你的密码"}');
        console.error('');
        console.error('说明: 自动登录会往邮箱发一封验证码邮件（无需读取）；30 天内登录过一次后会话自动永续，');
        console.error('      平时不再需要重新登录。配置好后运行:  node muse-daemon.cjs');
        console.error('==================================================\n');
        process.exit(2);
      }
    }
    if (credOk) console.log('凭据就绪（' + credEmail + '，来源: ' + credSource + '）。');
  }
  try { fs.writeFileSync(PIDF, String(process.pid)); } catch {}

  log({ event: 'daemon_start', mode: opts.mode, interval: opts.interval, decision: opts.decision, scope: opts.scope, fallbackOnce: opts.fallbackOnce, pid: process.pid, proxy: PROXY || 'direct' });
  const rpc = require('./work/muse-rpc.cjs');
  let conn = await connectWithHeal(rpc);
  log({ event: 'connected', pid: process.pid });
  if (opts.mode === 'once') {
    const n = await sweep(conn, opts, rpc);
    log({ event: 'once_done', decided: n });
    try { conn.ws.close(); } catch {}
    process.exit(0);
  }
  let stopped = false;
  process.on('SIGINT', () => { stopped = true; log({ event: 'sigint' }); try { conn.ws.close(); } catch {} process.exit(0); });
  let lastTouch = Date.now();  // connect() 刚 mint 过 token，无需立刻再 touch
  let lastTrim  = Date.now();  // 日志裁剪计时器
  while (!stopped) {
    if (fs.existsSync(STOP)) { log({ event: 'stop_file' }); break; }
    // 日志裁剪（每小时一次，防长期运行撑满磁盘）
    if (Date.now() - lastTrim > LOG_TRIM_MS) {
      lastTrim = Date.now();
      trimLog(DLOG); trimLog(ALOG); trimLog(CONSOLE_LOG);
    }
    if (Date.now() - lastTouch > TOUCH_MS) {
      try { await rpc.mintToken(); lastTouch = Date.now(); log({ event: 'session_touch_ok' }); }
      catch (e) {
        log({ event: 'session_touch_error', error: e.message });
        if (needsLogin(e)) {
          try {
            const r = await login({ log: m => log({ event: 'login', msg: m }) });
            log({ event: 'auto_login_ok', frlAccountId: r.frlAccountId, credentialSource: r.source });
            lastTouch = Date.now();
          } catch (e2) { log({ event: 'auto_login_error', error: e2.message, code: e2.code || null }); }
        }
      }
    }
    try {
      await sweep(conn, opts, rpc);
    } catch (e) {
      log({ event: 'sweep_error', error: e.message });
      try { conn.ws.close(); } catch {}
      await new Promise(r => setTimeout(r, 1500));
      try { conn = await connectWithHeal(rpc); log({ event: 'reconnected' }); }
      catch (e2) { log({ event: 'reconnect_error', error: e2.message }); await new Promise(r => setTimeout(r, 5000)); }
    }
    await new Promise(r => setTimeout(r, opts.interval));
  }
  try { conn.ws.close(); } catch {}
  process.exit(0);
})().catch(e => {
  if (e && e.code === 'NO_CREDENTIALS') { console.error('\n' + e.message + '\n'); process.exit(2); }
  console.error('DAEMON FATAL:', (e && e.message) || e);
  process.exit(1);
});