'use strict';
/*
 * login-guard：自动登录熔断。宁可停下等人工，也不要循环请求登录验证码。
 *
 * 每次自动登录都会发一封 OTP 邮件。会话失效 + 登录失败 + 守护被拉起重试，
 * 叠加起来可以在几天内发出上万次 send-otp，直接触发账号风控。本模块：
 *   - 把每次自动登录记入 data/login-attempts.json；WINDOW_MS 内超过 MAX_ATTEMPTS 次 -> 熔断
 *   - 登录失败且像是 验证码/限流/send-otp 被拒（429 / loginCodeSendFailed / try again ...） -> 熔断
 *   - token 端点返回 hatch_vm_auth_no_match（VM 绑定问题，重新登录解决不了） -> 熔断
 * 熔断 = 写 data/LOGIN_BLOCKED（持久标记）+ 打 CRITICAL 日志 + 可选通知钩子（只跑一次），
 *        调用方以 BLOCK_EXIT(75) 退出；守护启动时发现标记直接拒绝运行。
 *
 * 环境变量：
 *   MUSE_GUARD_MAX     窗口内允许的自动登录次数（默认 2）
 *   MUSE_GUARD_WINDOW_H 窗口小时数（默认 6）
 *   MUSE_GUARD_NOTIFY  熔断时执行的可执行文件，参数为一行说明文字（默认不执行）
 *   MUSE_GUARD_DATA    标记/计数文件目录（默认 data/，即 paths.DATA_DIR）
 * 非法的 MUSE_GUARD_MAX / MUSE_GUARD_WINDOW_H 回退到默认值，避免静默关掉熔断。
 * NO_CREDENTIALS 在发验证码之前就返回：不计入次数、不写标记，调用方仍以退出码 2 结束。
 * 解除：人工登录确认账号正常后  rm data/LOGIN_BLOCKED data/login-attempts.json
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const paths = require('./paths.cjs');
const DATA = process.env.MUSE_GUARD_DATA || paths.DATA_DIR;
const MARKER = path.join(DATA, 'LOGIN_BLOCKED');
const ATTEMPTS = path.join(DATA, 'login-attempts.json');
const NOTIFY = process.env.MUSE_GUARD_NOTIFY || '';
function envNonNegInt(name, dflt) {
  const raw = process.env[name];
  if (raw == null || raw === '') return dflt;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : dflt;
}
function envPositiveFloat(name, dflt) {
  const raw = process.env[name];
  if (raw == null || raw === '') return dflt;
  const n = parseFloat(raw);
  return Number.isFinite(n) && n > 0 ? n : dflt;
}
const MAX_ATTEMPTS = envNonNegInt('MUSE_GUARD_MAX', 2);
const WINDOW_MS = envPositiveFloat('MUSE_GUARD_WINDOW_H', 6) * 3600 * 1000;
function ensureData() { fs.mkdirSync(DATA, { recursive: true }); }
const BLOCK_EXIT = 75;
const CLEAR_HINT = 'rm data/LOGIN_BLOCKED data/login-attempts.json';
const BLOCK_RE = /\b429\b|too many|rate.?limit|try again|again later|throttl|captcha|verif|otp required|code required|2fa|稍后|过几分钟|频繁|验证码/i;

function isBlockingError(e) {
  const s = String((e && e.message) || e) + ' ' + String((e && e.code) || '');
  if (e && e.code === 'NO_CREDENTIALS') return false;
  if (BLOCK_RE.test(s)) return true;
  // send-otp / confirm-password 非 2xx：服务端拒绝了 OTP/密码步骤，重试只会继续发邮件
  return /send-otp (failed|[45]\d\d)|loginCodeSend|confirm-password (failed|[45]\d\d)|no hatch_sess/i.test(s);
}
function isVmAuthNoMatch(e) { return /hatch_vm_auth_no_match|Gateway VM auth token unavailable/i.test(String((e && e.message) || e)); }
function isBlocked() { return fs.existsSync(MARKER); }
function readMarker() { try { return JSON.parse(fs.readFileSync(MARKER, 'utf8')); } catch { return null; } }
function loadAttempts() {
  try { const a = JSON.parse(fs.readFileSync(ATTEMPTS, 'utf8')); return Array.isArray(a) ? a.filter(n => Number.isFinite(n)) : []; } catch { return []; }
}
function recentAttempts(now = Date.now()) { return loadAttempts().filter(t => now - t < WINDOW_MS); }
function recordAttempt(now = Date.now()) {
  ensureData();
  const a = recentAttempts(now); a.push(now);
  fs.writeFileSync(ATTEMPTS, JSON.stringify(a), { mode: 0o600 });
  return now;
}
/* 缺凭据的尝试没有发出验证码，从窗口里撤掉，避免几次 exit 2 之后被 attempt_cap 熔断 */
function forgetAttempt(ts) {
  const a = loadAttempts();
  const i = a.lastIndexOf(ts);
  if (i >= 0) a.splice(i, 1);
  if (a.length === 0) { try { fs.rmSync(ATTEMPTS); } catch {} return; }
  fs.writeFileSync(ATTEMPTS, JSON.stringify(a), { mode: 0o600 });
}
/* 写标记（已存在则不覆盖、不重复通知），返回 code=LOGIN_BLOCKED 的错误供调用方抛出 */
function tripBlock(reason, detail, log = console.error) {
  if (!isBlocked()) {
    ensureData();
    const m = { reason, detail: String(detail || '').slice(0, 300), at: new Date().toISOString(),
      attempts_in_window: recentAttempts().length, host: os.hostname(), notified: false, clear: CLEAR_HINT };
    fs.writeFileSync(MARKER, JSON.stringify(m, null, 2) + '\n', { mode: 0o600 });
    log({ event: 'LOGIN_BLOCKED', level: 'CRITICAL', reason, detail: m.detail, marker: MARKER,
      msg: 'muse 自动登录已熔断（验证码/限流/VM 鉴权），不再请求验证码。人工处理后执行: ' + CLEAR_HINT });
    if (NOTIFY) {
      try {
        const r = require('child_process').spawnSync(NOTIFY, [`[${m.host}] MuseAutoApprove 已停止：自动登录熔断（${reason}），不会再发验证码。人工处理后执行 ${CLEAR_HINT}`], { timeout: 30000 });
        m.notified = r.status === 0;
        fs.writeFileSync(MARKER, JSON.stringify(m, null, 2) + '\n', { mode: 0o600 });
      } catch (e) { log({ event: 'LOGIN_BLOCKED_notify_error', error: e.message }); }
    }
  }
  const err = new Error('LOGIN_BLOCKED: ' + reason); err.code = 'LOGIN_BLOCKED'; return err;
}
/* 包装 login()：已熔断/超次数直接拒绝；失败按类型决定是否熔断 */
function guardedLogin(login, opts, log) {
  return (async () => {
    if (isBlocked()) throw Object.assign(new Error('LOGIN_BLOCKED marker present'), { code: 'LOGIN_BLOCKED' });
    if (recentAttempts().length >= MAX_ATTEMPTS) throw tripBlock('attempt_cap', `>= ${MAX_ATTEMPTS} auto-logins within window`, log);
    const ts = recordAttempt();
    try { return await login(opts); }
    catch (e) {
      if (e && e.code === 'NO_CREDENTIALS') { try { forgetAttempt(ts); } catch {} throw e; }
      if (isBlockingError(e)) throw tripBlock('login_refused', e.message, log);
      throw e;
    }
  })();
}
module.exports = { isVmAuthNoMatch, guardedLogin, isBlocked, readMarker, tripBlock, isBlockingError, recentAttempts, MARKER, ATTEMPTS, BLOCK_EXIT, MAX_ATTEMPTS, CLEAR_HINT };
