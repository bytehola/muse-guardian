'use strict';
/*
 * muse.ai 审批自动批准器 v2 (auto-approve)
 * 依赖: muse-rpc.cjs（已模块化导出 connect/rpcCall）
 *
 * 用法:
 *   node work/auto-approve.cjs --once                      # 拉一次 pending，逐条 allow_once
 *   node work/auto-approve.cjs --once --always             # 永久模式: allow_always + scope=destination_domain
 *   node work/auto-approve.cjs --loop 10000 --always       # 永久模式持续挂机
 *   node work/auto-approve.cjs --once --always --fallback-once   # allow_always 失败时回退 allow_once
 *   node work/auto-approve.cjs --once --decision allow_session
 *   node work/auto-approve.cjs --once --dry                # 只看不批（演练）
 *
 * decision 说明:
 *   allow_once    仅本次(默认)
 *   allow_session 本任务期间(UI: Allow for this task)
 *   allow_always  永久允许(UI: Always allow) —— 必须带 scope:
 *                   - 普通网络审批: destination_domain (UI: Always allow this site)
 *                   - deny_always 同样带 scope
 *   发送形状(复刻前端 eJ): { approval_id, decision, always_scope: S, allow_always_scope: S }
 *     - always_scope 在 allow_always/deny_always 时都带
 *     - allow_always_scope 仅 allow_always 额外带
 *
 * 日志: log/auto-approve-log.ndjson（每条一行 JSON: decided / error / heartbeat）
 * 退出: --once 模式处理完即退出；--loop 模式 Ctrl+C 或写 data/auto-approve.stop 文件停止
 */
const fs = require('fs');
const paths = require('./paths.cjs');
const { connect, rpcCall } = require('./muse-rpc.cjs');

const LOG = paths.AUTO_APPROVE_LOG_PATH;
const STOP = paths.AUTO_APPROVE_STOP_PATH;

function log(obj) {
  const line = JSON.stringify({ ts: Date.now(), ...obj });
  fs.appendFileSync(LOG, line + '\n');
  console.log(line);
}

function parseArgs(argv) {
  const a = { mode: 'once', interval: 10000, decision: 'allow_once', scope: null, fallbackOnce: false, dry: false };
  for (let i = 0; i < argv.length; i++) {
    const v = argv[i];
    if (v === '--once') a.mode = 'once';
    else if (v === '--loop') { a.mode = 'loop'; if (argv[i + 1] && /^\d+$/.test(argv[i + 1])) a.interval = parseInt(argv[++i], 10); }
    else if (v === '--decision') a.decision = argv[++i];
    else if (v === '--always') { a.decision = 'allow_always'; if (!a.scope) a.scope = 'destination_domain'; }
    else if (v === '--scope') a.scope = argv[++i];
    else if (v === '--fallback-once') a.fallbackOnce = true;
    else if (v === '--dry') a.dry = true;
  }
  if ((a.decision === 'allow_always' || a.decision === 'deny_always') && a.scope == null) a.scope = 'destination_domain';
  return a;
}

function buildDecideParams(id, opts) {
  const params = { approval_id: id, decision: opts.decision };
  if ((opts.decision === 'allow_always' || opts.decision === 'deny_always') && opts.scope) {
    params.always_scope = opts.scope;
    if (opts.decision === 'allow_always') params.allow_always_scope = opts.scope;
  }
  return params;
}

async function sweep(conn, opts) {
  let list;
  try {
    list = await rpcCall(conn, 'egress.approvals', {});
  } catch (e) {
    log({ event: 'list_error', error: e.message });
    return 0;
  }
  const pending = (list && list.pending) || [];
  const pa = (list && list.pending_approvals) || [];
  const ids = new Set([...pending.map(p => p.approval_id), ...pa.map(p => p.approval_id)].filter(Boolean));
  if (ids.size === 0) { log({ event: 'heartbeat', pending: 0 }); return 0; }

  log({ event: 'pending_found', count: ids.size, ids: [...ids] });
  let done = 0;
  for (const id of ids) {
    if (opts.dry) { log({ event: 'dry_skip', approval_id: id, would_decide: opts.decision, scope: opts.scope }); continue; }
    try {
      const r = await rpcCall(conn, 'egress.approval.decide', buildDecideParams(id, opts));
      const a = (r && r.approval) || {};
      log({
        event: 'decided', approval_id: id, decision: opts.decision, scope: opts.scope,
        status: a.status, wire_decision: a.decision, wire_scope: a.always_scope || a.allow_always_scope,
        applied_rules: Array.isArray(a.applied_rule_entries) ? a.applied_rule_entries.length : null,
        decided_at_ms: a.decided_at_ms
      });
      done++;
    } catch (e) {
      log({ event: 'decide_error', approval_id: id, decision: opts.decision, scope: opts.scope, error: e.message, data: e.data ? JSON.stringify(e.data).slice(0, 300) : undefined });
      if (opts.fallbackOnce && opts.decision !== 'allow_once') {
        try {
          const r2 = await rpcCall(conn, 'egress.approval.decide', { approval_id: id, decision: 'allow_once' });
          const a2 = (r2 && r2.approval) || {};
          log({ event: 'decided_fallback', approval_id: id, decision: 'allow_once', status: a2.status, decided_at_ms: a2.decided_at_ms });
          done++;
        } catch (e2) {
          log({ event: 'fallback_error', approval_id: id, error: e2.message });
        }
      }
    }
  }
  return done;
}

async function connectRetry(maxTries = 4, gapMs = 1500) {
  let lastErr = null;
  for (let i = 1; i <= maxTries; i++) {
    try { return await connect(); }
    catch (e) { lastErr = e; log({ event: 'connect_retry', attempt: i, error: e.message }); await new Promise(r => setTimeout(r, gapMs)); }
  }
  throw lastErr;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  log({ event: 'start', mode: opts.mode, interval: opts.interval, decision: opts.decision, scope: opts.scope, fallbackOnce: opts.fallbackOnce, dry: opts.dry });
  const conn = await connectRetry(20, 2000);
  log({ event: 'connected' });

  if (opts.mode === 'once') {
    const n = await sweep(conn, opts);
    log({ event: 'once_done', decided: n });
    try { conn.ws.close(); } catch {}
    process.exit(0);
  }

  // loop 模式：连接断开自动重连
  let curConn = conn;
  let stopped = false;
  process.on('SIGINT', () => { stopped = true; log({ event: 'sigint' }); try { curConn.ws.close(); } catch {} process.exit(0); });

  while (!stopped) {
    if (fs.existsSync(STOP)) { log({ event: 'stop_file' }); break; }
    try {
      await sweep(curConn, opts);
    } catch (e) {
      log({ event: 'sweep_error', error: e.message });
      try { curConn.ws.close(); } catch {}
      await new Promise(r => setTimeout(r, 1500));
      try { curConn = await connectRetry(10, 2000); log({ event: 'reconnected' }); } catch (e2) { log({ event: 'reconnect_error', error: e2.message }); }
    }
    await new Promise(r => setTimeout(r, opts.interval));
  }
  try { curConn.ws.close(); } catch {}
  process.exit(0);
}

if (require.main === module) {
  main().catch(e => { console.error('ERR:', e.message); process.exit(1); });
}

module.exports = { main, sweep, parseArgs, connectRetry };