'use strict';
/*
 * 统一代理层：所有出网的代理配置集中在这里
 * - 未设置 MUSE_PROXY      -> 直连（适合无需代理的网络环境）
 * - 设置 MUSE_PROXY=<url>  -> 所有出网走该代理（如本机 http://127.0.0.1:7890）
 * installProxy(): 把 npm undici 的 fetch 装成 globalThis.fetch
 *   （Node 22 全局 fetch 用的是内置 undici，npm undici 的 setGlobalDispatcher 管不到它，必须整体替换）
 *   设置代理时装 ProxyAgent；直连时不装，走 undici 默认 dispatcher（即直接连目标）。
 * createWS(url): 返回 ws 包的 WebSocket（DOM 风格 onmessage/binaryType，兼容既有代码）
 *   设置代理时经 https-proxy-agent 走代理，直连时不传 agent。
 */
const RAW_PROXY = (process.env.MUSE_PROXY || '').trim();

// 允许省略协议头（MUSE_PROXY=127.0.0.1:7890 与 http://127.0.0.1:7890 等价）
const PROXY = RAW_PROXY
  ? (/^[a-z][a-z0-9+.-]*:\/\//i.test(RAW_PROXY) ? RAW_PROXY : 'http://' + RAW_PROXY)
  : null;   // null 表示直连

function installProxy() {
  const undici = require('undici');
  if (PROXY) undici.setGlobalDispatcher(new undici.ProxyAgent(PROXY));
  globalThis.fetch = (input, init) => undici.fetch(input, init);
  return PROXY;
}

function createWS(url, opts = {}) {
  const WS = require('ws');
  const defaults = {
    origin: 'https://muse.ai',
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0',
    },
    perMessageDeflate: false,
  };
  if (PROXY) {
    const m = require('https-proxy-agent');
    const HttpsProxyAgent = m.HttpsProxyAgent || m;
    defaults.agent = new HttpsProxyAgent(PROXY);
  }
  return new WS(url, { ...defaults, ...opts });
}

module.exports = { PROXY, installProxy, createWS };