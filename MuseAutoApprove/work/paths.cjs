'use strict';
/*
 * 统一目录布局：代码在 work/，持久化数据在 data/，日志在 log/。
 * 三个目录都位于项目根目录（本文件所在 work/ 的上一级）。
 *
 *   work/   代码模块（本文件、login-lib、muse-rpc、muse-noise、proxy、auto-approve）
 *   data/   持久化数据：凭据、会话 cookie、vmId 缓存、最近 token、pid / stop 控制文件
 *   log/    日志：daemon-log.ndjson、auto-approve-log.ndjson
 *
 * data/ 与 log/ 在首次 require 本模块时自动创建（mkdir 幂等，已存在则什么都不做），
 * 因此脚本不会因为目录缺失而写文件失败。新增文件路径请加在这里，其余模块一律引用，
 * 不要在各自的文件里再拼一遍路径。
 */
const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');    // 项目根目录
const WORK_DIR = path.join(ROOT_DIR, 'work');      // 代码模块
const DATA_DIR = path.join(ROOT_DIR, 'data');      // 持久化数据
const LOG_DIR = path.join(ROOT_DIR, 'log');        // 日志

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(LOG_DIR, { recursive: true });

module.exports = {
  ROOT_DIR,
  WORK_DIR,
  DATA_DIR,
  LOG_DIR,

  // data/ 下的文件
  CRED_PATH: path.join(DATA_DIR, 'credentials.json'),
  COOKIE_PATH: path.join(DATA_DIR, 'cookies.json'),
  VM_CONFIG_PATH: path.join(DATA_DIR, 'muse-config.json'),
  TOKEN_PATH: path.join(DATA_DIR, 'token-last.json'),
  DAEMON_PID_PATH: path.join(DATA_DIR, 'muse-daemon.pid'),
  DAEMON_STOP_PATH: path.join(DATA_DIR, 'muse-daemon.stop'),
  AUTO_APPROVE_STOP_PATH: path.join(DATA_DIR, 'auto-approve.stop'),

  // log/ 下的文件
  DAEMON_LOG_PATH: path.join(LOG_DIR, 'daemon-log.ndjson'),
  AUTO_APPROVE_LOG_PATH: path.join(LOG_DIR, 'auto-approve-log.ndjson'),
};