'use strict';

/**
 * 构建检查：对全部源码做语法检查（node --check），
 * 并加载模块依赖图确认可解析。失败时以非零码退出。
 */

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const SCAN_DIRS = ['src', 'scripts', 'test'];

function collectJsFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...collectJsFiles(full));
    else if (entry.isFile() && entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

let failed = 0;

for (const dir of SCAN_DIRS) {
  for (const file of collectJsFiles(path.join(ROOT, dir))) {
    const res = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
    if (res.status !== 0) {
      failed += 1;
      console.error(`✗ 语法检查失败：${path.relative(ROOT, file)}\n${res.stderr}`);
    } else {
      console.log(`✓ 语法检查通过：${path.relative(ROOT, file)}`);
    }
  }
}

// 模块依赖图加载检查（main.js 会监听端口，不在此加载）。
for (const mod of ['./src/rotation', './src/store', './src/page', './src/server']) {
  try {
    require(path.join(ROOT, mod));
    console.log(`✓ 模块加载成功：${mod}`);
  } catch (err) {
    failed += 1;
    console.error(`✗ 模块加载失败：${mod} — ${err.message}`);
  }
}

if (failed > 0) {
  console.error(`构建检查失败：${failed} 项`);
  process.exit(1);
}
console.log('构建检查全部通过。');
