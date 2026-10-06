'use strict';

/**
 * 验收入口（compose 中的 verify 服务）：
 *   1. 运行轮换规则单元测试（node --test）；
 *   2. 运行构建检查（scripts/build-check.js）；
 *   3. 对运行中的服务做 HTTP 冒烟：
 *      - 创建二钥、门限为二的设备域；
 *      - 错误父摘要 / 篡改载荷 / 重复重传 / 非成员签名均被拒且链头不变；
 *      - 补齐两名有效签名后，接口可读回已激活链头与两份签名证据；
 *      - 页面渲染出相同结果；
 *      - 激活后的竞争候选与迟到补签被拒；
 *      - 并发竞争候选只收敛为一个活动检查点；
 *      - 应用重启后链头、历史检查点与签名证据保持一致；
 *      - 健康端点反映设备域状态。
 *   全部通过退出码 0，否则退出码 1。
 */

const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const APP_URL = (process.env.APP_URL || 'http://127.0.0.1:3000').replace(/\/+$/, '');

// Ed25519 SPKI DER 前缀（OID 1.3.101.112），后接 32 字节原始公钥。
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/** 逐份核对证据：签名必须由公钥持有者针对指定的规范 UTF-8 消息签署。 */
function verifies(message, signatureHex, publicKeyHex) {
  const key = crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKeyHex, 'hex')]),
    format: 'der',
    type: 'spki',
  });
  return crypto.verify(null, Buffer.from(message, 'utf8'), key, Buffer.from(signatureHex, 'hex'));
}

let failures = 0;

function pass(name) {
  console.log(`  ✓ ${name}`);
}

function fail(name, detail) {
  failures += 1;
  console.error(`  ✗ ${name}`);
  if (detail) console.error(`    ${String(detail).split('\n').join('\n    ')}`);
}

async function step(name, fn) {
  try {
    await fn();
    pass(name);
  } catch (err) {
    fail(name, err && err.message ? err.message : err);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) throw new Error(`${message}（期望 ${expected}，实际 ${actual}）`);
}

function runProcess(args, options = {}) {
  const res = spawnSync(process.execPath, args, { cwd: ROOT, encoding: 'utf8', timeout: 120000, ...options });
  return { status: res.status, output: `${res.stdout || ''}${res.stderr || ''}` };
}

async function api(method, urlPath, body) {
  const res = await fetch(`${APP_URL}${urlPath}`, {
    method,
    headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(10000),
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* 非 JSON 响应（如 HTML 页面） */
  }
  return { status: res.status, json, text };
}

function genKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  return { publicKey: pub, privateKey };
}

function sign(key, message) {
  return crypto.sign(null, Buffer.from(message, 'utf8'), key.privateKey).toString('hex');
}

function flipHex(hex) {
  const last = hex.slice(-1);
  const flipped = last === '0' ? '1' : '0';
  return hex.slice(0, -1) + flipped;
}

async function waitForHealth(timeoutMs, predicate) {
  const deadline = Date.now() + timeoutMs;
  let lastError = '未收到响应';
  while (Date.now() < deadline) {
    try {
      const res = await api('GET', '/healthz');
      if (res.status === 200 && res.json && res.json.status === 'ok') {
        if (!predicate || predicate(res.json)) return res.json;
        lastError = '健康响应不满足等待条件';
      } else {
        lastError = `HTTP ${res.status}`;
      }
    } catch (err) {
      lastError = err.message;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`等待服务健康超时：${lastError}`);
}

async function main() {
  console.log(`验收目标：${APP_URL}\n`);

  console.log('— 阶段 1：轮换规则单元测试 —');
  await step('node --test 轮换规则测试全部通过', async () => {
    const res = runProcess(['--test', 'test/']);
    assertEqual(res.status, 0, `单元测试失败：\n${res.output.trim().split('\n').slice(-30).join('\n')}`);
  });

  console.log('— 阶段 2：构建检查 —');
  await step('全部源码语法检查与模块加载检查通过', async () => {
    const res = runProcess([path.join('scripts', 'build-check.js')]);
    assertEqual(res.status, 0, `构建检查失败：\n${res.output}`);
  });

  console.log('— 阶段 3：HTTP 冒烟 —');
  let bootId = null;

  await step('服务健康且健康响应可用于反映设备域状态', async () => {
    const health = await waitForHealth(60000);
    assert(health.bootId && health.startedAt, '健康响应缺少 bootId/startedAt');
    assert(Array.isArray(health.domains), '健康响应缺少设备域列表');
    bootId = health.bootId;
  });

  // —— 验收主域：二钥、门限为二 ——
  const memberA = genKey();
  const memberB = genKey();
  const nextC = genKey();
  const nextD = genKey();
  const outsider = genKey();
  let domainId;
  let genesisHead;
  let rotationDigest;
  let sigA;
  let sigB;

  await step('创建二钥且门限为二的设备域（公钥乱序提交，服务端排序）', async () => {
    const res = await api('POST', '/api/domains', {
      name: '验收域-2of2',
      publicKeys: [memberB.publicKey, memberA.publicKey],
      threshold: 2,
    });
    assertEqual(res.status, 201, `创建设备域失败：${res.text}`);
    domainId = res.json.id;
    const expectedKeys = [memberA.publicKey, memberB.publicKey].sort();
    assert(JSON.stringify(res.json.keys) === JSON.stringify(expectedKeys), '密钥集未按规范排序');
    assertEqual(res.json.generation, 0, '创世代次应为 0');
    genesisHead = res.json.headDigest;
    assert(/^[0-9a-f]{64}$/.test(genesisHead), '链头摘要格式非法');
  });

  await step('健康响应反映新设备域状态', async () => {
    const health = (await api('GET', '/healthz')).json;
    const entry = health.domains.find((d) => d.id === domainId);
    assert(entry, '健康响应中找不到新设备域');
    assertEqual(entry.headDigest, genesisHead, '健康响应中的链头与接口不一致');
  });

  await step('错误父摘要的轮换候选被拒且链头不变', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations`, {
      rotationId: 'bad-parent',
      parentDigest: 'ab'.repeat(32),
      publicKeys: [nextC.publicKey, nextD.publicKey],
      threshold: 2,
    });
    assertEqual(res.status, 422, `应返回 422：${res.text}`);
    assertEqual(res.json.error.code, 'wrong_parent_digest', '拒因应为 wrong_parent_digest');
    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, genesisHead, '链头被错误请求改变');
  });

  await step('创建轮换候选：固定父摘要、下一代次、排序后新公钥集、新门限', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations`, {
      rotationId: 'rot-2026-001',
      parentDigest: genesisHead,
      publicKeys: [nextD.publicKey, nextC.publicKey],
      threshold: 2,
    });
    assertEqual(res.status, 201, `创建轮换失败：${res.text}`);
    rotationDigest = res.json.digest;
    assertEqual(res.json.parentDigest, genesisHead, '父摘要未固定为当前链头');
    assertEqual(res.json.generation, 1, '下一代次应为 1');
    assertEqual(res.json.threshold, 2, '新门限应为 2');
    assert(JSON.stringify(res.json.keys) === JSON.stringify([nextC.publicKey, nextD.publicKey].sort()), '新公钥集未排序');
    assertEqual(res.json.status, 'pending', '候选应处于待签状态');
  });

  await step('篡改载荷与非成员签名被拒且链头不变', async () => {
    const msgRes = await api('GET', `/api/domains/${domainId}/rotations/rot-2026-001/message`);
    assertEqual(msgRes.status, 200, '应能读取规范待签消息');
    const message = msgRes.json.message;
    assert(message.includes(`parent=${genesisHead}`), '待签消息未绑定父摘要');
    sigA = sign(memberA, message);
    sigB = sign(memberB, message);

    const tampered = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: flipHex(sigA) }],
    });
    assertEqual(tampered.json.results[0].code, 'invalid_signature', '篡改签名应给出 invalid_signature');

    const wrongMessage = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: sign(memberA, message + '\nforged=1') }],
    });
    assertEqual(wrongMessage.json.results[0].code, 'invalid_signature', '签错消息应给出 invalid_signature');

    const notMember = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: outsider.publicKey, signature: sign(outsider, message) }],
    });
    assertEqual(notMember.json.results[0].code, 'not_parent_member', '非父成员应给出 not_parent_member');

    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, genesisHead, '被拒签名改变了链头');
    assertEqual(head.evidence.length, 0, '被拒签名不应产生证据');
  });

  await step('第一批签名（1/2）：候选保持待签，链头不提前生效', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: sigA }],
    });
    assertEqual(res.status, 200, `提交签名失败：${res.text}`);
    assertEqual(res.json.results[0].status, 'accepted', '有效签名应被接受');
    assertEqual(res.json.activated, false, '未达门限不应激活');
    assertEqual(res.json.signers, 1, '应记录 1 名签名者');
    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, genesisHead, '未达门限链头不应前进');
  });

  await step('重传同一签名：给出重复拒因且不改变状态', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: sigA }],
    });
    assertEqual(res.json.results[0].code, 'duplicate_signature', '重传应给出 duplicate_signature');
    assertEqual(res.json.signers, 1, '重传不应增加签名者');
    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, genesisHead, '重传不应改变链头');
  });

  await step('补齐第二名有效签名：同一提交中激活，接口读回链头与两份证据', async () => {
    const res = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberB.publicKey, signature: sigB }],
    });
    assertEqual(res.json.results[0].status, 'accepted', '第二名签名应被接受');
    assertEqual(res.json.activated, true, '达到父门限应激活');
    assertEqual(res.json.headDigest, rotationDigest, '链头应前进到候选摘要');

    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, rotationDigest, '链头摘要与候选摘要不一致');
    assertEqual(head.generation, 1, '链头代次应为 1');
    assertEqual(head.threshold, 2, '新门限应生效');
    assert(JSON.stringify(head.keys) === JSON.stringify([nextC.publicKey, nextD.publicKey].sort()), '新密钥集应生效');
    assertEqual(head.evidence.length, 2, '应恰好有两份签名证据');
    const evidenceKeys = head.evidence.map((e) => e.publicKey).sort();
    assert(JSON.stringify(evidenceKeys) === JSON.stringify([memberA.publicKey, memberB.publicKey].sort()), '证据签名者不符');
    const evidenceSigs = Object.fromEntries(head.evidence.map((e) => [e.publicKey, e.signature]));
    assertEqual(evidenceSigs[memberA.publicKey], sigA, '成员 A 的签名证据不符');
    assertEqual(evidenceSigs[memberB.publicKey], sigB, '成员 B 的签名证据不符');
  });

  await step('激活后的迟到补签与竞争候选均被拒且链头不变', async () => {
    const late = await api('POST', `/api/domains/${domainId}/rotations/rot-2026-001/signatures`, {
      signatures: [{ publicKey: memberA.publicKey, signature: sigA }],
    });
    assertEqual(late.status, 409, `迟到补签应返回 409：${late.text}`);
    assertEqual(late.json.error.code, 'rotation_already_activated', '迟到补签应给出拒因');

    const staleParent = await api('POST', `/api/domains/${domainId}/rotations`, {
      rotationId: 'stale-competitor',
      parentDigest: genesisHead,
      publicKeys: [outsider.publicKey, genKey().publicKey],
      threshold: 2,
    });
    assertEqual(staleParent.status, 422, '旧父摘要的竞争候选应被拒');
    assertEqual(staleParent.json.error.code, 'wrong_parent_digest', '拒因应为 wrong_parent_digest');

    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, rotationDigest, '竞争请求改变了链头');
  });

  // —— 第二设备域：并发竞争只收敛为一个活动检查点 ——
  let domain2Id;
  let domain2Head;
  await step('并发竞争候选：恰好一个激活，其余被取代', async () => {
    const members = [genKey(), genKey()];
    const created = await api('POST', '/api/domains', {
      name: '并发竞争域',
      publicKeys: members.map((m) => m.publicKey),
      threshold: 2,
    });
    assertEqual(created.status, 201, `创建第二设备域失败：${created.text}`);
    domain2Id = created.json.id;
    const parent = created.json.headDigest;

    for (const rid of ['race-1', 'race-2']) {
      const keys = [genKey(), genKey()];
      const res = await api('POST', `/api/domains/${domain2Id}/rotations`, {
        rotationId: rid,
        parentDigest: parent,
        publicKeys: keys.map((k) => k.publicKey),
        threshold: 2,
      });
      assertEqual(res.status, 201, `创建竞争候选失败：${res.text}`);
    }
    const detail = (await api('GET', `/api/domains/${domain2Id}`)).json;
    const batch = (rid) => {
      const rot = detail.rotations.find((r) => r.rotationId === rid);
      return members.map((m) => ({ publicKey: m.publicKey, signature: sign(m, rot.message) }));
    };
    const [r1, r2] = await Promise.all([
      api('POST', `/api/domains/${domain2Id}/rotations/race-1/signatures`, { signatures: batch('race-1') }),
      api('POST', `/api/domains/${domain2Id}/rotations/race-2/signatures`, { signatures: batch('race-2') }),
    ]);
    const outcomes = [r1, r2];
    const activated = outcomes.filter((o) => o.status === 200 && o.json.activated === true);
    const superseded = outcomes.filter((o) => o.status === 409 && o.json.error && o.json.error.code === 'rotation_superseded');
    assertEqual(activated.length, 1, '并发下应恰好一个候选激活');
    assertEqual(superseded.length, 1, '落选候选应给出取代拒因');

    const after = (await api('GET', `/api/domains/${domain2Id}`)).json;
    const activeRotations = after.rotations.filter((r) => r.status === 'activated');
    assertEqual(activeRotations.length, 1, '应只有一个已激活轮换');
    assertEqual(after.headDigest, activeRotations[0].digest, '链头应等于唯一激活候选');
    const gen1 = after.checkpoints.filter((c) => c.generation === 1);
    assertEqual(gen1.length, 1, '同一代次应只有一个活动检查点');
    const loser = after.rotations.find((r) => r.status === 'superseded');
    assert(loser && loser.rejectedReason, '落选候选应记录拒因');
    domain2Head = after.headDigest;
  });

  // —— 跨设备域同名候选：相同父公钥集 + 同名轮换标识，证据不得跨域凑门限 ——
  const crossParents = [genKey(), genKey()];
  const nextX = [genKey(), genKey()];
  const nextY = [genKey(), genKey()];
  let crossXId;
  let crossYId;
  let crossXHead;
  let crossYHead;
  let crossDigestX;
  let crossDigestY;
  let msgCrossX;
  let msgCrossY;
  const CROSS_RID = 'cross-shared-rot';

  await step('跨域场景：创建父公钥相同、门限均为二的两个设备域及同名（新公钥集不同）候选', async () => {
    const dx = await api('POST', '/api/domains', {
      name: '跨设备域-X',
      publicKeys: crossParents.map((m) => m.publicKey),
      threshold: 2,
    });
    const dy = await api('POST', '/api/domains', {
      name: '跨设备域-Y',
      publicKeys: crossParents.map((m) => m.publicKey),
      threshold: 2,
    });
    assertEqual(dx.status, 201, `创建跨域 X 失败：${dx.text}`);
    assertEqual(dy.status, 201, `创建跨域 Y 失败：${dy.text}`);
    crossXId = dx.json.id;
    crossYId = dy.json.id;
    crossXHead = dx.json.headDigest;
    crossYHead = dy.json.headDigest;
    assert(crossXHead !== crossYHead, '不同设备域的创世摘要不应相同（域 ID 不同）');

    for (const [did, head, keys, out] of [
      [crossXId, crossXHead, nextX, 'x'],
      [crossYId, crossYHead, nextY, 'y'],
    ]) {
      const res = await api('POST', `/api/domains/${did}/rotations`, {
        rotationId: CROSS_RID,
        parentDigest: head,
        publicKeys: keys.map((k) => k.publicKey),
        threshold: 2,
      });
      assertEqual(res.status, 201, `跨域 ${out} 创建同名候选失败：${res.text}`);
      if (out === 'x') crossDigestX = res.json.digest;
      else crossDigestY = res.json.digest;
    }
    assert(crossDigestX !== crossDigestY, '不同载荷的同名候选摘要不应相同');
    const mx = await api('GET', `/api/domains/${crossXId}/rotations/${CROSS_RID}/message`);
    const my = await api('GET', `/api/domains/${crossYId}/rotations/${CROSS_RID}/message`);
    msgCrossX = mx.json.message;
    msgCrossY = my.json.message;
    assert(msgCrossX !== msgCrossY, '两个候选的规范待签消息必须不同');
  });

  await step('跨域场景：只为第一个候选提交一名父成员的有效签名，保持待签', async () => {
    const sigXA = sign(crossParents[0], msgCrossX);
    const res = await api('POST', `/api/domains/${crossXId}/rotations/${CROSS_RID}/signatures`, {
      signatures: [{ publicKey: crossParents[0].publicKey, signature: sigXA }],
    });
    assertEqual(res.json.activated, false, '单名签名不应激活');
    assertEqual(res.json.signers, 1, '应记录 1 名签名者');
  });

  await step('跨域场景：重启应用后第二个候选仍待签，链头/详情/页面/健康均无外来证据', async () => {
    const restart = await api('POST', '/api/admin/restart');
    assertEqual(restart.status, 202, `重启端点应返回 202：${restart.text}`);
    const health = await waitForHealth(60000, (h) => h.bootId !== bootId);
    bootId = health.bootId;

    const rx = (await api('GET', `/api/domains/${crossXId}`)).json.rotations.find((r) => r.rotationId === CROSS_RID);
    const ry = (await api('GET', `/api/domains/${crossYId}`)).json.rotations.find((r) => r.rotationId === CROSS_RID);
    assertEqual(rx.status, 'pending', '第一个候选重启后应仍待签');
    assertEqual(rx.signers, 1, '第一个候选的本域签名应保留');
    assertEqual(ry.status, 'pending', '第二个候选不得被外来签名错误激活');
    assertEqual(ry.signers, 0, '第一个设备域的签名不得泄漏为第二个候选的证据');

    for (const [did, head] of [[crossXId, crossXHead], [crossYId, crossYHead]]) {
      const h = (await api('GET', `/api/domains/${did}/head`)).json;
      assertEqual(h.digest, head, `设备域 ${did} 重启后链头不应前进`);
      assertEqual(h.evidence.length, 0, '创世链头不应带有任何签名证据');
      const hz = (await api('GET', '/healthz')).json;
      const entry = hz.domains.find((d) => d.id === did);
      assertEqual(entry.headDigest, head, '健康响应中的链头与链头接口不一致');
    }

    const page = await api('GET', '/');
    assertEqual(page.status, 200, '重启后页面应可访问');
    assert(page.text.includes(crossXHead) && page.text.includes(crossYHead), '页面未显示两个设备域的创世链头');
    assert(!page.text.includes(crossDigestY) || page.text.includes('待签'), '页面不得把第二个候选展示为已激活');
  });

  await step('跨域场景：第二个候选仅收到自身一名有效签名时继续待签（链头/详情/页面/健康一致）', async () => {
    const sigYB = sign(crossParents[1], msgCrossY);
    const res = await api('POST', `/api/domains/${crossYId}/rotations/${CROSS_RID}/signatures`, {
      signatures: [{ publicKey: crossParents[1].publicKey, signature: sigYB }],
    });
    assertEqual(res.json.activated, false, '外来签名不得凑门限：仅自身一名签名必须继续待签');
    assertEqual(res.json.signers, 1, '应仅记录第二个候选自身的 1 名签名者');
    assertEqual(res.json.headDigest, crossYHead, '链头不得前进');

    const detail = (await api('GET', `/api/domains/${crossYId}`)).json;
    const ry = detail.rotations.find((r) => r.rotationId === CROSS_RID);
    assertEqual(ry.status, 'pending', '详情接口中候选应仍为待签');
    assertEqual(ry.signers, 1, '详情接口中签名者数应为 1');
    // 逐份核对：保留的签名必须验证第二个候选自身的消息。
    assertEqual(ry.signatures.length, 1);
    assert(verifies(msgCrossY, ry.signatures[0].signature, ry.signatures[0].publicKey), '已收签名无法验证本候选消息');

    const head = (await api('GET', `/api/domains/${crossYId}/head`)).json;
    assertEqual(head.digest, crossYHead, '链头接口不应显示被错误激活的检查点');
    const hz = (await api('GET', '/healthz')).json;
    assertEqual(hz.domains.find((d) => d.id === crossYId).headDigest, crossYHead, '健康响应中的链头不一致');
    const page = await api('GET', '/');
    assert(page.text.includes('待签'), '页面应保持候选为待签分组');
  });

  await step('跨域场景：第二名父成员针对第二个候选消息补签后才激活，逐份证据验证本候选', async () => {
    const sigYA = sign(crossParents[0], msgCrossY);
    const res = await api('POST', `/api/domains/${crossYId}/rotations/${CROSS_RID}/signatures`, {
      signatures: [{ publicKey: crossParents[0].publicKey, signature: sigYA }],
    });
    assertEqual(res.json.activated, true, '两名父成员都针对本候选签名后应激活');
    assertEqual(res.json.headDigest, crossDigestY, '链头应前进到第二个候选摘要');

    const head = (await api('GET', `/api/domains/${crossYId}/head`)).json;
    assertEqual(head.digest, crossDigestY, '链头接口摘要不符');
    assertEqual(head.evidence.length, 2, '应恰好有两份证据');
    // 逐份证据核对：每份都验证第二个候选的规范消息，且都不能验证第一个候选的消息。
    for (const entry of head.evidence) {
      assert(verifies(msgCrossY, entry.signature, entry.publicKey), '证据无法验证第二个候选的规范消息');
      assert(!verifies(msgCrossX, entry.signature, entry.publicKey), '证据不应能验证第一个设备域的消息');
    }
    const detail = (await api('GET', `/api/domains/${crossYId}`)).json;
    assertEqual(detail.headDigest, crossDigestY, '域详情链头不符');
    const cp = detail.checkpoints.find((c) => c.digest === crossDigestY);
    assert(cp && cp.evidence.length === 2, '域详情缺少已激活检查点或证据份数不符');
    const hz = (await api('GET', '/healthz')).json;
    assertEqual(hz.domains.find((d) => d.id === crossYId).headDigest, crossDigestY, '健康响应链头不符');
    const page = await api('GET', '/');
    assert(page.text.includes(crossDigestY), '页面未显示新激活链头');
  });

  await step('跨域场景：第一个设备域的链头、证据与历史完全不受影响', async () => {
    const detail = (await api('GET', `/api/domains/${crossXId}`)).json;
    assertEqual(detail.headDigest, crossXHead, '第一个设备域链头不应变化');
    assertEqual(detail.generation, 0, '第一个设备域代次不应变化');
    assertEqual(detail.checkpoints.length, 1, '第一个设备域历史不应新增检查点');
    const rx = detail.rotations.find((r) => r.rotationId === CROSS_RID);
    assertEqual(rx.status, 'pending', '第一个设备域的同名候选应仍待签');
    assertEqual(rx.signers, 1, '第一个设备域的候选应仍只有自身那 1 份签名');
    assert(verifies(msgCrossX, rx.signatures[0].signature, rx.signatures[0].publicKey), '第一域证据必须验证其自身消息');
    const head = (await api('GET', `/api/domains/${crossXId}/head`)).json;
    assertEqual(head.digest, crossXHead, '链头接口中第一域链头变化');
    assertEqual(head.evidence.length, 0, '第一域创世链头不应出现证据');
  });

  // —— 重启一致性 ——
  let domain1Before;
  let domain2Before;
  await step('应用重启后：链头、历史检查点与签名证据保持一致', async () => {
    domain1Before = (await api('GET', `/api/domains/${domainId}`)).json;
    domain2Before = (await api('GET', `/api/domains/${domain2Id}`)).json;

    const restart = await api('POST', '/api/admin/restart');
    assertEqual(restart.status, 202, `重启端点应返回 202：${restart.text}`);

    const health = await waitForHealth(60000, (h) => h.bootId !== bootId);
    assert(health.bootId !== bootId, '重启后 bootId 应变化（确为新进程）');

    const domain1After = (await api('GET', `/api/domains/${domainId}`)).json;
    const domain2After = (await api('GET', `/api/domains/${domain2Id}`)).json;
    assert(
      JSON.stringify(domain1After) === JSON.stringify(domain1Before),
      '验收域重启前后状态不一致（链头/检查点/证据丢失）',
    );
    assert(
      JSON.stringify(domain2After) === JSON.stringify(domain2Before),
      '并发域重启前后状态不一致（链头/检查点/证据丢失）',
    );
    const head = (await api('GET', `/api/domains/${domainId}/head`)).json;
    assertEqual(head.digest, rotationDigest, '重启后链头摘要变化');
    assertEqual(head.evidence.length, 2, '重启后签名证据份数变化');
  });

  await step('健康响应在重启后仍反映设备域状态', async () => {
    const health = (await api('GET', '/healthz')).json;
    const d1 = health.domains.find((d) => d.id === domainId);
    const d2 = health.domains.find((d) => d.id === domain2Id);
    assert(d1 && d1.headDigest === rotationDigest, '健康响应中验收域链头不符');
    assert(d2 && d2.headDigest === domain2Head, '健康响应中并发域链头不符');
  });

  await step('页面显示与接口相同的结果（链头、证据、检查点分组）', async () => {
    const page = await api('GET', '/');
    assertEqual(page.status, 200, '页面应可访问');
    assert(page.text.includes(rotationDigest), '页面未显示已激活链头摘要');
    assert(page.text.includes(memberA.publicKey), '页面未显示成员 A 的签名证据');
    assert(page.text.includes(memberB.publicKey), '页面未显示成员 B 的签名证据');
    assert(page.text.includes(sigA), '页面未显示成员 A 的签名值');
    assert(page.text.includes('rot-2026-001'), '页面未显示轮换标识');
    assert(page.text.includes('已激活'), '页面缺少已激活检查点分组');
    assert(page.text.includes('已拒'), '页面缺少已拒检查点分组');
    assert(page.text.includes('待签'), '页面缺少待签检查点分组');
    assert(page.text.includes('race-1') && page.text.includes('race-2'), '页面未显示竞争候选记录');
  });

  console.log('');
  if (failures > 0) {
    console.error(`验收失败：${failures} 项未通过`);
    process.exit(1);
  }
  console.log('验收全部通过。');
  process.exit(0);
}

main().catch((err) => {
  console.error(`验收执行异常：${err.stack || err}`);
  process.exit(1);
});
