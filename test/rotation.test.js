'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const rotation = require('../src/rotation');
const { Store } = require('../src/store');

const NOW = '2026-10-06T00:00:00.000Z';

function genKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  return { publicKey: pub, privateKey };
}

function sign(privateKey, message) {
  return crypto.sign(null, Buffer.from(message, 'utf8'), privateKey).toString('hex');
}

function freshState() {
  return { version: 1, domains: {} };
}

function makeDomain(state, keys, threshold) {
  const { state: s2, result } = rotation.createDomain(
    state,
    { name: '测试域', publicKeys: keys.map((k) => k.publicKey), threshold },
    NOW,
  );
  return { state: s2, domain: result };
}

test('密钥集校验：排序、去重、数量与门限边界', () => {
  const a = 'a'.repeat(64);
  const b = 'B'.repeat(64); // 大写应归一化
  const c = 'c'.repeat(64);
  const { keys, threshold } = rotation.validateKeySet([c, a, b], 2);
  assert.deepEqual(keys, ['a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64)]);
  assert.equal(threshold, 2);

  assert.throws(() => rotation.validateKeySet([a, a], 1), /重复/);
  assert.throws(() => rotation.validateKeySet([a], 1), (e) => e.code === 'invalid_key_set');
  assert.throws(() => rotation.validateKeySet([a, b, c, 'd'.repeat(64), 'e'.repeat(64), 'f'.repeat(64)], 1), /2–5/);
  assert.throws(() => rotation.validateKeySet([a, 'zz'.repeat(32)], 1), /十六进制/);
  assert.throws(() => rotation.validateKeySet([a, b], 0), (e) => e.code === 'invalid_threshold');
  assert.throws(() => rotation.validateKeySet([a, b], 3), (e) => e.code === 'invalid_threshold');
  assert.throws(() => rotation.validateKeySet([a, b], 1.5), (e) => e.code === 'invalid_threshold');
});

test('检查点摘要与授权消息：规范化、确定性、与输入顺序无关', () => {
  const base = {
    domainId: 'dom-1',
    rotationId: 'rot-1',
    parentDigest: '0'.repeat(64),
    generation: 1,
    threshold: 2,
    keys: rotation.sortKeys(['b'.repeat(64), 'a'.repeat(64)]),
  };
  const same = { ...base, keys: rotation.sortKeys(['a'.repeat(64), 'b'.repeat(64)]) };
  assert.equal(rotation.checkpointDigest(base), rotation.checkpointDigest(same));
  assert.match(rotation.checkpointDigest(base), /^[0-9a-f]{64}$/);

  const message = rotation.authorizationMessage(base);
  assert.ok(message.includes('parent=' + '0'.repeat(64)));
  assert.ok(message.includes('keys=' + 'a'.repeat(64) + ',' + 'b'.repeat(64)));
  // 任一字段变化都会改变待签消息（篡改载荷必然验签失败）。
  assert.notEqual(rotation.authorizationMessage({ ...base, threshold: 3 }), message);
  assert.notEqual(rotation.authorizationMessage({ ...base, rotationId: 'rot-2' }), message);
  assert.notEqual(rotation.authorizationMessage({ ...base, parentDigest: '1'.repeat(64) }), message);
});

test('创建设备域：创世检查点立即激活并成为链头', () => {
  const keys = [genKey(), genKey()];
  const { state, domain } = makeDomain(freshState(), keys, 2);
  assert.equal(domain.generation, 0);
  assert.equal(domain.headDigest, Object.keys(domain.checkpoints)[0]);
  const genesis = domain.checkpoints[domain.headDigest];
  assert.equal(genesis.status, 'activated');
  assert.equal(genesis.parentDigest, '0'.repeat(64));
  assert.deepEqual(genesis.keys, rotation.sortKeys(keys.map((k) => k.publicKey)));
  assert.ok(state.domains[domain.id]);
});

test('创建轮换：错误父摘要被拒且不改变状态；同标识幂等；冲突载荷被拒', () => {
  const keys = [genKey(), genKey()];
  const { state, domain } = makeDomain(freshState(), keys, 2);
  const next = [genKey(), genKey()];

  assert.throws(
    () => rotation.createRotation(state, domain.id, { rotationId: 'r1', parentDigest: 'f'.repeat(64), publicKeys: next.map((k) => k.publicKey), threshold: 2 }, NOW),
    (e) => e.code === 'wrong_parent_digest',
  );

  const input = { rotationId: 'r1', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2 };
  const first = rotation.createRotation(state, domain.id, input, NOW);
  assert.equal(first.result.created, true);
  assert.equal(first.result.rotation.generation, 1);
  assert.equal(first.result.rotation.parentDigest, domain.headDigest);

  const again = rotation.createRotation(first.state, domain.id, input, NOW + 'x');
  assert.equal(again.result.created, false);
  assert.equal(again.state, first.state, '幂等创建不应改变状态');

  assert.throws(
    () => rotation.createRotation(first.state, domain.id, { ...input, threshold: 1 }, NOW),
    (e) => e.code === 'conflicting_rotation',
  );
});

test('签名提交：非成员、篡改载荷、重复签名均被拒且不改变状态', () => {
  const members = [genKey(), genKey()];
  const outsider = genKey();
  const { state, domain } = makeDomain(freshState(), members, 2);
  const next = [genKey(), genKey()];
  const created = rotation.createRotation(
    state,
    domain.id,
    { rotationId: 'r1', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2 },
    NOW,
  );
  const rot = created.result.rotation;
  const message = rotation.authorizationMessage(rot);

  // 非父密钥成员
  const notMember = rotation.submitSignatures(
    created.state, domain.id, 'r1',
    [{ publicKey: outsider.publicKey, signature: sign(outsider.privateKey, message) }],
    NOW,
  );
  assert.equal(notMember.result.results[0].code, 'not_parent_member');
  assert.equal(notMember.state, created.state);

  // 篡改载荷：签的是别的消息
  const tampered = rotation.submitSignatures(
    created.state, domain.id, 'r1',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message + '\nextra=1') }],
    NOW,
  );
  assert.equal(tampered.result.results[0].code, 'invalid_signature');
  assert.equal(tampered.state, created.state);

  // 合法签名被接受
  const one = rotation.submitSignatures(
    created.state, domain.id, 'r1',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) }],
    NOW,
  );
  assert.equal(one.result.results[0].status, 'accepted');
  assert.equal(one.result.activated, false);
  assert.equal(one.result.signers, 1);

  // 重传同一签名 → 重复拒因，状态不变
  const dup = rotation.submitSignatures(
    one.state, domain.id, 'r1',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) }],
    NOW,
  );
  assert.equal(dup.result.results[0].code, 'duplicate_signature');
  assert.equal(dup.state, one.state);

  // 同批内重复也只计一次
  const sameBatch = rotation.submitSignatures(
    created.state, domain.id, 'r1',
    [
      { publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) },
      { publicKey: members[0].publicKey, signature: sign(members[0].privateKey, message) },
    ],
    NOW,
  );
  assert.equal(sameBatch.result.results[0].status, 'accepted');
  assert.equal(sameBatch.result.results[1].code, 'duplicate_signature');
  assert.equal(sameBatch.result.signers, 1);
});

test('达到父门限即激活：链头前进、证据完整、竞争候选被取代、迟到签名被拒', () => {
  const members = [genKey(), genKey()];
  const { state, domain } = makeDomain(freshState(), members, 2);
  const nextA = [genKey(), genKey()];
  const nextB = [genKey(), genKey(), genKey()];

  const s1 = rotation.createRotation(state, domain.id, { rotationId: 'win', parentDigest: domain.headDigest, publicKeys: nextA.map((k) => k.publicKey), threshold: 2 }, NOW).state;
  const s2 = rotation.createRotation(s1, domain.id, { rotationId: 'lose', parentDigest: domain.headDigest, publicKeys: nextB.map((k) => k.publicKey), threshold: 2 }, NOW).state;

  const rotWin = s2.domains[domain.id].rotations.win;
  const msgWin = rotation.authorizationMessage(rotWin);
  const rotLose = s2.domains[domain.id].rotations.lose;
  const msgLose = rotation.authorizationMessage(rotLose);

  // 两个候选各收一票（竞争提交进行中）
  const s3 = rotation.submitSignatures(s2, domain.id, 'win', [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgWin) }], NOW).state;
  const s4 = rotation.submitSignatures(s3, domain.id, 'lose', [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgLose) }], NOW).state;

  // win 达到门限 → 激活；lose 在同一迁移中被取代
  const done = rotation.submitSignatures(s4, domain.id, 'win', [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, msgWin) }], NOW);
  assert.equal(done.result.activated, true);
  const after = done.state.domains[domain.id];
  assert.equal(after.headDigest, rotWin.digest);
  assert.equal(after.generation, 1);
  assert.deepEqual(after.keys, rotWin.keys);
  const headCp = after.checkpoints[after.headDigest];
  assert.equal(headCp.evidence.length, 2);
  assert.deepEqual(headCp.evidence.map((e) => e.publicKey).sort(), members.map((m) => m.publicKey).sort());
  assert.equal(after.rotations.lose.status, 'superseded');
  assert.match(after.rotations.lose.rejectedReason, /取代/);

  // 迟到的签名（激活后补签）被拒，链头不变
  assert.throws(
    () => rotation.submitSignatures(done.state, domain.id, 'win', [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgWin) }], NOW),
    (e) => e.code === 'rotation_already_activated',
  );
  assert.throws(
    () => rotation.submitSignatures(done.state, domain.id, 'lose', [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, msgLose) }], NOW),
    (e) => e.code === 'rotation_superseded',
  );
  assert.equal(done.state.domains[domain.id].headDigest, rotWin.digest);

  // 激活后用旧父摘要创建竞争候选 → 错误父摘要
  assert.throws(
    () => rotation.createRotation(done.state, domain.id, { rotationId: 'late', parentDigest: domain.headDigest, publicKeys: nextA.map((k) => k.publicKey), threshold: 2 }, NOW),
    (e) => e.code === 'wrong_parent_digest',
  );
});

test('持久化：提交后重载状态一致；并发补签只收敛为一个活动检查点', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-store-'));
  const file = path.join(dir, 'state.json');
  const store = new Store(file);
  store.load();

  const members = [genKey(), genKey()];
  const domain = await store.commit((s) => rotation.createDomain(s, { name: '并发域', publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW));
  const next = [genKey(), genKey()];
  await store.commit((s) => rotation.createRotation(s, domain.id, { rotationId: 'r1', parentDigest: domain.headDigest, publicKeys: next.map((k) => k.publicKey), threshold: 2 }, NOW));
  const rot = store.state.domains[domain.id].rotations.r1;
  const message = rotation.authorizationMessage(rot);

  // 并发提交两批签名 + 两批重传（乱序到达的补签与重传）
  const batch = (m) => [{ publicKey: m.publicKey, signature: sign(m.privateKey, message) }];
  const outcomes = await Promise.allSettled([
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'r1', batch(members[0]), NOW)),
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'r1', batch(members[1]), NOW)),
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'r1', batch(members[0]), NOW)),
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'r1', batch(members[1]), NOW)),
  ]);
  const fulfilled = outcomes.filter((o) => o.status === 'fulfilled').map((o) => o.value);
  const rejected = outcomes.filter((o) => o.status === 'rejected').map((o) => o.reason);
  assert.equal(fulfilled.filter((o) => o.activated).length, 1, '恰好一次提交触发激活');
  for (const late of rejected) assert.equal(late.code, 'rotation_already_activated', '激活后的重传应被拒');
  for (const f of fulfilled) {
    if (!f.activated) assert.ok(f.results.every((r) => r.status === 'rejected' || f.signers <= 2));
  }
  const finalDomain = store.state.domains[domain.id];
  assert.equal(finalDomain.headDigest, rot.digest);
  assert.equal(finalDomain.rotations.r1.signatures.length, 2, '重传被去重，仅两名签名者');
  assert.equal(finalDomain.checkpoints[rot.digest].evidence.length, 2);

  // 重载（模拟重启）后链头、检查点、证据完全一致
  const reloaded = new Store(file);
  reloaded.load();
  assert.deepEqual(reloaded.state, store.state);
  assert.ok(!fs.existsSync(`${file}.tmp`), '原子提交不残留临时文件');
});

test('跨设备域同名候选：父公钥相同也不能串用签名证据', () => {
  // 两个设备域使用完全相同的父公钥集与门限，但轮换候选的新公钥集不同。
  const members = [genKey(), genKey()];
  const createdX = makeDomain(freshState(), members, 2);
  const createdY = makeDomain(createdX.state, members, 2);
  const nextX = [genKey(), genKey()];
  const nextY = [genKey(), genKey()];

  const withX = rotation.createRotation(
    createdY.state, createdX.domain.id,
    { rotationId: 'same-rot', parentDigest: createdX.domain.headDigest, publicKeys: nextX.map((k) => k.publicKey), threshold: 2 },
    NOW,
  );
  const withBoth = rotation.createRotation(
    withX.state, createdY.domain.id,
    { rotationId: 'same-rot', parentDigest: createdY.domain.headDigest, publicKeys: nextY.map((k) => k.publicKey), threshold: 2 },
    NOW,
  );
  const state = withBoth.state;
  const rotX = state.domains[createdX.domain.id].rotations['same-rot'];
  const rotY = state.domains[createdY.domain.id].rotations['same-rot'];
  const msgX = rotation.authorizationMessage(rotX);
  const msgY = rotation.authorizationMessage(rotY);
  assert.notEqual(msgX, msgY, '设备域不同，规范消息必然不同');

  // 成员 A 签署的是 X 候选的消息；提交给 Y 候选必须判为验签失败。
  const foreign = rotation.submitSignatures(
    state, createdY.domain.id, 'same-rot',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgX) }],
    NOW,
  );
  assert.equal(foreign.result.results[0].code, 'invalid_signature');
  assert.equal(foreign.state, state, '外来签名不得改变状态');

  // 即使绕过提交逻辑把外来签名塞进 Y 候选，它也不能计入授权证据、不能触发激活。
  const poisoned = structuredClone(state);
  poisoned.domains[createdY.domain.id].rotations['same-rot'].signatures = [
    { publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgX), receivedAt: NOW },
  ];
  const { evidence } = rotation.validEvidence(
    poisoned.domains[createdY.domain.id].checkpoints,
    poisoned.domains[createdY.domain.id].rotations['same-rot'],
  );
  assert.equal(evidence.length, 0, '外来签名不得成为 Y 候选的授权证据');

  // Y 只收到自身一名成员签名时继续待签。
  const oneOwn = rotation.submitSignatures(
    state, createdY.domain.id, 'same-rot',
    [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgY) }],
    NOW,
  );
  assert.equal(oneOwn.result.activated, false);
  assert.equal(oneOwn.result.signers, 1);
  // 两名父成员都针对 Y 候选自身消息签名后才激活，证据逐份可验证。
  const twoOwn = rotation.submitSignatures(
    oneOwn.state, createdY.domain.id, 'same-rot',
    [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, msgY) }],
    NOW,
  );
  assert.equal(twoOwn.result.activated, true);
  const head = twoOwn.state.domains[createdY.domain.id].checkpoints[rotY.digest];
  assert.equal(head.evidence.length, 2);
  for (const entry of head.evidence) {
    assert.equal(rotation.verifyAuthorization(msgY, entry.signature, entry.publicKey), true);
    assert.equal(rotation.verifyAuthorization(msgX, entry.signature, entry.publicKey), false, '证据不应能验证 X 候选');
  }
  // X 域链头与历史不受影响。
  assert.equal(twoOwn.state.domains[createdX.domain.id].headDigest, createdX.domain.headDigest);
});

test('持久化：跨设备域同名候选的签名落盘与重载互不串用，重启后补签行为正确', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-cross-'));
  const file = path.join(dir, 'state.json');
  const store = new Store(file);
  store.load();

  const members = [genKey(), genKey()];
  const dx = await store.commit((s) => rotation.createDomain(s, { name: '域X', publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW));
  const dy = await store.commit((s) => rotation.createDomain(s, { name: '域Y', publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW));
  const nx = [genKey(), genKey()];
  const ny = [genKey(), genKey()];
  await store.commit((s) => rotation.createRotation(s, dx.id, { rotationId: 'same-rot', parentDigest: dx.headDigest, publicKeys: nx.map((k) => k.publicKey), threshold: 2 }, NOW));
  await store.commit((s) => rotation.createRotation(s, dy.id, { rotationId: 'same-rot', parentDigest: dy.headDigest, publicKeys: ny.map((k) => k.publicKey), threshold: 2 }, NOW));

  const msgX = rotation.authorizationMessage(store.state.domains[dx.id].rotations['same-rot']);
  // 只为 X 候选提交一名父成员的有效签名。
  await store.commit((s) => rotation.submitSignatures(s, dx.id, 'same-rot', [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgX) }], NOW));

  // 重启：Y 候选不得带出来自 X 候选的签名。
  const reloaded = new Store(file);
  reloaded.load();
  assert.equal(reloaded.state.domains[dx.id].rotations['same-rot'].signatures.length, 1);
  assert.equal(reloaded.state.domains[dy.id].rotations['same-rot'].signatures.length, 0);
  assert.equal(reloaded.state.domains[dy.id].headDigest, dy.headDigest);

  // 再只为 Y 候选提交另一名父成员针对 Y 自身消息的签名：仍须待签。
  const rotY = reloaded.state.domains[dy.id].rotations['same-rot'];
  const msgY = rotation.authorizationMessage(rotY);
  const onlyOne = await reloaded.commit((s) => rotation.submitSignatures(s, dy.id, 'same-rot', [{ publicKey: members[1].publicKey, signature: sign(members[1].privateKey, msgY) }], NOW));
  assert.equal(onlyOne.activated, false);
  assert.equal(onlyOne.signers, 1);
  assert.equal(onlyOne.headDigest, dy.headDigest);

  // 第二名父成员也签 Y 自身消息后才激活；证据逐份验证 Y 消息。
  const activated = await reloaded.commit((s) => rotation.submitSignatures(s, dy.id, 'same-rot', [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgY) }], NOW));
  assert.equal(activated.activated, true);
  const head = rotation.headView(reloaded.state.domains[dy.id]);
  assert.equal(head.digest, rotY.digest);
  assert.equal(head.evidence.length, 2);
  for (const entry of head.evidence) {
    assert.equal(rotation.verifyAuthorization(msgY, entry.signature, entry.publicKey), true);
  }
  // X 域链头、历史与候选签名完全不变。
  const afterX = reloaded.state.domains[dx.id];
  assert.equal(afterX.headDigest, dx.headDigest);
  assert.equal(afterX.rotations['same-rot'].signatures.length, 1);
  assert.equal(Object.keys(afterX.checkpoints).length, 1);
});

test('启动自愈：回滚靠他域签名错误激活的链头，恢复被错误取代的候选，保留本域有效证据', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-heal-'));
  const file = path.join(dir, 'state.json');
  const store = new Store(file);
  store.load();

  const members = [genKey(), genKey()];
  const dx = await store.commit((s) => rotation.createDomain(s, { name: '自愈域X', publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW));
  const dy = await store.commit((s) => rotation.createDomain(s, { name: '自愈域Y', publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW));
  const nx = [genKey(), genKey()];
  const ny = [genKey(), genKey()];
  await store.commit((s) => rotation.createRotation(s, dx.id, { rotationId: 'same-rot', parentDigest: dx.headDigest, publicKeys: nx.map((k) => k.publicKey), threshold: 2 }, NOW));
  await store.commit((s) => rotation.createRotation(s, dy.id, { rotationId: 'same-rot', parentDigest: dy.headDigest, publicKeys: ny.map((k) => k.publicKey), threshold: 2 }, NOW));
  await store.commit((s) => rotation.createRotation(s, dy.id, { rotationId: 'loser', parentDigest: dy.headDigest, publicKeys: [genKey().publicKey, genKey().publicKey], threshold: 2 }, NOW));

  const msgX = rotation.authorizationMessage(store.state.domains[dx.id].rotations['same-rot']);
  const rotY = store.state.domains[dy.id].rotations['same-rot'];
  const msgY = rotation.authorizationMessage(rotY);
  const sigAx = sign(members[0].privateKey, msgX); // 签署的是 X 候选消息
  const sigBy = sign(members[1].privateKey, msgY); // 签署 Y 候选自身消息

  // 伪造旧缺陷版本落盘的损坏记录：Y 靠“X 的签名 + 自己的一票”错误激活。
  const corrupted = structuredClone(store.state);
  const y = corrupted.domains[dy.id];
  const badCheckpoint = {
    digest: rotY.digest, domainId: dy.id, rotationId: 'same-rot', parentDigest: rotY.parentDigest,
    generation: 1, threshold: rotY.threshold, keys: rotY.keys, status: 'activated', activatedAt: NOW,
    evidence: [
      { publicKey: members[0].publicKey, signature: sigAx, receivedAt: NOW },
      { publicKey: members[1].publicKey, signature: sigBy, receivedAt: NOW },
    ],
  };
  y.checkpoints[badCheckpoint.digest] = badCheckpoint;
  y.headDigest = badCheckpoint.digest;
  y.generation = 1;
  y.keys = rotY.keys;
  y.threshold = rotY.threshold;
  y.rotations['same-rot'].status = 'activated';
  y.rotations['same-rot'].activatedAt = NOW;
  y.rotations['same-rot'].signatures = badCheckpoint.evidence;
  y.rotations.loser.status = 'superseded';
  y.rotations.loser.rejectedReason = '已被轮换 same-rot 取代（损坏记录）';
  fs.writeFileSync(file, JSON.stringify(corrupted, null, 2) + '\n');

  const healed = new Store(file);
  healed.load();
  const hy = healed.state.domains[dy.id];
  assert.equal(hy.headDigest, dy.headDigest, '链头必须回退到有效父检查点（创世）');
  assert.equal(hy.generation, 0);
  assert.equal(hy.rotations['same-rot'].status, 'pending', '未获完整授权的候选恢复待签');
  assert.deepEqual(
    hy.rotations['same-rot'].signatures.map((e) => e.publicKey),
    [members[1].publicKey],
    '只保留能验证本域消息的签名，外来签名必须剔除',
  );
  assert.ok(!hy.checkpoints[rotY.digest], '无效活动检查点必须从链上移除');
  assert.equal(hy.rotations.loser.status, 'pending', '被无效激活取代的候选必须恢复待签');

  // X 域（本域证据有效）逐字节不变。
  assert.deepEqual(healed.state.domains[dx.id], store.state.domains[dx.id]);

  // 自愈结果已重新落盘：再次重启保持修复后的状态。
  const again = new Store(file);
  again.load();
  assert.equal(again.state.domains[dy.id].headDigest, dy.headDigest);
  assert.equal(again.state.domains[dy.id].rotations['same-rot'].signatures.length, 1);

  // 补齐两名成员针对 Y 自身消息的签名后正常激活，证据逐份可验证。
  const out = await again.commit((s) => rotation.submitSignatures(s, dy.id, 'same-rot', [{ publicKey: members[0].publicKey, signature: sign(members[0].privateKey, msgY) }], NOW));
  assert.equal(out.activated, true);
  const head = rotation.headView(again.state.domains[dy.id]);
  for (const entry of head.evidence) {
    assert.equal(rotation.verifyAuthorization(msgY, entry.signature, entry.publicKey), true);
  }
});

test('持久化：竞争候选并发达标，磁盘上只有一个活动检查点', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-race-'));
  const store = new Store(path.join(dir, 'state.json'));
  store.load();

  const members = [genKey(), genKey()];
  const domain = await store.commit((s) => rotation.createDomain(s, { name: '竞争域', publicKeys: members.map((m) => m.publicKey), threshold: 2 }, NOW));
  for (const rid of ['race-1', 'race-2']) {
    const keys = [genKey(), genKey()];
    await store.commit((s) => rotation.createRotation(s, domain.id, { rotationId: rid, parentDigest: domain.headDigest, publicKeys: keys.map((k) => k.publicKey), threshold: 2 }, NOW));
  }
  const dom = () => store.state.domains[domain.id];
  const msg = (rid) => rotation.authorizationMessage(dom().rotations[rid]);
  const fullBatch = (rid) => members.map((m) => ({ publicKey: m.publicKey, signature: sign(m.privateKey, msg(rid)) }));

  const results = await Promise.allSettled([
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'race-1', fullBatch('race-1'), NOW)),
    store.commit((s) => rotation.submitSignatures(s, domain.id, 'race-2', fullBatch('race-2'), NOW)),
  ]);
  const fulfilled = results.filter((r) => r.status === 'fulfilled').map((r) => r.value);
  const rejected = results.filter((r) => r.status === 'rejected').map((r) => r.reason);
  assert.equal(fulfilled.filter((o) => o.activated).length, 1, '只有一个候选激活');
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].code, 'rotation_superseded');

  const finalDomain = dom();
  const activated = Object.values(finalDomain.rotations).filter((r) => r.status === 'activated');
  assert.equal(activated.length, 1);
  assert.equal(finalDomain.headDigest, activated[0].digest);
  assert.equal(Object.values(finalDomain.checkpoints).filter((c) => c.generation === 1).length, 1, '同代次只有一个活动检查点');
});
