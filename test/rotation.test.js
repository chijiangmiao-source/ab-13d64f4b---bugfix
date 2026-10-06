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

test('跨设备域同名候选：重启后外来签名不得凑门限，逐份证据必须能验证本候选', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rotation-cross-'));
  const file = path.join(dir, 'state.json');
  const store = new Store(file);
  store.load();

  // 两个设备域使用完全相同的父公钥集与门限 2。
  const parents = [genKey(), genKey()];
  const domainX = await store.commit((s) =>
    rotation.createDomain(s, { name: '跨域-X', publicKeys: parents.map((k) => k.publicKey), threshold: 2 }, NOW));
  const domainY = await store.commit((s) =>
    rotation.createDomain(s, { name: '跨域-Y', publicKeys: parents.map((k) => k.publicKey), threshold: 2 }, NOW));

  // 同名轮换标识，但新公钥集不同 → 规范消息必然不同。
  const nextX = [genKey(), genKey()];
  const nextY = [genKey(), genKey()];
  await store.commit((s) => rotation.createRotation(s, domainX.id, {
    rotationId: 'shared-rot', parentDigest: domainX.headDigest,
    publicKeys: nextX.map((k) => k.publicKey), threshold: 2,
  }, NOW));
  await store.commit((s) => rotation.createRotation(s, domainY.id, {
    rotationId: 'shared-rot', parentDigest: domainY.headDigest,
    publicKeys: nextY.map((k) => k.publicKey), threshold: 2,
  }, NOW));

  const rotX = () => store.state.domains[domainX.id].rotations['shared-rot'];
  const rotY = () => store.state.domains[domainY.id].rotations['shared-rot'];
  const msgX = rotation.authorizationMessage(rotX());
  const msgY = rotation.authorizationMessage(rotY());
  assert.notEqual(msgX, msgY, '不同设备域/载荷的规范消息必须不同');

  // 重启前：只为第一个候选提交一名父成员的有效签名。
  const sigXA = sign(parents[0].privateKey, msgX);
  const submitX = await store.commit((s) => rotation.submitSignatures(
    s, domainX.id, 'shared-rot', [{ publicKey: parents[0].publicKey, signature: sigXA }], NOW));
  assert.equal(submitX.activated, false);
  assert.equal(submitX.signers, 1);

  // 重启（旧实现会把同名候选的签名数组跨域覆盖）。
  const reloaded = new Store(file);
  reloaded.load();
  const rx = reloaded.state.domains[domainX.id].rotations['shared-rot'];
  const ry = reloaded.state.domains[domainY.id].rotations['shared-rot'];
  assert.equal(rx.status, 'pending');
  assert.equal(rx.signatures.length, 1, '第一个设备域的签名应保留');
  assert.equal(ry.status, 'pending', '第二个候选重启后必须仍然待签');
  assert.equal(ry.signatures.length, 0, '第一个设备域的签名不得泄漏到同名候选');
  assert.equal(reloaded.state.domains[domainY.id].headDigest, domainY.headDigest, '第二域链头不得前进');
  assert.equal(reloaded.state.domains[domainX.id].headDigest, domainX.headDigest, '第一域链头不得变化');

  // 重启后：只为第二个候选提交另一名父成员针对“其自身消息”的签名。
  const sigYB = sign(parents[1].privateKey, msgY);
  const oneForY = rotation.submitSignatures(
    reloaded.state, domainY.id, 'shared-rot',
    [{ publicKey: parents[1].publicKey, signature: sigYB }], NOW);
  assert.equal(oneForY.result.activated, false, '仅一名本域有效签名时必须继续待签');
  assert.equal(oneForY.result.signers, 1);
  assert.equal(oneForY.state.domains[domainY.id].headDigest, domainY.headDigest);

  // 两名父成员都针对第二个候选的规范 UTF-8 消息签名后才激活。
  const sigYA = sign(parents[0].privateKey, msgY);
  const activated = rotation.submitSignatures(
    oneForY.state, domainY.id, 'shared-rot',
    [{ publicKey: parents[0].publicKey, signature: sigYA }], NOW);
  assert.equal(activated.result.activated, true);
  const yAfter = activated.state.domains[domainY.id];
  assert.equal(yAfter.headDigest, rotY().digest);
  const evidence = yAfter.checkpoints[yAfter.headDigest].evidence;
  assert.equal(evidence.length, 2);
  // 逐份证据核对：每份都必须能验证第二个候选自身的消息。
  for (const entry of evidence) {
    assert.ok(
      rotation.verifyAuthorization(msgY, entry.signature, entry.publicKey),
      '证据无法验证第二个候选的规范消息',
    );
    assert.ok(
      !rotation.verifyAuthorization(msgX, entry.signature, entry.publicKey),
      '证据不应能验证第一个设备域的消息',
    );
  }

  // 第一个设备域的链头、证据与历史完全不受影响。
  const xAfter = activated.state.domains[domainX.id];
  assert.equal(xAfter.headDigest, domainX.headDigest);
  assert.equal(xAfter.rotations['shared-rot'].status, 'pending');
  assert.equal(xAfter.rotations['shared-rot'].signatures.length, 1);
  assert.deepEqual(xAfter.checkpoints, store.state.domains[domainX.id].checkpoints);
});

test('历史受损记录修复：带外来证据的错误活动链头在加载时回退，外来签名被清除', () => {
  const parents = [genKey(), genKey()];
  const { state: s0, domain: dx } = makeDomain(freshState(), parents, 2);
  const createdY = rotation.createDomain(s0, { name: '跨域-Y', publicKeys: parents.map((k) => k.publicKey), threshold: 2 }, NOW);
  const s1 = createdY.state;
  const dy = createdY.result;
  const nextX = [genKey(), genKey()];
  const nextY = [genKey(), genKey()];
  const s2 = rotation.createRotation(s1, dx.id, {
    rotationId: 'shared-rot', parentDigest: dx.headDigest,
    publicKeys: nextX.map((k) => k.publicKey), threshold: 2,
  }, NOW).state;
  const s3 = rotation.createRotation(s2, dy.id, {
    rotationId: 'shared-rot', parentDigest: dy.headDigest,
    publicKeys: nextY.map((k) => k.publicKey), threshold: 2,
  }, NOW).state;

  const rx = s3.domains[dx.id].rotations['shared-rot'];
  const ry = s3.domains[dy.id].rotations['shared-rot'];
  const msgX = rotation.authorizationMessage(rx);
  const msgY = rotation.authorizationMessage(ry);
  // 旧的落盘缺陷会让 Y 持有 X 的签名；再补一份 Y 自身签名后被错误激活。
  const foreign = { publicKey: parents[0].publicKey, signature: sign(parents[0].privateKey, msgX), receivedAt: NOW };
  const own = { publicKey: parents[1].publicKey, signature: sign(parents[1].privateKey, msgY), receivedAt: NOW };
  const corrupted = structuredClone(s3);
  const yDomain = corrupted.domains[dy.id];
  yDomain.rotations['shared-rot'] = {
    ...ry, status: 'activated', activatedAt: NOW, signatures: [foreign, own],
  };
  yDomain.checkpoints[ry.digest] = {
    digest: ry.digest, domainId: dy.id, rotationId: 'shared-rot', parentDigest: ry.parentDigest,
    generation: ry.generation, threshold: ry.threshold, keys: ry.keys,
    status: 'activated', activatedAt: NOW, evidence: [foreign, own],
  };
  yDomain.headDigest = ry.digest;
  yDomain.generation = 1;
  yDomain.keys = ry.keys;
  yDomain.threshold = ry.threshold;

  assert.equal(rotation.isCheckpointAuthorized(
    yDomain.checkpoints[ry.digest], yDomain.checkpoints[ry.parentDigest]), false);

  const repairedOnce = rotation.reconcileState(corrupted);
  assert.ok(repairedOnce.changes > 0, '修复应报告变更');
  const yFixed = repairedOnce.state.domains[dy.id];
  assert.equal(yFixed.headDigest, dy.headDigest, '未经本域完整授权的链头必须回退');
  assert.equal(yFixed.generation, 0);
  assert.equal(yFixed.checkpoints[ry.digest], undefined, '无法验证的活动检查点不得保留');
  assert.equal(yFixed.rotations['shared-rot'].status, 'pending', '候选应回退为待签');
  assert.deepEqual(
    yFixed.rotations['shared-rot'].signatures.map((e) => e.publicKey),
    [parents[1].publicKey],
    '外来签名必须清除，仅保留通过本域消息验签的签名',
  );
  // 第一个设备域不被修复过程改动。
  assert.deepEqual(repairedOnce.state.domains[dx.id], s3.domains[dx.id]);
  // 修复幂等：再次校验不再产生变更。
  assert.equal(rotation.reconcileState(repairedOnce.state).changes, 0);
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
