'use strict';

/**
 * 设备域密钥轮换 —— 纯领域逻辑（不依赖 I/O）。
 *
 * 授权链模型：
 *  - 设备域创建时产生创世检查点（第 0 代，立即激活）。
 *  - 轮换候选绑定固定父摘要（创建时的当前链头）、下一代次、
 *    排序后的新公钥集与新门限。
 *  - 父检查点密钥成员对“规范 UTF-8 授权消息”做 Ed25519 签名；
 *    去重后的签名者达到父门限时，候选在同一次持久化提交中激活，
 *    同一父摘要下的其余待签候选在同一提交中被取代（已拒）。
 */

const crypto = require('node:crypto');

const CHECKPOINT_VERSION = 'maintenance-rotation-checkpoint/v1';
const AUTHORIZATION_VERSION = 'maintenance-rotation-authorization/v1';
const GENESIS_ROTATION_ID = 'genesis';
const GENESIS_PARENT_DIGEST = '0'.repeat(64);

const KEY_HEX_RE = /^[0-9a-f]{64}$/; // Ed25519 公钥：32 字节 → 64 位小写十六进制
const SIG_HEX_RE = /^[0-9a-f]{128}$/; // Ed25519 签名：64 字节 → 128 位小写十六进制
const DIGEST_HEX_RE = /^[0-9a-f]{64}$/; // SHA-256 摘要
const ROTATION_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const MIN_KEYS = 2;
const MAX_KEYS = 5;

// Ed25519 SPKI DER 前缀（OID 1.3.101.112），后接 32 字节原始公钥。
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

class DomainError extends Error {
  constructor(code, reason) {
    super(reason);
    this.name = 'DomainError';
    this.code = code;
  }
}

function isHexKey(value) {
  return typeof value === 'string' && KEY_HEX_RE.test(value);
}

function isHexSignature(value) {
  return typeof value === 'string' && SIG_HEX_RE.test(value);
}

/** 排序并去重（输入须已校验为合法十六进制公钥）。 */
function sortKeys(keys) {
  return [...new Set(keys.map((k) => k.toLowerCase()))].sort();
}

/**
 * 规范化并校验密钥集与门限：2–5 把 Ed25519 公钥（去重、排序），
 * 门限为 1..n 的整数。
 */
function validateKeySet(publicKeys, threshold) {
  if (!Array.isArray(publicKeys)) {
    throw new DomainError('invalid_key_set', 'publicKeys 必须是公钥数组');
  }
  const normalized = publicKeys.map((k) => (typeof k === 'string' ? k.trim().toLowerCase() : ''));
  if (normalized.some((k) => !KEY_HEX_RE.test(k))) {
    throw new DomainError('invalid_key_set', '每把公钥必须是 64 位小写十六进制（32 字节 Ed25519 公钥）');
  }
  const keys = sortKeys(normalized);
  if (keys.length !== normalized.length) {
    throw new DomainError('invalid_key_set', '公钥集存在重复项');
  }
  if (keys.length < MIN_KEYS || keys.length > MAX_KEYS) {
    throw new DomainError('invalid_key_set', `设备域需要 ${MIN_KEYS}–${MAX_KEYS} 把 Ed25519 公钥`);
  }
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > keys.length) {
    throw new DomainError('invalid_threshold', `门限必须是 1..${keys.length} 的整数`);
  }
  return { keys, threshold };
}

function validateRotationId(rotationId) {
  if (typeof rotationId !== 'string' || !ROTATION_ID_RE.test(rotationId)) {
    throw new DomainError(
      'invalid_rotation_id',
      '轮换标识须以字母或数字开头，仅含字母、数字、点、下划线、连字符，最长 128 字符',
    );
  }
  return rotationId;
}

function validateDomainName(name) {
  if (name === undefined || name === null || name === '') return null;
  if (typeof name !== 'string' || name.length > 80 || [...name].some((c) => c < ' ')) {
    throw new DomainError('invalid_name', '设备域名称须为不超过 80 字符的纯文本');
  }
  return name;
}

/** 检查点的规范 UTF-8 序列化（用于计算摘要）。 */
function canonicalCheckpointDocument(cp) {
  return [
    CHECKPOINT_VERSION,
    `domain=${cp.domainId}`,
    `rotation=${cp.rotationId}`,
    `parent=${cp.parentDigest}`,
    `generation=${cp.generation}`,
    `threshold=${cp.threshold}`,
    `keys=${cp.keys.join(',')}`,
  ].join('\n');
}

/** 检查点摘要 = SHA-256(规范 UTF-8 文档)。 */
function checkpointDigest(cp) {
  return crypto.createHash('sha256').update(canonicalCheckpointDocument(cp), 'utf8').digest('hex');
}

/** 父密钥成员签署的规范 UTF-8 授权消息。 */
function authorizationMessage(rotation) {
  return [
    AUTHORIZATION_VERSION,
    `domain=${rotation.domainId}`,
    `rotation=${rotation.rotationId}`,
    `parent=${rotation.parentDigest}`,
    `generation=${rotation.generation}`,
    `threshold=${rotation.threshold}`,
    `keys=${rotation.keys.join(',')}`,
  ].join('\n');
}

function publicKeyFromHex(publicKeyHex) {
  return crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKeyHex, 'hex')]),
    format: 'der',
    type: 'spki',
  });
}

/** 以规范 UTF-8 消息做 Ed25519 验签；任何异常都视为验签失败。 */
function verifyAuthorization(message, signatureHex, publicKeyHex) {
  try {
    return crypto.verify(
      null,
      Buffer.from(message, 'utf8'),
      publicKeyFromHex(publicKeyHex),
      Buffer.from(signatureHex, 'hex'),
    );
  } catch {
    return false;
  }
}

function mustDomain(state, domainId) {
  const domain = state.domains[domainId];
  if (!domain) throw new DomainError('unknown_domain', `设备域不存在：${domainId}`);
  return domain;
}

function mustRotation(domain, rotationId) {
  const rotation = domain.rotations[rotationId];
  if (!rotation) throw new DomainError('unknown_rotation', `轮换候选不存在：${rotationId}`);
  return rotation;
}

/**
 * 计算候选的“有效授权证据”：只有满足下列全部条件的签名才计入：
 *  - 签名者是该候选固定父检查点的密钥成员；
 *  - 签名能通过该候选自身规范 UTF-8 授权消息的 Ed25519 验签
 *    （消息固定绑定设备域、轮换标识、父摘要、代次、门限与新公钥集，
 *     因此他域同名候选的签名即使父公钥相同也无法通过）；
 *  - 按签名者去重。
 *
 * 激活门限永远以这里的结果为准，而不是直接信任已存储的签名数量。
 */
function validEvidence(checkpoints, candidate) {
  const parentCheckpoint = checkpoints[candidate.parentDigest];
  if (!parentCheckpoint) return { parentCheckpoint: null, evidence: [] };
  const message = authorizationMessage(candidate);
  const seen = new Set();
  const evidence = [];
  for (const entry of Array.isArray(candidate.signatures) ? candidate.signatures : []) {
    const publicKey = entry && typeof entry.publicKey === 'string' ? entry.publicKey : null;
    const signature = entry && typeof entry.signature === 'string' ? entry.signature : null;
    if (!publicKey || !signature || seen.has(publicKey)) continue;
    if (!parentCheckpoint.keys.includes(publicKey)) continue;
    if (!verifyAuthorization(message, signature, publicKey)) continue;
    seen.add(publicKey);
    evidence.push(entry);
  }
  return { parentCheckpoint, evidence };
}

/**
 * 创建设备域：产生创世检查点（第 0 代，立即激活）并作为链头。
 */
function createDomain(state, input, now) {
  const name = validateDomainName(input.name);
  const { keys, threshold } = validateKeySet(input.publicKeys, input.threshold);
  const id = `dom-${crypto.randomUUID()}`;
  const genesis = {
    digest: null,
    domainId: id,
    rotationId: GENESIS_ROTATION_ID,
    parentDigest: GENESIS_PARENT_DIGEST,
    generation: 0,
    threshold,
    keys,
    status: 'activated',
    activatedAt: now,
    evidence: [],
  };
  genesis.digest = checkpointDigest(genesis);
  const domain = {
    id,
    name: name || id,
    createdAt: now,
    headDigest: genesis.digest,
    generation: 0,
    keys,
    threshold,
    checkpoints: { [genesis.digest]: genesis },
    rotations: {},
  };
  return {
    state: { ...state, domains: { ...state.domains, [id]: domain } },
    result: domain,
  };
}

/**
 * 创建轮换候选。父摘要必须等于当前链头（固定父摘要）；
 * 同一轮换标识重复创建且载荷一致时幂等返回，载荷不同则拒绝。
 */
function createRotation(state, domainId, input, now) {
  const domain = mustDomain(state, domainId);
  const rotationId = validateRotationId(input.rotationId);
  const parentDigest = typeof input.parentDigest === 'string' ? input.parentDigest.trim().toLowerCase() : '';
  if (!DIGEST_HEX_RE.test(parentDigest)) {
    throw new DomainError('invalid_parent_digest', '父摘要必须是 64 位小写十六进制 SHA-256');
  }
  if (parentDigest !== domain.headDigest) {
    throw new DomainError(
      'wrong_parent_digest',
      `父摘要与当前链头不一致：期望 ${domain.headDigest}，收到 ${parentDigest}`,
    );
  }
  const { keys, threshold } = validateKeySet(input.publicKeys, input.threshold);

  const existing = domain.rotations[rotationId];
  if (existing) {
    const samePayload =
      existing.parentDigest === parentDigest &&
      existing.threshold === threshold &&
      existing.keys.length === keys.length &&
      existing.keys.every((k, i) => k === keys[i]);
    if (samePayload) return { state, result: { rotation: existing, created: false } };
    throw new DomainError('conflicting_rotation', `轮换标识 ${rotationId} 已存在且载荷不同，拒绝覆盖`);
  }

  const parentCheckpoint = domain.checkpoints[parentDigest];
  if (!parentCheckpoint) {
    throw new DomainError('wrong_parent_digest', '父摘要对应的检查点不在授权链上');
  }
  const rotation = {
    rotationId,
    domainId,
    parentDigest,
    generation: parentCheckpoint.generation + 1,
    threshold,
    keys,
    digest: null,
    status: 'pending',
    createdAt: now,
    activatedAt: null,
    rejectedReason: null,
    signatures: [],
  };
  rotation.digest = checkpointDigest(rotation);
  const nextDomain = { ...domain, rotations: { ...domain.rotations, [rotationId]: rotation } };
  return {
    state: { ...state, domains: { ...state.domains, [domainId]: nextDomain } },
    result: { rotation, created: true },
  };
}

/**
 * 为同一轮换标识分批提交签名。
 *
 * 每条签名独立给出“接受/拒因”；只有去重后的父密钥成员签名数
 * 达到父门限时，候选才激活。激活、签名证据落盘、竞争候选被取代
 * 全部发生在同一次状态迁移中（由 Store 保证同一次持久化提交）。
 */
function submitSignatures(state, domainId, rotationId, signatures, now) {
  const domain = mustDomain(state, domainId);
  const rotation = mustRotation(domain, rotationId);
  if (rotation.status === 'activated') {
    throw new DomainError('rotation_already_activated', `轮换 ${rotationId} 已激活，迟到的签名不会改变链头`);
  }
  if (rotation.status === 'superseded') {
    throw new DomainError('rotation_superseded', `轮换 ${rotationId} 已被取代：${rotation.rejectedReason}`);
  }
  if (!Array.isArray(signatures) || signatures.length === 0) {
    throw new DomainError('invalid_batch', '签名批次必须是非空数组');
  }
  if (signatures.length > 64) {
    throw new DomainError('invalid_batch', '单批签名数量超出上限（64）');
  }

  const parentCheckpoint = domain.checkpoints[rotation.parentDigest];
  if (!parentCheckpoint) {
    throw new DomainError('wrong_parent_digest', '父检查点不在授权链上，拒绝签名');
  }
  const message = authorizationMessage(rotation);
  const seen = new Set(rotation.signatures.map((s) => s.publicKey));
  const results = [];
  const accepted = [];

  signatures.forEach((entry, index) => {
    const publicKey = typeof entry?.publicKey === 'string' ? entry.publicKey.trim().toLowerCase() : '';
    const signature = typeof entry?.signature === 'string' ? entry.signature.trim().toLowerCase() : '';
    if (!isHexKey(publicKey) || !isHexSignature(signature)) {
      results.push({
        index,
        publicKey: publicKey || null,
        status: 'rejected',
        code: 'malformed_signature',
        reason: '公钥或签名不是规范的十六进制编码',
      });
    } else if (!parentCheckpoint.keys.includes(publicKey)) {
      results.push({
        index,
        publicKey,
        status: 'rejected',
        code: 'not_parent_member',
        reason: '签名者不是父检查点密钥成员',
      });
    } else if (seen.has(publicKey)) {
      results.push({
        index,
        publicKey,
        status: 'rejected',
        code: 'duplicate_signature',
        reason: '该父密钥成员已提交过签名（重复/重传），已忽略',
      });
    } else if (!verifyAuthorization(message, signature, publicKey)) {
      results.push({
        index,
        publicKey,
        status: 'rejected',
        code: 'invalid_signature',
        reason: '签名未通过规范 UTF-8 消息验签（载荷可能被篡改）',
      });
    } else {
      seen.add(publicKey);
      accepted.push({ publicKey, signature, receivedAt: now });
      results.push({ index, publicKey, status: 'accepted' });
    }
  });

  if (accepted.length === 0) {
    return {
      state,
      result: {
        rotation,
        results,
        activated: false,
        signers: rotation.signatures.length,
        threshold: parentCheckpoint.threshold,
        headDigest: domain.headDigest,
      },
    };
  }

  const mergedSignatures = rotation.signatures.concat(accepted);
  let nextRotation = { ...rotation, signatures: mergedSignatures };
  let nextDomain = { ...domain, rotations: { ...domain.rotations, [rotationId]: nextRotation } };
  let activated = false;

  // 激活门限以“能验证本候选自身消息的去重父成员证据”为准，
  // 绝不直接信任已存储签名数量（防止他域同名候选的签名串用）。
  const { evidence: authorizingEvidence } = validEvidence(nextDomain.checkpoints, nextRotation);
  if (authorizingEvidence.length >= parentCheckpoint.threshold) {
    activated = true;
    const checkpoint = {
      digest: rotation.digest,
      domainId,
      rotationId,
      parentDigest: rotation.parentDigest,
      generation: rotation.generation,
      threshold: rotation.threshold,
      keys: rotation.keys,
      status: 'activated',
      activatedAt: now,
      evidence: authorizingEvidence,
    };
    nextRotation = { ...nextRotation, status: 'activated', activatedAt: now };
    const nextRotations = { ...nextDomain.rotations, [rotationId]: nextRotation };
    // 同一父摘要下的其余待签候选在同一迁移中被取代（已拒）。
    for (const [rid, candidate] of Object.entries(nextRotations)) {
      if (rid !== rotationId && candidate.status === 'pending' && candidate.parentDigest === rotation.parentDigest) {
        nextRotations[rid] = {
          ...candidate,
          status: 'superseded',
          rejectedReason: `已被轮换 ${rotationId} 取代（检查点 ${rotation.digest} 先达到父门限）`,
          supersededAt: now,
        };
      }
    }
    nextDomain = {
      ...nextDomain,
      headDigest: rotation.digest,
      generation: rotation.generation,
      keys: rotation.keys,
      threshold: rotation.threshold,
      checkpoints: { ...nextDomain.checkpoints, [rotation.digest]: checkpoint },
      rotations: nextRotations,
    };
  }

  return {
    state: { ...state, domains: { ...state.domains, [domainId]: nextDomain } },
    result: {
      rotation: nextDomain.rotations[rotationId],
      results,
      activated,
      signers: mergedSignatures.length,
      threshold: parentCheckpoint.threshold,
      headDigest: nextDomain.headDigest,
    },
  };
}

/** 当前活动链头视图（含签名证据）。 */
function headView(domain) {
  const head = domain.checkpoints[domain.headDigest];
  return {
    domainId: domain.id,
    digest: head.digest,
    rotationId: head.rotationId,
    parentDigest: head.parentDigest,
    generation: head.generation,
    threshold: head.threshold,
    keys: head.keys,
    status: head.status,
    activatedAt: head.activatedAt,
    evidence: head.evidence,
  };
}

module.exports = {
  DomainError,
  CHECKPOINT_VERSION,
  AUTHORIZATION_VERSION,
  GENESIS_ROTATION_ID,
  GENESIS_PARENT_DIGEST,
  MIN_KEYS,
  MAX_KEYS,
  sortKeys,
  validateKeySet,
  canonicalCheckpointDocument,
  checkpointDigest,
  authorizationMessage,
  verifyAuthorization,
  validEvidence,
  createDomain,
  createRotation,
  submitSignatures,
  headView,
};
