'use strict';

/**
 * 持久化存储：单写者串行队列 + 原子文件提交。
 *
 * 每次 commit(mutator)：
 *  1. 在串行队列中执行 mutator（纯函数：state → {state, result}）；
 *  2. 若返回了新状态，则一次性写入临时文件、fsync、rename 替换、
 *     fsync 目录 —— 这是一次“持久化提交”，要么完整生效要么不生效；
 *  3. 只有落盘成功后才更新内存状态。
 *
 * 因此“收集到足够签名 → 激活候选 → 取代竞争候选 → 链头前进”
 * 永远落在同一次持久化提交里；并发的补签/重传在队列中串行收敛，
 * 不会产生第二个活动检查点。
 */

const fs = require('node:fs');
const path = require('node:path');

const rotation = require('./rotation');

const STATE_VERSION = 1;

function initialState() {
  return { version: STATE_VERSION, domains: {} };
}

/**
 * 落盘快照。签名证据只属于创建它时固定的“设备域 + 轮换候选”，
 * 因此每个设备域、每个候选的签名数组都独立序列化，绝不按轮换标识
 * 跨设备域共享（早期实现曾用全局轮换标识做数组复用，导致同名候选
 * 在重启后串用他域签名）。
 */
function snapshotForDisk(state) {
  return structuredClone(state);
}

/**
 * 启动自愈：逐域重放并校验授权链。
 *
 *  - 每个非创世检查点的每份证据都必须是其父检查点密钥成员对
 *    “该候选自身规范 UTF-8 消息”的有效签名，且去重签名者达到父门限；
 *  - 无法验证的外来签名从候选签名集与检查点证据中剔除；
 *  - 证据不完整（含历史缺陷持久化的他域签名）的检查点视为从未获得
 *    本域授权：从链上移除，链头回退到最后一个有效父检查点，对应
 *    候选恢复待签，被该无效激活取代的候选也恢复待签。
 *
 * 返回 true 表示状态被修复（调用方须立即原子落盘）。
 */
function revalidateState(state) {
  let repaired = false;
  for (const domain of Object.values(state.domains)) {
    if (repairDomain(domain)) repaired = true;
  }
  return repaired;
}

function repairDomain(domain) {
  let changed = false;
  if (!domain.checkpoints || typeof domain.checkpoints !== 'object') {
    domain.checkpoints = {};
    changed = true;
  }
  if (!domain.rotations || typeof domain.rotations !== 'object') {
    domain.rotations = {};
    changed = true;
  }
  const { checkpoints, rotations } = domain;

  const genesis = Object.values(checkpoints).find(
    (cp) => cp.generation === 0 && cp.parentDigest === rotation.GENESIS_PARENT_DIGEST,
  );
  if (!genesis) return changed; // 无创世检查点的异常状态不在自愈范围内。

  // 返回 entries 中“父成员 + 对该候选自身消息验签通过 + 按签名者去重”后的子集。
  const cleanEvidence = (rot, parentCp, entries) => {
    const list = Array.isArray(entries) ? entries : [];
    if (!parentCp) {
      if (list.length > 0) changed = true;
      return [];
    }
    const message = rotation.authorizationMessage(rot);
    const seen = new Set();
    const out = [];
    for (const entry of list) {
      const publicKey = entry && typeof entry.publicKey === 'string' ? entry.publicKey : null;
      const signature = entry && typeof entry.signature === 'string' ? entry.signature : null;
      if (
        !publicKey ||
        !signature ||
        seen.has(publicKey) ||
        !parentCp.keys.includes(publicKey) ||
        !rotation.verifyAuthorization(message, signature, publicKey)
      ) {
        changed = true; // 外来的、重复的或无法验证的证据一律不得保留。
        continue;
      }
      seen.add(publicKey);
      out.push(entry);
    }
    return out;
  };

  // 从创世检查点开始逐代重建唯一有效链。
  const validDigests = new Set([genesis.digest]);
  let tip = genesis;
  for (;;) {
    const children = Object.values(checkpoints)
      .filter((cp) => cp.generation === tip.generation + 1 && cp.parentDigest === tip.digest)
      .sort((a, b) => (a.rotationId < b.rotationId ? -1 : a.rotationId > b.rotationId ? 1 : 0));
    let extended = false;
    for (const cp of children) {
      const rot = rotations[cp.rotationId];
      const evidence = Array.isArray(cp.evidence) ? cp.evidence : [];
      const signers = new Set();
      let allEvidenceValid =
        rot &&
        rot.digest === cp.digest &&
        rotation.checkpointDigest(cp) === cp.digest &&
        evidence.length >= tip.threshold;
      if (allEvidenceValid) {
        const message = rotation.authorizationMessage(rot);
        for (const entry of evidence) {
          const publicKey = entry && entry.publicKey;
          if (
            !publicKey ||
            signers.has(publicKey) ||
            !tip.keys.includes(publicKey) ||
            !rotation.verifyAuthorization(message, entry.signature, publicKey)
          ) {
            allEvidenceValid = false;
            break;
          }
          signers.add(publicKey);
        }
      }
      if (allEvidenceValid) {
        validDigests.add(cp.digest);
        tip = cp;
        extended = true;
        break; // 同一父摘要至多一个有效激活；其余子检查点在下面移除。
      }
    }
    if (!extended) break;
  }

  // 任何不在有效链上的（已落盘）检查点都从未获得完整本域授权。
  for (const digest of Object.keys(checkpoints)) {
    if (!validDigests.has(digest)) {
      delete checkpoints[digest];
      changed = true;
    }
  }

  for (const rot of Object.values(rotations)) {
    const survivingCp = checkpoints[rot.digest];
    if (rot.status === 'activated' && !survivingCp) {
      // 激活所依赖的检查点未通过证据校验：候选恢复待签。
      rot.status = 'pending';
      rot.activatedAt = null;
      rot.rejectedReason = null;
      delete rot.supersededAt;
      changed = true;
    } else if (rot.status === 'superseded') {
      // 只有“取代它的激活仍在有效链上”时，取代状态才成立。
      const winnerAlive = Object.values(checkpoints).some(
        (cp) => cp.parentDigest === rot.parentDigest && cp.rotationId !== rot.rotationId,
      );
      if (!winnerAlive) {
        rot.status = 'pending';
        rot.rejectedReason = null;
        delete rot.supersededAt;
        changed = true;
      }
    }
    const parentCp = checkpoints[rot.parentDigest];
    rot.signatures = cleanEvidence(rot, parentCp, rot.signatures);
    if (rot.status === 'activated' && survivingCp) {
      const cpParent = checkpoints[survivingCp.parentDigest];
      survivingCp.evidence = cleanEvidence(rot, cpParent, survivingCp.evidence);
    }
  }

  if (domain.headDigest !== tip.digest || domain.generation !== tip.generation) changed = true;
  domain.headDigest = tip.digest;
  domain.generation = tip.generation;
  domain.keys = tip.keys;
  domain.threshold = tip.threshold;
  return changed;
}

class Store {
  constructor(file) {
    this.file = file;
    this.state = null;
    this._queue = Promise.resolve();
  }

  /** 启动时加载；状态文件不存在则初始化空状态并落盘。 */
  load() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    if (fs.existsSync(this.file)) {
      const raw = fs.readFileSync(this.file, 'utf8');
      const parsed = JSON.parse(raw);
      if (!parsed || parsed.version !== STATE_VERSION || typeof parsed.domains !== 'object' || parsed.domains === null) {
        throw new Error(`状态文件损坏或版本不受支持：${this.file}`);
      }
      this.state = parsed;
      // 启动自愈：任何无法验证本域授权的证据/活动链头都必须立即修复并落盘，
      // 包括历史缺陷版本写入的跨设备域同名候选串用签名。
      if (revalidateState(this.state)) {
        console.warn('[store] 检测到未经完整本域授权的持久化记录，已回滚并重新落盘');
        this._persist(this.state);
      }
    } else {
      this.state = initialState();
      this._persist(this.state);
    }
    return this.state;
  }

  /**
   * 串行执行一次状态迁移。mutator 抛错时不产生任何持久化变更；
   * mutator 返回原状态引用时跳过落盘（纯拒绝路径不改变链头）。
   */
  commit(mutator) {
    const run = this._queue.then(() => {
      const outcome = mutator(this.state);
      if (!outcome || typeof outcome !== 'object' || !('state' in outcome)) {
        throw new Error('mutator 必须返回 { state, result }');
      }
      const { state, result } = outcome;
      if (state !== this.state) {
        this._persist(state);
        this.state = state;
      }
      return result;
    });
    // 队列本身不因单次失败而中断。
    this._queue = run.catch(() => {});
    return run;
  }

  /** 原子提交：写临时文件 → fsync → rename → fsync 目录。 */
  _persist(state) {
    const tmp = `${this.file}.tmp`;
    const fd = fs.openSync(tmp, 'w');
    try {
      fs.writeSync(fd, JSON.stringify(snapshotForDisk(state), null, 2));
      fs.writeSync(fd, '\n');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, this.file);
    const dirFd = fs.openSync(path.dirname(this.file), 'r');
    try {
      fs.fsyncSync(dirFd);
    } finally {
      fs.closeSync(dirFd);
    }
  }
}

module.exports = { Store, initialState, STATE_VERSION };
