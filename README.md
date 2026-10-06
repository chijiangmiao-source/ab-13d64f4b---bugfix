# 隔离维护网 · 设备域命令签发密钥轮换

面向隔离维护网的远端设备命令签发密钥轮换服务。运营员沿**唯一授权链**轮换设备域的
Ed25519 密钥集：新密钥只有在**去重后的父密钥成员签名达到父门限**时，才会在**同一次
持久化提交**中激活；延迟签名、重复重传与竞争候选都不会让新密钥提前生效。

零第三方依赖（纯 Node.js 标准库，Node ≥ 20），Docker 构建完全离线可重现。

## 快速开始

```bash
# 一键验收（推荐）：构建镜像，启动应用，跑完 verify 后以其退出码报告结果
docker compose up --build --exit-code-from verify verify

# 仅启动服务（页面与 API 暴露在 http://localhost:3000）
docker compose up --build app

# 本地（无 Docker）运行
npm start                 # 启动服务（PORT、DATA_DIR、ALLOW_ADMIN_RESTART 可配）
npm test                  # 轮换规则单元测试
npm run check             # 构建检查（语法 + 模块加载）
APP_URL=http://127.0.0.1:3000 npm run verify   # 对运行中的服务做完整验收
```

`verify` 服务依次执行：轮换规则单元测试 → 构建检查 → HTTP 冒烟（创建二钥二门限设备域、
分批补齐两名有效签名、读回已激活链头与两份证据、校验页面一致、并发竞争收敛、
跨设备域同名候选在重启后不串用签名且证据逐份可验证、重启一致性），
完成后退出，退出码 0 表示全部通过。

## 授权链模型

- **设备域**：2–5 把 Ed25519 公钥（服务端排序去重）+ 门限（1..n）。创建时生成
  创世检查点（第 0 代，立即激活）作为链头。
- **轮换候选**：绑定**固定父摘要**（创建时的链头）、**下一代次**、**排序后新公钥集**、
  **新门限**。候选摘要 = SHA-256(规范 UTF-8 检查点文档)。
- **签名**：父检查点密钥成员对规范 UTF-8 授权消息做 Ed25519 签名，可为同一轮换标识
  分批提交。消息固定绑定**设备域 ID、轮换标识、父摘要、代次、门限与排序后新公钥集**，
  因此两个设备域即便父公钥集与轮换标识完全相同，他域同名候选的签名也无法验证本域候选。消息形如：

  ```
  maintenance-rotation-authorization/v1
  domain=<域ID>
  rotation=<轮换标识>
  parent=<父摘要hex>
  generation=<代次>
  threshold=<新门限>
  keys=<逗号分隔的排序后新公钥hex>
  ```

- **激活**：同一候选下去重后的父成员签名数达到父门限时，候选检查点、签名证据、
  链头前进、竞争候选被取代在**同一次原子文件提交**（写临时文件 → fsync → rename →
  fsync 目录）中生效。所有变更经单写者串行队列，并发补签/重传只会收敛为一个活动检查点。
- **拒因**（均不改变链头）：`wrong_parent_digest`（错误/过期父摘要）、
  `duplicate_signature`（重复/重传）、`invalid_signature`（篡改载荷/验签失败）、
  `not_parent_member`（非父成员）、`rotation_already_activated`（激活后的迟到补签）、
  `rotation_superseded`（被取代候选）、`conflicting_rotation`（同标识不同载荷）。

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 运营页面（链头、待签/已拒/已激活检查点、证据、操作表单） |
| GET | `/healthz` | 健康响应，反映各设备域链头/代次/门限状态 |
| POST | `/api/domains` | 创建设备域 `{name?, publicKeys[2..5], threshold}` |
| GET | `/api/domains` | 设备域摘要列表 |
| GET | `/api/domains/:id` | 域详情（检查点链 + 全部轮换候选及签名） |
| GET | `/api/domains/:id/head` | 当前活动链头（含签名证据） |
| POST | `/api/domains/:id/rotations` | 创建候选 `{rotationId, parentDigest, publicKeys, threshold}` |
| GET | `/api/domains/:id/rotations/:rid/message` | 规范 UTF-8 待签消息（供离线签名） |
| POST | `/api/domains/:id/rotations/:rid/signatures` | 分批提交签名 `{signatures:[{publicKey, signature}]}` |
| POST | `/api/admin/restart` | 进程退出（仅 `ALLOW_ADMIN_RESTART=1` 时可用，供验收验证重启一致性） |

公钥为 64 位小写十六进制（32 字节 Ed25519 原始公钥），签名为 128 位小写十六进制。

## 持久化与重启

状态存于 `DATA_DIR/state.json`（compose 中挂载卷 `rotation-data`）。每次状态迁移
原子落盘；签名证据按“设备域 + 候选”独立持久化，轮换标识不会跨设备域串用。
应用重启后从磁盘恢复，活动链头、历史检查点与签名证据保持一致
（验收中会真实重启进程并逐字节比对重启前后的域状态）。

启动时还会对已落盘记录做一次自愈校验：每份证据都必须是其父成员对**本候选自身
规范消息**的有效签名；证据不完整的检查点（例如历史缺陷版本写入的他域同名候选
签名）会被移除，链头回退到最后一个有效父检查点，被该无效激活取代的候选恢复待签，
修复结果立即原子落盘，之后页面、域详情、链头接口与健康响应保持一致。

## 目录结构

```
src/rotation.js   领域逻辑：规范消息、摘要、验签、状态迁移（纯函数）
src/store.js      单写者串行队列 + 原子文件提交
src/server.js     HTTP 路由与视图
src/page.js       服务端渲染的运营页面
src/static/app.js 页面交互脚本
src/main.js       服务入口
scripts/verify.js 验收入口（compose 的 verify 服务）
scripts/build-check.js 构建检查
test/rotation.test.js  轮换规则单元测试
```
