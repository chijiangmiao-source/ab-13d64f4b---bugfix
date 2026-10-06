'use strict';

const path = require('node:path');
const { Store } = require('./store');
const { createServer } = require('./server');

const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const ALLOW_ADMIN_RESTART = process.env.ALLOW_ADMIN_RESTART === '1';

const store = new Store(path.join(DATA_DIR, 'state.json'));
store.load();

const server = createServer({ store, allowAdminRestart: ALLOW_ADMIN_RESTART });
server.listen(PORT, () => {
  console.log(`[main] 密钥轮换服务已启动：http://0.0.0.0:${PORT}（数据目录 ${DATA_DIR}）`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    console.log(`[main] 收到 ${signal}，正在关闭…`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  });
}
