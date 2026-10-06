FROM node:20-alpine

ENV NODE_ENV=production
WORKDIR /app

# 零第三方依赖：无需 npm install，构建完全离线可重现。
COPY package.json ./
COPY src ./src
COPY scripts ./scripts
COPY test ./test

EXPOSE 3000
CMD ["node", "src/main.js"]
