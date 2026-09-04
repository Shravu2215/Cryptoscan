# Standalone service — no sibling-module dependencies, so the build context
# is this directory itself.
# Build with:  docker build -t cryptoscan-cbom-service ./cbom-service
FROM node:20-bookworm-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

ENV NODE_ENV=production
EXPOSE 4003

CMD ["node", "src/server.js"]
