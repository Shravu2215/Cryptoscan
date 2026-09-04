# Build context MUST be the repository root (not backend-core/), because
# backend-core reaches into sibling directories at runtime:
#   - ../../../blockchain-module  (anchor/verify scripts, ethers)
#   - ../../../integrity-service  (merkle tree, hybrid signatures, KMS)
#   - ../../../scanner            (spawned as a python subprocess)
#   - ../../frontend              (served statically)
# Build with:  docker build -f backend-core/Dockerfile -t cryptoscan-backend-core .
FROM node:20-bookworm-slim

# python3 is required at runtime — backend-core spawns scanner/pipeline.py
# via execFile for every scan.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 \
      python3-venv \
      python3-pip \
      openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# --- Sibling modules backend-core depends on at runtime ---------------------
COPY blockchain-module/package.json blockchain-module/package-lock.json ./blockchain-module/
RUN cd blockchain-module && npm ci --omit=dev

COPY blockchain-module ./blockchain-module
COPY integrity-service ./integrity-service
COPY scanner ./scanner
COPY frontend ./frontend

# Scanner's own Python dependencies (kept separate from the Node venv-setup
# script so the image build doesn't depend on network access to npm at
# container-start time).
RUN python3 -m venv scanner/.venv \
    && scanner/.venv/bin/pip install --no-cache-dir -r scanner/requirements.txt

# --- backend-core itself -----------------------------------------------------
COPY backend-core/package.json backend-core/package-lock.json ./backend-core/
WORKDIR /app/backend-core
# postinstall (scanner venv setup) already handled above; skip re-running it.
RUN npm ci --omit=dev --ignore-scripts

COPY backend-core .

RUN npx prisma generate

ENV NODE_ENV=production
EXPOSE 3000

# Apply pending migrations, then start the server. SQLite lives on a mounted
# volume (see docker-compose.yml) so it survives container restarts.
CMD ["sh", "-c", "npx prisma migrate deploy && node src/server.js"]
