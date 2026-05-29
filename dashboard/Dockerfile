# H-IDS dashboard — production image.
#
# Two-stage: node:20 runs `vite build`, then nginx:alpine serves the
# resulting static bundle. Image is ~30 MB; no Node runtime in the
# final layer.
#
# For active frontend development run `npm run dev` on the host — Vite
# HMR doesn't survive the file-watching round-trip across the WSL2/Docker
# boundary on Windows. This image is for staging + production.

# --- build stage -----------------------------------------------------
FROM node:20-alpine AS build

WORKDIR /app

# Install deps first so the layer caches when only src/ changes.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# VITE_API_URL is baked into the JS bundle at build time. Default
# matches the docker-compose `api` service's published port; override
# at build time via `--build-arg VITE_API_URL=https://api.example.com`
# for AWS / staging builds.
ARG VITE_API_URL=http://localhost:8000
ARG VITE_USE_MOCK=false
ENV VITE_API_URL=${VITE_API_URL} \
    VITE_USE_MOCK=${VITE_USE_MOCK}

RUN npm run build

# --- runtime stage ---------------------------------------------------
FROM nginx:alpine AS runtime

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

# nginx:alpine's default CMD already runs nginx in the foreground; no
# override needed.
