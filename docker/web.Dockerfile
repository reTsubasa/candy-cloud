# syntax=docker/dockerfile:1.7

# Web assets are architecture-neutral. Run Node on the native CI runner instead
# of emulating the target CPU, then copy the result into the target image.
FROM --platform=$BUILDPLATFORM node:22.18-alpine AS build
WORKDIR /app
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN corepack enable
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm run build

FROM --platform=$TARGETPLATFORM busybox:1.37.0-musl
WORKDIR /srv
COPY --from=build /app/dist/ /srv/
CMD ["sh", "-c", "trap : TERM INT; sleep infinity & wait"]
