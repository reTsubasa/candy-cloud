# syntax=docker/dockerfile:1.7

# Web assets are architecture-neutral. Run Node on the native CI runner instead
# of emulating the target CPU, then copy the result into the target image.
FROM --platform=$BUILDPLATFORM node:22.18-alpine AS build
WORKDIR /app
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
# Pin pnpm explicitly. Corepack's rolling package-manager resolution can
# select a version whose bundle is unavailable on the runner, leaving the
# shim pointing at a missing pnpm.cjs and failing before dependency install.
# Keep the builder reproducible and aligned with the lockfile toolchain.
RUN npm install --global pnpm@11.19.0
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm run build

FROM --platform=$TARGETPLATFORM busybox:1.37.0-musl
WORKDIR /srv
COPY --from=build /app/dist/ /srv/
CMD ["sh", "-c", "trap : TERM INT; sleep infinity & wait"]
