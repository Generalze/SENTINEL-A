# syntax=docker/dockerfile:1.7
# =============================================================================
# SENTINEL EDGE RUNTIME — the repository's first production container image.
#
# Build from the REPOSITORY ROOT, because this is a pnpm workspace member and
# a reproducible install needs the root lockfile:
#
#   docker build -f services/edge-runtime/Dockerfile -t sentinel-edge-runtime:<tag> .
#
# THE THREAT MODEL THIS IMAGE IS BUILT AGAINST, WHICH IS NOT CORE-API'S
# ---------------------------------------------------------------------
# core-api runs in a datacentre nobody walks into. An Edge is a box in a
# customer's wiring closet, on a customer's LAN, behind a lock a cleaner has a
# key to. Physical access is assumed, not excluded. That single difference
# drives every choice below, and it is why the answers here are stricter than
# a first Dockerfile would otherwise need to be:
#
#   * a shell in this container is a shell in the closet, so the process that
#     serves the network runs as a non-root user that owns NONE of its own code;
#   * an image layer is a file an attacker with the image can read at leisure,
#     so no key, no keyring, and no queue byte is ever in one;
#   * the durable queue holds Field operations that exist NOWHERE ELSE while
#     the WAN is down, so it lives on a mounted volume, never in the container's
#     ephemeral writable layer where `docker rm` destroys it silently.
#
# Every comment below says WHY. This file is precedent; the next service copies
# it, and a reason is the only thing that survives being copied.
# =============================================================================

# -----------------------------------------------------------------------------
# BASE IMAGE — ONE pin, shared by both stages, by DIGEST.
#
# node:24.18.0 matches `.nvmrc` (24.18.0) and CI (node-version 24), and
# satisfies the root `engines.node: ">=22"`. The `>=22` range is what the
# repository will TOLERATE; an image must state what it actually SHIPS, because
# "whatever `>=22` resolved to on build day" is not a version anyone can audit
# an incident against.
#
# The digest is the real pin. A tag — even an exact-version one — is a mutable
# pointer: `node:24.18.0-bookworm-slim` is rebuilt whenever Debian patches, so
# two builds a month apart from the same commit are not the same image. The
# digest makes the base bit-identical, and updating it is a visible diff that a
# human approves. That is the argument against `latest`, applied honestly
# rather than stopped one step early.
#
# `-bookworm-slim` over `-alpine`: glibc, not musl. Node's own release binaries
# and any future prebuilt native dependency are built against glibc, and an
# Edge is the last place to discover a musl behavioural difference — it is the
# node that is unreachable precisely when it misbehaves.
# -----------------------------------------------------------------------------
ARG NODE_IMAGE=node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d

# The exact pnpm the repository pins in root `packageManager` and CI installs.
# A different pnpm can resolve a different tree from the same lockfile, and a
# container that dependency-drifts from CI is a container CI never tested.
ARG PNPM_VERSION=10.34.5


# =============================================================================
# STAGE 1 — BUILD. Dev dependencies live and die here.
#
# Nothing from this stage reaches the final image except files copied by name.
# The compilers, the linters, the test runner, the pnpm binary itself, the
# source `.ts`, the lockfile, the whole workspace — all of it stays behind.
# =============================================================================
FROM ${NODE_IMAGE} AS build

ARG PNPM_VERSION

# Corepack activates the version the repository pins rather than whatever pnpm
# a bare `npm i -g pnpm` would fetch today. The prompt is disabled because a
# build has no stdin to answer it on.
ENV PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable && corepack prepare pnpm@${PNPM_VERSION} --activate

WORKDIR /repo

# -----------------------------------------------------------------------------
# MANIFESTS FIRST, SOURCES SECOND — the layer-cache split.
#
# Dependencies change rarely and take minutes; sources change constantly and
# take seconds. Copying the manifests alone means an ordinary source edit
# re-uses the install layer. That is cache hygiene, but it is also supply-chain
# hygiene: the install layer's cache key is the lockfile's content, so a
# dependency cannot change without visibly invalidating it.
# -----------------------------------------------------------------------------
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml tsconfig.base.json ./
COPY packages/contracts/package.json packages/contracts/
COPY services/edge-runtime/package.json services/edge-runtime/

# -----------------------------------------------------------------------------
# THE INSTALL, AND WHY IT IS SHAPED THIS WAY.
#
# `--frozen-lockfile`: the lockfile is authority. Without it pnpm will happily
# resolve a NEWER satisfying version than CI tested and rewrite the lockfile to
# match, which means the artefact shipped to a customer site could contain
# dependencies that never passed a test. In a container that must be fatal, so
# it is stated explicitly rather than relied upon from pnpm's CI heuristic —
# this build does not set CI=true.
#
# `--filter @sentinel/edge-runtime...`: the trailing `...` means "and its
# workspace dependencies", which is `@sentinel/contracts` and nothing else.
# core-api, the apps and their Prisma toolchains are never installed. The build
# stage is smaller and, more usefully, the build CANNOT come to depend on a
# package the runtime image will not contain.
#
# The store is a BuildKit cache mount, not a layer. A pnpm store in a layer is
# tens of megabytes of tarballs the runtime cannot use and an attacker can read
# for an exact dependency inventory; here it is reused across builds and never
# enters the image graph at all.
# -----------------------------------------------------------------------------
RUN --mount=type=cache,id=sentinel-pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile --filter @sentinel/edge-runtime...

# -----------------------------------------------------------------------------
# NODE'S OWN TYPES COME FROM THE PACKAGE THAT USES THEM.
#
# This stage used to build a symlink here, pointing `/repo/node_modules/@types/node`
# at the copy the lockfile had resolved for edge-runtime. That existed because
# `@sentinel/contracts` imported `node:crypto` while declaring no `@types/node`
# of its own, and compiled anyway ONLY because its test files import vitest and
# vitest drags the typings in as a transitive peer. This image excludes test
# files, which removed the accident and broke the contracts compile.
#
# THAT DEBT IS PAID. `packages/contracts/package.json` now declares
# `@types/node: ^22` as a devDependency, so the filtered install above places
# real, locked typings in `packages/contracts/node_modules/@types/node` and the
# compile resolves them the ordinary way.
#
# The symlink is REMOVED rather than left as harmless belt-and-braces. It
# resolved a path out of another package's tree, so it would have quietly gone
# on working if contracts' own declaration were ever deleted -- reintroducing
# the exact accident it was documenting, in a place nobody would look. The
# assertion below is what replaces it: the build fails loudly if contracts
# stops owning its types, instead of silently borrowing somebody else's.
#
# `--filter @sentinel/edge-runtime...` includes contracts as a workspace
# dependency, and pnpm installs a workspace package's devDependencies unless
# `--prod` is passed. Nothing here passes it; the runtime image is produced by
# `pnpm deploy` from the built output, not by installing this tree.
# -----------------------------------------------------------------------------
RUN test -f /repo/packages/contracts/node_modules/@types/node/package.json \
 || (echo "@sentinel/contracts must declare its own @types/node; it imports node: builtins" >&2 && exit 1)

# Sources. `.dockerignore` has already stripped the specs, the `.test.ts`
# files, the test-support anchor-signing helper, host `node_modules` and host
# `dist` from the context, so this copies source and nothing else.
COPY packages/contracts packages/contracts
COPY services/edge-runtime services/edge-runtime

# -----------------------------------------------------------------------------
# BUILD ORDER IS NOT INCIDENTAL. `@sentinel/contracts` publishes only `dist/`
# (its package `main`/`types` point there), so edge-runtime's `tsc` cannot
# resolve a single import until contracts has emitted. This is the same
# "Build contracts prerequisite" step CI runs before anything else, for the
# same reason; two commands rather than one `turbo run build` keeps a failure
# attributable to the package that actually failed.
# -----------------------------------------------------------------------------
RUN pnpm --filter @sentinel/contracts build \
 && pnpm --filter @sentinel/edge-runtime build

# -----------------------------------------------------------------------------
# `pnpm deploy` — THE WORKSPACE-AWARE STEP, AND WHY NOT `npm prune --production`.
#
# A pnpm workspace's `node_modules` is a forest of symlinks into a
# content-addressed store. Copying it into a runtime stage copies dangling
# links; copying the store with it copies back the dev dependencies you were
# trying to leave behind. And `@sentinel/contracts` is a `workspace:*` symlink
# pointing at `/repo/packages/contracts`, a path that will not exist in the
# final image at all.
#
# `pnpm deploy` is the command built for exactly this: it resolves the filtered
# package's PRODUCTION dependency graph and materialises it as a SELF-CONTAINED
# directory. Precisely: it writes a local `node_modules/.pnpm` containing every
# package as a real directory, with the top level linking into it by RELATIVE
# path, and it copies `@sentinel/contracts` in as ordinary files rather than
# leaving a `workspace:*` link. That local `.pnpm` is a dependency TREE, not
# the global content-addressed store and not a build cache — no tarballs, no
# other packages' versions, nothing the runtime does not load. The result runs
# under `node dist/main.js` with no pnpm, no store and no workspace on the box.
#
# `--legacy` is required under pnpm 10: the modern deploy path expects
# `inject-workspace-packages=true`, a root-level pnpm setting this lane has no
# business turning on for every other package in the monorepo. The legacy path
# produces the self-contained tree this image needs without touching shared
# configuration.
#
# `--prod` is the line that keeps `typescript`, `vitest`, `@nestjs/testing` and
# `@types/node` out of the shipped image. `--no-optional` refuses optional
# dependencies outright: an optional dependency is one whose ABSENCE its own
# authors called acceptable, and something acceptable to omit does not belong
# on a box nobody can drive to.
# -----------------------------------------------------------------------------
RUN --mount=type=cache,id=sentinel-pnpm-store,target=/pnpm/store \
    pnpm --filter @sentinel/edge-runtime deploy --legacy --prod --no-optional /deploy

# -----------------------------------------------------------------------------
# PRUNE OUR OWN EMITTED TYPE AND MAP FILES — IN THIS STAGE, NOT THE NEXT ONE.
#
# `tsconfig.base.json` sets `declaration`, `declarationMap` and `sourceMap`, all
# of which are for consumers of a package at BUILD time. `node dist/main.js`
# reads none of them. Two reasons they should not ship:
#
#   1. A `.js.map` names the absolute build paths and the exact file layout of
#      the source tree. It is a free map of the codebase handed to whoever
#      opens the image, in exchange for stack traces Node does not even resolve
#      unless started with `--enable-source-maps`.
#   2. `.d.ts` is a `.ts` file. "No TypeScript source in the image" should be
#      literally true and checkable with `find -name '*.ts'`, not true with an
#      asterisk that a future reviewer has to be told about.
#
# Done HERE rather than with a `RUN rm` in the runtime stage, because deleting
# a file in a later layer does not remove it from the image — the earlier layer
# still carries it, and `docker save` still finds it. The only way to keep a
# file out of an image is for it never to be COPYed in.
#
# Scoped to the two dist trees THIS repository emits, and the honest limit of
# that scope should be stated rather than discovered: the published tarballs of
# our dependencies still carry their own `.d.ts`, their own `.github/`
# directories and, in pino's case, their own test suite. `.dockerignore` cannot
# reach any of it — those files never pass through the build context, they
# arrive from the registry — and a blanket `find node_modules -name '*.test.*'
# -delete` is exactly how a package that genuinely reads its own metadata at
# runtime gets broken months later, on a box nobody can reach. So the claim
# this file makes is the true one: NO SENTINEL SOURCE, TEST OR TYPE FILE is in
# the image. Trimming upstream packages is a `node-prune`-shaped problem and a
# separate, evidenced decision.
# -----------------------------------------------------------------------------
RUN find /deploy/dist /deploy/node_modules/@sentinel/contracts/dist \
      \( -name '*.d.ts' -o -name '*.d.ts.map' -o -name '*.js.map' \) -delete


# =============================================================================
# STAGE 2 — RUNTIME. What actually ships to the closet.
#
# It starts from the same pinned base rather than from the build stage, so
# every dev dependency, every compiler and pnpm itself are absent by
# CONSTRUCTION rather than by deletion. A `RUN rm -rf` would only have hidden
# them one layer down, where `docker save` still finds them.
# =============================================================================
FROM ${NODE_IMAGE} AS runtime

# -----------------------------------------------------------------------------
# NODE_ENV=production is load-bearing, not decorative: Express and Nest read it
# to suppress verbose error output that would otherwise return stack traces —
# absolute source paths, dependency versions, internal structure — to anything
# on the customer LAN that can reach the port.
#
# EDGE_QUEUE_PATH names the directory THIS IMAGE creates, chowns and declares
# as a volume below. It is a path, not a policy — it says where bytes go, never
# what may be written there or for how long — and it is the one configuration
# value the image legitimately owns, because the image is what prepared the
# directory. Every other Edge variable (EDGE_ID, EDGE_ORGANISATION_ID,
# EDGE_KEY_ID, EDGE_KEY_VERSION, EDGE_AUTHORISED_SITE_IDS,
# SENTINEL_CENTRAL_URL) is deliberately left unset, so a misconfigured Edge
# fails loudly at boot instead of booting as a plausible-looking wrong Edge.
#
# NOTHING SECRET IS SET HERE, AND NOTHING SECRET MAY EVER BE. An `ENV` is
# visible in `docker inspect`, in `docker history`, in every copy of every
# layer of this image, and in `/proc/<pid>/environ` to anything in the
# container. The same goes for `ARG`: a build arg is recorded in image
# metadata, so no key may ever arrive that way either.
# -----------------------------------------------------------------------------
ENV NODE_ENV=production \
    EDGE_QUEUE_PATH=/var/lib/sentinel-edge/queue

# -----------------------------------------------------------------------------
# THE RUNTIME USER — created explicitly, at a fixed high UID.
#
# The base image ships a `node` user at UID 1000. This image does not use it:
# 1000 is the first UID on almost every Linux host, so a bind-mounted queue
# directory would end up owned by whichever unrelated human happens to be user
# 1000 on that Edge box. 10001 sits outside the normal human range, so
# ownership of Edge's durable state means Edge and nothing else.
#
# `--no-create-home`, `/nonexistent`, `/usr/sbin/nologin`: this account exists
# to own one process and one directory. It gets no home directory to drop files
# in, no login shell, and no way to be an account somebody signs in as.
# -----------------------------------------------------------------------------
RUN groupadd --system --gid 10001 sentinel \
 && useradd --system --uid 10001 --gid 10001 \
      --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sentinel

WORKDIR /app

# -----------------------------------------------------------------------------
# THE APPLICATION IS OWNED BY ROOT AND THE APPLICATION DOES NOT RUN AS ROOT.
#
# `--chown=root:root` at the default 0755 is deliberate, and it is the single
# most valuable line in this file. The `sentinel` user can READ and EXECUTE
# `/app` and can write to NONE of it. An attacker who reaches code execution
# through the HTTP surface therefore cannot rewrite `dist/main.js`, cannot drop
# a module into `node_modules` that the next restart would load, and cannot
# leave anything behind that survives `docker restart`. Their foothold dies
# with the process — which, on a box nobody visits for months, is the whole
# difference between an incident and a tenancy.
#
# Three explicit COPYs rather than one of `/deploy`: this is the exhaustive
# list of what an Edge needs in order to run, and naming it is what enforces
# it. `package.json` is here because Node reads `"type": "commonjs"` from it to
# decide how to parse `dist/main.js`; without it the CommonJS output is
# misread. Nothing else from `/deploy` — no lockfile, no `.npmrc`, no
# `pnpm-workspace.yaml` — reaches the image.
# -----------------------------------------------------------------------------
COPY --from=build --chown=root:root /deploy/node_modules ./node_modules
COPY --from=build --chown=root:root /deploy/dist ./dist
COPY --from=build --chown=root:root /deploy/package.json ./package.json

# -----------------------------------------------------------------------------
# DURABLE STATE: THE QUEUE DIRECTORY, AND THE VOLUME THAT MUST BACK IT.
#
# `EdgeQueueStorageProbe` fails readiness on `W_OK` here, and
# `edge-trusted-time.store.ts` writes its persisted anchor inside it. The
# directory is created and chowned in the image so a fresh named volume
# inherits UID 10001 ownership on first mount — otherwise the daemon creates
# the mountpoint root-owned, the probe reports `queue_storage: down`, and Edge
# correctly refuses work it cannot keep safe. Mode 0700 because the queue holds
# signed Field operations, duress signals among them, and nothing but Edge has
# any reason to read them.
#
# `VOLUME` is the guarantee, not the convenience. Without it, an operator who
# forgets `-v` gets a container that works perfectly — and writes the site's
# only copy of every queued operation into the container's ephemeral writable
# layer, where a routine `docker rm` during an upgrade destroys it with no
# error and no trace. With it, the daemon always provides real storage; a
# forgotten `-v` then costs an anonymous volume to garbage-collect instead of a
# site's evidence. Declared AFTER the chown, because filesystem changes made to
# a VOLUME path in later build steps are discarded.
# -----------------------------------------------------------------------------
RUN mkdir -p /var/lib/sentinel-edge/queue \
 && chown -R 10001:10001 /var/lib/sentinel-edge \
 && chmod 0700 /var/lib/sentinel-edge/queue
VOLUME ["/var/lib/sentinel-edge"]

# -----------------------------------------------------------------------------
# SECRET CUSTODY — WHAT ARRIVES BY MOUNT, AND WHAT IS NOT HERE AT ALL.
#
# `/run/secrets` is created empty, root-owned, mode 0555, as the agreed arrival
# point for material a secret manager (Compose secrets, a systemd credential, a
# CSI driver, a Vault agent sidecar) mounts read-only at RUN time. It is a
# mountpoint, never a store: nothing is written here by the image, and nothing
# is written here by Edge.
#
# THE EDGE RECEIPT-SIGNING KEY. `services/edge-runtime/src/config/env.schema.ts`
# deliberately has no `EDGE_SIGNING_KEY` and no `EDGE_PRIVATE_KEY`, and says
# why: WP-29B has not ruled on where the Edge signing key lives, and inventing
# a variable for it would settle that question by accident "in the least
# reviewable place available". A Dockerfile is an even less reviewable place,
# so this one does not settle it either. What it does is keep the question open
# SAFELY: no key in any layer, no build arg that could carry one, and a
# mountpoint ready for whichever answer the ruling gives.
#
# THE CENTRAL TRUSTED-TIME SIGNING KEY IS NOT AN EDGE CONCERN AND IS NOT HERE.
# `core-api/src/modules/edge-trusted-time/edge-trusted-time-signing-key.provider.ts`
# holds it at CENTRAL — mounted from a secret manager, read once, never logged
# and never serialised — and the reason it must never come near an Edge is
# stated in `edge-trusted-time.test-support.ts`: an Edge that could author its
# own anchor could choose what time it believed it was. This image cannot
# receive that key by any path, and no compose file in this repository should
# ever mount it here.
#
# THE VERIFICATION KEYRING is PUBLIC material and travels as
# `EDGE_TRUSTED_TIME_VERIFICATION_KEYS`, inline in the environment, exactly as
# the schema documents. It is not secret, and it is not baked in either:
# absent, Edge verifies nothing, persists no anchor, and central refuses at
# NO_TRUSTWORTHY_TIME_WITNESS. Fail-closed is the only defensible default for
# an image that will be built by people who are not deploying it.
# -----------------------------------------------------------------------------
RUN mkdir -p /run/secrets && chmod 0555 /run/secrets

# From here the container is unprivileged. Nothing after this line runs as
# root, and because there is no `USER root` below it, nothing in this image
# can.
USER 10001:10001

# 3100 is the `PORT` default in `env.schema.ts`. EXPOSE is documentation, not a
# control — it publishes nothing by itself. The actual exposure decision
# belongs to the deployment, which is why the compose file binds 127.0.0.1.
EXPOSE 3100

# -----------------------------------------------------------------------------
# HEALTHCHECK — LIVENESS ONLY, AND WIRED TO THE ENDPOINT THAT ALREADY EXISTS.
#
# `GET /health` is `EdgeHealthController.liveness`: it touches NO dependency and
# answers only "is this process running", which is the only question a restart
# policy may ask. `GET /health/ready` is deliberately NOT used here, and its own
# comment explains why that would be a catastrophe on an Edge: readiness goes
# `down` when the durable queue is unwritable, and a restart policy wired to it
# would power-cycle the box in a loop at exactly the moment a human needs to
# look at its disk. Readiness is for a load balancer and an operator; liveness
# is for a supervisor.
#
# Implemented with `node -e` in EXEC form — no shell, no `curl`, no `wget`. The
# slim base ships neither, and installing one to answer a health check would
# permanently add an HTTP client, a TLS stack and a package manager's worth of
# attack surface to a box in a closet in order to save eight lines. The runtime
# it uses instead is the one already required to be present.
#
# 127.0.0.1, never `localhost`: on a dual-stack host `localhost` may resolve to
# ::1 while Nest listens on 0.0.0.0, and the check would then fail forever
# against a perfectly healthy process.
#
# `start-period` is generous because a cold Edge validates its whole config and
# opens its queue before it listens, and a failure inside start-period is not
# counted against `retries`. Any status other than 200 is unhealthy: a liveness
# endpoint that has started answering 500 is a process that should be replaced.
# -----------------------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["node", "-e", "const http=require('node:http');const req=http.get({host:'127.0.0.1',port:process.env.PORT||3100,path:'/health',timeout:4000},res=>{res.resume();process.exit(res.statusCode===200?0:1);});req.on('timeout',()=>{req.destroy();process.exit(1);});req.on('error',()=>process.exit(1));"]

# -----------------------------------------------------------------------------
# ENTRYPOINT — node as PID 1, in exec form, with no shell in between.
#
# Shell form would fork `/bin/sh -c`, and the shell would receive SIGTERM while
# node received nothing. That matters more here than almost anywhere else in
# the system: `main.ts` calls `enableShutdownHooks()` specifically so the queue
# lane can finish a half-written entry, because a half-persisted entry is one
# whose payload no longer digests to the value the device signature covers —
# refused hours later, with the original bytes unrecoverable. Exec form is what
# lets that code run at all.
#
# Node as PID 1 does not reap orphaned children; Edge spawns none, so this is
# correct today. If that ever changes the fix is `docker run --init` /
# `init: true` in compose, which is a deployment change rather than a rebuild.
#
# ENTRYPOINT rather than CMD, and not `pnpm start`: `docker run <image> sh` must
# not silently replace the service with a shell in a wiring closet.
# -----------------------------------------------------------------------------
STOPSIGNAL SIGTERM
ENTRYPOINT ["node", "dist/main.js"]

# OCI provenance, last so a changed revision invalidates no build step.
# `org.opencontainers.image.revision` is a build arg with no default on
# purpose: an image that cannot say which commit it is, is an image nobody can
# audit an incident against — but a WRONG default would be worse than an empty
# one, so it is supplied at build time or left blank and visibly missing.
ARG GIT_REVISION
LABEL org.opencontainers.image.title="sentinel-edge-runtime" \
      org.opencontainers.image.description="Sentinel Edge runtime — the site-local time witness and offline queue" \
      org.opencontainers.image.licenses="SEE LICENSE.md" \
      org.opencontainers.image.base.name="node:24.18.0-bookworm-slim" \
      org.opencontainers.image.revision="${GIT_REVISION}"
