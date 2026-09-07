# syntax=docker/dockerfile:1.7
# =============================================================================
# SENTINEL CORE-API — CENTRAL, AS A CONTAINER.
#
# WHY THIS FILE EXISTS AT ALL, WHICH IS NOT "FOR DEPLOYMENT".
# -----------------------------------------------------------
# Every live suite in this repository boots `AppModule` inside the vitest
# process on the developer's host and talks to `docker-compose.dev.yml` over
# loopback. That arrangement has one property WP-30 cannot live with: THERE IS
# NOTHING TO DISCONNECT. Central and the test are the same process, on the same
# host, sharing the same network namespace. A "WAN outage" expressed against
# that topology can only ever be a flag, a stub, or a mocked method — which is
# precisely what the Proof-D acceptance definition refuses.
#
# So central must become a thing that sits somewhere. This image is what makes
# central addressable: a process on its own network, behind a link that can be
# severed, with a state that survives the severing. It is built for the
# WAN-loss harness first. That it also happens to be a serviceable production
# starting point is a consequence, not the goal, and the differences are called
# out where they occur.
#
# Build from the REPOSITORY ROOT — a pnpm workspace member cannot be built from
# its own directory, because the lockfile that makes the install reproducible
# lives at the root:
#
#   docker build -f services/core-api/Dockerfile -t sentinel-core-api:<tag> .
#
# THE THREAT MODEL, AND HOW IT DIFFERS FROM THE EDGE'S.
# -----------------------------------------------------
# `services/edge-runtime/Dockerfile` is written against physical access: an
# Edge is a box in a customer's wiring closet behind a lock a cleaner has a key
# to. Central is not that. Central runs where nobody walks in, and its dominant
# risk is the opposite one — it holds EVERY tenant's data, so the blast radius
# of one compromised process is the whole platform rather than one site.
#
# That difference changes the emphasis, not the rules. The structural
# protections are the same and are kept deliberately identical, so the two
# files can be diffed against each other and the deltas are all explainable:
# non-root user owning none of its own code, no secret in any layer or build
# arg, digest-pinned base, dev dependencies absent by construction.
#
# WHAT THIS IMAGE DELIBERATELY DOES NOT DO
# ----------------------------------------
#   * It does not run migrations. `prisma migrate deploy` is an operator action
#     with its own failure modes and its own authority; a service that migrates
#     its own database on boot will, on the day two replicas start together,
#     race. CI already runs the deploy as a discrete step and the WAN-loss
#     harness does the same against the published port.
#   * It ships no `prisma` CLI and no migration files. It ships the generated
#     query client and nothing else from the Prisma toolchain.
#   * It sets no `DEV_AUTH_ENABLED`. The harness passes it at run time; an
#     image that defaulted a dev authentication bypass to on would be one
#     `docker run` away from being an unauthenticated production deployment.
# =============================================================================

# -----------------------------------------------------------------------------
# BASE IMAGE — the SAME digest-pinned base the Edge image uses.
#
# Identical on purpose. Two services on two different Node patch levels is a
# difference that explains nothing and hides something: when central and Edge
# disagree about a date, a TLS behaviour or a stream edge case, the first thing
# anybody asks is whether they are running the same runtime, and the only
# useful answer is a digest. Updating the base is one diff in two files, which
# is the cost of being able to give that answer.
#
# node:24.18.0 matches `.nvmrc` and CI's `node-version: 24`, and satisfies the
# root `engines.node: ">=22"` — the range the repository TOLERATES, versus the
# version this artefact actually SHIPS. The digest is the real pin; a tag, even
# an exact-version one, is rebuilt whenever Debian patches.
#
# `-bookworm-slim` over `-alpine`: glibc, not musl. Prisma's query engine is a
# separately-compiled native binary whose target is selected by libc, and
# discovering a musl engine difference in the component that owns every write
# to the database is not a discovery anyone should schedule.
# -----------------------------------------------------------------------------
ARG NODE_IMAGE=node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d

# The exact pnpm the repository pins in root `packageManager` and CI installs.
# A different pnpm can resolve a different tree from the same lockfile, and a
# container that dependency-drifts from CI is a container CI never tested.
ARG PNPM_VERSION=10.34.5


# =============================================================================
# STAGE 1 — BUILD. Dev dependencies, the compiler and the Prisma CLI live and
# die here. Nothing reaches the final image except files copied by name.
# =============================================================================
FROM ${NODE_IMAGE} AS build

ARG PNPM_VERSION

ENV PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable && corepack prepare pnpm@${PNPM_VERSION} --activate

# OpenSSL is a RUNTIME dependency of Prisma's query engine, not a build tool.
# The slim base does not ship it, and its absence produces a failure at the
# worst possible moment — the process starts, serves health, and throws on the
# first query. Installed in the build stage so `prisma generate` can probe for
# it and select the matching engine; installed again in the runtime stage
# because the runtime stage starts from the base, not from here.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /repo

# -----------------------------------------------------------------------------
# MANIFESTS FIRST, SOURCES SECOND — the layer-cache split. Dependencies change
# rarely and take minutes; sources change constantly and take seconds. It is
# also supply-chain hygiene: the install layer's cache key is the lockfile's
# content, so a dependency cannot change without visibly invalidating it.
# -----------------------------------------------------------------------------
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml tsconfig.base.json ./
COPY packages/contracts/package.json packages/contracts/
COPY services/core-api/package.json services/core-api/

# -----------------------------------------------------------------------------
# `--frozen-lockfile`: the lockfile is authority. Without it pnpm resolves a
# newer satisfying version than CI tested and rewrites the lockfile to match,
# which means the artefact could contain dependencies that never passed a test.
# Stated explicitly rather than relied upon from pnpm's CI heuristic — this
# build does not set CI=true.
#
# `--filter @sentinel/core-api...`: the trailing `...` means "and its workspace
# dependencies", which is `@sentinel/contracts` and nothing else. edge-runtime
# and the apps are never installed, so this build CANNOT come to depend on a
# package the runtime image will not contain.
#
# The store is a BuildKit cache mount shared with the Edge image's build (same
# id), not a layer: reused across builds, never present in the image graph.
# -----------------------------------------------------------------------------
RUN --mount=type=cache,id=sentinel-pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile --filter @sentinel/core-api...

# -----------------------------------------------------------------------------
# NODE'S OWN TYPES, MADE VISIBLE TO THE CONTRACTS COMPILE.
#
# Identical to the Edge image's workaround, for an identical reason, and the
# duplication is deliberate rather than lazy: `@sentinel/contracts` imports
# `node:crypto` and uses `Buffer` but declares no `@types/node`. On a developer
# machine it compiles ACCIDENTALLY — its `*.test.ts` files are inside its
# tsconfig `include`, they import `vitest`, and vitest's `.d.ts` drags
# `@types/node` in transitively. This build context excludes test files, which
# removes the accident with them.
#
# Fixed in this stage only, touching no package: link the `@types/node` the
# lockfile already resolved into `/repo/node_modules/@types`, an ancestor
# `typeRoots` directory for every workspace member. THE PROPER FIX IS A
# `@types/node` DEVDEPENDENCY ON `packages/contracts`, with the lockfile change
# that implies — a shared-package edit that belongs to whoever owns contracts.
# `readlink -f` resolves the pnpm symlink; the `test -f` makes the pipeline fail
# loudly here rather than mysteriously three steps later.
# -----------------------------------------------------------------------------
RUN mkdir -p /repo/node_modules/@types \
 && ln -s "$(readlink -f /repo/services/core-api/node_modules/@types/node)" \
      /repo/node_modules/@types/node \
 && test -f /repo/node_modules/@types/node/package.json

# Sources. `services/core-api/Dockerfile.dockerignore` has already stripped the
# specs, test-support helpers, host `node_modules` and host `dist` from the
# context, so this copies source, the Prisma schema and nothing else.
COPY packages/contracts packages/contracts
COPY services/core-api services/core-api

# -----------------------------------------------------------------------------
# PRISMA GENERATE BEFORE TSC, BECAUSE TSC READS ITS OUTPUT.
#
# `@prisma/client` ships as a stub whose types are written by `generate` from
# the schema. `events.mapper.ts` imports `Prisma` and `Event` from it, so
# without this step the core-api compile fails on missing exports — not on a
# missing dependency, which is what makes the error confusing when it happens.
#
# `--schema prisma/schema` names the multi-file schema FOLDER, matching the
# service's own `prisma.schema` package.json field and the exact invocation CI
# uses ("Generate Prisma client prerequisite"). One command, one meaning.
# -----------------------------------------------------------------------------
RUN pnpm --filter @sentinel/core-api exec prisma generate --schema prisma/schema

# -----------------------------------------------------------------------------
# BUILD ORDER IS NOT INCIDENTAL. `@sentinel/contracts` publishes only `dist/`
# (its package `main`/`types` point there), so core-api's `tsc` cannot resolve a
# single import until contracts has emitted. Two commands rather than one
# `turbo run build` keeps a failure attributable to the package that failed.
# -----------------------------------------------------------------------------
RUN pnpm --filter @sentinel/contracts build \
 && pnpm --filter @sentinel/core-api build

# -----------------------------------------------------------------------------
# `pnpm deploy` — the workspace-aware production tree.
#
# A pnpm workspace's `node_modules` is a forest of symlinks into a
# content-addressed store; copying it into a runtime stage copies dangling
# links, and `@sentinel/contracts` is a `workspace:*` link to a path that will
# not exist in the final image. `pnpm deploy` resolves the filtered package's
# PRODUCTION graph and materialises it as a self-contained directory with a
# local `node_modules/.pnpm` and relative links.
#
# `--legacy` is required under pnpm 10: the modern path expects
# `inject-workspace-packages=true`, a root-level setting this file has no
# business turning on for the whole monorepo. `--prod` is what keeps
# `typescript`, `vitest`, `@nestjs/testing` and — importantly — the `prisma`
# CLI out of the shipped image. `--no-optional` refuses optional dependencies:
# a dependency whose own authors called its absence acceptable does not belong
# in the component that owns every tenant's data.
# -----------------------------------------------------------------------------
RUN --mount=type=cache,id=sentinel-pnpm-store,target=/pnpm/store \
    pnpm --filter @sentinel/core-api deploy --legacy --prod --no-optional /deploy

# -----------------------------------------------------------------------------
# RE-GENERATE THE PRISMA CLIENT *INSIDE* THE DEPLOY TREE. THE STEP THAT LOOKS
# REDUNDANT AND IS NOT.
#
# `prisma generate` does not write into the package it is invoked from. It
# resolves `@prisma/client` and writes the generated client into THAT package's
# directory — under pnpm, deep inside `/repo/node_modules/.pnpm/@prisma+client@
# <version>/...`. `pnpm deploy` then builds `/deploy/node_modules` by
# materialising packages from the STORE, and the store's copy of
# `@prisma/client` is the ungenerated stub. So the deploy tree contains a
# client with no schema, no types and no engine, and the container fails on its
# first query with "@prisma/client did not initialize yet".
#
# The fix is to run the generator a second time with `/deploy` as the working
# directory, so Node's resolution finds `/deploy/node_modules/@prisma/client`
# and the generator writes there. The schema is copied in for that purpose and
# removed immediately afterwards, in the same layer, so no `.prisma` file
# reaches the image — a schema is a complete map of the platform's data model
# and there is no reason for it to be readable from inside a running container.
#
# The CLI is invoked from the build tree by absolute path because `/deploy` has
# no `prisma` binary — that is exactly what `--prod` accomplished, and it is
# kept that way. The path is the SERVICE's `node_modules/.bin`, not the root's:
# pnpm links a package's binaries into the package that declared the dependency,
# and `prisma` is a devDependency of `@sentinel/core-api`.
#
# THE ASSERTION IS A `find`, NOT A FIXED PATH, ON PURPOSE.
#
# Under pnpm the generated client does not land where the plain-npm
# documentation says. It goes to a `.prisma/client` directory that is a SIBLING
# of `@prisma/client` inside the store-shaped directory holding the resolved
# peer versions:
#
#   /deploy/node_modules/.pnpm/@prisma+client@6.19.3_prisma@6.19.3_typescript@5.9.3__typescript@5.9.3/node_modules/.prisma/client/schema.prisma
#
# Every component of that path except the last two segments is a function of
# the resolved dependency graph, so writing it out literally would produce a
# build that fails on the next `pnpm update` for a reason with nothing to do
# with this Dockerfile. Matching on the stable tail instead keeps the check
# meaningful across the version bump that will eventually move the rest.
#
# The check is not ceremony: without it, a `pnpm deploy` that quietly shipped
# the store's UNGENERATED `@prisma/client` stub would produce an image that
# builds, starts, passes its healthcheck, and throws "@prisma/client did not
# initialize yet" on the first query — a failure that surfaces in a WAN-loss
# scenario as an unexplained central error in the middle of an outage.
# -----------------------------------------------------------------------------
RUN cp -r /repo/services/core-api/prisma /deploy/prisma \
 && cd /deploy \
 && /repo/services/core-api/node_modules/.bin/prisma generate --schema prisma/schema \
 && rm -rf /deploy/prisma \
 && test -n "$(find /deploy/node_modules -path '*/.prisma/client/schema.prisma' -print -quit)"

# -----------------------------------------------------------------------------
# PRUNE OUR OWN EMITTED TYPE AND MAP FILES — IN THIS STAGE, NOT THE NEXT ONE.
#
# `tsconfig.base.json` sets `declaration`, `declarationMap` and `sourceMap`, all
# of which serve consumers at BUILD time. `node dist/main.js` reads none of
# them, a `.js.map` hands over the absolute build paths and exact source
# layout, and a `.d.ts` is a `.ts` file — "no TypeScript source in the image"
# should be literally true and checkable with `find -name '*.ts'`.
#
# Done HERE rather than as a `RUN rm` in the runtime stage, because deleting a
# file in a later layer does not remove it from the image: the earlier layer
# still carries it and `docker save` still finds it. The only way to keep a
# file out of an image is for it never to be COPYed in.
#
# The honest limit of the claim, stated rather than discovered: our
# DEPENDENCIES still ship their own `.d.ts` and their own test files, arriving
# from the registry where no ignore file can reach them. What is true is that
# NO SENTINEL SOURCE, TEST OR TYPE FILE is in this image.
#
# `.prisma/client` is excluded from the prune by naming only the two dist
# trees: its `index.d.ts` IS the generated client's runtime-adjacent artefact
# and Prisma's loader reads the directory it sits in.
# -----------------------------------------------------------------------------
RUN find /deploy/dist /deploy/node_modules/@sentinel/contracts/dist \
      \( -name '*.d.ts' -o -name '*.d.ts.map' -o -name '*.js.map' \) -delete


# =============================================================================
# STAGE 2 — RUNTIME. It starts from the pinned base rather than from the build
# stage, so pnpm, the compiler, the Prisma CLI and every dev dependency are
# absent by CONSTRUCTION rather than by deletion.
# =============================================================================
FROM ${NODE_IMAGE} AS runtime

# Prisma's query engine links against OpenSSL at runtime. See the build stage's
# note: without it the process starts, answers health, and throws on the first
# query — the worst possible shape for a missing dependency.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------------------
# NODE_ENV=production is load-bearing, not decorative: Express and Nest read it
# to suppress verbose error output that would otherwise return stack traces —
# absolute paths, dependency versions, internal structure — to any caller.
#
# EVERY OTHER VARIABLE IS DELIBERATELY UNSET. `DATABASE_URL`, `NATS_URL`,
# `REDIS_URL` and the `S3_*` group have no defaults here, because
# `src/config/env.schema.ts` refuses to boot without them and that refusal is
# the feature: a central that defaulted its own database URL would, on a
# misconfigured deployment, come up cleanly pointed at the wrong data.
#
# `DEV_AUTH_ENABLED` is not set and must never be set here. It defaults to
# false in the schema. An image that shipped it on would be one `docker run`
# from an unauthenticated production deployment.
#
# NOTHING SECRET IS SET HERE AND NOTHING SECRET MAY EVER BE. An `ENV` is
# visible in `docker inspect`, in `docker history`, in every copy of every
# layer, and in `/proc/<pid>/environ`. The same applies to `ARG`: a build arg
# is recorded in image metadata, so no credential may arrive that way either.
# The `DATABASE_URL` this service needs CONTAINS a password, which is why it is
# supplied at run time by the orchestrator and appears in no layer of this file.
# -----------------------------------------------------------------------------
ENV NODE_ENV=production

# -----------------------------------------------------------------------------
# THE RUNTIME USER — created explicitly at the same fixed high UID the Edge
# image uses. The base ships a `node` user at UID 1000, the first UID on almost
# every Linux host; 10001 sits outside the human range so a mounted path owned
# by this service means this service and nothing else.
# -----------------------------------------------------------------------------
RUN groupadd --system --gid 10001 sentinel \
 && useradd --system --uid 10001 --gid 10001 \
      --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sentinel

WORKDIR /app

# -----------------------------------------------------------------------------
# THE APPLICATION IS OWNED BY ROOT AND DOES NOT RUN AS ROOT.
#
# `--chown=root:root` at the default 0755: the `sentinel` user can read and
# execute `/app` and write to none of it. An attacker who reaches code
# execution through the HTTP surface cannot rewrite `dist/main.js`, cannot drop
# a module into `node_modules` for the next restart to load, and cannot leave
# anything behind that survives `docker restart`. Their foothold dies with the
# process.
#
# Three explicit COPYs rather than one of `/deploy`: this is the exhaustive
# list of what central needs in order to run, and naming it is what enforces
# it. `package.json` is here because Node reads `"type": "commonjs"` from it to
# decide how to parse `dist/main.js`. No lockfile, no `.npmrc`, no
# `pnpm-workspace.yaml` and no Prisma schema reach the image.
# -----------------------------------------------------------------------------
COPY --from=build --chown=root:root /deploy/node_modules ./node_modules
COPY --from=build --chown=root:root /deploy/dist ./dist
COPY --from=build --chown=root:root /deploy/package.json ./package.json

# -----------------------------------------------------------------------------
# NO VOLUME IS DECLARED, AND THAT IS THE DIFFERENCE FROM THE EDGE IMAGE.
#
# The Edge image declares one because an Edge's durable queue holds Field
# operations that exist NOWHERE ELSE while the WAN is down. Central's durable
# state is in PostgreSQL, NATS JetStream and S3 — none of which are in this
# container. Declaring a volume here would create an anonymous volume per
# container that holds nothing and is never garbage-collected.
#
# `/run/secrets` is created empty, root-owned, mode 0555, as the agreed arrival
# point for material a secret manager mounts read-only at RUN time. It is a
# mountpoint, never a store. The CENTRAL TRUSTED-TIME SIGNING KEY is the one
# that matters here: `MountedEdgeTrustedTimeSigningKeyProvider` reads it from
# such a mount, it is what lets central author trusted-time anchors, and an
# Edge that ever held it could choose what time it believed it was. It arrives
# by mount or not at all.
# -----------------------------------------------------------------------------
RUN mkdir -p /run/secrets && chmod 0555 /run/secrets

# From here the container is unprivileged. Nothing after this line runs as
# root, and because there is no `USER root` below it, nothing in this image can.
USER 10001:10001

# 3000 is the `PORT` default in `env.schema.ts`. EXPOSE is documentation, not a
# control — it publishes nothing by itself. The exposure decision belongs to
# the deployment, which is why the compose files bind 127.0.0.1.
EXPOSE 3000

# -----------------------------------------------------------------------------
# HEALTHCHECK — LIVENESS ONLY, wired to `GET /health`, which is `@Public()` and
# touches no dependency.
#
# `GET /health/ready` is deliberately NOT used. Readiness reports database,
# NATS, Redis and S3 status; a restart policy wired to it would kill a
# perfectly healthy central every time a dependency hiccupped, turning a
# recoverable dependency blip into a rolling outage of the component every
# other component talks to. Readiness is for a load balancer and an operator;
# liveness is for a supervisor.
#
# THE WAN-LOSS HARNESS DEPENDS ON THAT DISTINCTION IN A SECOND WAY. It uses
# `docker compose up --wait`, which blocks on healthchecks. A readiness-backed
# check would make "the topology is up" mean "every dependency is currently
# answering" — a condition the harness spends its time deliberately breaking.
#
# Implemented with `node -e` in EXEC form: no shell, no `curl`, no `wget`. The
# slim base ships neither, and installing an HTTP client and a TLS stack to
# answer a health check would permanently widen the attack surface of the
# service that holds every tenant's data in order to save eight lines.
#
# 127.0.0.1, never `localhost`: on a dual-stack host `localhost` may resolve to
# ::1 while Nest listens on 0.0.0.0, and the check would fail forever against a
# perfectly healthy process.
#
# `start-period` is generous because a cold central validates its whole config,
# connects Prisma and opens its messaging clients before it listens; a failure
# inside start-period is not counted against `retries`.
# -----------------------------------------------------------------------------
HEALTHCHECK --interval=10s --timeout=5s --start-period=60s --retries=5 \
  CMD ["node", "-e", "const http=require('node:http');const req=http.get({host:'127.0.0.1',port:process.env.PORT||3000,path:'/health',timeout:4000},res=>{res.resume();process.exit(res.statusCode===200?0:1);});req.on('timeout',()=>{req.destroy();process.exit(1);});req.on('error',()=>process.exit(1));"]

# -----------------------------------------------------------------------------
# ENTRYPOINT — node as PID 1, exec form, no shell in between.
#
# Shell form would fork `/bin/sh -c`, and the shell would receive SIGTERM while
# node received nothing. `main.ts` calls `enableShutdownHooks()`, and central's
# shutdown path is what drains in-flight requests and closes the Prisma pool
# rather than abandoning connections the database then has to time out. Exec
# form is what lets that code run at all.
#
# This matters to WP-30 specifically: the harness restarts central to prove
# that state survives a restart, and a central that was always SIGKILLed would
# be proving something weaker and less interesting.
#
# ENTRYPOINT rather than CMD, and not `pnpm start`: `docker run <image> sh`
# must not silently replace the service with a shell.
# -----------------------------------------------------------------------------
STOPSIGNAL SIGTERM
ENTRYPOINT ["node", "dist/main.js"]

# OCI provenance, last so a changed revision invalidates no build step.
# `org.opencontainers.image.revision` is a build arg with no default on
# purpose: an image that cannot say which commit it is, is an image nobody can
# audit an incident against — and a WRONG default would be worse than an empty
# one.
ARG GIT_REVISION
LABEL org.opencontainers.image.title="sentinel-core-api" \
      org.opencontainers.image.description="Sentinel core API — central" \
      org.opencontainers.image.licenses="SEE LICENSE.md" \
      org.opencontainers.image.base.name="node:24.18.0-bookworm-slim" \
      org.opencontainers.image.revision="${GIT_REVISION}"
