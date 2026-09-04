#!/usr/bin/env bash
#
# MC-01 — THE MIGRATION CHAIN MUST EQUAL THE DATAMODEL.
#
# For eight work packages a fresh database built from the committed migration
# chain was not identical to the committed Prisma datamodel. Nothing failed:
# every test passed against either shape, because the difference was 25
# foreign-key NAMES and 8 database defaults the application never relied on.
# That is precisely why it survived — the defect was invisible to the runtime
# suite, and only visible to `migrate diff`.
#
# The cost was real anyway. While the chain and the datamodel disagree, the
# engine tries to reconcile them inside EVERY newly generated migration, so
# WP-24, WP-25 and WP-26 each had to strip the same 33 statements out by hand.
# One inattentive pass would have shipped them.
#
# This gate asserts the invariant that makes that impossible to reintroduce:
#
#     empty database -> apply every migration -> diff against the datamodel
#                    -> the diff MUST be empty
#
# It deliberately does NOT count migrations. A correct count proves nothing; a
# chain of the right length can still build the wrong schema. The only
# assertion worth making is that the schema the chain produces IS the schema
# the application declares.
#
# Usage:  scripts/migration-drift-gate.sh
# Needs:  DATABASE_URL pointing at a database that was built BY THE MIGRATION
#         CHAIN — which is exactly what CI has, because its PostgreSQL service
#         container starts empty and `prisma migrate deploy` runs against it
#         before this gate does.
#
# It compares that live datasource against the datamodel, so it needs no
# scratch database, no shadow database and no `psql` client. That matters:
# a gate with its own external dependencies is a gate that gets skipped.
#
# Run it against a hand-modified developer database and it will report that
# database's drift, which is a true answer to a different question. The
# authoritative run is the CI one, immediately after a from-empty deploy.
set -euo pipefail

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "migration drift gate: DATABASE_URL is not set" >&2
  exit 1
fi

cd "$(dirname "$0")/../services/core-api"

DIFF="$(pnpm exec prisma migrate diff   --from-schema-datasource prisma/schema   --to-schema-datamodel prisma/schema   --script 2>/dev/null)"

# Prisma reports "no difference" as a comment-only script. Strip comments and
# blank lines; anything left is a real statement, and therefore a real drift.
STATEMENTS="$(printf "%s" "${DIFF}" | grep -vE '^[[:space:]]*--' | grep -vE '^[[:space:]]*$' || true)"

if [[ -n "${STATEMENTS}" ]]; then
  echo "migration drift gate: FAILED - the deployed schema is not the declared datamodel." >&2
  echo "" >&2
  echo "${STATEMENTS}" >&2
  echo "" >&2
  echo "Fix this with a FORWARD migration that reconciles the difference." >&2
  echo "Do not edit an already-applied migration, and do not change the datamodel" >&2
  echo "merely to match whatever the database happens to contain (MC-01)." >&2
  exit 1
fi

echo "migration drift gate: passed - the chain builds exactly the declared datamodel"
