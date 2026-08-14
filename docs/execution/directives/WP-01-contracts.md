# Directive WP-01 — Contracts Package

**Issued by:** Lead (Fable 5) · **Lane:** Core (Sonnet, certified CERT-S); lead co-authors and owns final schemas · **Wave:** 1
**Review chain:** Opus adversarial review → Lead merge gate

## Objective
Implement `packages/contracts` — the single source of truth for every message shape in Sentinel. Everything downstream imports from here; nothing redefines these shapes locally.

## Spec references (architecture doc, `docs/architecture/`)
- §40 Normalised Event Contract (verbatim field list — events are append-only; corrections are new records referencing the original)
- §64.1 Idempotency and duplicate control
- §11.2 Threat-state model (states 0–5), §11.3 four separated values (detection confidence / threat probability / potential impact / operational severity)
- §12.1 Incident object, §12.2 severity SEV-1..SEV-5, §12.3 response modes STANDARD/DISCREET/SILENT
- §76 delivery semantics REQUESTED/DELIVERED/ACKNOWLEDGED/EXECUTED/FAILED/UNKNOWN
- §5.2 Decision Ledger record shape

## Deliverables (Zod v3 + inferred types, one file per domain)
- `src/event.ts` — NormalisedEvent (the certified CERT-H probe implementation is the approved starting point — port it, fix the unused-import lint defect)
- `src/idempotency.ts` — key derivation per §64.1
- `src/threat.ts` — ThreatState enum, ThreatAssessment (four separated values), Hypothesis shape with supporting/contradicting event id arrays
- `src/incident.ts` — Incident, Severity, ResponseMode
- `src/delivery.ts` — DeliveryState machine types per §76
- `src/ledger.ts` — DecisionLedgerEntry: inputs snapshot, rule/model versions, evidence for AND against, confidence, policy version, approvals, action, outcome
- `src/index.ts` — barrel export; `SCHEMA_VERSION = 1` exported constant
- Vitest tests per file: valid, invalid, boundary cases (≥ 6 per schema)

## Constraints
- Strict TS, no `any`. Schemas are the API — no behaviour beyond validation/derivation.
- Field names snake_case exactly as §40; do not "improve" naming.
- Every schema carries `schema_version`.

## Acceptance criteria
1. All tests pass; each acceptance-relevant rule has a named test.
2. No downstream package can construct an invalid event without `parse` throwing.
3. Lead sign-off on every schema (contracts are lead-owned).

## Out of scope
Persistence, NATS, HTTP — this package has zero runtime dependencies beyond zod.
