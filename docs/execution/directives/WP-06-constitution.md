# Directive WP-06 — Constitution Engine

**Lane:** Senior (Opus) · **Wave:** 2 · **Depends:** WP-01, WP-02
**Review chain:** Lead review + Sonnet secondary read

## Spec references
§5.1 (hardened, versioned, signed policy layer), §58.2 (two-person list), §62.1 (permission conjuncts), §61 (deterministic domain rules — AI may inform, never silently replace).

## Approved starting point
The certified CERT-O implementation (`docs/execution/certification/artifacts/cert-o/constitution.ts`) is the approved core — port with semantics intact, keep all 35 tests.

## Mandatory additions (the gaps CERT-O itself disclosed)
1. **Approver-role validation:** an approval only counts if the approver's roles (loaded from Identity, WP-03) include approval authority for the action's category. Add `approverRoles` to the policy category (`approval_roles: string[]`) and a new check `APPROVAL_ROLE_AUTHORISED` in the sequence. Tests: unauthorised approver's approval does not count toward two-person; two approvals where only one is role-authorised → still REQUIRE_TWO_PERSON.
2. **`validatePolicy(policy)` at load time:** rejects dangling category references, actions granted to roles but unregistered, prohibited actions that appear in any role grant, empty approval_roles on ONE/TWO_PERSON categories. Boot fails on invalid policy.
3. **Versioned storage:** policies persist in Prisma (`ConstitutionPolicy`: version, JSON body, content SHA-256, status draft|active|retired, created_by, activated_at). Exactly one active version. Activation is itself a Constitution-gated action (`constitution.rules.alter.core`, two-person) — enforced by the engine evaluating its own change requests. Seed the baseline policy from CERT-O as version 1 via migration/seed (seed is exempt from the gate, documented).
4. **Ledger hook:** every `evaluate()` call emits a `DecisionRecord` DTO (inputs snapshot, policy version + hash, trace, decision) to an injected `LedgerSink` interface. WP-08 provides the real sink; until then a buffering stub. No evaluation may skip the sink.

## Deliverables
`services/core-api/src/modules/constitution`: ported evaluator + additions, policy repository, `ConstitutionService.evaluate(request)` used by other modules in-process, `GET /api/v1/constitution/policy` (active version metadata + hash, admin-only), tests (ported 35 + new coverage for all four additions).

## Acceptance criteria
1. All ported CERT-O tests still pass unmodified in semantics.
2. Approver-role tests as specified above.
3. Invalid policy cannot boot; test proves each validatePolicy rule.
4. Policy activation without two-person approval → REQUIRE_TWO_PERSON, and nothing changes.
5. Every evaluation produces exactly one DecisionRecord (test counts them).

## Out of scope
Cryptographic policy signing (Milestone 2 — hash + audit now), UI, workflow timers (WP-07).
