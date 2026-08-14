# SENTINEL — Agent Certification Record

**Certifying authority:** Lead Developer (Claude Fable 5)
**Date:** 2026-08-14 · **Method:** live probe against real SENTINEL domain problems, graded blind against a fixed rubric
**Rubric:** spec fidelity 40 · edge cases & tests 30 · code quality 20 · doctrine/terminology fidelity 10
**Probe artifacts:** `./artifacts/` (graded source preserved verbatim)

---

## Results

| Agent | Probe | Score | Verdict | Certified lane |
|---|---|---|---|---|
| **Haiku 4.5** | CERT-H — normalised event contract (§40) + idempotency derivation (§64.1) | **94/100** | PASS | **Junior** — mechanical implementation from precise specs |
| **Sonnet 5** | CERT-S — Fusion threat-state machine: trust weighting, diversity caps, contradiction handling, life-safety gate (§11) | **98/100** | PASS with distinction | **Core** — domain services, APIs, tests; cleared for reasoning-heavy work under tight directives |
| **Opus 5** | CERT-O — Constitution evaluator: deny-by-default, §58.2 two-person control, Decision-Ledger traces (§5.1/§62.1) | **99/100** | PASS with distinction | **Senior** — security-critical policy and correlation logic; adversarial reviewer for all lanes |

## Grading notes

### CERT-H (Haiku 4.5) — 94
- All 17 contract fields correct, including the `ingested_at >= occurred_at` refinement and exact idempotency bucketing semantics; 10 tests against an 8-test minimum.
- **Defects:** one unused type import (would fail strict lint). Confirms the standing rule: Haiku output is always double-reviewed (Sonnet adversarial pass, then lead) before merge.
- **Assignment boundary:** no security-decision logic, no multi-module refactors. Scaffolding, config, contracts-from-spec, test expansion, docs.

### CERT-S (Sonnet 5) — 98
- All eight rules implemented; chose and *justified* a noisy-OR evidence combinator (order-independent, bounded, contradiction strictly monotonic downward) and documented every assumption where the spec left room.
- 16 hand-computed tests including immutability and a test proving confidence and severity never conflate — core §11.3 doctrine.
- **Assignment boundary:** full domain-service ownership (WP-03/04/08/09/10/12, co-lead WP-07/11). Contract changes remain lead-owned.

### CERT-O (Opus 5) — 99
- No-short-circuit design: all 11 checks always run in a fixed exported sequence, each emitting a trace entry with the compared values — exactly what the Decision Ledger needs to explain outcomes without re-execution.
- Structural security properties, not incidental ones: prohibition outranks grants by construction; registration, permission, and prohibition are separate maps; no wildcard grants possible; fail-closed on every unknown; prototype-pollution-safe lookups; deep-frozen policy and output.
- Added one hard check beyond the literal spec (classification-label/level consistency) and **disclosed it explicitly** rather than smuggling it in — correct senior behaviour (−1 spec-discipline; security-positive).
- Self-identified production gap — approver *roles* are not validated against the action — now a mandatory requirement in directive WP-06.
- **Assignment boundary:** WP-05 Fusion, WP-06 Constitution, WP-07 workflow lead, adversarial review of all security-relevant diffs.

## Standing rules

1. No agent works a lane it is not certified for. New domain class ⇒ new probe.
2. Two failed lead-reviews in a lane ⇒ scope demotion + tighter directives; recertification to return.
3. Certified probe artifacts are approved reference implementations: CERT-H seeds WP-01 (`packages/contracts`), CERT-S seeds WP-05 (Fusion), CERT-O seeds WP-06 (Constitution) — each to be ported under its WP's directive, defects fixed, tests executed in CI (probes were graded on source; runtime verification happens in the WP).
4. The lead certifies, directs, reviews, merges, and signs off milestones. This record is updated on every recertification event.
