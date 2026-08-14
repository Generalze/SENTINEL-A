# Directive WP-05 — Fusion v1 (rule-based)

**Lane:** Senior (Opus) · **Wave:** 3 · **Depends:** WP-04
**Review chain:** Lead review (senior work still gets a second Sonnet read for clarity)

## Spec references
§11 (threat states, four separated values, contradictory-evidence engine), §65.1 (v1 is transparent rules, NOT a learned model), §65.2 (correlation dimensions), §65.3 (hypothesis record).

## Approved starting point
The certified CERT-S implementation (`docs/execution/certification/artifacts/cert-s/threatState.ts`) is the approved core. Port it into the module unchanged in semantics; keep its tests.

## Deliverables (`services/core-api/src/modules/fusion`)
1. **Pure core:** `threatState.ts` (ported CERT-S) + `correlation.ts` — correlation key = `(organisation_id, site_id, zone_id ?? 'site-wide', 15-min tumbling window)`. Transparent and documented; no ML.
2. **Signal mapping:** NormalisedEvent → Signal. `kind` derives from a declarative `EVENT_TYPE_RULES` table (e.g. `access.granted.valid` with matching schedule context CONTRADICTS an intrusion hypothesis; `zone.restricted.entry`, `object.threat_like`, `violence.possible`, `field.report.hostile` SUPPORT). Table is data, versioned, unit-tested — rule_version recorded on every hypothesis update (§65.3 `rule_or_model_versions`).
3. **Persistence:** Prisma `Hypothesis` model per §65.3: state, four values, supporting/contradicting event id arrays, source diversity, confidence_explanation, rule versions, timestamps. Transitions stored as append-only `HypothesisTransition` rows.
4. **Consumer:** durable JetStream consumer on `sentinel.events.>`; on each event: resolve correlation key → load-or-create hypothesis → `applySignal` → persist → publish `sentinel.fusion.hypothesis.{organisation_id}` update. Idempotent per event_id (reprocessing an already-applied event is a no-op — store applied event ids).
5. **Incident trigger:** when a hypothesis crosses state ≥ 2, emit `sentinel.fusion.incident-candidate.{organisation_id}` exactly once per hypothesis (latched; de-escalation then re-escalation re-emits with `re_escalation: true`).
6. **Contradiction surfacing:** hypothesis API (`GET /api/v1/hypotheses`, tenant-scoped) always returns supporting AND contradicting evidence together — the UI must never be able to show one without the other (§11.4 doctrine: contradiction search is first-class).

## Acceptance criteria
1. Replay of a scripted 3-source scenario produces exactly one hypothesis reaching state 3, with transitions logged and explanation strings present.
2. Same scenario + a strong contradicting access event → state forced down; contradiction visible in API output.
3. Duplicate event redelivery does not double-apply (idempotency test).
4. Single prolific source capped at state 2 (diversity rule) — integration-level test, not just the ported unit test.
5. Rule-version stamping verified in a test.

## Out of scope
Incident object creation (WP-07 consumes incident-candidates), ML models, cross-site correlation, vehicle/identity tracks.
