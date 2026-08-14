# Directive WP-10 — Sentinel Simulator

**Lane:** Core (Sonnet) · **Wave:** 3 · **Depends:** WP-01
**Review chain:** Sonnet peer review → Lead merge gate

## Spec references
§52 (build the simulator early), §80 Proof A (the scenario this must power), §32.1 (coordinated intrusion signals as scenario inspiration).

## Deliverables (`packages/simulator`)
1. **Scenario format:** typed `Scenario` = ordered `ScenarioStep[]`; step = { at_offset_ms, event: NormalisedEvent template } with placeholders for organisation_id/site_id/zone ids and trace_id injected at run time. Validated with contracts schemas — the simulator can never emit an invalid event.
2. **Runner:** `runScenario(scenario, { baseUrl, orgId, siteId, zoneIds, apiHeaders, speed })` — POSTs each event to `/api/v1/events` at its offset (speed multiplier for tests, `speed: Infinity` = as fast as possible while preserving order); returns per-event delivery results including duplicate flags. Retries transient failures with backoff (idempotency makes this safe).
3. **Scenario library** (data files, versioned):
   - `proof-a-intrusion@1`: camera person-detected (restricted zone, trusted, conf .78) → access denied-attempt (different source) → camera loitering (conf .74) → field report hostile-observation (humanAuthorised, conf .9) → THE CONTRADICTION VARIANT adds a valid access.granted with matching schedule.
   - `single-source-noise@1`: one camera spamming 6 supporting events (must cap at state 2 downstream).
   - `duplicate-delivery@1`: same event posted 3×.
4. **CLI:** `pnpm --filter @sentinel/simulator run-scenario -- --name proof-a-intrusion --org ... --site ...` (plain node arg parsing, no CLI framework dep).

## Acceptance criteria
1. Scenario files validate against contracts at build time (test imports and parses all).
2. Runner ordering guarantee test (offsets respected relative to speed).
3. Against the live stack: `proof-a-intrusion` runs green end-to-end at the ingestion level (200s, duplicate variant returns duplicate flags).

## Out of scope
Load/performance generation, camera video simulation, UI.
