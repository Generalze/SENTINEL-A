# Directive WP-13 — Proof A Integration & Milestone Sign-off

**Lane:** Lead (Fable) + Opus support · **Wave:** 5 · **Depends:** all
**Review chain:** Lead executes; Opus adversarial pass on the test itself

## Spec reference
§80 Proof A: "Simulator emits multi-source events; Fusion correlates; Constitution authorises; Command receives; Field acknowledges; evidence and Decision Ledger complete."

## Deliverable
`tests/integration/proof-a.test.ts` — one automated test (vitest, run against the live compose stack + booted core-api) executing the EXECUTION_PLAN §2 exit criteria end to end:

1. Seed org/site/zones/users (WP-03 seed).
2. Run `proof-a-intrusion@1` via the simulator programmatically.
3. Assert: exactly one hypothesis reaches state ≥ 3 with ≥ 2 diverse sources; four separated values present; transitions logged.
4. Assert: exactly one incident created; severity computed; timeline populated.
5. Assert: Constitution evaluated the dispatch (ledger entry exists with trace + policy version + hash chain intact via verifyChain).
6. Connect a WS client as an org operator; assert `incident.updated` received.
7. Ack the dispatch task as the field user via API; assert ACKNOWLEDGED + timeline entry + WS update.
8. Assert: evidence snapshot exists, hash verifies, custody events INGESTED (+ VIEWED after a read).
9. Run the contradiction variant; assert state forced down and contradicting event visible in the hypothesis API.
10. Run `duplicate-delivery@1` and `single-source-noise@1`; assert dedup and the state-2 cap.
11. Negative: cross-org operator sees nothing (list APIs empty, WS silent).

This test is **Crucible regression zero** — it enters CI (compose services via GitHub Actions service containers or compose action) and never leaves the suite.

## Sign-off checklist (lead, recorded in docs/execution/MILESTONE-1-SIGNOFF.md)
- All WP acceptance criteria re-verified on the integrated build.
- `pnpm -r typecheck && lint && test` + proof-a green from clean clone.
- No `any`, no TODO in security-critical paths (grep sweep).
- EXECUTION_PLAN risk register reviewed against what actually happened.
- Tag `milestone-1-proof-a`.
