# WP-28 — Physical DEVICE_ACTION Whisper Proof C

**Status:** AUTHORITATIVE DIRECTIVE ISSUED.
**Implementation:** BLOCKED — NOT STARTED.
**Blocking gate:** WP-26 PHYSICAL ACCEPTANCE PASS.
**Directive authority:** CTO. **Issued:** 2026-09-03.

No WP-28 code is authorised at this time. This document exists so the scope is
recorded before the hardware arrives, not so it can be started early.

---

## 1. Baseline

```text
WP-27 development base    6d3b430037b2c9ae6112ce4198279a57adcb870d
WP-27 qualified head      6747896951d852224f7aae934fa966bf75c4ef10
WP-27 integration head    662a91c7c59b6bfa408a4c930950f7a3e8ff082f
post-main Server CI       33736100744 SUCCESS
post-main Android CI      33736100742 SUCCESS
migrations                23

WP-26 PHYSICAL ACCEPTANCE  DEFERRED — NOT WAIVED
Proof C                    UNCLAIMED
Proof D                    UNCLAIMED
```

## 2. The start gate

WP-28 implementation must not begin while:

```text
WP-26 PHYSICAL ACCEPTANCE != PASS
```

The missing positive StrongBox-capable Android hardware is a **hard
dependency**. Until it is met, do not: cut a WP-28 branch; modify Whisper
orchestration for WP-28; create test substitutes for the physical gate; use
emulator success as physical evidence; use deterministic test keys as Proof C;
weaken the StrongBox requirement; substitute TEE-backed signing; or treat the
Galaxy S8 as positive StrongBox evidence.

## 3. The unblock sequence

**Gate A — resume WP-26 first.** Execute
`docs/execution/WP-26-PHYSICAL-ACCEPTANCE-RUNBOOK.md` against the **frozen
WP-26 candidate `943a8fc2de18ae2f0d1e160062efc2ba23d005a6`**. Do not silently
substitute current `main` for it.

```text
physical acceptance fails on an implementation defect
    -> STOP. Do not begin WP-28. Return through the WP-26 correction gate.

physical acceptance passes
    -> record WP-26 PHYSICAL ACCEPTANCE = PASS. Only then is WP-28 released.
```

**Gate B — the branch base.** Identify the then-current qualified `main`,
require all mandatory workflows green, freeze that exact SHA, and branch
`wp-28-device-action-proof-c` from it. **Do not assume `662a91c7…` will still
be the correct base** — legitimate repository changes may land before hardware
becomes available.

## 4. Objective

WP-28 closes the boundary WP-27 deliberately left. WP-27 ends at
`VERIFIED_STATEMENT`; WP-28 carries that verified security object through
genuine Whisper orchestration:

```text
VERIFIED_STATEMENT
   -> normalised DEVICE_ACTION recognition
   -> organisation-configured ACTIVE Whisper signal
   -> intent
   -> configured response protocol
   -> SILENT execution
   -> authenticated acknowledgement
   -> audit / evidence
   -> PROOF C
```

## 5. Rulings

**D28-01 — WP-27 verification remains authoritative.** Do not duplicate or
bypass it. WP-28 begins from the verified v2 result. A raw, unsigned or
unverified DEVICE_ACTION payload must never enter the response pipeline.

**D28-02 — v1 remains frozen.** `sentinel.whisper.device-action.v1` stays
Ed25519. No reinterpretation to admit P-256 devices, no algorithm union, no
automatic v1→v2 conversion.

**D28-03 — a shared downstream orchestration seam IS authorised.** The two
paths keep their own cryptographic verification and converge below it:

```text
v1 raw result -> v1 schema + Ed25519 verification -> verified recognition ─┐
                                                                          ├─> SHARED
v2 DEVICE_ACTION -> WP-27 gateway + P-256 -> VERIFIED_STATEMENT ──────────┘   ORCHESTRATION
```

That seam may own or call signal resolution, lifecycle/state checks,
organisation/site applicability, threshold handling, intent creation,
receipt/audit creation, protocol mapping, incident/response handoff and
acknowledgement tracking. A behaviour-preserving refactor is authorised where
necessary.

**D28-04 — v2 must not pretend to be v1.** No fabricated
`DeviceActionWhisperResult`, no `signature_algorithm: Ed25519`, no cast into a
v1 type, no faked `AuthenticatedWhisperDeviceContext`, no re-signing under an
alternate Ed25519 identity. Convergence happens only **after** each path's own
trust proof is complete.

**D28-05 — the verified object stays narrow.** Carry only what downstream
needs: organisation, site, operative, device, signal, signal version, modality,
action, confidence, verified freshness/replay identity, verified trust
provenance. No private-key material, no certificate chains, no gateway
secrets.

**D28-06 — provenance survives convergence.** After the paths merge, Sentinel
must still be able to say **how** a recognition was verified — at minimum
distinguishing `DEVICE_ACTION_V1_ED25519` from
`DEVICE_ACTION_V2_P256_ENROLLED_DEVICE`. Identical downstream intent is not a
reason to erase trust provenance.

**D28-07 — signal configuration remains authoritative.** A verified signature
proves origin and integrity; it does not grant operational authority. The
signal must be organisation-owned, correctly scoped, in the required lifecycle
state, ACTIVE, DEVICE_ACTION-compatible, valid for this user/device/site/
context, above threshold, and mapped to an authorised protocol.

**D28-08 — Proof C needs a real Studio lifecycle.** The signal must reach
ACTIVE through the supported lifecycle. **No manual ACTIVE row, no bypassed
validation, no test-only activation route.** Evidence identifies organisation,
signal id, version, `modality = DEVICE_ACTION`, `status = ACTIVE`, intent,
`response_mode = SILENT`, protocol id — without exposing restricted secrets.

**D28-09 — SILENT means operationally silent.** No acknowledgement behaviour
may reveal to a local aggressor that the discreet signal was recognised, unless
the configured acknowledgement channel is itself designed to stay discreet. Do
not substitute a visible toast or dialog because it demonstrates more easily.

**D28-10 — execution is distinct from recognition.** Keep the states apart:

```text
RECOGNISED / VERIFIED -> PROTOCOL REQUESTED -> DELIVERED -> ACKNOWLEDGED -> EXECUTED
```

Transport acceptance is not execution. A verified statement is not an
acknowledged protocol.

**D28-11 — authenticated acknowledgement is mandatory.** Invoking the Silent
protocol is not sufficient. The acknowledgement must pass the real
authentication and authorisation controls and must be bound to the intended
recipient/principal **and** the intended execution. A forged or unrelated
acknowledgement fails closed.

**D28-12 — replay must never re-trigger the protocol.** A spent DEVICE_ACTION
produces no second recognition, protocol invocation, incident, acknowledgement
expectation or side effect. Gateway byte-identical retry convergence remains a
distinct concern from action replay.

**D28-13 — duplicate delivery stays truthful.** Retries and duplicated internal
messages must not manufacture a second protocol execution; prior state may be
returned under existing idempotency semantics.

**D28-14 — WP-28 is hardware-in-loop.** The final acceptance run must use the
accepted StrongBox-capable physical device. **Automated tests are qualification
evidence, never final Proof C evidence.**

**D28-15 — negative control.** The Galaxy S8 may be used as a negative control
if the trust path classifies it ineligible: unsupported hardware assurance → no
trusted enrolment → no accepted positive DEVICE_ACTION. Do not modify it to
fake the positive path. Useful, but not sufficient for Proof C.

## 6. Discovery before code (after unblock)

Produce a contract ledger — `file · symbol · current behaviour · change
required YES/NO` — for: the WP-27 `VERIFIED_STATEMENT` representation; v1
post-verification machinery; signal lookup; ACTIVE validation; threshold
evaluation; intent generation; protocol resolver; SILENT handling;
response/incident creation; acknowledgement creation; acknowledgement
authentication; audit/receipt records; Decision Ledger impact;
idempotency/replay boundary; the realtime path used for acknowledgement; and
the physical Android action trigger.

**If authenticated acknowledgement machinery does not exist, STOP and report
that missing contract before inventing it. If orchestration cannot be shared
without changing frozen semantics, STOP and report the exact seam problem.**

## 7. Migration ruling

```text
current 23 · default WP-28 budget 0
```

Add persistence only if the existing schema cannot truthfully represent the
required protocol/acknowledgement state. If it cannot: STOP and report the
missing state, why the schema is insufficient, the smallest additive migration,
tenant/site consequences and rollback implications. A migration needs separate
CTO approval.

## 8. Required automated tests

```text
verified v2 action + ACTIVE signal          protocol requested
inactive signal                             no protocol
wrong organisation / site / user / device   reject
wrong signal version                        reject
confidence below threshold                  no authorised protocol
mutated object / invalid provenance         reject
spent replay                                no re-execution
transport retry                             no duplicate effect
duplicate internal delivery                 no duplicate protocol
SILENT signal                               no visible unsafe response
valid authenticated acknowledgement         accepted
acknowledgement wrong principal/device      reject
acknowledgement wrong protocol/execution    reject
acknowledgement replay                      reject / idempotent no-op
v1 regression suite                         unchanged
v2 verification regression suite            unchanged
```

## 9. The physical Proof C run

In order: the organisation owns a configured DEVICE_ACTION signal; it passes
the required test/activation lifecycle; it is ACTIVE; it maps to an authorised
SILENT protocol; a positively accepted StrongBox device is enrolled; a real
user performs the action; the device builds the canonical v2 statement; signs
with the accepted protected key; the genuine Device Gateway receives it; WP-27
verification reaches `VERIFIED_STATEMENT`; shared orchestration resolves the
ACTIVE signal; the correct intent is produced; the correct SILENT protocol is
requested; it reaches its intended recipient; a genuine authenticated
acknowledgement returns; Sentinel binds it to the correct execution; replay of
the spent action creates no second response; audit and provenance records are
complete.

## 10. Pass condition

Only after that run succeeds may the repository claim `Proof C — Whisper PASS`.
Anything less remains `UNCLAIMED` — or `FAILED` if a real attempt genuinely
fails. **`DEFERRED` must not be used after a real attempt that fails.**

## 11. Proof D is out of scope

WP-28 claims nothing about degraded operations, WAN failure, Edge behaviour,
queued Field messages or duplicate-safe recovery. `Proof D` stays `UNCLAIMED`
throughout.

## 12. Merge control

```text
WP-26 PHYSICAL ACCEPTANCE PASS -> WP-28 branch authorised -> contract ledger
-> implementation -> local qualification -> hosted Server + Android CI
-> PR -> MERGE HOLD -> CTO review
```

The physical run may be ordered before or after the software PR merges,
depending on deployability at the time. **No Proof C PASS may be declared until
the genuine physical run succeeds against an attributable qualified build.**

---

```text
WP-27                       COMPLETE
WP-28                       BLOCKED — NOT STARTED
WP-28 blocker               WP-26 PHYSICAL ACCEPTANCE
WP-26 PHYSICAL ACCEPTANCE   DEFERRED — NOT WAIVED
Proof C                     UNCLAIMED
Proof D                     UNCLAIMED
migrations                  23
```
