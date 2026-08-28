# Milestone 3 - Trusted Device & Degraded Operations

**Status:** Planning. **WP-23 roadmap + directive authoring GO; all
implementation HOLD.**
**Frozen development base:** `f660407c78f3600c6c6307d2bd3c7d310274f026`
(`milestone-2-field-workflow`)
**Owner of record:** masterzee001

Milestone 2 proved the **server side** of the Field workflow: assignment,
state, messaging, patrol, offline replay, and a Whisper runtime that turns a
signed device action into a SILENT incident without ever becoming an approval.

It deliberately did **not** prove two things, and the frozen M2 evidence record
names both:

- **Proof C** — no production-authenticated *physical device* has entered
  Sentinel's trust boundary. The Whisper runtime is exercised through a
  server-constructed `AuthenticatedWhisperDeviceContext` and a test-injected
  key.
- **Proof D** — no *actual* WAN outage has been survived. The ordering,
  idempotency and recovery machinery is exercised through an internal replay
  service, not a real client queue behind a severed link.

Milestone 3 exists to close exactly those two gaps, and nothing else.

## Objective

> **A real trusted Field device shall securely participate in Sentinel
> operations, originate an authenticated Whisper action, continue authorised
> critical functions during connectivity loss, and reconcile truthfully when
> connectivity returns.**

## The two halves, deliberately sequenced

M3 splits internally so device identity and network resilience are never
implemented in one uncontrolled wave. Each half ends in a proof gate, and the
second half depends on the first: *reconciling truthfully after an outage is
meaningless if the thing reconnecting cannot be authenticated.*

```text
M3A — Trusted Device                     M3B — Edge Resilience
      target: Proof C                          target: Proof D

WP-23  device identity contract lock     WP-29  Edge + offline client
WP-24  Shield device registry            WP-30  WAN-loss recovery
WP-25  authenticated device gateway      WP-31  Proof D + M3 Crucible
WP-26  Field mobile foundation
WP-27  real DEVICE_ACTION Whisper
WP-28  Proof C gate
```

## Work packages

| WP | Name | Primary outcome |
|---|---|---|
| **WP-23** | Device Identity & Trust Contract Lock | Freeze device identity, enrollment, keys, trust states, revocation, authenticated-device context and sync contracts. **No runtime.** |
| **WP-24** | Shield Device Registry | Persistent device registration, ownership, key binding, trust lifecycle, revoke/quarantine/compromise handling. |
| **WP-25** | Authenticated Device Gateway | Replace the server-constructed trusted context with a genuine authenticated-device boundary. |
| **WP-26** | Field Mobile Foundation | Minimal real Field client: identity, assignments, state, messaging, patrol, secure local storage. |
| **WP-27** | Real DEVICE_ACTION Whisper | The device signs the canonical Whisper statement with its protected key and submits through the genuine boundary. |
| **WP-28** | **Proof C Gate** | Physical device → authenticated identity → signed Whisper → SILENT incident → two distinct operational approvals → authenticated acknowledgement. |
| **WP-29** | Edge + Offline Client Foundation | Local encrypted queue, policy cache with expiry, Edge buffering, reconnect/sync protocol, degraded-state reporting. |
| **WP-30** | WAN-Loss Recovery | Sever the WAN, operate locally, reconnect, reconcile ordering and idempotency with no duplicate operational effect. |
| **WP-31** | **Proof D + M3 Crucible / Sign-off** | Device theft, replay, revocation, stale policy, Edge restart, split connectivity, sequence recovery, final M3 evidence. |

Every work package follows the M2 discipline that produced a clean milestone:
a contract/authority lock before runtime, one substantial implementation pass,
whole-effective-diff adversarial audit, one consolidated correction batch,
SHA-bound merge authorization, and a green post-main run.

## What M3 inherits and must not weaken

M2's boundaries are frozen and carry forward as constraints, not suggestions:

- **Recognition initiates; it never approves.** Two distinct commander
  approvals remain the only route to SILENT dispatch, through the existing
  Constitution path. A real device changes who signs the action — it changes
  nothing about who authorises the response.
- **The Whisper contract is frozen** (`packages/contracts/src/whisper.ts`).
  M3 supplies a genuine `AuthenticatedWhisperDeviceContext`; it does not
  redefine what one means.
- **A re-provisioned device is a new identity.** WP-20/C10-03 already ruled
  that a device needing a fresh sequence namespace requires a new
  authenticated device identity, never a reset. M3's enrollment must honour
  that, because the offline replay identity is keyed by device id.
- **No public device endpoint may exist before the facility that
  authenticates it.** WP-25 is what finally lifts that prohibition — and only
  for a surface that consumes real device authentication.
- **Client claims stay evidence.** Confidence, freshness, context and now
  attestation are inputs to a server judgement, never the judgement.

## Proof C — locked acceptance definition

Proof C succeeds only when a **genuine client device** performs the operation
end to end:

```text
REAL PHYSICAL DEVICE
  -> DEVICE ENROLLMENT
  -> PROTECTED DEVICE KEY (private key never leaves the device)
  -> USER AUTHENTICATION
  -> DEVICE AUTHENTICATION
  -> SERVER DEVICE REGISTRY
  -> CURRENT TRUST + AUTHORITY
  -> DEVICE SIGNS WHISPER ACTION
  -> SERVER VERIFIES SIGNATURE
  -> ANTI-REPLAY + FRESHNESS + CONTEXT
  -> WHISPER RECOGNITION
  -> SILENT_INCIDENT_RESPONSE
  -> ZERO AUTOMATIC APPROVALS
  -> TWO DISTINCT COMMANDER APPROVALS
  -> FIELD DELIVERY
  -> AUTHENTICATED DEVICE ACKNOWLEDGEMENT
```

No part of that chain may be simulated, stubbed, or server-constructed. A test
harness that builds the device context, injects the key, or signs on the
device's behalf proves the server boundary — which M2 already proved — and not
Proof C.

## Proof D — locked acceptance definition

Proof D requires an **actual** outage, not a mocked method call and not an
`offline = true` flag:

```text
central Sentinel online, real Field device connected, Edge operational
  -> WAN physically or logically severed
  -> central unreachable
  -> Edge continues authorised critical local functions
  -> Field client recognises degraded state
  -> allowed operations queued locally
  -> some operations EXPLICITLY REFUSED because policy expired or
     authority is unavailable
  -> WAN restored
  -> authenticated reconnect
  -> ordered synchronisation
  -> duplicates converge, changed requests conflict
  -> stale authority cannot rewrite current state
  -> no duplicate incident action
  -> complete audit trail
```

The refusals matter as much as the successes. A degraded client that quietly
allows everything has not survived an outage — it has stopped enforcing.

## Explicitly out of scope for M3

Not prerequisites for the trusted-device and degraded-operation boundary, and
each would enlarge a security-critical surface without advancing either proof:

Vision/ONVIF, camera or facial recognition, gesture and voice Whisper
modalities, DarkWatch, OpenIntel, Controlled Reality, advanced Pursuit, Guest
Protection expansion, Kubernetes migration, and broad Command UI redesign.

These remain part of the wider Sentinel architecture; they are simply not this
milestone.

## Current gate

```text
MILESTONE 2                       FROZEN at f660407
new development base              f660407c78f3600c6c6307d2bd3c7d310274f026

MILESTONE 3                       PLANNING
M3A target                        Proof C — genuine authenticated device
M3B target                        Proof D — genuine WAN-loss / Edge recovery

WP-23 roadmap + directive         GO (this document and the directive)
WP-23 implementation              HOLD
WP-24 .. WP-31                    HOLD

Proof C                           UNCLAIMED
Proof D                           UNCLAIMED
original repository               FROZEN at bd6076e
```
