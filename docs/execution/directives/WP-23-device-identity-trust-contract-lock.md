# Directive WP-23 - Device Identity & Trust Contract Lock

**Issued by:** Lead (/root) - **Lane:** Core with adversarial review - **Wave:** 12
**Milestone:** 3 (M3A — Trusted Device, target Proof C)
**Frozen base:** `f660407c78f3600c6c6307d2bd3c7d310274f026` (`milestone-2-field-workflow`)
**Branch (this document):** `docs/m3-device-trust-roadmap`
**Status:** **Directive authoring only.** Contract implementation, registry,
gateway, mobile client and every runtime surface are **HOLD** pending the
lead's review of this device-trust model.

## Purpose

Answer the dangerous questions **before** anybody writes the device gateway.

WP-21A did this for Whisper and it worked: the contract was made unforgiving
while it was still cheap, and the runtime that followed inherited a boundary it
could not quietly widen. WP-23 does the same for device identity — a larger
blast radius, because a device credential is what will eventually let a piece
of hardware in someone's pocket raise a silent duress dispatch.

The governing sentence for the whole work package:

> **A device credential proves which hardware is speaking. A user session
> proves who is speaking. Neither creates the other, and a production Field
> operation needs both, plus site/context authority, plus Constitution policy
> where applicable.**

## The two rules locked immediately

### D23-01 — A valid user login must never manufacture trusted device identity

Authenticating as an operative proves a person's credentials were presented.
It says nothing about the hardware presenting them, which may be an
attacker's laptop, an emulator, a jailbroken handset, or a device reported
stolen an hour ago. Device trust must come from a device credential the
server issued and can revoke, checked against a registry the device does not
control.

### D23-02 — A registered device must never manufacture current user authority

A trusted device in the right hands is still only a device. Whether *this*
operative may accept this assignment, verify this checkpoint or fire this
Whisper signal is a live authorisation question answered from current roles,
site scope and Constitution policy — recomputed per operation, exactly as
WP-21B/C12-01 already requires. A device that could vouch for a user would
recreate the borrowed-authority defect at hardware scale.

Together: **authenticated user authority + authenticated device trust +
site/context authority + policy**. All four, every time. This is the
production boundary behind the server-constructed context M2 deliberately
refused to call Proof C.

## Contract surface to be locked

The contract must define, at minimum, each of the following. Where a ruling
below constrains one, the ruling is binding on the contract's shape.

```text
Device identity            Key identity / key version      Enrollment states
Device enrollment          Server-known public key         Revocation semantics
Device ownership           Private-key custody boundary    Re-enrollment semantics
Org/site association       Key rotation
User-device association    Key revocation

Device trust: TRUSTED | DEGRADED | SUSPICIOUS | QUARANTINED | COMPROMISED | OFFLINE

Authenticated device principal      Attestation / integrity claims
User principal                      Freshness
User-auth vs device-auth boundary   Nonce / anti-replay
                                    Clock skew

Device-context issuance    Offline queue identity     Edge identity
Device-context expiry      Operation sequence         Edge-device relationship
Site entitlement           Policy-cache expiry        Edge trust
Current-user entitlement   Reconnect handshake        Edge buffer ownership

Lost-device response     Compromised-key response   Recovery behaviour
Stolen-device response   Quarantine behaviour       Audit events
```

## Locked rulings

### D23-03 — Private keys never leave the device, and enrollment proves possession

The device generates its own keypair in hardware-backed storage (Secure
Enclave / StrongBox / equivalent) and Sentinel receives **only the public
key**. There is no code path — enrollment, backup, escrow, support, migration
or debug — in which a device private key reaches the server, a log, a backup,
or another device. A platform that cannot offer hardware-backed key storage
cannot hold a TRUSTED credential; it may enrol at a lower trust state, and the
contract must express that rather than pretending otherwise.

Enrollment is a **challenge-response proving possession** of the private key,
never an upload. A public key arriving without a fresh server-issued challenge
signed by the matching private key is not an enrollment; it is a claim.

### D23-04 — The enrollment bootstrap is the hardest problem, and it is not a shared secret

Every device-trust system is only as strong as how the *first* credential is
issued. An unenrolled device has, by definition, nothing to authenticate with.

The contract must define a **bootstrap enrollment token** that is:
single-use, short-lived, bound to exactly one organisation + site + intended
user, issued through an authenticated Command action by a principal holding an
explicit enrollment capability, auditable to the issuing human, and revocable
before use. It is **not** a shared organisational secret, not a QR code with
an indefinite lifetime, and not something an operative can mint for
themselves.

Consuming a bootstrap token binds one device public key, exactly once, and
burns the token — a second use is a conflict and an audit event, never a
second device. If a token is used from an unexpected context, the enrollment
must fail closed and the token must die rather than degrade.

### D23-05 — Trust is server-owned state, not a device self-report

The six trust states are the platform's judgement about a device. A device may
supply *evidence* — attestation results, integrity signals, its own health
telemetry — and may never supply the conclusion. This is the M2 rule
(`deviceTrust` lives in the context, never in the submitted result) restated
at registry scale, and it is why a COMPROMISED device cannot rescue itself by
claiming to be TRUSTED.

The contract must define which transitions are automatic (evidence-driven),
which require a human with a named capability, and which are terminal.
`COMPROMISED` in particular must be a decision no device can reverse, and
`QUARANTINED` must be reachable *fast* — the point of quarantine is to act on
suspicion before certainty.

### D23-06 — Attestation is evidence, and an attestation outage must not become an authority outage

Platform attestation (Play Integrity, DeviceCheck/App Attest, or equivalent)
is a strong signal that the app and OS are unmodified. It is still a claim
about the device, produced by a third party that can be unavailable.

The contract must therefore state both halves: attestation failure or
staleness may **lower** trust, and attestation success may never **be** the
authorisation. The uncomfortable case must be ruled explicitly rather than
discovered in production — if the attestation provider is unreachable, a
device's trust degrades on a defined schedule, and a degraded device cannot
fire Whisper (W21-05 already fixes TRUSTED-only invocation) while every
ordinary alarm and reporting path stays open to the operative. WP-23 must say
plainly that this is a deliberate trade: we would rather a duress signal fall
back to a loud channel than accept a silent dispatch from hardware we can no
longer vouch for.

### D23-07 — The device context is a short-lived, server-issued, revocation-checked assertion

`AuthenticatedWhisperDeviceContext` and its Field equivalent become
**server-issued** rather than server-constructed. The contract must define
issuance inputs (authenticated user session + authenticated device credential
+ current registry state), a **bounded lifetime**, and the rule that its
lifetime is the maximum window in which revocation can be outrun.

That framing is the point: a long-lived device context is a bearer credential
that survives the theft it was supposed to protect against. The contract must
therefore either keep the TTL short enough that the exposure is acceptable, or
require a registry check at use — and it must say which, in numbers, the way
W21-08 named its freshness bounds instead of hiding them in a service.

A context must never be transferable between users, devices, sites or
organisations, and must carry the key version it was issued against so a
rotation invalidates it.

### D23-08 — Revocation must be evaluated at reconciliation, and a revoked device's queue is refused

The hard case is not a revoked device online — that is easy. It is a **stolen
device that was offline when it was revoked**, reconnecting with a queue of
operations it signed while nobody knew.

The contract must rule that:

- revocation is evaluated against **server-known** revocation time at
  reconciliation, never against timestamps the device supplies;
- operations arriving from a revoked or compromised device are **refused
  wholesale**, including ones the device claims predate the revocation.

That second clause deliberately discards work that may have been legitimate.
It is the correct trade: a thief's queue and an honest operative's queue are
indistinguishable once the credential is in the wrong hands, and the entire
purpose of revocation is to stop trusting anything that credential says. The
contract must state the consequence honestly — a genuinely lost queue is
recoverable only through human-attested re-entry, not by trusting the device.

### D23-09 — Re-enrollment produces a new device identity, never a reset

WP-20/C10-03 already locked that a device needing a fresh sequence namespace
requires a new authenticated identity. M3 must honour it: a wipe, reinstall,
key rotation past recovery, or re-enrollment after quarantine yields a **new
device id**, a new key identity, and a fresh offline sequence namespace.

The old identity is retired, not reused. Reusing it would let a re-enrolled
device inherit a replay namespace whose consumed positions it no longer knows,
which is precisely how a duplicate operational effect gets in.

### D23-10 — Edge is a buffer and a transport, never an authority

Edge holds operations on behalf of devices during an outage. The contract must
state that Edge **does not re-sign, re-authorise, or vouch for** the
operations it carries: the device's signature and the device's identity travel
intact and are verified centrally on arrival.

Edge has its own identity and its own trust state — it is a principal in its
own right, for its own local functions — but a compromised Edge must be able
to *delay, drop or corrupt* traffic without being able to *forge a Field
action*. If Edge compromise could manufacture a signed device action, the
whole device-trust model collapses to trusting the box in the wiring closet.

### D23-11 — Offline authority is bounded by a policy cache that expires

A disconnected client may act only within a cached policy, and that cache must
have an explicit expiry after which the client **refuses** rather than assumes.
The contract must define the cache's contents, its maximum age, and what
happens at expiry.

The refusals are the proof (see Proof D): a degraded client that keeps
allowing everything has not survived an outage, it has stopped enforcing.
Operations whose authority cannot be established offline must be refusable
locally with a clear reason the operative can act on, not silently queued to
fail hours later.

### D23-12 — Freshness, nonce and clock skew are server-judged, at device scale

M2's rules carry forward unchanged in principle: the server's receipt clock is
authoritative, client-reported freshness is telemetry, nonces are one-shot and
scoped to the identity that consumed them. WP-23 must restate the bounds for a
world where devices are genuinely offline for long periods — which means
saying explicitly which operations may legitimately arrive stale (a queued
assignment acknowledgement) and which may not (a duress signal), rather than
applying one window to both.

### D23-13 — The sync/reconnect handshake authenticates before it synchronises

The reconnect handshake must establish user identity, device identity, current
trust and current entitlement **before** any queued operation is examined, and
must fail closed as a whole rather than partially admitting a queue. The
offline queue identity, operation sequence and conflict semantics remain
WP-20's — contiguous per-device sequencing, request-bound fingerprints,
effectively-once with claim fencing — now keyed to a device identity that is
real.

### D23-14 — Audit records the decision, never the secret

Enrollment, issuance, rotation, revocation, quarantine, trust transitions,
reconnect handshakes and refusals must all be auditable to a device, a user, a
time and a reason. No audit payload, log line, metric or realtime signal may
carry a private key, a bootstrap token, an attestation blob, a nonce, or the
contents of a device context. This is W21-14 applied to a domain with more
secrets in play.

### D23-15 — Lost, stolen, compromised: three responses, defined in advance

The contract must define what each of these does to: the device's trust state,
its issued contexts, its queued operations, its Edge buffer, and its ability
to re-enrol — and who may declare each, with what capability. "Lost" (may come
back), "stolen" (assume adversarial possession) and "compromised key" (assume
the credential itself is copied) are different threats and must not collapse
into one flag.

### D23-16 — Nothing in WP-23 is executable

This work package produces a directive and, when authorised, contracts and
contract tests. No registry, no gateway, no endpoint, no mobile client, no
migration. If implementation appears to prove a contract impossible or
internally inconsistent, **STOP and report** rather than silently adjusting
the model — the WP-21A precedent.

## WP-23 deliverables (when contract authoring is authorised)

- A device-identity contract module under `packages/contracts/src/` covering
  the surface above, with strict schemas, bounded values, and pure helpers for
  every decision the runtime will need (trust transitions, context validity,
  revocation comparison, enrollment token consumption, sequence namespace
  derivation).
- Its Crucible test suite.
- No changes to the frozen Whisper contract beyond additive integration points
  the lead approves.

### Mandatory Crucible cases

```text
a user session alone cannot produce device trust
a device credential alone cannot produce user authority
a bootstrap token is single-use, expiring, scope-bound, and dies on misuse
an enrollment without proof-of-possession is refused
a device context cannot be replayed across user, device, site or organisation
a device context is invalid after its key version rotates
a revoked device's queued operations are refused wholesale
a device claiming an operation predates its revocation is still refused
re-enrollment yields a new device identity and a fresh sequence namespace
a device cannot assert its own trust state
attestation failure lowers trust and never raises authority
an expired policy cache refuses rather than assumes
Edge cannot forge, re-sign or re-authorise a device operation
stale offline operations are judged against the server clock
audit payloads carry no key, token, attestation blob, nonce or context
```

## Out of scope

Device runtime, registry persistence, gateway endpoints, mobile client, Edge
implementation, WAN-loss work, and every M3 non-goal already listed in the
Milestone-3 roadmap. Whisper modalities remain DEVICE_ACTION-only.

## Gate state

```text
WP-23 directive authoring         DELIVERED (this document)
WP-23 contract implementation     HOLD — pending lead review of this model
WP-24 .. WP-31                    HOLD

public device endpoint            PROHIBITED until WP-25 delivers the facility
Whisper contract                  FROZEN
Proof C                           UNCLAIMED
Proof D                           UNCLAIMED
original repository               FROZEN at bd6076e
```
