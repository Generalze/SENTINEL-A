# WP-25 — Authenticated Device Gateway

**Status:** DESIGN PASSED with an addendum (CTO gate, 2026-09-02).
**IMPLEMENTATION GO.**
**Base:** `578055a288d436d4e51b10fb428c1ba025d2c5b2` (the WP-24 merge commit).
**Branch:** `wp-25-authenticated-device-gateway`.
**Execution repository:** `Generalze/SENTINEL-A`. The original repository
`masterzee001/SENTINEL-A` remains frozen at `bd6076e` and is untouched.

---

## 0. The question this work package answers

> **How does an incoming connection prove that it is the registered physical
> device Shield represents, while separately proving the current human actor
> and the current authorisation, without either credential manufacturing the
> other?**

WP-23 froze the contracts. WP-24 made them authoritative server state and
deliberately shipped **no** device-facing boundary — every route it could have
added, it refused to add, because there was still no facility that could
authenticate an incoming physical device. WP-25 is the work package that lifts
that prohibition, and it lifts it **only** for a surface that consumes real
device authentication.

The governing invariant is unchanged and is the whole point:

```text
USER AUTHORITY  +  DEVICE IDENTITY  +  CURRENT DEVICE TRUST
                +  SITE / CONTEXT AUTHORITY  +  POLICY WHERE REQUIRED

must remain INDEPENDENT facts.
```

The frozen contract already states this as executable policy —
`DEVICE_CREDENTIAL_ESTABLISHES` is `device_identity`, `device_key_continuity`,
`device_trust`; `USER_SESSION_ESTABLISHES` is `user_identity`, `user_roles`,
`user_site_scope`; and `evaluateDeviceOperationPrincipals` refuses when either
side is missing. **WP-25 consumes that evaluator. It does not restate it.**

---

## D25-01 — There is no device bearer token. Ever.

This is the ruling every other rule in this directive depends on, and it is
C14-03's, carried forward without softening.

`AuthenticatedDeviceContext` is a **scope statement, not a credential**. It
carries no token, no secret and no authorization field, and the Crucible
already proves it cannot. Holding one proves nothing: it says what a device
*would* be entitled to *if* the hardware were present.

Therefore:

```text
EVERY device-authenticated request carries a FRESH DeviceRequestProof,
signed by the hardware key, over the canonical request-proof statement.

A context id presented WITHOUT a matching possession proof is refused
POSSESSION_NOT_PROVEN. There is no "session cookie" path, no
"authenticated socket" path, and no per-connection exemption.
```

This is what *sender-constrained* means here, and it is stronger than the usual
reading: the proof is bound to the context, the key version, the purpose, the
payload digest and a one-shot nonce, so a captured request cannot be replayed,
retargeted at another payload, or reused for another purpose.

**A long-lived socket does not change this.** If a realtime transport is used,
each device-originated *message* that causes an effect carries its own proof.
Connection-time authentication authorises the connection, never the traffic on
it. "Sockets carry a signal; REST is authoritative" already applies, and this
directive extends it: a socket may not authorise anything a REST call would
have required a proof for.

---

## D25-02 — The ingress pipeline: preflight, then ONE effect transaction

**AMENDED at the design gate.** The first draft ended `9. consume the replay
identity → 10. execute`, which is precisely the failure class WP-24 spent two
correction batches eliminating: if consumption commits and the domain effect
then fails, Sentinel remembers an operation that never happened. Replay
consumption and the domain effect are now one transaction.

```text
PREFLIGHT — establishes nothing, commits nothing
────────────────────────────────────────────────
parse the typed operation envelope     gateway-owned, canonical (D25-10)
resolve the persisted context          server state, never a credential
resolve the current registry key       by key_id + key_version, in-org
bind the server profile                bindClaimedSignatureProfile
import the key                         WP-24's P-256 importer, OpenSSL
verify the signature                   over the canonical statement
build current registry + actor facts   DeviceRegistryFacts, read now
classify existing replay state         WITHOUT creating an effect
evaluateDeviceRequestProof             the frozen evaluator, unmodified
evaluateDeviceOperationPrincipals      both principals, independently

FINAL EFFECT TRANSACTION — one transaction, or nothing
──────────────────────────────────────────────────────
re-read AND LOCK:  persisted context (open, unexpired)
                   current device, current key, key version
                   revocation state, effective trust
                   current actor authority, current site authority
                   the domain target itself
then atomically:   claim the replay identity
                   execute the domain effect
                   record the authoritative outcome reference
                   append the gateway security audit
COMMIT TOGETHER
```

The governing invariant, in the same words WP-24 earned:

```text
NO FIRST_SEEN DEVICE REPLAY CONSUMPTION MAY SURVIVE
WITHOUT ITS CORRESPONDING DOMAIN EFFECT.
```

```text
same identity + same fingerprint + a committed outcome that RESOLVES
    -> CONVERGE
same identity + different fingerprint
    -> CONFLICT
a stored outcome reference that cannot be proved against the actual
authoritative domain row
    -> FAIL CLOSED, never manufacture convergence
```

Two properties the ordering exists to hold. **The key is never taken from the
request** — it is resolved from the registry, and there is no parameter through
which a caller could supply one. And **possession is proven before any domain
effect**, never alongside it.

Steps 9 and 10 of the preflight stay separate on purpose. One asks *is this
proof good for this context?*; the other asks *are both principals present and
sufficient?* Collapsing them would let a strong device proof paper over a
missing session.

**If an approved domain service cannot participate safely in that transaction,
implementation STOPS and reports the missing transactional seam.** It does not
duplicate or reinterpret that domain's security logic inside the gateway.

## D25-03 — Establishing a context, without the circularity

**AMENDED at the design gate. The first draft was circular and wrong.** It said
"the device signs a context request, the server verifies, the server mints a
context" — but the frozen `DeviceRequestProof` is itself bound to a
`context_id`, and its evaluator takes an `AuthenticatedDeviceContext`. Requiring
an issued context in order to obtain the first context cannot work. The defect
was mine; this is the corrected ceremony.

It is NOT solved with a bearer bootstrap token, and NOT by inventing another
cryptographic domain.

### D25-03A — the pre-context establishment challenge

```text
CURRENT HUMAN SESSION requests establishment for a registered device + site
        |
        v
SERVER resolves, from its own state only:
   organisation · current actor · device · current key id + version
   current registry standing · current actor/site intersection
        |
        v
SERVER creates a short-lived, ONE-SHOT establishment challenge:
   establishment_id · PROPOSED context_id · organisation_id
   actor_user_id · device_id · site_id · key_id + key_version
   server nonce · issued_at · expires_at
        |
        v
   NO CONTEXT HAS BEEN ISSUED.  NO DEVICE AUTHORITY EXISTS.
        |
        v
DEVICE signs a frozen DeviceRequestProof:
   context_id     = the PROPOSED context_id
   purpose        = RECONNECT_HANDSHAKE
   payload_digest = digest of the EXACT establishment challenge
        |
        v
SERVER reconstructs an IN-MEMORY CANDIDATE context from SERVER facts
        |
        v
P-256 signature verified against the CURRENT Shield registry key
        |
        v
evaluateDeviceRequestProof (authentication-only semantics)
   + evaluateDeviceOperationPrincipals
        |
        v
FINAL TRANSACTION: re-read current facts · consume the establishment
challenge · consume the replay identity · persist the issued context ·
persist the audit
        |
        v
AuthenticatedDeviceContext ISSUED
```

**The candidate is not an issued context.** It is assembled in memory from
server facts purely so the frozen evaluator has something to judge; it is never
returned to the client and is accepted nowhere else. That distinction is the
whole reason this is not a bearer bootstrap.

**The establishment challenge is not a secret.** Stealing `establishment_id`,
the proposed `context_id` and the server nonce confers ZERO device authority
without both the registered private key AND the independent current human
session. It is single-use and short-lived because a one-shot identity is
cheaper to reason about than a secret, not because it is one.

The server owns every field of the minted context. `device_trust` is copied at
issuance because the frozen contract requires the field, but it is **historical
issuance state only** — every operation uses current Shield standing, via
WP-24's effective-standing helper, so an attestation that ages out mid-context
degrades the answer immediately.

A context is bound to one `key_id + key_version`; a rotation invalidates every
context issued against the superseded version, which the frozen evaluator
already enforces as `KEY_VERSION_ROTATED`.

**STOP CONDITION A.** If the frozen `DeviceRequestProof` proves incapable of
expressing this ceremony safely, implementation STOPS and reports. It does not
preemptively add a signed-statement domain.

## D25-04 — Revocation must land inside a live session

The exposure window is bounded twice, and both bounds are already frozen:

- the context TTL is at most 300 s; and
- **the registry is consulted on every request**, so a revocation, a
  quarantine, a key rotation, a lost site entitlement or a withdrawn capability
  takes effect on the *next request*, not at the end of the context's life.

Device-level and key-level withdrawal are asked **independently** (C15-R4-final,
D24-09). Neither may mask the other, and no caller may assume the two rows moved
together.

The realtime consequence must be stated rather than discovered: **an open
connection is not a grant.** When a device is revoked mid-session, in-flight and
subsequent effects are refused, and the connection is not treated as
pre-authorised because it was established before the revocation.

---

## D25-05 — Reconnect authentication is not queue admission

C15-R2 split these into two decisions and WP-25 is the first runtime to consume
both. It must keep them apart:

```text
evaluateDeviceReconnectAuthentication    establishes possession and current
                                         identity. Its success arm carries the
                                         literal `queue_examination_permitted:
                                         false`.

evaluateDeviceOfflineQueueAdmission      decides the queue, against CURRENT
                                         registry trust, CURRENT actor
                                         authority and CURRENT site entitlement,
                                         at the fixed purpose OFFLINE_SYNC.
```

A device returning from the dark authenticates on possession; it becomes
queue-capable only through an evidenced trust transition. **Authentication does
not restore operational authority by itself**, and the gateway must not
reintroduce that shortcut for convenience.

The authentication verdict's binding (organisation, context, actor, device, key
id, key version) is re-checked at admission, and a key rotation in the gap is
refused as `KEY_VERSION_ROTATED` — C15-R2-final.

---

## D25-06 — Authenticated acknowledgement

§76's lifecycle is `REQUESTED → DELIVERED → ACKNOWLEDGED → EXECUTED`, and
`ACKNOWLEDGED` is the first transition a *device* can cause. It therefore obeys
the same rule as everything else: an acknowledgement is a device-authenticated
request carrying its own proof and its own one-shot replay identity.

An acknowledgement that arrives without possession is not a weaker
acknowledgement; it is not an acknowledgement. Delivery evidence stays
server-owned, and the device's claim about when it saw something remains
telemetry, never authority.

---

## D25-07 — What WP-25 must NOT do

```text
NO real Whisper DEVICE_ACTION flow          WP-27 owns it
NO wiring WHISPER_DEVICE_KEY_RESOLVER       it verifies Ed25519 under frozen
   to the Shield registry                   Whisper v1; the registry holds
                                            P-256 under the M3 profile
NO mobile client / Flutter                  WP-26
NO Edge runtime, offline client queue,      WP-29 / WP-30
   or WAN-loss implementation
NO production attestation vendor            the WP-24 seam stays a seam
   integration
NO Proof C claim                            WP-28
NO Proof D claim                            WP-31
```

**A gateway that authenticates a test process holding a P-256 key is not Proof
C.** Proof C requires a real physical device with a hardware-backed key,
through a real client. WP-25 builds the boundary that makes Proof C *possible*;
it cannot claim it, and neither the tests nor the report may imply otherwise.

The Whisper prohibition deserves its own sentence, because WP-25 is the first
work package with the technical means to break it: the gateway will be able to
authenticate a device, and it must still refuse to become the physical-device
Whisper path. Turning Whisper v1 into that path by quietly pointing its resolver
at the Shield registry would reinterpret a frozen M2 contract, which is exactly
what C14-01 versioned forward to avoid.

---

## D25-08 — Engineering debt carried into WP-25 as constraints

Two conditions were verified during WP-24 and ruled out of its scope. Neither
blocks WP-25, and both constrain it:

1. **Migration-history drift.** Diffing the pre-WP-24 chain against its
   datamodel emits 8 `ALTER COLUMN … DROP DEFAULT` and 25 `RENAME CONSTRAINT`
   statements on a clean base. Deployment of all 21 migrations is green, so it
   is not a blocker. It belongs to a dedicated migration-hygiene work package
   with its own reproduction, compatibility ruling and migration proof. **WP-25
   does not repair it and does not rewrite historical migrations.**

2. **Shared-Postgres live-suite contention.** Twelve live suites run in
   parallel against one database; a single pre-existing test fails
   intermittently on a developer machine. One identified contributor is
   `test/app.e2e.spec.ts`, which boots AppModule through `NestFactory.create`
   and so runs a **live patrol sweeper**, while every other live spec overrides
   `PATROL_SWEEP_SCHEDULER` with the WP-22 no-op seam. Hosted CI is green, so it
   is not a blocker. It belongs to a dedicated test-infrastructure work package.

   **The constraint on WP-25 is explicit: add no uncontrolled background
   scheduler, and do not increase cross-suite state coupling.** Any new live
   spec that boots the app overrides the sweeper seam. If this contention ever
   fails hosted CI, or could mask a gateway security assertion, it stops being
   debt and becomes a blocker immediately — it is never something to retry away.

---

## D25-09 — Proof discipline

```text
Proof A     must remain green
Proof C     UNCLAIMED
Proof D     UNCLAIMED
```

The Crucible must make its own limits legible: every "device" in WP-25's tests
is a key the test process generated, and the specs say so, exactly as WP-24's
do.

---

## Open questions for the gate

These are design decisions I will not make unilaterally, because each changes
the shape of the work:

1. **Transport surface.** REST-only for WP-25, with realtime device ingress
   deferred to WP-26 when there is a real client to speak it? My recommendation
   is yes: a socket path with no client to exercise it is an untested
   authenticated surface, and D25-01's per-message proof rule is easier to prove
   against a request/response boundary first.
2. **Context storage.** Persist minted contexts, or keep them stateless and
   verifiable? Persisting gives immediate server-side invalidation and an audit
   trail; stateless keeps the context genuinely worthless without a proof.
   Given that the registry is re-read on every request anyway, my
   recommendation is to persist — the audit trail is worth more than the saved
   row, and revocation-during-session becomes observable rather than inferred.
3. **Which existing domain surfaces gain a device-authenticated variant first.**
   My recommendation is the narrowest useful set — Field state, assignment
   acknowledgement and the §76 acknowledgement — rather than a broad
   re-plumbing, so the boundary is proven before it is spread.
4. **Whether the gateway is a new module or an ingress layer** consumed by
   existing controllers. My recommendation is a distinct module owning the
   pipeline, with existing modules unchanged, so D25-02's ordering has exactly
   one implementation.

---

# Gate addendum - CTO rulings, 2026-09-02

The four open questions are ruled. These are locked; they are not re-litigated
during implementation.

## D25-10 - Locked scope

| Question | Ruling |
|---|---|
| Transport | **REST only.** Device-originated REST ingress. No device WebSocket authentication path in WP-25. Existing server-to-client realtime is untouched. |
| Context storage | **Persist.** Both the establishment challenge and the issued context, as server state - never credentials. |
| Initial surfaces | **Exactly three**, below. |
| Module boundary | **A dedicated module**, `services/core-api/src/modules/device-gateway/`. |

WP-26/27 may later add device realtime ingress. When they do the rule is
unchanged: **socket authenticated is not message authorized**, and every
effect-causing device message carries its own fresh signed proof.

### The three initial operations, exactly

```text
A. Field state update
B. Assignment acknowledgement - ACCEPT and DECLINE ONLY
   NOT start, complete, cancel or reassign
C. Incident Field Message acknowledgement - DELIVERED -> ACKNOWLEDGED
```

B reuses the Field domain's existing `accept` and `decline` semantics rather
than inventing a generic acknowledgement. C adapts
`FieldMessagingService.acknowledge()` - which already permits only the named
recipient to acknowledge their own delivery row, and already preserves the
delivery-state and idempotency behaviour. **A second Delivery implementation is
not created.**

All three map to the frozen `purpose = FIELD_OPERATION`. **No new
`DeviceRequestPurpose` value is added** merely because there are three route
types; their semantic distinction lives in the canonical payload digest.

The module owns context establishment, proof parsing, registry and key
resolution, cryptographic verification, current-principal assembly, replay
orchestration, the domain adapters, gateway audit and the REST controller. It
does **not** own Field, Delivery, Shield, Whisper or Identity, and device-proof
verification is not scattered into their controllers. Existing human controller
behaviour is unchanged.

## D25-11 - The canonical typed operation envelope

A device must not sign `SHA256(whatever JSON arrived)`. The gateway owns a
canonical typed envelope and hashes the **parsed semantic object**:

```text
schema_version . operation_kind
organisation_id . site_id . actor_user_id . device_id
target_type . target_id
semantic_payload
```

```text
FIELD_STATE_UPDATE . ASSIGNMENT_ACCEPT . ASSIGNMENT_DECLINE
INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE
```

**The route chooses `operation_kind` and `purpose`. Neither is caller-controlled
security input.** This is what stops a valid proof for an assignment accept
being carried to a field-state update because the two bodies happened to
serialise similarly.

## D25-12 - Timing constants

The frozen values are used exactly, and WP-25 introduces no second freshness
opinion:

```text
DEVICE_CONTEXT_MAX_LIFETIME_MS           = 300_000
DEVICE_REQUEST_PROOF_MAX_AGE_MS          =  60_000     (sixty seconds, not 120)
DEVICE_REQUEST_PROOF_MAX_FUTURE_SKEW_MS  =   5_000
```

One new WP-25 ceiling is approved, with its own name and its own tests, and it
does **not** alter the frozen 60-second request-proof freshness:

```text
DEVICE_CONTEXT_ESTABLISHMENT_MAX_AGE_MS  = 120_000
```

Expiry is evaluated at request time. **No expiry scheduler** - which also
satisfies D25-08's constraint against new background schedulers.

## D25-13 - The refusal boundary is not an enumeration oracle

Externally indistinguishable, internally precise:

```text
foreign-tenant device      nonexistent device
foreign context            nonexistent context
device not usable by this actor / site
```

all shape the same external refusal. The precise security reason and the trace
id are appended to the internal audit. No raw signature, private key,
authentication credential or bearer-like secret enters an audit payload. The
`context_id` itself is safe to expose, precisely because it authorises nothing.

## D25-14 - Migration budget

```text
WP-24 canonical total   21
WP-25                   +1
candidate total         22
```

The frozen WP-24 migration is not touched.

## D25-15 - The two mid-pass STOP conditions

Everything else is an ordinary implementation finding, accumulated and fixed
inside the one pass. Only these two come back before improvisation:

```text
A. the frozen DeviceRequestProof cannot safely perform the D25-03A
   pre-context establishment ceremony;

B. an approved initial domain surface has no safe transaction-aware seam,
   and using it would require duplicating or reinterpreting that domain's
   security logic.
```
