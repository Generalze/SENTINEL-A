# WP-25 — Authenticated Device Gateway

**Status:** DIRECTIVE / DESIGN GO. **Implementation HOLD** pending the gate on
this document.
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

## D25-02 — The ingress pipeline, in a fixed order

Every device-authenticated request runs exactly this, and the order is the
argument:

```text
 1. parse the DeviceRequestProof            contract boundary; a malformed or
                                            high-S signature cannot exist in a
                                            parsed proof at all (C15-01)
 2. resolve the registry record             SERVER-owned, by key_id + key_version,
                                            within the organisation
 3. bind the claimed profile                bindClaimedSignatureProfile; the client
                                            never selects its verifier
 4. import the registered key               WP-24's P-256 importer, OpenSSL
 5. verify the signature                    over the canonical statement, with
                                            the SERVER's profile
 6. build DeviceRegistryFacts               current trust, revocation, key state,
                                            AND the current actor's authority
 7. evaluateDeviceRequestProof              the frozen evaluator, unmodified
 8. evaluateDeviceOperationPrincipals       both principals, independently
 9. consume the replay identity             durable, transactional, WP-24's seam
10. execute                                 the domain, unchanged
```

Two properties this ordering exists to hold. **The key is never taken from the
request** — step 2 resolves it from the registry, and there is no parameter
through which a caller could supply one. And **possession is checked before any
domain effect**, never alongside it.

Steps 7 and 8 are separate on purpose. Step 7 asks *is this proof good for this
context?*; step 8 asks *are both principals present and sufficient?* Collapsing
them would let a strong device proof paper over a missing session.

---

## D25-03 — Establishing a context is itself device-authenticated

A context is minted only by a request that already proved possession. The
bootstrap problem is real and is solved without an exemption:

```text
device holds a registered key
   -> device signs a context REQUEST with that key
   -> server verifies against the REGISTRY record
   -> user session presented alongside, independently authenticated
   -> server mints AuthenticatedDeviceContext, bounded by
      DEVICE_CONTEXT_MAX_LIFETIME_MS (300 s, frozen)
```

The server owns every field of the minted context. `device_trust` is copied
from the registry at issuance and is **never** authority at use — D23-07 and
C15-04 already require the registry to be re-read on every request, and WP-24's
effective-standing helper is what answers it, so an attestation that aged out
mid-context degrades the answer immediately.

A context is bound to one `key_id + key_version`. A rotation invalidates every
context issued against the superseded version, which `evaluateDeviceRequestProof`
already enforces as `KEY_VERSION_ROTATED`.

---

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
