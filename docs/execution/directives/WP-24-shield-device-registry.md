# WP-24 — Shield Device Registry

**Status:** IMPLEMENTATION GO (CTO directive).
**Base:** `ded82d596f4198088d9f717f53aab1d3f03c3466` (WP-23 merge commit).
**Branch:** `wp-24-shield-device-registry`.
**Execution repository:** `Generalze/SENTINEL-A`. The original repository
`masterzee001/SENTINEL-A` remains frozen at `bd6076e` and is untouched.

---

## 0. What this work package is

WP-23 froze the device-security contracts and deliberately shipped **no**
registry, gateway, endpoint, persistence or cryptographic runtime. WP-24 is the
crossing point: it turns those contracts into **authoritative persistent server
state**.

The governing question:

```text
What device is this?
Which organisation and sites own / authorise it?
Which public key and version is authoritative?
What is its current server-owned trust?
Has the device or credential been lost, stolen, rotated,
revoked, quarantined or compromised?
```

The governing invariant, unchanged from §62.1 and carried through every M3 work
package:

```text
USER AUTHORITY
       +
DEVICE IDENTITY
       +
CURRENT DEVICE TRUST
       +
SITE / CONTEXT AUTHORITY
       +
POLICY WHERE REQUIRED

must remain INDEPENDENT facts.
```

A user login never manufactures trusted hardware. A registered device never
manufactures user authority. Neither is permitted to stand in for the other at
any point in this module.

---

## D24-01 — The WP-23 contracts are authoritative and are not reinterpreted

Every device concept this module persists already exists as a frozen contract in
`packages/contracts/src/device-*.ts`. The runtime **imports** them; it does not
restate, widen or re-derive them.

Reused without modification:

```text
DeviceRegistryKeyRecord          DeviceIdentity
DeviceCustody                    DeviceKeyStorage
DeviceKeyLifecycleState          DeviceRevocationDisposition
DeviceTrust                      DeviceNonceConsumption
DeviceAttestation*               deviceEnrollmentRequestFingerprint
DevicePossessionChallenge        DevicePossessionVerificationResult
deviceSequenceNamespaceId        deviceCanonicalDigest / canonicalDeviceJson
bindClaimedSignatureProfile      the WP-23 timing ceilings
```

**The four-state key lifecycle is not collapsed into a boolean.** `CURRENT`,
`ROTATED`, `REVOKED` and `COMPROMISED` are persisted as four states, because
they answer two different questions — *may this key authorise new work?* and
*may this key still verify what it legitimately signed?* — and a boolean
`revoked` can answer only one of them. Routine rotation and compromise are not
the same event and must never be stored as though they were.

The registry persists the **actual canonical public key**, its key id and
version, the server-selected signature profile, the storage class and the
lifecycle state. A thumbprint alone cannot verify a signature, and a registry
that cannot verify is not a registry.

---

## D24-02 — Device-security authority is explicit, never inherited

New action vocabulary, added to the §62 registry in
`services/core-api/src/modules/identity/roles.ts`:

```text
device.registry.read         read the device roster and a device's standing
device.enrollment.issue      issue a bootstrap grant
device.enrollment.approve    approve one exact enrollment request
device.trust.manage          change a device's server-owned trust
device.key.rotate            authorise a key rotation
device.revoke                revoke / quarantine / declare compromised
```

Locked initial matrix:

```text
                            site.commander   operator   all others

device.registry.read              Y             Y            -
device.enrollment.issue           Y             -            -
device.enrollment.approve         Y             -            -
device.trust.manage               Y             -            -
device.key.rotate                 Y             -            -
device.revoke                     Y             -            -
```

(Revised per the CTO ruling in D24-02a below: the originally issued matrix
also listed a `field.supervisor` column, and that role is deliberately not
minted in this work package.)

Three rules ride with it, and each is enforced rather than documented:

- **`admin` receives no implicit device-security write authority.** Platform
  administration — `org.admin`, `site.admin`, `user.admin` — is not authority
  over hardware trust. This is the WP-18 `incident.field-message.oversight.read`
  and WP-21B Whisper reasoning applied again: an authority that can decide what
  hardware Sentinel trusts must be granted deliberately, never inherited as a
  side effect of holding something else.
- **A Field operative's participation is not device-management authority.**
  Being the intended or current user of a device grants nothing in this table.
- **An internal machine lookup is not a human action.** When WP-25's gateway
  later resolves a registry record to authenticate an incoming device, that is
  an internal service call, not a `device.registry.read` performed by a person,
  and it must not be modelled as one.

Every `Y` remains organisation- and site-scoped through the existing ABAC
boundary. The action table is RBAC only; site scope, clearance and purpose are
layered on top by the access guard exactly as they are for every other action.

### D24-02a — `field.supervisor` is NOT minted here (CTO ruling)

The directive's original matrix named a role that is not in the §62 `ROLES`
registry. I flagged it rather than inventing it, and the CTO has ruled:

> **Do not add a new application role just to satisfy this matrix.** The
> architecture conceptually includes Field Supervisor, but introducing a
> partially implemented supervisor role whose only capability is
> device-registry read would create a misleading role boundary.
> `field.supervisor` stays an architectural role awaiting deliberate
> activation across the broader authority model.

The matrix WP-24 implements is therefore:

```text
                            site.commander   operator   all others

device.registry.read              Y             Y            -
device.enrollment.issue           Y             -            -
device.enrollment.approve         Y             -            -
device.trust.manage               Y             -            -
device.key.rotate                 Y             -            -
device.revoke                     Y             -            -
```

A role that exists in half the authority model is worse than a role that does
not exist yet: it reads as though supervisors have been considered everywhere
when they have been considered in exactly one place. `ROLES` is unchanged.

---

## D24-03 — Enrollment requires a dual human/device binding

The ceremony is WP-23's, implemented exactly:

```text
authenticated commander
    -> bootstrap grant
    -> physical device generates a hardware-backed key
    -> enrollment request (public key + attestation evidence)
    -> exact request fingerprint
    -> INDEPENDENT commander approval of THAT fingerprint
    -> intended user authenticates
    -> fresh server challenge
    -> device proves possession of the APPROVED key
    -> server verifies cryptographically
    -> one transaction commits the device identity
```

Two separations are enforced at commit, not merely at the API surface:

```text
bootstrap issuer  !=  request approver
request approver  !=  intended user
```

There is no self-approval path. **A bootstrap grant creates zero device
authority**: it is provenance for a ceremony, never a credential, and on its own
it can enrol nothing. This is C14-02's ruling — proof of possession proves
possession of *the key being enrolled*, and says nothing about whether that is
the hardware the issuer intended, which is why a human must approve the exact
request fingerprint.

### D24-03a — Bootstrap token storage

The grant *record* has no token field (D23-14). The secret exists only in
transit, and the persistence rule is the one used for any bearer secret:

```text
>= 256 bits of cryptographically random entropy
returned ONCE to the authorised issuing caller
persisted ONLY as a cryptographic digest
never persisted raw, never logged, never in an audit payload
```

The grant is single-use, revocable, bounded by the WP-23 lifetime ceiling, and
bound to organisation, site, intended user and issuer. A second use is a
conflict and a refusal — never a second device. Presenting a grant in an
unexpected organisation, site or user context **burns the grant** and raises a
security event: a probe is not a typo, and a grant that survives being probed is
a grant an attacker may keep trying.

---

## D24-04 — Persistence, and tenant integrity below the service layer

A dedicated `shield.prisma` schema file. Device security is not folded into
Whisper or Field, because the module that answers *what hardware do we trust*
must be reviewable on its own.

Persistent concepts:

```text
Device                      DeviceSiteScope             DeviceKey
EnrollmentBootstrapGrant    EnrollmentRequest           EnrollmentApproval
PossessionChallenge         PossessionVerification
DeviceNonceConsumption
DeviceAttestationObservation  DeviceTrustTransition     DeviceSecurityEvent
```

The `Device` record persists at minimum: server-generated device id,
organisation, custody mode, enrollment provenance, the **derived**
`sequence_namespace_id`, current trust, security/revocation disposition,
`revoked_at` where applicable, current key identity and version, the enrollment
request identity, and creation/enrolment timestamps.

`sequence_namespace_id` is recomputed by the server from
`deviceSequenceNamespaceId` and is never caller-selected. Site scope is
authoritative **server** persistence, not a list a client sends.

For `PERSONAL` custody the assigned custodian is persisted. For
`CONTROLLED_SHARED` the authorised site scope is persisted **without** converting
whoever is currently authenticated into permanent hardware identity — C14-02's
"custody is not identity".

### D24-04a — Composite tenant-aware referential integrity

Service checks are not the only defence. `Site` already carries the
`(id, organisation_id)` candidate key for exactly this purpose (WP-17A), so
device/site relationships use composite references and the database itself
rejects a row pairing one tenant's organisation with another tenant's site.

For `User` relationships the same protection requires a
`(id, organisation_id)` candidate key on `User`. That key is added — and
nothing else about Identity changes. It introduces no column, alters no
existing constraint and changes no behaviour; it exists so the device tables can
reference the pair.

The migration must reject, at the database level:

```text
org-A device      + org-B site
org-A enrollment  + org-B intended user
org-A approval    + org-B device / request
cross-tenant key attachment
```

Nothing in this schema cascades from a Site or a User into security history.
Live-state rows use `onDelete: Restrict`; historical artefacts (security events,
trust transitions, attestation observations, consumption rows) carry no
lifecycle FK at all, per the WP-17A live-state / historical-artefact doctrine —
a site's lifecycle must never erase the record of what Sentinel decided about a
piece of hardware (§61).

---

## D24-05 — The cryptographic runtime boundary

WP-23 performed canonical **structural** key validation and explicitly deferred
curve and import validation to runtime. WP-24 is that runtime, and this is where
the deferral is paid off.

```text
contract parse
    -> server profile resolution
    -> runtime crypto-provider P-256 import
    -> curve / key validation succeeds
    -> ONLY THEN may the key be registered as CURRENT
```

Import uses the platform crypto provider (Node / OpenSSL). **No custom elliptic
curve arithmetic is implemented anywhere in this work package.** A structurally
perfect but off-curve P-256 point parses at the contract boundary — that is the
documented limit of a contracts package — and must be refused here, by the
provider, before it can become an active verification credential.

The verification profile is always read from the server registry record.
`claimed_*` fields remain claims and never select a verifier (C11-04 / C15-01).

---

## D24-06 — The enrollment commit is one transaction

Every authority-bearing row is re-read and locked inside the transaction, and
re-validated at commit rather than trusted from an earlier read:

```text
bootstrap consumption identity      approval identity
exact request fingerprint           issuer != approver
approver != intended user           organisation and site
intended user exists in tenant      request chronology
challenge chronology                possession-verification binding
public-key import validity          attestation standing
key storage class                   nonce consumption
no previous enrollment commit for this request
```

Then, atomically: the device, its initial key, the site/custody association, the
initial trust, and the audit and security events.

```text
exact retry of a committed request      -> converges on the SAME device identity
same replay identity, changed semantics -> conflict, and NO second device
```

---

## D24-07 — Attestation is a server-owned seam, not a vendor integration

No Play Integrity, App Attest or DeviceCheck integration in this work package.
What is built is the **internal server-owned evaluation seam** WP-25/WP-26 will
later feed, plus append-only observation persistence.

C14-05's split is preserved exactly:

```text
VERIFIED                     positive evidence
NEGATIVE / INVALID / REVOKED device evidence; may lower trust or quarantine
UNAVAILABLE                  NOT negative evidence
```

A provider outage is not a statement about a device. A device that has **never**
been verified cannot become TRUSTED during unavailability; a device with
existing verified evidence may rely on it only within the WP-23 bounded grace.
The frozen timing constants are not changed.

---

## D24-08 — Initial trust and trust transitions

Initial trust comes from the WP-23 helper (`initialDeviceTrustOnEnrollment`),
not from policy restated in a service:

```text
HARDWARE_BACKED + qualifying current verified evidence   -> may be TRUSTED
SOFTWARE key                                             -> never TRUSTED
new identity with no qualifying current evidence         -> never TRUSTED
```

**No request DTO may submit the registry's trust conclusion.** Trust is
concluded by the server from server-owned evidence; a field a client could set
would make the whole model decorative.

The registry is authoritative and device-submitted telemetry is evidence only.
The six-state vocabulary is unchanged: `TRUSTED`, `DEGRADED`, `SUSPICIOUS`,
`QUARANTINED`, `COMPROMISED`, `OFFLINE`.

Every trust change writes an append-only transition record carrying
organisation, device, previous trust, new trust, reason, server evidence
reference(s), the authorised human where one is involved, timestamp and
`trace_id`.

```text
COMPROMISED is TERMINAL for that device identity.
A device can never promote itself.
Recovery from QUARANTINED requires an explicit authorised server
decision AND qualifying current evidence.
```

---

## D24-09 — Lost, stolen and compromised are three different facts

```text
LOST             quarantine / suspend. A controlled restoration path remains
                 available if hardware credential continuity still exists and
                 current evidence qualifies.

STOLEN           assume hostile possession. Revoke the device credential. No
                 unapplied queued work from it may later create a new effect.

COMPROMISED_KEY  the key is COMPROMISED and the device identity is
                 COMPROMISED. Terminal. Recovery is a NEW enrolled identity —
                 never rehabilitation of the compromised credential.
```

Device-level and key-level revocation are **independent checks**. No caller may
assume both rows moved together; either one saying the credential is gone is
sufficient on its own. This is C15-R4-final's rule, applied to the device side
of the same problem.

---

## D24-10 — Key rotation preserves identity; it never resets it

Routine authenticated rotation:

```text
preserves device_id                 preserves sequence_namespace_id
old key CURRENT -> ROTATED          new key becomes CURRENT
increments key version              invalidates contexts bound to the old version
```

It must never reset a sequence, resurrect an older key, return a `ROTATED` key
to `CURRENT`, reuse a key version, or change device identity.

Rotation must prove **continuity** with the currently registered credential and
**possession** of the new key. A wipe, re-provision or irrecoverable credential
loss is **re-enrollment**, not rotation — D23-09 already rules that a
re-enrollment produces a new identity with a fresh sequence namespace.

If the frozen contracts do not carry enough to express a safe rotation proof
without inventing a new signed statement, implementation **stops and reports the
exact missing contract** rather than improvising one.


### D24-10A — The key-rotation possession contract (CTO ruling, prerequisite)

D24-10's stop condition fired. WP-23 could express rotation CONTINUITY — a
`DeviceRequestProof` with `purpose: 'DEVICE_KEY_ROTATION'` signed by the
current key — but had no way at all to express POSSESSION OF THE NEW KEY. The
only possession statement in the frozen contracts is enrollment-scoped
(`sentinel.device.possession-challenge.v1`, binding `enrollment_request_id`
and `enrollment_request_fingerprint`), and repurposing it would have made a
rotation proof BYTE-IDENTICAL to an enrollment proof for the same ids —
collapsing the domain separation the domain tag exists for — while filing
rotation consumption under an enrollment replay identity.

**This is not a reopening of WP-23.** WP-23 remains closed at `ded82d596`.
This is a WP-24 PREREQUISITE contract extension, versioned forward because
WP-24 is the first runtime that needs a safe rotation ceremony. It lives in a
new file, adds two new domains, and changes nothing frozen.

```text
packages/contracts/src/device-key-rotation.ts
sentinel.device.key-rotation-possession.v1
sentinel.device.key-rotation.replay-identity.v1
```

#### Rotation is a two-key proof, and neither half substitutes for the other

```text
CURRENT REGISTERED KEY
    | DeviceRequestProof, purpose = DEVICE_KEY_ROTATION
    | payload_digest = the EXACT rotation-request fingerprint
    v
CONTINUITY OF THE OLD CREDENTIAL
    +  server validates and IMPORTS the new public key
    +  server issues a rotation challenge
    v
NEW KEY SIGNS sentinel.device.key-rotation-possession.v1
    v
POSSESSION OF THE NEW CREDENTIAL
    v
transaction re-reads current registry state
    v
old key CURRENT -> ROTATED     new key -> CURRENT
```

Binding the continuity proof's `payload_digest` to the exact rotation-request
fingerprint is what stops an otherwise valid current-key proof being borrowed
for a DIFFERENT replacement key.

#### The rotation request is an exact semantic object

Not "some payload". The canonical request binds `schema_version`,
`rotation_request_id`, `organisation_id`, `device_id`, `current_key_id`,
`current_key_version`, `proposed_key_id`, `proposed_key_version`,
`new_public_key`, `new_public_key_thumbprint`, `new_key_storage` and the
`server_resolved_signature_profile`. The thumbprint stays DERIVED from the
canonical public key, never independently trusted.

```text
proposed_key_version === current_key_version + 1
```

Exactly one, not merely "greater than". No skipped versions, and no client
choosing a version that shapes registry history — the server generates the
proposed key identity and version.

#### The new-key possession statement

Binds organisation, device, `rotation_request_id` and its fingerprint, the
current key id/version, the proposed key id/version, the new public-key
thumbprint, the rotation challenge id and nonce, and the SERVER-RESOLVED
signature profile. The new public key itself is not repeated inside the signed
bytes — the request fingerprint already commits to it — but the thumbprint
stays explicit as a readable cryptographic binding.

#### The rotation challenge and its own ceiling

`DeviceKeyRotationChallenge` is server-issued and binds the whole proposal, so
a challenge cannot be answered for a different rotation.

```text
DEVICE_KEY_ROTATION_CHALLENGE_MAX_AGE_MS = 120_000
```

Numerically equal to the enrollment possession ceiling today, and deliberately
its OWN constant with its OWN tests: rotation policy and enrollment policy must
not become silently coupled because they once happened to share a duration.
`expires_at` follows the existing exclusive-boundary doctrine.

#### The verification result, and no naked boolean

A server-owned `DeviceKeyRotationPossessionVerificationResult`, source
`SENTINEL_DEVICE_KEY_ROTATION_VERIFIER`, binding organisation, device, request
id and fingerprint, challenge id, current and proposed key identity, new
thumbprint, profile, the canonical statement fingerprint and `verified_at`. A
verdict from another rotation, challenge, device, proposed key or request
fingerprint is structurally unusable. **There is no
`newKeyPossessionVerified: true` anywhere in the runtime.**

#### Replay identity, kept distinct from the fingerprint

Its own one-shot identity under
`sentinel.device.key-rotation.replay-identity.v1`, binding organisation,
device, rotation request id, challenge id, current key id/version, proposed key
id/version and nonce. The WP-23 rule is unchanged: same identity + same
fingerprint converges and never rotates twice; same identity + changed
fingerprint conflicts and mutates nothing.

#### Import precedes possession

The new key passes structural parse, canonical public-key checks, server
profile resolution and Node/OpenSSL P-256 import **before** its signature can
establish possession. An off-curve key cannot acquire a valid rotation
verification result. No elliptic-curve arithmetic is added to contracts.

#### The commit transaction refuses a moved world

At commit the runtime re-reads and requires: the same device identity; the same
current key id, version and `CURRENT` status; the current key not
independently revoked; the device not independently revoked or compromised;
`proposed === current + 1`; exact request fingerprint, continuity proof,
possession verdict and unexpired challenge; an admissible replay fact; and a
runtime-valid new key whose thumbprint and server-selected profile match.

Then atomically: old key `CURRENT -> ROTATED` with `rotated_at` at
authoritative server time, new key `CURRENT`, and the device keeping its
`device_id` and `sequence_namespace_id` while its current key reference and
version advance.

If the current key moved while the ceremony was in progress the answer is
`STALE_ROTATION` — never a helpful rotation from whatever key happens to be
current now.

#### Migration consequence

The rotation request, challenge and replay persistence belong inside the SAME
single WP-24 migration. The chain target is unchanged: `20 -> 21`. This is
precisely why the stop happened before schema work rather than after.
---

## D24-11 — Anti-replay becomes persistent transactional state

The WP-23 seam is implemented as durable state with the same three outcomes:

```text
FIRST_SEEN                        proceed
EXACT_DUPLICATE                   converge on the stored outcome; NO second effect
REUSED_WITH_CHANGED_SEMANTICS     conflict; never a convergence
```

Both the **replay identity** and the **canonical statement fingerprint** are
stored. **The unique database key is the replay identity itself, never the
fingerprint** — the entire purpose of the row is to detect changed semantics
hiding behind a reused identity, and keying on the fingerprint would file two
different requests as two unrelated rows and detect nothing.

Bootstrap grant consumption and possession-challenge consumption use this same
table and doctrine.

---

## D24-12 — Append-only security audit with an allowlisted payload

An append-only security event stream covering, at minimum:

```text
BOOTSTRAP_ISSUED        BOOTSTRAP_REVOKED       BOOTSTRAP_CONSUMED
BOOTSTRAP_REPLAY_REFUSED
ENROLLMENT_REQUESTED    ENROLLMENT_APPROVED     ENROLLMENT_REFUSED
POSSESSION_VERIFIED     DEVICE_ENROLLED         TRUST_CHANGED
DEVICE_QUARANTINED      DEVICE_LOST             DEVICE_STOLEN
DEVICE_REVOKED          KEY_ROTATED             KEY_REVOKED
KEY_COMPROMISED         REPLAY_CONFLICT
```

Payloads are strict **allowlists**, not filtered free-form objects. Never
recorded:

```text
private key material            raw bootstrap token
raw possession secret/response  raw attestation vendor blob
signatures unless required      authentication / session credentials
```

Fingerprints, key ids, request ids and reason codes instead. Security events are
append-only: there is no application update or delete path, and a source guard
regression protects that property rather than trusting review to notice.

---

## D24-13 — There is still no public device boundary

This is the prohibition that keeps Proof C honest.

WP-24 exposes internal service methods for tests and for WP-25 to build on. It
adds **none** of:

```text
POST /devices/enroll        POST /device-context
POST /devices/authenticate  POST /device-actions
POST /whisper/device
```

There is still no production facility that authenticates an incoming physical
device request. **WP-25 is the work package that lifts this prohibition.**

Human Command-side HTTP management endpoints are also not required and are not
added: the controller surface is not enlarged merely to demonstrate the
registry. Integration tests drive the service with authenticated server
principal fixtures.

The Whisper device-key resolver seam (`WHISPER_DEVICE_KEY_RESOLVER`) is
deliberately **not** wired to this registry. It resolves Ed25519 under the
frozen v1 Whisper contract; the registry holds P-256 under the M3 profile, and
connecting a real physical-device Whisper path is WP-27's work, not a side
effect of building a registry.

---

## D24-14 — Migration gate

WP-24 adds **one** migration. The chain goes `20 -> 21`. More than one requires
an explanation before review. The migration applies from zero on hosted CI. No
historical migration is edited and no destructive reset instruction is used.

---

## D24-15 — Proof discipline

```text
Proof A     must remain green
Proof C     UNCLAIMED
Proof D     UNCLAIMED
```

A successful **server** enrollment test is not Proof C. There is still no
genuine physical-device gateway and no client, so nothing in this work package
can claim it. A P-256 test key that enrols successfully proves the registry
works; it proves nothing about hardware.

---

## Scope boundary

```text
MAY ADD                              MUST NOT ADD
Prisma models                        public device-facing HTTP endpoints
one migration                        authenticated device gateway
Shield/device-registry module        mobile application / Flutter
repositories, internal services      Whisper physical-device endpoint
crypto import/verification seam      real Whisper invocation
enrollment runtime                   Edge runtime
key lifecycle runtime                offline client queue
trust lifecycle runtime              WAN-loss implementation
revocation / quarantine runtime      production attestation vendor integration
persistent anti-replay               a Proof C claim
append-only security audit           a Proof D claim
unit + live integration + Crucible
```

```text
WP-25  owns the authenticated device gateway
WP-26  owns the Field mobile client
WP-27  owns physical-device Whisper
```
