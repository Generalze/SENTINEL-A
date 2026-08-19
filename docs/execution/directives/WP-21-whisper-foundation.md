# Directive WP-21 - Whisper Foundation Gate

**Issued by:** Lead (/root) - **Lane:** Core with adversarial review - **Wave:** 10
**Depends:** WP-15 Field Contracts, WP-16 Field Domain, WP-18 Incident Field Messaging, WP-20 Offline Operation Contracts
**Review chain:** Adversarial review -> Lead merge gate
**Accepted base:** `3b1d7fe` (WP-20 closure boundary)
**Status:** **WP-21A — Contract + Authority Lock** delivered. Whisper
persistence, `roles.ts`, services, controllers and SILENT integration code are
**HOLD** pending the lead's WP-21A review.

## Objective

Lock the security model, contracts, lifecycle, device-authentication seam,
anti-replay semantics and the exact SILENT-response integration boundary
**before** any Whisper persistence or executable runtime is written.

Whisper is an organisation-configured discreet signalling capability, not a
universal secret-command system. The one sentence that governs the whole work
package:

> **Recognition INITIATES the approved silent response protocol. It never
> constitutes either of the human approvals, never carries an executable
> command, and never becomes a hidden command channel.**

Current `main` holds the initial Whisper contracts and **no** Whisper service,
Prisma model, migration, module or controller. WP-21A therefore extends the
existing contract rather than inventing a second Whisper model.

## Locked rulings

### W21-01 — DEVICE_ACTION only

Milestone 2 admits exactly one modality: deterministic device actions. No
phrase, voice, gesture, camera, biometric, wearable or general AI recognition
enters this package. The architecture prescribes proving one safe device-action
modality first; the contract enforces it with `modality: z.literal('DEVICE_ACTION')`,
so no other modality can even parse.

### W21-02 — Signal family/version semantics

`whisper_signal_id + signal_version` identifies the exact configuration.
Configuration is editable **only while DRAFT**. The moment a version enters
SIMULATION it begins accumulating evidence — false-positive results, anti-spoof
results, a field drill, an approval — and editing underneath that evidence
would leave an approval attesting to a signal that no longer exists. That is
how a "tested and safe" label ends up on something nobody tested.

Six fields are semantic: `modality`, `device_action_id`, `authorised_user_ids`,
`context_requirements`, `minimum_confidence`, `response_protocol_id`. `name`
and `trace_id` are deliberately excluded (a rename changes no authority);
`status` is excluded because advancing the lifecycle **is** the audited
transition, not a configuration edit.

A semantic change creates a **new version**; the former active version is
rotated or retired. `classifyWhisperConfigurationEdit` returns `EDITABLE` /
`UNCHANGED` / `REQUIRES_NEW_VERSION`, and the fingerprint treats the authorised
roster as a set and object key order as insignificant, so a re-serialised
requirement is not mistaken for an edit.

### W21-03 — Exact lifecycle, no shortcuts

```text
DRAFT -> SIMULATION -> FALSE_POSITIVE_TEST -> ANTI_SPOOF_TEST
      -> FIELD_DRILL -> APPROVAL -> ACTIVE -> ROTATED | RETIRED
```

No DRAFT→ACTIVE administrative shortcut, no reactivation of ROTATED/RETIRED, no
in-place mutation of an active definition. The contract test enumerates the
full status × status matrix and asserts that exactly the eight canonical edges
are permitted.

### W21-04 — Configuration eligibility is not runtime authority

`authorised_user_ids` is an allowlist, **not** a standing grant. Invocation must
additionally satisfy: the current authenticated actor, organisation/site scope,
current role/capability, live device trust and server-owned context. Removing
someone's current authority must stop them even while an older active version
still lists their id — `evaluateWhisperRuntimeEligibility` therefore takes
`actorHoldsCurrentAuthority` as a separate, freshly computed input and refuses
when either half is missing.

### W21-05 — Trusted device-identity seam

No public Whisper-result HTTP endpoint exists in WP-21A, and none may be added
in the first runtime implementation unless a genuine authenticated-device
facility exists. The eventual service accepts a **server-supplied trusted
context**, exactly as WP-20/C10-02 requires:

```ts
interface AuthenticatedWhisperDeviceContext {
  organisationId; actorUserId; deviceId;
  authorisedSiteIds; deviceTrust; verificationKeyId;
}
```

`deviceTrust` lives in the context, never read from the submitted result — a
compromised device would otherwise assert its own trustworthiness.
`verificationKeyId` names the registry key the signature is checked against, so
verification never uses a key travelling with the claim it authenticates.

**Only `TRUSTED` may invoke.** A silent duress dispatch raised from a device the
platform has already flagged SUSPICIOUS, QUARANTINED or COMPROMISED is precisely
the attack this modality invites; DEGRADED and OFFLINE cannot support the
signature and freshness guarantees the protocol depends on. A blocked
invocation leaves every ordinary alarm path available.

The production device registry belongs to the later Shield/Edge identity
architecture. WP-21 must not fake one merely to expose a route.

### W21-06 — The canonical signed statement

`device_action_id` is added to the result and bound into the signed statement.
Without it, a signature proves only that *some* action occurred on a trusted
device for some version — so a captured signature could be re-presented for a
different configured action of the same family.

```text
canonical JSON object, keys sorted, over:
  domain = sentinel.whisper.device-action.v1
  schema_version, organisation_id, site_id, actor_user_id, device_id,
  whisper_signal_id, whisper_signal_version, device_action_id,
  recognised_at, confidence, anti_replay_nonce
```

See C11-01 below: the statement is domain-tagged **canonical JSON**, not a
delimiter-joined string. The domain tag prevents a signature minted for another
Sentinel purpose being replayed here. **Absent by design:**
`response_protocol_id` (the server resolves it — a device that could sign the
protocol could choose its own consequence), `freshness_ms` and `context`
(telemetry), and `device_trust` (the platform's judgement). `confidence` IS
signed — see C11-04.

### W21-07 — Client confidence and context cannot authorize

`confidence`, `freshness_ms` and client-reported context are evidence, never
authority. Server authority comes from signature verification, authenticated
device identity, authoritative receipt time, current device trust and
server-owned context. Every declared context requirement is matched against a
**server-established fact**; `on_duty` must be derived from authoritative Field
state, and a fact the server cannot establish (absent or null) **fails closed** —
unknown is not permission, and a silent dispatch is not granted on a guess.

### W21-08 — Authoritative freshness

Named, reviewable bounds rather than magic constants:

```text
MAX_WHISPER_RECOGNITION_AGE_MS          = 120_000   (2 minutes)
MAX_WHISPER_RECOGNITION_FUTURE_SKEW_MS  =   5_000   (5 seconds)
```

Age is measured against the **authoritative receipt time**. Two minutes is
deliberately short: a dispatch raised from a recognition captured long ago is
more likely a replayed or delayed artefact than a live emergency, and the
operative can always signal again. Five seconds of future skew tolerates
ordinary clock drift while refusing a device that claims to signal from the
future to extend its own window. The submitted `freshness_ms` plays no part.

### W21-09 — Anti-replay is persistence-backed

The replay identity binds tenant, site, **actor**, device, signal and version
plus the nonce, and is exposed as a STRUCTURE
(`deviceActionWhisperReplayIdentity`) because WP-21B must key its uniqueness on
a real composite constraint over those seven columns — never on a concatenated
string or a hash (C11-01). The actor belongs in the key because two people may be
authorised on one version and may share a device between shifts. The same
canonical signed statement must converge to the stored result; a reused replay
identity whose statement differs is a **generic conflict** that invokes no
second protocol. `whisperRecognitionFingerprint` is the digest a receipt stores.

### W21-10 — Signal and response protocol remain separate

A signal carries no executable content — no Constitution action name, no
controller route, no severity override, no protocol steps. It carries a
reference resolved through a **server-owned allowlist**, encoded as an enum so a
signal author cannot invent a protocol and an approved signal cannot later be
pointed at something never reviewed. Milestone 2 needs exactly one:
`SILENT_INCIDENT_RESPONSE`.

### W21-11 — Whisper enters, never replaces, the existing SILENT path

No Whisper-specific approval engine, dispatch engine or two-person approval
implementation is permitted. The runtime terminates conceptually as:

```text
authenticated DEVICE_ACTION evidence
  -> exact ACTIVE signal version
  -> runtime eligibility + context + trust + freshness
  -> anti-replay receipt
  -> server-owned response_protocol_id resolution
  -> SILENT incident/response entry point
  -> EXISTING Constitution evaluation
  -> EXISTING distinct site-commander approvals
  -> EXISTING SILENT dispatch
  -> EXISTING Field acknowledgement
```

### W21-12 — Explicit authority vocabulary (proposed, not yet wired)

```text
                       signal.read   signal.manage   signal.approve   invoke
site.commander              Y             Y               Y             -
dispatcher                  -             -               -             -
operator                    -             -               -             -
field.operative             -             -               -          OWN ONLY
investigator                -             -               -             -
evidence.custodian          -             -               -             -
admin                       -             -               -             -
```

Four separate capabilities: `whisper.signal.read`, `whisper.signal.manage`,
`whisper.signal.approve`, `whisper.device-action.invoke`. `admin` holds nothing
operational — platform administration is not authority over a silent duress
channel — consistent with the existing explicit-capability model where patrol,
messaging and SILENT approval are never consequences of `incident.view`.
`OWN ONLY` means every runtime entitlement check still applies on top (W21-04).

The matrix is published in the contract as `PROPOSED_WHISPER_ROLE_ACTIONS` so
the eventual `roles.ts` change is a mechanical, reviewable transcription rather
than a fresh judgement. **`roles.ts` is untouched in WP-21A.**

Activation additionally requires an authenticated person **distinct from the
version's creator**: a creator approving their own signal would make the entire
test-and-approve lifecycle self-attesting, letting one compromised account mint
an active silent-dispatch trigger end to end.

### W21-13 — Activation approval is not SILENT-response approval

Two different authorities. Activation attests that a tested, organisation-
defined action is safe to *recognise*. When that active signal later fires, the
existing SILENT response still requires its own Constitution-governed
approvals. `WhisperActivationApprovalSchema` is `.strict()` and carries no
incident, task or dispatch reference, so no code path can replay one as the
other; it binds `configuration_fingerprint`, so an approval cannot survive a
configuration it never saw.

### W21-14 — Audit without secret leakage

`WhisperAuditPayloadSchema` is a strict allowlist. Lifecycle transitions,
activation approval, recognition outcome, replay/conflict, protocol identity and
the incident linkage are all recordable; the discreet action definition,
signature material, public keys, the authorised-user roster, the nonce and the
context values have **no field at all**, so a future edit cannot quietly widen
an audit row into a disclosure of the secret the modality depends on.

## C11 correction batch (applied at the WP-21A audit)

The lead's contract-lock audit accepted the direction of W21-01..W21-14 and
returned four corrections, all applied here:

**C11-01 — Canonical serialization was ambiguous.** Both the signed statement
and the replay key joined raw caller-supplied values with a delimiter, so two
different tuples could produce identical bytes: organisation `"a:b"` with site
`"c"` collided with organisation `"a"` with site `"b:c"`. For a signature that
means one verification covering two identities; for the replay key it means one
tenant consuming another's nonce slot. Both now use domain-tagged **canonical
JSON**, which escapes separators inside values and names every field. The
replay identity is additionally exposed as a structure so persistence keys on a
real composite constraint.

**C11-02 — The runtime gate could not prove tenancy.** It received only claimed
site/version/action. It now takes the SIGNED result identity and the STORED
signal's own scope, and binds — before anything is revealed or invoked —
`result.organisation_id/actor_user_id/device_id` against the trusted context,
`result.site_id` against the device's authorised sites, and the signal's
organisation against the same trusted organisation. A signal with
`site_id: null` is **explicitly organisation-wide**, and that is not a bypass:
the device must still be entitled to the site it fires at. Mismatches fail
closed; the service layer must collapse these codes so they cannot become an
existence oracle.

**C11-03 — Fingerprints could be lossy.** `context_requirements` accepted
arbitrary `unknown`, and `JSON.stringify` drops `undefined` members and renders
`NaN`/`Infinity` as `null` — so materially different requirement objects could
collapse onto one digest that an activation approval then attested to. Context
values are now a recursive **JSON-safe** union (string, finite number, boolean,
null, array, object) at every depth, and the canonicaliser **throws** on
anything it cannot represent rather than normalising it.

**C11-04 — Unsigned confidence affected authorization.** `confidence` was
excluded from the signed statement as telemetry, yet the gate compared it to
`minimum_confidence` — so an intercepted recognition whose confidence was raised
in flight could turn REFUSED into ELIGIBLE. Any field that can flip that
decision is security-relevant whatever it is called. `confidence` is now part
of the signed evidence; it still never authorises on its own and can only
reduce what is permitted. `signature_algorithm` is pinned to **Ed25519** so a
client-named algorithm can never select the verifier; the server's key registry
remains the algorithm authority.

## WP-21A deliverables (this checkpoint)

- `packages/contracts/src/whisper.ts` — extended: JSON-safe context values and
  a refusing canonicaliser; response-protocol registry;
  `device_action_id` on the result; actor-bound replay key; configuration
  freeze/fingerprint helpers; terminal-status helper; the authenticated device
  context and trust gate; the canonical signed statement and recognition
  fingerprint; named freshness bounds and classifier; server-fact context
  evaluation; the ordered runtime-eligibility gate and its conflict vocabulary;
  the proposed authority matrix; activation approval; audit allowlist.
- `packages/contracts/src/whisper.test.ts` — the Crucible pinning every ruling
  above.
- This directive and the roadmap update.

**Untouched, as required:** Prisma schema and migrations, any core-api Whisper
module, controllers/HTTP, services/repositories, `identity/roles.ts`,
Constitution implementation, incident-response implementation, simulator/WP-22,
and every native/mobile/Edge or recognition-AI concern.

## WP-21B — HOLD until the lead passes WP-21A

Expected scope when authorized: minimal Whisper Studio persistence, lifecycle
and audit persistence, signed device-action verification with persistence-backed
anti-replay, and the narrow adapter into the existing SILENT Incident and
Constitution machinery. A public device-facing endpoint remains out of scope
until a genuine server-authenticated device identity can populate
`AuthenticatedWhisperDeviceContext`.

## Gate state

```text
WP-20 implementation              FROZEN
Wave 9                            CLOSED

WP-21A directive/contracts        DELIVERED — awaiting lead review
WP-21 Prisma                      HOLD
WP-21 roles.ts                    HOLD
WP-21 services/controllers        HOLD
WP-21 SILENT integration code     HOLD
WP-22                             HOLD
```
