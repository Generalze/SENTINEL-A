# Field Mobile — Android (WP-26)

The first Sentinel client whose private credential is generated and protected by
physical hardware rather than by a test process.

**This is not Proof C.** A real device that can enrol and operate is not a real
device invoking a real `DEVICE_ACTION` Whisper and being gated end to end. WP-26
makes Proof C possible (WP-28 claims it); it does not claim it, and nothing in
this directory should be reported as though it did.

---

## Why this directory has no `package.json`

`pnpm-workspace.yaml` globs `apps/*`. A `package.json` here would pull an
Android project into `pnpm -r typecheck`, `pnpm -r lint` and `pnpm -r test`,
none of which can say anything about it. D26-10's ruling is **Option B,
tightened**: in-repo, outside pnpm, with its own required workflow
(`.github/workflows/android.yml`).

The consequence, stated rather than discovered: **the workspace test count stops
being a complete measure of the system.** The gate reads two numbers.

---

## The three independent evidence classes

```text
SERVER CI                   migrations, lint, typecheck, all suites, Proof A
                            .github/workflows/ci.yml  — untouched by WP-26

ANDROID CI                  Android build, lint, Kotlin/JVM unit tests, at the
                            EXACT candidate SHA
                            .github/workflows/android.yml

PHYSICAL DEVICE ACCEPTANCE  genuine supported Android hardware; StrongBox
                            available; server-issued challenge; the key attests
                            as StrongBox; the private key is non-exportable; a
                            commander-approved enrollment; WP-25 context
                            establishment; at least one approved Field
                            operation signed by the physical key
```

**An emulator is not a hardware test.** It cannot establish that a private key
lived in a physical StrongBox, and this project has no instrumented tests at
all — not as an oversight, as a refusal.

---

## What is proven where

| Property | Proven by |
|---|---|
| DER → IEEE P1363 conversion, incl. 33-byte integers and short scalars | `CanonicalSignatureTest` (JVM) |
| Low-S canonicalisation, incl. `s == floor(n/2)` and `s == floor(n/2)+1` | `CanonicalSignatureTest` (JVM) |
| Canonical JSON byte-identical to `canonicalDeviceJson` | `CanonicalJsonTest` (JVM, fixtures from V8) |
| The four signed statements and their digests | `DeviceStatementsTest` (JVM, fixtures from V8) |
| Canonical SEC1 public key and computed thumbprint | `CanonicalPublicKeyTest` (JVM) |
| No private-key export path exists in the source | `NoPrivateKeyExportSourceTest` (source scan) |
| No public member exposes a key type | `StrongBoxKeyManagerSurfaceTest` (reflection) |
| StrongBox requested exactly once, never `false`, no TEE fallback | `NoPrivateKeyExportSourceTest` (source scan) |
| **The key really is in StrongBox** | **physical device acceptance only** |
| **The key really is non-exportable** | **physical device acceptance only** |
| **The attestation chain verifies against Google's real roots** | **physical device acceptance only** |
| **The ceremony works against a live core-api** | **physical device acceptance only** |

The bottom four cannot be established by any job in this repository. Nothing in
CI should be read as evidence for them.

---

## The ceremony this client drives (D26-04A)

```text
sign in (human session)
 -> POST attestation-challenge          presenting the bootstrap grant token
 -> GENERATE the StrongBox key WITH THAT EXACT CHALLENGE      <- must be after
 -> POST requests                       public key + certificate chain
 -> [an INDEPENDENT COMMANDER approves the exact request
     fingerprint, out of band, in Command web]
 -> POST possession-challenge
 -> sign the possession statement, POST possession
 -> POST commit                         -> a REGISTERED DEVICE
 -> WP-25 context establishment
 -> one Field operation, signed by the hardware key
```

The ordering is the security property. Android Key Attestation is produced
**when the key is generated**: `setAttestationChallenge()` places the relying
party's challenge inside the certificate precisely so the key can be shown to
have been created in response to a specific request. Generate first and submit
afterwards, and the server can be handed a certificate minted last year.

**There is no approve button and no code path to one.** Approval never crosses
the device boundary; if the phone could cause its own approval the ceremony
would be decorative.

---

## Layout

```text
src/main/kotlin/com/sentinel/field/
  security/   CanonicalJson          pure Kotlin, no Android imports
              CanonicalSignature     pure Kotlin, no Android imports
              CanonicalPublicKey     pure Kotlin, no Android imports
              DeviceStatements       pure Kotlin, no Android imports
              ClientNonce            pure Kotlin, no Android imports
              StrongBoxKeyManager    THE ONLY FILE THAT TOUCHES THE KEYSTORE
  net/        SentinelHttp           OkHttp transport, session header only
              EnrollmentCeremony     the five enrollment crossings, in order
              GatewaySession         WP-25 establishment + the three operations
              FieldReads             the four ordinary authenticated READ routes
              FieldViews             their response shapes, read out by name
  store/      KeyValueStore          the one way anything reaches disk
              ClientState            the six ids this app may remember
              ClientStateStore       the allowlist and the refusals, pure Kotlin
              EncryptedClientState   the Android half; policy-free adapter
  ui/         MainActivity           a few buttons and a log, deliberately
```

The split is the point: everything security-critical except the keystore calls
themselves is pure Kotlin, so the CI unit tests cover real logic rather than
covering nothing. `store/` follows the same rule — the RULES about what may be
persisted are pure Kotlin and JVM-tested; only the encrypted file itself needs a
device.

---

## The D26-06 surface

| Capability | Route | How |
|---|---|---|
| Current identity | `GET /api/v1/field/state/mine` | session |
| Assignments (read) | `GET /api/v1/field/assignments/mine` | session |
| Assignment accept / decline | `POST …/device-gateway/operations/assignments/{id}/{accept\|decline}` | hardware-signed |
| Field state | `POST …/device-gateway/operations/field-state` | hardware-signed |
| Messages (read) | `GET /api/v1/field-messages/incidents/{incidentId}/mine` | session |
| Message acknowledgement | `POST …/device-gateway/operations/messages/{id}/acknowledge` | hardware-signed |
| Patrol runs (read) | `GET /api/v1/patrol/runs` | session |

READS use the ordinary authenticated human routes and carry the session only —
reading produces no effect to attribute to a device, and WP-25 exposes no read
operation to invent one through. The three EFFECT operations, and only those,
go through the gateway with a fresh hardware signature over a fresh one-shot
nonce.

PATROL IS READ ONLY, and that is not an oversight: the gateway has no patrol
write. There is no start, no abandon and no checkpoint verification here.

ROLES ARE NOT DISPLAYED, because no route this client may call reports them —
the core API has no `/me`, and the user, site and organisation listings are
gated on admin actions a `field.operative` does not hold. The screen says so
rather than printing a role list it decided for itself.

THERE IS NO OFFLINE QUEUE. WP-29 owns queueing. A failed operation fails.

---

## Secure local storage, and the one secret on the screen

Client state — the enrolled device id, the last established context id and its
expiry, and the last identity the server reported — is held in
`EncryptedSharedPreferences` under a keystore-held master key. Six keys, on an
allowlist, and no method that takes a caller-chosen key. If the encrypted store
cannot be opened the app remembers nothing; it never falls back to plaintext.

THE BOOTSTRAP GRANT IS NEVER PERSISTED. It is masked in the input
(`textPassword`), excluded from view-state save/restore (`saveEnabled="false"`)
and from autofill, and cleared as soon as it has been presented for the last
time or the ceremony fails terminally.
`BootstrapTokenNeverPersistedSourceTest` fails the build if any of that stops
being true. The honest limit: a Kotlin String cannot be wiped, only
dereferenced, so what is established is that nothing holds a live reference and
nothing writes it anywhere.

---

## Pinned versions

| | |
|---|---|
| Gradle | 8.7 |
| Android Gradle Plugin | 8.3.2 |
| Kotlin | 1.9.24 |
| `compileSdk` / `targetSdk` | 34 |
| `minSdk` | 28 (StrongBox arrived in API 28) |
| JDK | 17 (temurin) |
| `androidx.core:core-ktx` | 1.13.1 |
| `androidx.appcompat:appcompat` | 1.6.1 |
| `androidx.lifecycle:lifecycle-runtime-ktx` | 2.7.0 |
| `com.squareup.okhttp3:okhttp` | 4.12.0 |
| `org.jetbrains.kotlinx:kotlinx-serialization-json` | 1.6.3 |
| `androidx.security:security-crypto` | 1.1.0-alpha06 |
| `junit:junit` | 4.13.2 |

`security-crypto` is an alpha, stated plainly. It is the version in general use
for `EncryptedSharedPreferences` and the first line carrying the `MasterKey`
API. The alternative — plain preferences wrapped by a keystore AES/GCM key of
our own — would put `Cipher.getInstance` and a second `KeyGenParameterSpec` into
this application, both of which `NoPrivateKeyExportSourceTest` refuses on sight;
weakening that gate to make room for hand-rolled storage encryption would trade
a proven property for an unproven one.

## The Gradle wrapper

`gradle/wrapper/gradle-wrapper.properties` pins Gradle 8.7 and `gradlew` /
`gradlew.bat` are present, but **`gradle-wrapper.jar` is deliberately not
committed** — it is binary content that could not be produced offline, and
inventing binary content is not an option. CI installs Gradle 8.7 with
`gradle/actions/setup-gradle`, runs `gradle wrapper` to materialise the jar
(which also replaces the two launcher scripts with the official generated ones),
and only then builds through `./gradlew`.

`distributionSha256Sum` is likewise absent rather than guessed. Add the real
value from <https://gradle.org/release-checksums/> when a reviewer can copy it.

To build locally: install Gradle 8.7 and an Android SDK with platform 34, then

```bash
cd apps/field-mobile-android
gradle wrapper
./gradlew :app:assembleDebug :app:lintDebug :app:testDebugUnitTest
```

## Configuration that must agree with the server

* **`applicationId` is `com.sentinel.field`.** The server's Android Key
  Attestation verifier compares the leaf's `attestationApplicationId` against
  `expectedPackageName`, which is **server configuration** — an app identity a
  device could choose is not an app identity. Changing it here alone produces
  `APPLICATION_PACKAGE_UNEXPECTED` at enrollment.
* **The signing identity** must be in the server's `expectedSigningDigests`.
  This project ships no release signing config; that is a deployment act.
* **The Google trust anchors and the revocation snapshot** are server-owned and
  unconfigured by default (`UnconfiguredAndroidAttestationTrustMaterial`), so
  the verifier returns `UNAVAILABLE` and enrollment lands at `SOFTWARE` until a
  deployment wires the real roots. That wiring is part of physical device
  acceptance, not of this client.

## Authentication

The session header is `x-dev-user-id` — the Milestone-1 dev-auth placeholder
(`services/core-api/src/modules/identity/dev-auth.guard.ts`), which trusts the
header outright. This client inherits that weakness exactly and adds none of its
own: there is no device token, no device session cookie and no header this
client sends that any controller reads as a device credential (D25-01). When
real authentication replaces that guard, one constant in `SentinelHttp` changes.

## Physical-device acceptance

The full procedure — Google trust anchors, revocation snapshot, the acceptance
signing identity and the exact fingerprint format the server expects — is in
[`docs/execution/WP-26-PHYSICAL-ACCEPTANCE-RUNBOOK.md`](../../docs/execution/WP-26-PHYSICAL-ACCEPTANCE-RUNBOOK.md).

Two things worth knowing before you start:

* `assembleDebug` needs nothing and is what hosted CI builds. `assembleRelease`
  **fails loudly** without the acceptance signing identity rather than emitting
  an unsigned APK or quietly falling back to the debug key — a debug key's
  fingerprint differs between machines, so pinning it server-side would break on
  the next build.
* The server compares **lowercase hex SHA-256 with no separators**. `keytool`
  prints uppercase with colons. Normalise it, or acceptance fails in a way that
  reads like a device fault.
