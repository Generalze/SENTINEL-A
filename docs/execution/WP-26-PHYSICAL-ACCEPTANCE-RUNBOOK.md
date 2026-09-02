# WP-26 — Physical-Device Acceptance Runbook

**Candidate SHA:** the acceptance must be performed against the exact PR #19 head.
**Status:** NOT PERFORMED. This document exists so that whoever holds the
hardware can perform it without re-deriving any of it.

I cannot run this myself — there is no Android device, JDK, Gradle or Android
SDK on the authoring machine. Everything below is the enabling work; the run is
someone else's to execute.

---

## 0. What this proves, and what it does not

```text
KNOWN GOOGLE ATTESTATION ROOT
   + VALID CERTIFICATE CHAIN
   + NOT REVOKED
   + STRONGBOX SECURITY LEVEL
   + LOCKED / VERIFIED BOOT
   + SERVER-ISSUED FRESH CHALLENGE
   + EXACT GENERATED PUBLIC KEY
   + PACKAGE = com.sentinel.field
   + KNOWN SENTINEL APP SIGNING CERTIFICATE
        -> VERIFIED -> HARDWARE_BACKED -> eligible for TRUSTED
```

**This is WP-26 acceptance. It is NOT Proof C.** Proof C is the WP-28 gate over
a real device invoking a real DEVICE_ACTION Whisper, and WP-27 has not started.

## 1. The four trust questions, and which setting answers each

| Question | Setting |
|---|---|
| Do I trust the authority that says this key came from secure Android hardware? | `ANDROID_ATTESTATION_TRUST_ANCHORS` + `..._TRUST_ANCHOR_SET_VERSION` |
| Has any certificate in that chain since been revoked? | `ANDROID_ATTESTATION_REVOCATION_SNAPSHOT` + `..._VERSION` + `..._FETCHED_AT` |
| Does the app claim to be Sentinel Field? | `ANDROID_ATTESTATION_PACKAGE_NAME` |
| Was the installed APK signed by a certificate we recognise? | `ANDROID_ATTESTATION_SIGNING_DIGESTS` |

The phone must never be able to say *"here is my root, trust it"* — the anchor is
configured independently, and the verifier refuses a chain that does not reach
it. Package name alone is insufficient: anyone can build an APK calling itself
`com.sentinel.field`, which is why the signing certificate is checked too.

**Sentinel never receives a private key.** Not Google's, not the APK signing
key, not the StrongBox key. Only public verification material.

## 2. Obtain the Google material — from Google, not from memory

Fetch both from Google's official published source. **Do not copy certificate
text from a blog, a search result, or from anyone's recollection**, including
mine — a *wrong* anchor fails **open**, which is worse than a missing one. The
server is deliberately built so that absent material fails closed: every verdict
stays `UNAVAILABLE` and no device reaches `TRUSTED`.

- the Android attestation **root certificates** (there is currently more than
  one valid anchor; a newer root began signing chains in 2026)
- the **certificate revocation status list**

Record the version/date you fetched each at — those go into the
`..._SET_VERSION`, `..._SNAPSHOT_VERSION` and `..._FETCHED_AT` settings and are
stamped onto every attestation artifact, including refusals, so an artifact can
always be traced to the material that judged it.

The snapshot has a bounded freshness. Stale material answers `UNAVAILABLE` — it
never silently assumes "not revoked".

## 3. Establish the acceptance signing identity

A debug APK is signed with an auto-generated debug keystore whose fingerprint
differs between machines and can be regenerated at any time. Pinning that would
either break on the next build or pin a key nobody controls, so the build now
refuses to produce a release APK without a deliberate identity.

```bash
keytool -genkeypair -v \
  -keystore sentinel-field-acceptance.jks \
  -alias sentinel-field-acceptance \
  -keyalg RSA -keysize 4096 -validity 3650 \
  -storetype PKCS12
```

Keep the keystore and its passwords private; `.gitignore` refuses `*.jks`,
`*.keystore` and `signing.properties` as a second line of defence, but the rule
is "never commit it", not "the ignore file will catch it".

### Extract the fingerprint in the format the server actually wants

The verifier compares **lowercase hex SHA-256, no separators**. `keytool` prints
uppercase with colons, so it must be normalised — a format mismatch here fails
acceptance in a way that reads like a device fault.

```bash
keytool -list -v -keystore sentinel-field-acceptance.jks \
        -alias sentinel-field-acceptance \
  | grep -i 'SHA256:' \
  | sed 's/.*SHA256: *//' | tr -d ':' | tr 'A-Z' 'a-z'
```

That value is `ANDROID_ATTESTATION_SIGNING_DIGESTS`.

## 4. Build and sign the exact candidate

Build from the **exact PR #19 head**, not from a working copy.

```bash
git fetch && git checkout <candidate SHA>
cd apps/field-mobile-android
gradle assembleRelease \
  -PsentinelAcceptanceStoreFile=/abs/path/sentinel-field-acceptance.jks \
  -PsentinelAcceptanceStorePassword=... \
  -PsentinelAcceptanceKeyAlias=sentinel-field-acceptance \
  -PsentinelAcceptanceKeyPassword=...
```

Equivalent environment variables also work:
`SENTINEL_ACCEPTANCE_STORE_FILE`, `_STORE_PASSWORD`, `_KEY_ALIAS`, `_KEY_PASSWORD`.

Without them the build **fails loudly** rather than producing an unsigned APK or
silently falling back to the debug key. Confirm what actually signed the APK:

```bash
apksigner verify --print-certs app-release.apk   # SHA-256 must equal step 3
```

## 5. Configure the server, then verify it is actually configured

Set the six settings, restart, and confirm the provider reports itself
configured — if any part is missing, invalid or stale, the whole material is
treated as unconfigured and every verdict stays `UNAVAILABLE`. That is by
design, and it means **a silently mis-set value looks exactly like a device
failure**, so check this before touching the phone.

## 6. The device

A supported handset with **StrongBox actually available** — the client refuses
and reports the device unsupported rather than falling back to TEE, and a TEE
certificate is never promoted into the StrongBox profile. Verified boot and a
locked bootloader are part of the `VERIFIED` profile.

## 7. The ceremony

```text
commander issues a bootstrap grant (org + site + intended user)
  -> operative signs in on the handset; presents the grant
  -> SERVER issues the attestation challenge          <- before key generation
  -> phone generates a StrongBox P-256 key WITH that exact challenge
  -> phone submits public key + certificate chain
  -> server verifies -> VERIFIED -> HARDWARE_BACKED
  -> an INDEPENDENT commander approves the exact request fingerprint
  -> possession challenge -> StrongBox signs -> server verifies
  -> enrollment commits -> TRUSTED
  -> WP-25 context established
  -> one Field operation, signed by the hardware key, commits
```

## 8. What to report — and what never to send

Report: candidate SHA, Android build SHA, device model / API level / StrongBox
availability, the server attestation **artifact id and chain hash**, trust-anchor
and revocation-snapshot versions, the server-derived outcome / key storage /
trust, enrollment and device ids, the context result, and the Field-operation
result.

**Never send**: the raw attestation certificate chain, any private key, the
bootstrap token, or any session credential. The server already refuses to put
the chain in an audit payload or any client-readable response; the same rule
applies to the report.

## 9. If it fails

The refusal reason is deliberately **not** in the HTTP response — external
answers are shaped so they cannot become an enumeration oracle. The precise
reason is in the server's internal audit against the trace id. Start there
rather than inferring from the phone, and check in this order: trust material
actually configured, revocation snapshot fresh, signing digest format
(lowercase hex, no colons), package name, StrongBox availability, boot state.
