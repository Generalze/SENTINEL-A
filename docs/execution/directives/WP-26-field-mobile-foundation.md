# WP-26 — Field Mobile Foundation

**Status:** DIRECTIVE / DESIGN GO. **Implementation HOLD** pending the gate on
this document.
**Base:** `572ab324d0d21de60c6192234599f028d6497f0a` (the WP-25 merge commit).
**Branch:** `wp-26-field-mobile-foundation`.
**Execution repository:** `Generalze/SENTINEL-A`. The original repository
`masterzee001/SENTINEL-A` remains frozen at `bd6076e` and is untouched.

---

## 0. What changes at this work package

Every M3 work package so far has been server-side, and each one ended with the
same honest sentence: every "device" in the Crucible is a keypair a test process
generated. WP-26 is where that stops being true.

> **WP-25 proved the server can authenticate a registered device. WP-26 must
> produce an actual Field client whose private credential is generated and
> protected by the physical device rather than by a test process.**

The target chain, end to end:

```text
PHYSICAL MOBILE DEVICE
   -> hardware-backed P-256 key generation
   -> the private key is NEVER exportable, to Sentinel or to the app
   -> platform attestation / hardware evidence
   -> Shield enrollment ceremony
   -> registered physical device identity
   -> human authentication, still independent
   -> WP-25 context establishment
   -> a fresh hardware signature for EVERY effect
   -> Field mobile operation
```

WP-26 does not claim Proof C. A real device that exists and can participate is
not the same as a real device invoking a real DEVICE_ACTION Whisper (WP-27) and
being gated end to end (WP-28).

---

## D26-01 — The enrollment bridge is the load-bearing design question

The CTO named this before implementation started, and it is correctly named.

```text
WP-24  built the enrollment ceremony as an INTERNAL service with, deliberately,
       ZERO HTTP surface. Verified at this base: the Shield module declares no
       controller and no route.

WP-25  built an authenticated gateway that requires an ESTABLISHED CONTEXT,
       which requires an ALREADY REGISTERED device.

WP-26  has a physical phone holding a freshly generated hardware key that is
       registered nowhere, and therefore cannot use either.
```

A new phone cannot become registered merely because the app generated a key.
That is the whole point of C14-02: proof of possession proves possession of
*the key being enrolled*, and says nothing about whether that is the hardware
the issuer intended.

### The rule the bridge must not break

```text
A BOOTSTRAP GRANT CREATES ZERO DEVICE AUTHORITY.

issuer  !=  approver  !=  intended user

and a human still approves THE EXACT REQUEST FINGERPRINT.
```

The bridge must not become a bootstrap credential that bypasses the two-sided
ceremony. Anything that lets a stolen grant plus an attacker-generated key
produce a registered device is a failure, and WP-24's Crucible already contains
that exact adversarial case.

### What the bridge actually is

The device is **not authenticated at enrollment-request time**. It cannot be —
it has no registered key, and that is not a gap to be plugged but the reason
the ceremony exists. What substitutes for device authentication is the second
human approving the exact fingerprint. That must be stated plainly in the
implementation rather than discovered.

So the enrollment ingress is authenticated by **two independent facts, neither
of them the device**:

```text
(1) the INTENDED USER's authenticated human session   proves WHO
(2) the one-shot bootstrap grant secret               proves THIS CEREMONY
                                                      was authorised by a
                                                      commander, for this
                                                      org + site + user
```

and the device contributes **evidence**, not authority: its public key and its
hardware attestation. The grant is already single-use, short-lived (600 s
frozen ceiling), and bound to organisation, site, intended user and issuer;
presenting it in an unexpected context already burns it and raises a security
event (D24-03a).

### Why this is a NEW ingress and not the WP-25 gateway

The WP-25 gateway's entire pipeline begins by resolving a persisted context and
a registry key. Neither exists yet. Bending it to accept a device that has
neither would mean adding an unauthenticated path to the one surface whose
purpose is that there is no such path. The enrollment ingress is therefore
separate, narrower, and reachable only for the pre-registration ceremony.

### The three crossings, and only three

```text
A. ENROLLMENT REQUEST      device public key + attestation evidence
                           authenticated by intended-user session + grant
                           -> creates a REQUEST, never a device

B. POSSESSION RESPONSE     the device's signature over the server's challenge
                           -> the FIRST cryptographic act; still commits nothing
                              until the commit gate re-validates everything

C. (Command-side only)     the independent commander's approval of the exact
                           fingerprint. NOT a device crossing. It happens in
                           Command web, by a different human.
```

Approval never crosses the device boundary. If the phone can cause its own
approval, the ceremony is decorative.

---

## D26-02 — Hardware-backed key generation, and what "protected" must mean

```text
generated ON the device, in hardware-backed storage
NEVER exportable — not to Sentinel, not to the server, not to app storage,
                   not to a backup, not to a log
signing happens IN PLACE; the app holds a handle, never key material
```

The app must have no code path that can produce the private key as bytes. This
is a property to be proven by the client's own tests and by review, not
asserted in a README.

`DeviceKeyStorage` is already a frozen contract value with exactly two members,
`HARDWARE_BACKED` and `SOFTWARE`, and D23-03 already rules that a
software-backed key can never become `TRUSTED`. WP-26 supplies the first real
`HARDWARE_BACKED` value Sentinel has ever seen. It must be *earned* by platform
evidence, never asserted by the client — a client that can claim
`HARDWARE_BACKED` is a client that can claim TRUSTED, which is the whole model
inverted.

---

## D26-03 — One platform family first

The CTO ruled this and it is correct: prove one genuine hardware-backed client
path before earning any cross-platform abstraction.

**Recommendation: Android, with StrongBox-backed keys and Android Key
Attestation.** The argument is specific and it is about evidence, not
familiarity:

```text
Android Key Attestation produces an X.509 CERTIFICATE CHAIN, rooted in a
Google hardware root, that cryptographically asserts THIS KEY was generated
in hardware, is non-exportable, and carries the security level
(TEE vs StrongBox) plus the app identity it was bound to.

iOS App Attest attests THE APP. Secure Enclave keys have no equivalent
per-key attestation chain a server can verify offline.
```

Sentinel's requirement is "prove this private key lives in hardware", and only
one of those two answers that question directly. StrongBox additionally
guarantees ECDSA P-256 — the profile WP-23 versioned forward to in C14-01
precisely because the mainstream keystores guarantee it.

iOS is not abandoned; it is sequenced. The abstractions for a second platform
should be earned by a second platform, not designed in advance for one that has
not been built.

---

## D26-04 — Attestation: evidence in, seam unchanged

WP-24 built the attestation evaluator as an internal server-owned seam that
returns `UNAVAILABLE` and deliberately invents nothing. WP-26 is the first work
package with real evidence to feed it.

The frozen split is preserved exactly:

```text
VERIFIED                     positive evidence
NEGATIVE / INVALID / REVOKED device evidence; may lower trust or quarantine
UNAVAILABLE                  NOT negative evidence
```

Whether WP-26 *implements* key-attestation chain verification, or only
transports the evidence and leaves the evaluator returning `UNAVAILABLE`, is an
open question for the gate — see below. What is not open: the client never
supplies the verdict, only the evidence, and the frozen timing constants do not
change.

---

## D26-05 — The human principal stays independent

C17-01 is a closed ruling and WP-26 inherits it without softening. A mobile
client is exactly the context in which "the device is right here, surely that is
enough" becomes tempting.

```text
the SESSION proves WHO
the POSSESSION PROOF proves WHICH HARDWARE
the LIVE RE-READ proves STILL AUTHORISED NOW

none of them substitutes for another, on a phone or anywhere else
```

The app therefore authenticates its human the ordinary way and holds that
session independently of the device credential. A device credential must never
become an implicit login, and a login must never become an implicit device.

---

## D26-06 — What the client actually does

Per the roadmap: a **minimal** real Field client — identity, assignments,
state, messaging, patrol, and secure local storage. Minimal is the operative
word; this is a foundation for a proof, not a product.

Every effect-causing operation goes through the WP-25 gateway with a fresh
hardware signature (D25-01), over the three surfaces WP-25 actually exposes:
Field state update, assignment ACCEPT/DECLINE, and incident Field message
acknowledgement. Read surfaces use the ordinary authenticated human routes.

Secure local storage in WP-26 is for client state only. **The offline queue is
WP-29** and is not built here.

---

## D26-07 — Out of scope

```text
NO Whisper of any kind                       WP-27 owns the physical-device path
NO touching the frozen Whisper resolver      it verifies Ed25519 under frozen v1;
                                             a real phone existing does not
                                             authorise changing a frozen M2
                                             cryptographic domain
NO offline queue / Edge / WAN-loss           WP-29 / WP-30
NO second mobile platform                    D26-03
NO Proof C claim                             WP-28
NO Proof D claim                             WP-31
NO rewriting historical migrations           standing debt, its own work package
NO uncontrolled background scheduler,        D25-08, still binding
   no new cross-suite test coupling
```

---

## D26-08 — Proof discipline

```text
Proof A     must remain green
Proof C     UNCLAIMED
Proof D     UNCLAIMED
```

**A real device that can enrol and operate is not Proof C.** Proof C is the
WP-28 gate over a real device invoking a real DEVICE_ACTION Whisper. WP-26 may
report "a physical device enrolled and operated"; it may not report anything
that reads as the proof.

---

## Open questions for the gate

Each changes the shape of the work, so none is decided here.

1. **How is a mobile client verified in CI at all?** This is the practical
   question most likely to derail implementation. Hosted CI today is a pnpm
   workspace plus Postgres, NATS, Redis and MinIO; it has no JDK, no Android
   SDK and no emulator. Options: (a) add an Android toolchain and an
   instrumented-test job — heavy, slow, and it puts a device emulator on the
   critical path of every merge; (b) keep the client in-repo but **outside the
   pnpm test graph**, with its own workflow, and keep the *server-side*
   contract of the bridge fully covered by the existing live suite; (c) a
   separate repository — which I do not recommend, because it breaks the
   single-boundary discipline every gate so far has relied on.
   **My recommendation is (b)**, with the explicit consequence stated: the
   workspace test count stops being a complete measure of the system, and the
   gate must read two numbers instead of one.

2. **Does WP-26 verify the Android Key Attestation chain, or only transport
   it?** Verifying it is offline X.509 validation against Google's published
   root — arguably not the "attestation vendor integration" D24-07 excluded,
   since it calls no vendor API. But it is a substantial security component
   with its own revocation and root-pinning concerns.
   **My recommendation: verify it in WP-26**, because without it the first real
   `HARDWARE_BACKED` value in Sentinel's history would be a client claim, and
   D26-02 forbids exactly that. If the CTO prefers to defer, then WP-26 must
   enrol at `SOFTWARE`/`DEGRADED` and say so, and Proof C moves further out.

3. **Native Kotlin, or a cross-platform framework with platform channels?**
   Every security-critical primitive here — StrongBox key generation,
   attestation, in-place signing — is platform-native regardless.
   **My recommendation: native Kotlin for the first path**, so the auditable
   part is not wrapped in a layer that has to be audited too.

4. **Where does the enrollment ingress live?** A new narrowly-scoped module, or
   a second controller inside Shield? **My recommendation: a new module**, so
   Shield keeps its property of having no HTTP surface and the ingress's
   different authentication model has exactly one implementation.

5. **Does the phone or the commander submit the enrollment request?** The
   directive above assumes the phone submits it (crossing A) under the intended
   user's session plus the grant. The alternative — the commander transcribes
   the public key and attestation out of the app via QR — removes crossing A
   entirely at the cost of a manual step and a much larger payload to
   transcribe. **My recommendation: the phone submits**, because attestation
   evidence is a certificate chain, not something a human transcribes, and the
   security property is carried by the approval, not by the transport.
