# WP-26-HW-ACCEPTANCE-DEFERRED

```text
Status                  DEFERRED — NOT WAIVED
Reason                  No StrongBox-capable physical Android device presently
                        available.
Qualified implementation
                        943a8fc2de18ae2f0d1e160062efc2ba23d005a6
Required before closure
                        The physical StrongBox acceptance procedure in
                        docs/execution/WP-26-PHYSICAL-ACCEPTANCE-RUNBOOK.md
```

**Deferred does not become passed.** This file exists so that the distinction
survives the passage of time and the arrival of later work packages. Nothing in
WP-27 or beyond may cite WP-26 physical acceptance as though it had occurred.

---

## The three states, and where WP-26 stands

```text
IMPLEMENTED           reached
SOFTWARE QUALIFIED    reached   — Server CI and Android CI green at 943a8fc2
PHYSICALLY ACCEPTED   NOT reached
```

## Why merging is nonetheless safe

The implementation is deliberately **fail-closed** on every axis the physical
run would exercise, so merging asserts nothing about hardware:

- With no trust material configured, the provider reports itself unconfigured
  and **every attestation verdict is `UNAVAILABLE`**. No device can reach
  `TRUSTED`. Partial, invalid or stale material is treated as unconfigured
  rather than partially applied.
- `HARDWARE_BACKED` is derived from the server's verdict, never from a client
  claim, so it cannot be asserted into existence.
- The client requires StrongBox and has **no TEE fallback branch**; a device
  without it is reported unsupported.
- A TEE-level certificate is never promoted into the StrongBox profile.

A merged `main` therefore carries a capability that refuses to operate until a
deployment supplies real trust material AND a real device satisfies it. That is
the opposite of an unearned claim.

## The hardware constraint

The device to hand is a **Galaxy S8**. It is Knox-secured, but it predates
Samsung Knox Vault, which arrived with the Galaxy S21 generation. Android
StrongBox requires a dedicated secure processor, so the S8 cannot produce the
**positive** result WP-26 requires:

```text
StrongBox hardware -> hardware attestation -> server verification -> TRUSTED
```

We wait for suitable hardware to become naturally available rather than buying
unsuitable equipment to satisfy a schedule.

## The S8 keeps a role — the negative path

It is not discarded from the test programme. It provides evidence for the half
that matters just as much:

```text
Galaxy S8
   -> no acceptable StrongBox
   -> Sentinel attempts enrollment
   -> the StrongBox requirement cannot be met
   -> NO TEE FALLBACK
   -> UNAVAILABLE / enrollment denied
```

That demonstrates Sentinel genuinely refuses lower-assurance hardware instead of
quietly weakening its own policy — which is a real acceptance result, and one
worth capturing when convenient. It simply is not the positive half.

## What remains blocked, and what does not

```text
WP-27 SOFTWARE WORK              released
WP-27 acceptance criteria that
  depend on a successfully
  enrolled StrongBox device      PENDING until hardware exists
Proof C                          LOCKED — UNCLAIMED
Proof D                          LOCKED — UNCLAIMED
```

Proof C is unchanged by any of this. It requires the organisation to create,
test and activate a device/wearable Whisper signal and invoke the silent
protocol with authenticated acknowledgement — a real device doing real work,
which no amount of software qualification substitutes for.

## Closing this item

When a StrongBox-capable device is available:

1. Run the procedure in `WP-26-PHYSICAL-ACCEPTANCE-RUNBOOK.md` against the
   merged implementation, retaining its relationship to `943a8fc2`.
2. Record the evidence the runbook lists — and none of the material it forbids.
3. Only then may WP-26 be closed.
