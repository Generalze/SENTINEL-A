# D29A-26 — WP-29A Device Policy Lease Persistence

**Status:** RULED. Implemented by WP-29A.
**Directive authority:** CTO. **Issued:** 2026-09-05.
**Migration authority:** 24 → 25, exactly one forward migration.

This record exists because WP-29A's source cites `D29A-26 §3`, `§7`, `§8`, `§9`,
`§16`, `§22` and others in permanent comments, and the ruling itself lived only
in the governance conversation. A reader of
`device-policy-lease.service.ts` could not resolve a single one of those
references from the repository. That is a provenance defect in its own right:
a comment that cites an unreachable authority is indistinguishable from a
comment that invented one.

Recorded after the fact and deliberately not back-dated into the four WP-29A
implementation commits, which remain unamended.

---

## 1. The blocker this ruling released

`policy_lease_id` has always been a required field inside the signed bytes of a
`DeviceOfflineOperationEnvelope`, so an operation created while disconnected
NAMES the authority it acted under. Nothing resolved that name: the frozen
WP-23 contract had no persistence, so `evaluateOfflineOperationAdmissibility`
refused every envelope with `LEASE_MISSING` and the offline path could not run
at all.

The alternative — holding the migration budget at zero — was rejected, because
it would have made WP-29A bypass the exact cached-authority mechanism WP-23
created for offline operation.

## 2. §3 — the lease is a first-class authority artefact

It may NOT be represented by JSON embedded in another record, Android-only
storage, session state, cache-only state, request-body reconstruction, a client
timestamp, or a device assertion.

The server must be able to resolve `envelope.policy_lease_id` to an
authoritative persisted `DevicePolicyLease` after connectivity has been lost and
restored.

Contract ID representations are preserved as frozen; they were not changed for
database convenience.

## 3. §4 — tenant integrity

Composite, tenant-aware relations with `ON DELETE RESTRICT`:

```text
(device_id, organisation_id)     -> devices(id, organisation_id)
(site_id, organisation_id)       -> sites(id, organisation_id)
(actor_user_id, organisation_id) -> users(id, organisation_id)
```

No cascade deletion for authority artefacts. A lease naming an organisation-A
device and an organisation-B site is refused by the database, not merely by the
service — the D24-04a rule this repository already applies to
`DeviceSiteScope`.

Note the type discipline this forces: `device_id` is `@db.Uuid` because
`devices.id` is, while `site_id` and `actor_user_id` are `@db.Text` because
those ids are cuids. A mismatch makes the composite key unbuildable and fails
at migration apply time, not at typecheck.

## 4. §5 — `authority_basis_id` is a historical identifier, with NO foreign key

Ruled explicitly. The column records the `user_roles` row whose capability
justified issuance, as a plain column following the
`DeviceTrustTransition.authorisedByUserId` precedent — "the identifier as
recorded at decision time".

A `Restrict` relation to a live, mutable role was forbidden:

```text
CURRENT AUTHORITY                 HISTORICAL FACT
may be revoked / removed    !=    this lease was issued under basis X
```

A six-hour historical lease must not hold a live role in existence merely to
preserve provenance. Revoking present authority must remain independent of
explaining past authority — otherwise removing a user's role could be blocked
for up to six hours by a queued acknowledgement.

Where an actor holds several covering assignments, the narrowest is recorded
(site-scoped preferred over organisation-wide, ties broken by lowest id).

## 5. §6 — scope

Persisted as the repository's scalar-list representation, drawn from the frozen
`FieldOfflineOperationKind` set. Never unconstrained JSON.

Issuance may never grant a scope broader than the server-authorised
device/user/site capability. The lease is the INTERSECTION of what was asked for
with what the device and the actor may currently do.

## 6. §7 — the six-hour ceiling

`DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS` remains authoritative and is imported,
never copied. `expires_at - issued_at <= 6 hours`, clamped server-side. A
client-requested expiry may never enlarge it; a shorter server-chosen lifetime
is permitted.

## 7. §8 — server time is authoritative

`issued_at`, `expires_at` and `revoked_at` are server-derived. A device clock
never establishes lease validity, and there is no parameter through which one
could be supplied. The device may cache these values for local queue decisions;
central always re-resolves the authoritative persisted record.

## 8. §9 / §26 — revocation is a state, never a deletion

A lease may be revoked before expiry. `revoked_at` is set; the row is not
deleted and its historical identity is not overwritten. Revocation remains
auditable.

WP-29A must not add ordinary runtime deletion of policy leases. Expiration and
revocation are states, not reasons to erase the record. Retention policy is out
of scope.

**Implementation note.** A revoked lease resolves to `null`, producing
`LEASE_MISSING`. This is deliberate rather than an omission: the frozen
evaluator has no revocation input — it judges identity, scope and the window —
so returning a revoked lease would have it judged as live and the operation
ADMITTED. Withholding it is the correct fail-closed answer, and the row itself
is untouched so provenance survives.

## 9. §10 — historical artefact, not live-state cascade

The lease must remain resolvable after later security-state changes: device
revoked, actor disabled, site permission changed, policy changed. Ordinary
device/user state changes must not erase the lease record.

The relation is restrictive/historical rather than cascade-owned live state, so
Sentinel can still answer: *what authority did this queued operation claim to
act under, and what was the authoritative state of that lease?*

## 10. §11 / §12 — issuance authority

A lease is issued only after verifying the authenticated device's entitlement to
the organisation and site through `DeviceSiteScope`, and the actor's authority
through the established policy model — role, organisation, site scope, device
trust, authority basis, Constitution/policy.

The lease may never out-scope the device. A valid Site foreign key is necessary
but not sufficient; application authority checks remain mandatory.

## 11. §13 — issuance path

Issued only through an already-authenticated online device/session context,
integrated into the existing context-establishment flow. No unauthenticated
standalone lease-minting endpoint, and no second device-authentication
mechanism.

**Implementation note.** The lease is a side effect of a successful ceremony,
never something a caller asks for: there is no request field naming a scope, a
lifetime or a site, so no client can widen its own offline authority. It is
issued on a fresh issuance only and not on a converged retry, so one ceremony
mints one lease.

## 12. §14 — the local copy is a cache

Android may persist the issued lease for local eligibility decisions,
`policy_lease_id` binding, expiry awareness and outbox construction. It is not
the authoritative record. Tampering with or staleness of the local copy must
never cause central acceptance, because central re-resolves the persisted lease.

## 13. §15 — envelope binding unchanged

`policy_lease_id` remains non-nullable inside the signed canonical material. It
may not be made nullable, and the server may not substitute the device's
"current" or "latest" lease when the submitted envelope named another. The
server evaluates the exact lease identified by the signed operation — otherwise
the backdating the signed field exists to prevent returns by another route.

## 14. §16 / §17 / §18 — receipt provenance

`FieldOfflineOperationReceipt.policy_lease_id`, nullable in the database and
mandatory in the application.

Nullable for backward compatibility with receipts created before WP-29A. For
the offline-envelope path, application-level absence is an invariant violation:
every new receipt created from a `DeviceOfflineOperationEnvelope` MUST store the
resolved lease, and that path has no branch that writes NULL.

Bound with `ON DELETE RESTRICT` and nullable relationship semantics for
pre-WP-29A rows. No cascade. One index, for the demonstrated audit lookup.

Without this linkage the lease would influence admission and then vanish from
the durable operational record, which is precisely the provenance the lease
table was added to preserve.

## 15. §20 / §21 — no backfill, and two honest eras

No lease backfill, no receipt backfill, no fabricated historical leases.
Existing receipts remain `policy_lease_id = NULL`, because those operations
predate the mechanism.

```text
pre-WP-29A receipt   NULL       created before persisted offline policy leases
WP-29A receipt       NOT NULL   authority lease explicitly preserved
```

NULL is an era marker, not a quality flag. History is not rewritten to make the
two eras appear identical.

## 16. §22 — the admissibility path

```text
DeviceOfflineOperationEnvelope
   -> authenticated WP-25 gateway
   -> AuthenticatedDeviceContext
   -> resolve envelope.policy_lease_id
   -> DevicePolicyLease server record
   -> evaluateOfflineOperationAdmissibility(...)
   -> FieldOfflineReplayService
```

If resolution returns no lease, `LEASE_MISSING` remains fail-closed. The
authorised acknowledgement operation is not special-cased around this
requirement: its stale tolerance removes the need for a time witness, never the
need for a lease.

## 17. §25 — historical explainability

A future audit must be able to answer, from persisted server state and without
trusting a device-only record: which offline operation, which device, which
actor, which organisation and site, which policy lease, what scope it contained,
what authority basis supported it, when it was issued, when it expired, whether
it was later revoked, and what receipt or result the operation produced.

## 18. §27 / §28 — migration boundary and MC-01

Migration 25 contains only the schema changes required for the lease table, its
tenant-safe relations, minimal indexes, the receipt column, and its relation and
index. No unrelated schema changes.

If generated Prisma SQL had included MC-01's historical drift statements, that
would have been a regression to STOP on — not to strip. The drift gate must
catch them.

After migration 25:

```text
empty DB -> all 25 migrations -> current datamodel -> ZERO DRIFT
```

**Outcome:** the generated migration contained only WP-29A's own statements.
This was the first work package after MC-01 to confirm that gate holds.

## 19. §29 — rollback characterisation

Dropping the lease table would cause new offline-envelope evaluation to fail
closed. But once WP-29A produces receipts linked to leases, a destructive
downgrade must not be described as operationally harmless, because it would
destroy authority provenance.

Deployment rollback is therefore normally an application rollback while the
additive schema remains. Schema rollback is not an ordinary runtime recovery
mechanism.

---

## 20. Superseded and corrected after issuance

**D29A-27 — Queued Submission Audit Truth.** Issued after review of the WP-29A
candidate found that `authenticateQueueSubmission` emitted a final
`OPERATION_COMMITTED` audit event before the downstream offline-envelope checks
had run, so a submission that authenticated and was then refused left a durable
record claiming it had committed. Authentication success means only that
authentication succeeded. See the WP-29A execution record for the correction.

---

```text
WP-29A                       IMPLEMENTED
D29A-26                      RULED — this record
D29A-27                      audit-truth correction, required before merge
migrations                   24 -> 25
schema drift                 ZERO
Proof D                      UNCLAIMED
```
