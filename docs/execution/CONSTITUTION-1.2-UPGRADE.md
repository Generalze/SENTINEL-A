# Constitution 1.2 Upgrade Procedure

This procedure applies to an existing Sentinel environment whose active policy is `sentinel-constitution-1.1.0`. Fresh databases bootstrap directly to the certified `1.2.0` baseline.

The service deliberately does not replace an existing active policy at boot. Until 1.2 is activated, response dispatch fails closed because 1.1 does not register the response-dispatch actions.

## Controlled activation

1. Verify the active version and content hash through `GET /api/v1/constitution/policy` using an authorised administrator.
2. Record a change reference and identify a platform-authorised actor plus two distinct, independently resolved approvers permitted by the active 1.1 `alter_core_constitution_rules` category. The actor cannot approve their own request.
3. Stage the exact exported `SENTINEL_BASELINE_POLICY` as a draft by calling `ConstitutionService.createDraft`. Confirm its version is `sentinel-constitution-1.2.0` and its stored SHA-256 matches `policyContentSha256(SENTINEL_BASELINE_POLICY)`.
4. Call `ConstitutionService.activatePolicy` with the platform actor, the two approvals, server-resolved `approver_roles`, and a change-record trace ID. Do not accept roles asserted only by the request.
5. Require `activated: true` and a Constitution decision of `ALLOW`. Confirm the Decision Ledger contains the same trace ID, policy hash, approval identities, and complete decision trace.
6. Re-read active-policy metadata and verify 1.2 is active and 1.1 is retained as `retired`; no policy row is overwritten or deleted.
7. Exercise one STANDARD dispatch and confirm a Ledger-backed `ALLOW`. Exercise a SILENT dispatch without approvals and confirm it remains `REQUESTED` with `REQUIRE_TWO_PERSON`.

## Failure and recovery

- `DENY` or `REQUIRE_TWO_PERSON` means the activation did not occur. Correct the authority or approval evidence and submit a new audited attempt.
- A hash/version mismatch is a hard stop and must be investigated as possible policy-store tampering.
- Do not reactivate 1.1 to recover service. Prepare a new reviewed policy version and pass it through the same two-person activation path.
- Do not edit active policy JSON or status directly in PostgreSQL.

The regression `certified baseline upgrade from 1.1 to 1.2` in `constitution.service.spec.ts` exercises the draft, two-person activation, retirement, and Ledger trace sequence.
