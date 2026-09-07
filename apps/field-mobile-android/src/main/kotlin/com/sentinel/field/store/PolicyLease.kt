package com.sentinel.field.store

import java.time.Instant

/**
 * ============================================================================
 * THE SERVER-ISSUED POLICY LEASE, AS THIS DEVICE REMEMBERS IT.
 *
 * Field for field, `DevicePolicyLeaseSchema` in
 * `packages/contracts/src/device-offline.ts`. Every value here was ISSUED BY
 * THE SERVER and is transcribed, never composed: there is no constructor call
 * anywhere in this application that invents a lease id, widens a scope or moves
 * an expiry.
 *
 * ============================================================================
 * THIS IS A CACHE. IT IS NEVER AUTHORITY. THE DISTINCTION IS THE WHOLE POINT.
 * ============================================================================
 *
 * D23-11 expires cached authority; D23-12 refuses to trust the client clock.
 * What the lease is FOR, on this side, is exactly two things:
 *
 *   1. supplying `policy_lease_id`, which goes INSIDE the signed envelope so
 *      the operation names the authority it acted under (C14-04); and
 *   2. letting a disconnected device REFUSE LOCALLY — decline to queue work its
 *      cached policy does not cover, rather than queue it and discover hours
 *      later that none of it was ever admissible.
 *
 * What it is NOT for is deciding that anything will be accepted. On arrival the
 * server RE-RESOLVES the lease by id from its own record and judges the
 * operation against THAT — its own scope, its own issue and expiry instants,
 * against its own receipt clock or an independent Edge witness. A device that
 * edited this cache to widen its scope, push out its expiry or name another
 * actor would change precisely nothing about the outcome: the envelope would be
 * refused LEASE_SCOPE_MISMATCH, EXPIRED or LEASE_ACTOR_MISMATCH by a server
 * that never read the device copy at all. Local tampering and local staleness
 * are equally powerless, and that is by construction rather than by our
 * diligence in keeping this file honest.
 *
 * The asymmetry runs one way and only one way: THIS CACHE MAY REFUSE, AND IT MAY
 * NEVER PERMIT. A local refusal is safe — the operative is told, nothing is
 * queued, nothing is lost. A local acceptance is worth nothing on its own, and
 * no code here should ever be written as though it were.
 * ============================================================================
 */
data class PolicyLease(
    val leaseId: String,
    val organisationId: String,
    val siteId: String,
    /** Issued TO one device identity. It is not a site-wide permit. */
    val deviceId: String,
    /**
     * C15-06. The lease names the ACTOR whose authority justified it.
     *
     * On a shared handset this is the load-bearing field: operative A causes the
     * lease to be issued, the device passes to operative B at shift change, and
     * B — who holds nothing — must not be able to ride A cached authority. The
     * server refuses a mismatch between this and the envelope actor, and this
     * client must not queue one either.
     */
    val actorUserId: String,
    /** The specific grant the issuance rested on, for audit and revalidation. */
    val authorityBasisId: String,
    /** The operation kinds this lease covers. An allowlist, never a hint. */
    val scope: List<String>,
    val issuedAt: String,
    val expiresAt: String,
) {

    /**
     * True when the cached scope names [operationKind].
     *
     * A local gate on what may be QUEUED. It is not a prediction of what will be
     * accepted: the server checks the SAME rule against the lease record it
     * holds, and that check is the one that decides.
     */
    fun permits(operationKind: String): Boolean = scope.contains(operationKind)

    /**
     * True when this cached copy places [now] inside its own window.
     *
     * FAIL-CLOSED, IN EVERY DIRECTION. An unreadable instant answers false, not
     * true, which mirrors C15-07 — the server answers TIME_NOT_AUTHORITATIVE for
     * an instant it cannot parse, and that is not VALID either. Expiry is
     * EXCLUSIVE, as it is server-side: at the expiry instant the lease is over.
     *
     * [now] comes from the device clock, which this platform does not trust and
     * which this method does not pretend to redeem. A "false" here is a useful
     * local refusal. A "true" is not evidence of anything and must never be
     * treated as though the operation is thereby authorised.
     */
    fun looksUsableAt(now: Instant): Boolean = standingAt(now) == LeaseStanding.IN_FORCE

    /**
     * The same judgement as [looksUsableAt], but saying WHICH WAY it failed.
     *
     * One parse site, two callers, and the split exists for the operative
     * rather than for the server. Central collapses all of this into a single
     * `LEASE_NOT_IN_FORCE` refusal, and it is right to: a refusal that
     * distinguished "too early" from "too late" would be an oracle about lease
     * windows offered to whoever is holding the handset. But this is the LOCAL
     * side of the same question, and locally the two are different situations
     * with different remedies — an EXPIRED lease means reconnect and be issued
     * a new one, a NOT_YET_VALID one means this device's clock disagrees with
     * the server that stamped the lease, and telling an operative "refused" for
     * both is telling them nothing they can act on.
     *
     * FAIL-CLOSED IN EVERY DIRECTION, exactly as before. An unreadable instant
     * is [LeaseStanding.WINDOW_UNREADABLE], which is not IN_FORCE, which
     * refuses — mirroring C15-07, where an instant the server cannot parse
     * answers TIME_NOT_AUTHORITATIVE rather than passing. Expiry is EXCLUSIVE:
     * at the expiry instant the lease is over.
     *
     * [now] is the device clock, which this platform does not trust and which
     * this method does not redeem. Anything but IN_FORCE is a useful local
     * refusal; IN_FORCE is evidence of nothing and must never be read as
     * authorisation.
     */
    fun standingAt(now: Instant): LeaseStanding {
        val issued = parseOrNull(issuedAt) ?: return LeaseStanding.WINDOW_UNREADABLE
        val expires = parseOrNull(expiresAt) ?: return LeaseStanding.WINDOW_UNREADABLE
        if (now.isBefore(issued)) return LeaseStanding.NOT_YET_VALID
        if (now.isBefore(expires)) return LeaseStanding.IN_FORCE
        return LeaseStanding.EXPIRED
    }

    /**
     * A one-line rendering for the log.
     *
     * Safe to print in full: a lease is a scope statement, not a credential.
     * Holding one says what a device WOULD be entitled to if the hardware key
     * were present and the named actor were the one acting, and it authorises
     * nothing on its own.
     */
    fun describe(): String =
        "cached lease $leaseId  actor=$actorUserId  site=$siteId  device=$deviceId  " +
            "basis=$authorityBasisId  scope=${scope.joinToString(",")}  " +
            "issued=$issuedAt  expires=$expiresAt"

    private fun parseOrNull(value: String): Instant? = try {
        Instant.parse(value)
    } catch (error: Exception) {
        null
    }
}

/**
 * Where the device clock falls against a cached lease's own window.
 *
 * Four members, and none of them is "VALID". The name matters: this enum
 * describes where a clock this platform does not trust sits relative to two
 * instants a server stamped, and nothing more. `IN_FORCE` is the absence of a
 * local reason to refuse — it is not a finding that the operation will be
 * admitted, and the server re-runs the whole judgement against its own record
 * and its own receipt clock on arrival.
 */
enum class LeaseStanding {
    /** An instant on the cached lease does not parse. Fail-closed; not IN_FORCE. */
    WINDOW_UNREADABLE,

    /** The device clock is before the instant the server says the lease began. */
    NOT_YET_VALID,

    /** No local reason to refuse. NOT a prediction that anything will be accepted. */
    IN_FORCE,

    /** The device clock is at or past the expiry. Expiry is exclusive. */
    EXPIRED,
}
