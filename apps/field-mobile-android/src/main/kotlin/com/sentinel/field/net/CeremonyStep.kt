package com.sentinel.field.net

/**
 * ============================================================================
 * THE RESULT OF ONE STEP OF THE CEREMONY.
 *
 * Four outcomes, and only four:
 *
 *   OK                    the server answered, and the answer parsed.
 *
 *   REFUSED               everything else the SERVER can say TERMINALLY. D25-13's
 *                         discipline, inherited by the enrollment ingress: a
 *                         dead grant, a foreign tenant, a spent challenge, an
 *                         expired one, a chain that does not verify and a
 *                         session that is not the intended user all shape the
 *                         SAME external refusal, with the same body. There is
 *                         nothing to branch on and this client does not pretend
 *                         otherwise — `detail` is for a human reading a log,
 *                         never for a code path.
 *
 *   COMPLETION_UNKNOWN    C18-R1. THE SERVER MAY HAVE COMMITTED AND THIS CLIENT
 *                         CANNOT PROVE IT EITHER WAY. Two sources, one meaning:
 *                         the server's own `409` — "your submission spent the
 *                         challenge, I cannot yet say what it produced" — and
 *                         every local failure in which no answer arrived, which
 *                         INCLUDES the case where the request reached the
 *                         server, the server committed, and the response was
 *                         lost on the way back.
 *
 *                         IT IS A SEPARATE OUTCOME FROM `REFUSED` FOR ONE
 *                         REASON, AND IT IS NOT COSMETIC. A refusal is terminal,
 *                         so a client that receives one correctly throws away
 *                         the ceremony material. Doing that on an UNPROVEN
 *                         outcome destroys the grant, the challenge and the key
 *                         that are the ONLY way to reach the convergence the
 *                         server built for exactly this case. Collapsing the two
 *                         is the defect C18-R1 exists to close.
 *
 *   DEVICE_UNSUPPORTED    D26-03A. StrongBox is not usable on this handset. It
 *                         is a separate outcome from a refusal and from a
 *                         generic failure precisely so that nobody can "make it
 *                         work" by collapsing it into an error and adding the
 *                         TEE fallback the directive forbids.
 *
 * WHY THIS IS NOT A SEALED CLASS
 * ------------------------------
 * A generic sealed hierarchy would be the idiomatic Kotlin. This is a plain
 * class with a `kind` because the whole client is written to be verified by
 * hosted CI rather than by a compiler on the author's machine, and a shape whose
 * correctness depends on generic smart-cast inference is a shape that can fail
 * to compile in a way nobody can see until the runner does. Boring and certain
 * beats idiomatic and unverified.
 * ============================================================================
 */
class CeremonyStep<T> private constructor(
    val kind: Kind,
    private val carried: T?,
    /** The HTTP status, or 0 when the failure was local. */
    val status: Int,
    /** For a human reading a log. Never an authorisation or control input. */
    val detail: String,
) {

    enum class Kind { OK, REFUSED, COMPLETION_UNKNOWN, DEVICE_UNSUPPORTED }

    val isOk: Boolean get() = kind == Kind.OK

    val isDeviceUnsupported: Boolean get() = kind == Kind.DEVICE_UNSUPPORTED

    /**
     * C18-R1 — the outcome is UNPROVEN, so nothing may be discarded on it.
     *
     * The single predicate the ceremony's callers branch on when deciding
     * whether the bootstrap grant may be released. Stated as one named property
     * rather than an inline status comparison so that "we could not prove it" is
     * a fact about one line of this client rather than a convention several call
     * sites happen to share.
     */
    val isCompletionUnknown: Boolean get() = kind == Kind.COMPLETION_UNKNOWN

    /** The carried value. Call only after checking [isOk]. */
    fun valueOrThrow(): T =
        carried ?: throw IllegalStateException("the ceremony step did not succeed: $kind $detail")

    /** The carried value, or null on any non-OK outcome. */
    fun valueOrNull(): T? = carried

    fun describe(): String = when (kind) {
        Kind.OK -> "ok"
        Kind.REFUSED -> "refused ($status): $detail"
        Kind.COMPLETION_UNKNOWN -> "COMPLETION UNKNOWN ($status): $detail"
        Kind.DEVICE_UNSUPPORTED -> "DEVICE UNSUPPORTED: $detail"
    }

    companion object {
        fun <T> ok(value: T): CeremonyStep<T> = CeremonyStep(Kind.OK, value, 200, "")

        fun <T> refused(status: Int, detail: String): CeremonyStep<T> =
            CeremonyStep(Kind.REFUSED, null, status, detail)

        /**
         * C18-R1. `status` is the server's own status where there was one (409),
         * and 0 where no answer arrived at all — which is itself the case that
         * matters most, because a lost RESPONSE is indistinguishable from a lost
         * REQUEST from here.
         */
        fun <T> completionUnknown(status: Int, detail: String): CeremonyStep<T> =
            CeremonyStep(Kind.COMPLETION_UNKNOWN, null, status, detail)

        fun <T> deviceUnsupported(detail: String): CeremonyStep<T> =
            CeremonyStep(Kind.DEVICE_UNSUPPORTED, null, 0, detail)

        /** Carries a non-OK outcome across a change of value type. */
        fun <T> carryFailure(other: CeremonyStep<*>): CeremonyStep<T> =
            CeremonyStep(other.kind, null, other.status, other.detail)
    }
}
