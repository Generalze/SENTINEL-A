package com.sentinel.field.net

/**
 * ============================================================================
 * THE RESULT OF ONE STEP OF THE CEREMONY.
 *
 * Three outcomes, and only three:
 *
 *   OK                    the server answered, and the answer parsed.
 *
 *   REFUSED               everything else the SERVER can say. D25-13's
 *                         discipline, inherited by the enrollment ingress: a
 *                         dead grant, a foreign tenant, a spent challenge, an
 *                         expired one, a chain that does not verify and a
 *                         session that is not the intended user all shape the
 *                         SAME external refusal, with the same body. There is
 *                         nothing to branch on and this client does not pretend
 *                         otherwise — `detail` is for a human reading a log,
 *                         never for a code path.
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

    enum class Kind { OK, REFUSED, DEVICE_UNSUPPORTED }

    val isOk: Boolean get() = kind == Kind.OK

    val isDeviceUnsupported: Boolean get() = kind == Kind.DEVICE_UNSUPPORTED

    /** The carried value. Call only after checking [isOk]. */
    fun valueOrThrow(): T =
        carried ?: throw IllegalStateException("the ceremony step did not succeed: $kind $detail")

    /** The carried value, or null on any non-OK outcome. */
    fun valueOrNull(): T? = carried

    fun describe(): String = when (kind) {
        Kind.OK -> "ok"
        Kind.REFUSED -> "refused ($status): $detail"
        Kind.DEVICE_UNSUPPORTED -> "DEVICE UNSUPPORTED: $detail"
    }

    companion object {
        fun <T> ok(value: T): CeremonyStep<T> = CeremonyStep(Kind.OK, value, 200, "")

        fun <T> refused(status: Int, detail: String): CeremonyStep<T> =
            CeremonyStep(Kind.REFUSED, null, status, detail)

        fun <T> deviceUnsupported(detail: String): CeremonyStep<T> =
            CeremonyStep(Kind.DEVICE_UNSUPPORTED, null, 0, detail)

        /** Carries a non-OK outcome across a change of value type. */
        fun <T> carryFailure(other: CeremonyStep<*>): CeremonyStep<T> =
            CeremonyStep(other.kind, null, other.status, other.detail)
    }
}
