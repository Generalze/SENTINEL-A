package com.sentinel.field.security

import java.security.SecureRandom
import java.time.Instant
import java.util.Base64

/**
 * The client-minted values that are NOT secrets and NOT authority: the
 * per-proof nonce, and the client's claimed mint time.
 *
 * `DeviceRequestProof.nonce` is one-shot and scoped by the SERVER to the
 * identity that consumes it (D23-12) — the device does not get to decide that a
 * nonce is fresh, only that it is unpredictable. 24 bytes of `SecureRandom`
 * encode to 32 unpadded base64url characters, comfortably inside
 * `DeviceNonceSchema`'s 16..256 bound.
 *
 * `issued_at` is CLIENT-CLAIMED and is judged against the SERVER clock, never
 * trusted as authority: the frozen bounds are 60 s of age and 5 s of future
 * skew. A handset with a badly wrong clock will therefore be refused, and that
 * refusal is correct — it is also, in practice, the first thing to check when a
 * physically present device is being refused for no visible reason.
 */
object ClientNonce {

    private const val NONCE_BYTES = 24

    private val random = SecureRandom()

    /** A fresh, unpredictable, unpadded base64url nonce. */
    fun next(): String {
        val bytes = ByteArray(NONCE_BYTES)
        random.nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    /**
     * The current instant in the shape every Sentinel timestamp takes.
     *
     * `Instant.toString()` produces ISO-8601 with a `Z` suffix and 0, 3, 6 or 9
     * fractional digits, which is exactly what the contract's
     * `z.string().datetime()` accepts. A local-offset format (`+01:00`) is NOT
     * accepted, which is why this never goes near `OffsetDateTime` or a
     * user-facing formatter.
     */
    fun nowIso(): String = Instant.now().toString()
}
