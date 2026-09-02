package com.sentinel.field.security

import java.math.BigInteger
import java.util.Base64

/**
 * ============================================================================
 * DER -> IEEE P1363, AND LOW-S CANONICALISATION.
 *
 * THE MISMATCH THIS FILE EXISTS TO CLOSE
 * --------------------------------------
 * Android's `Signature.getInstance("SHA256withECDSA")` emits an X9.62 DER
 * `SEQUENCE { INTEGER r, INTEGER s }`. `packages/contracts/src/device-signature.ts`
 * accepts exactly one representation and it is not that one:
 *
 *     IEEE P1363 raw `r || s`, 64 bytes, canonical UNPADDED base64url, LOW-S.
 *
 * and it says so in as many words — "DER is not an alternate accepted input; it
 * is a different length and fails here like any other malformed value". A client
 * that posts what the platform handed it produces a signature the server refuses
 * `WRONG_LENGTH`, every time, with no partial success to debug from.
 *
 * WHY LOW-S IS THE SIGNER'S JOB AND NOT THE VERIFIER'S
 * ---------------------------------------------------
 * `(r, s)` and `(r, n - s)` are both valid ECDSA signatures over the same
 * message under the same key. The contract REFUSES a high-S value outright
 * (`S_NOT_LOW`) rather than normalising it, because a verifier that normalised
 * would accept two distinct wire values for one signature — which is exactly
 * the malleability the single-representation rule removes. The contract's own
 * `lowSCanonicaliseForSigning` is marked SIGNER-SIDE ONLY for that reason. This
 * is the signer. Choosing between two equivalent forms is legitimate here and
 * only here, and roughly half of all hardware signatures need it, so a client
 * that skips this step fails intermittently — the worst possible failure mode.
 *
 * EVERYTHING IN THIS FILE IS PURE KOTLIN. It touches no key, no keystore and no
 * Android API, so the JVM unit tests cover it completely: the boundary
 * `s == floor(n/2)`, the value one above it, `s == n - 1`, minimal-length
 * scalars, 33-byte DER integers with a leading zero, and every malformed
 * encoding. That coverage is the point of keeping it separate from
 * `StrongBoxKeyManager`.
 * ============================================================================
 */
object CanonicalSignature {

    /** Order of the P-256 base point. Copied from `device-signature.ts`. */
    val P256_CURVE_ORDER: BigInteger =
        BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

    /** `floor(n/2)`. A signature is low-S when `s <= this` — INCLUSIVE. */
    val P256_HALF_CURVE_ORDER: BigInteger =
        BigInteger("7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8", 16)

    const val P256_SCALAR_BYTES = 32
    const val P256_SIGNATURE_BYTES = P256_SCALAR_BYTES * 2

    /** 64 bytes encode to exactly 86 base64url characters with no padding. */
    const val P256_SIGNATURE_BASE64URL_LENGTH = 86

    /** Raised for any DER the contract's decoder would also refuse downstream. */
    class MalformedSignature(message: String) : IllegalArgumentException(message)

    /** A decoded pair of scalars. */
    data class Scalars(val r: BigInteger, val s: BigInteger)

    /**
     * The one call a signing path should make: platform DER in, wire form out.
     *
     * It parses, range-checks, canonicalises `s` to the low half, and encodes.
     * There is deliberately no variant that skips the low-S step.
     */
    fun canonicalWireSignature(derSignature: ByteArray): String {
        val scalars = parseDerSignature(derSignature)
        return encodeP1363(scalars.r, lowSCanonicaliseForSigning(scalars.s))
    }

    /** True when `s` is already in the accepted lower half of the order. */
    fun isLowS(s: BigInteger): Boolean =
        s >= BigInteger.ONE && s <= P256_HALF_CURVE_ORDER

    /**
     * SIGNER-SIDE ONLY. `s` if it is already low, `n - s` otherwise.
     *
     * The exact boundary is the case worth stating: `floor(n/2)` IS low-S and
     * is returned unchanged. `floor(n/2) + 1` is the smallest high-S value, and
     * because `n = 2 * floor(n/2) + 1`, it maps back to `floor(n/2)` exactly.
     * An off-by-one either way here produces signatures that verify
     * mathematically and are refused by the contract.
     */
    fun lowSCanonicaliseForSigning(s: BigInteger): BigInteger {
        if (s < BigInteger.ONE || s >= P256_CURVE_ORDER) {
            throw MalformedSignature("s is outside the P-256 scalar range")
        }
        return if (s > P256_HALF_CURVE_ORDER) P256_CURVE_ORDER.subtract(s) else s
    }

    /**
     * Encodes `r || s` as the contract's one accepted wire form.
     *
     * Refuses anything `decodeCanonicalP256Signature` would refuse, so a value
     * this function returns is a value the server can decode — the client-side
     * half of "the parse IS the boundary".
     */
    fun encodeP1363(r: BigInteger, s: BigInteger): String {
        if (r < BigInteger.ONE || r >= P256_CURVE_ORDER) {
            throw MalformedSignature("r is outside the P-256 scalar range")
        }
        if (!isLowS(s)) {
            throw MalformedSignature("s must be low-S; canonicalise on the signer before encoding")
        }
        val bytes = ByteArray(P256_SIGNATURE_BYTES)
        writeScalar(r, bytes, 0)
        writeScalar(s, bytes, P256_SCALAR_BYTES)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    /**
     * A non-negative scalar as a fixed-width 32-byte big-endian field.
     *
     * `BigInteger.toByteArray()` is two's complement, so it returns 33 bytes
     * with a leading `0x00` whenever the top bit of the value is set, and fewer
     * than 32 bytes for a small value. Both cases are handled explicitly; a
     * naive `copyInto` gets the second one wrong by right-aligning nothing and
     * silently emits a signature for a different scalar.
     */
    private fun writeScalar(value: BigInteger, out: ByteArray, offset: Int) {
        val raw = value.toByteArray()
        var start = 0
        var length = raw.size
        if (length > P256_SCALAR_BYTES) {
            // Only a single leading sign byte may be dropped, and only if it is
            // zero. Anything else means the value does not fit, which is a bug
            // rather than something to trim.
            val excess = length - P256_SCALAR_BYTES
            for (index in 0 until excess) {
                if (raw[index] != 0.toByte()) {
                    throw MalformedSignature("scalar does not fit in $P256_SCALAR_BYTES bytes")
                }
            }
            start = excess
            length = P256_SCALAR_BYTES
        }
        val destination = offset + (P256_SCALAR_BYTES - length)
        System.arraycopy(raw, start, out, destination, length)
    }

    /**
     * Strict X9.62 DER: `30 <len> 02 <len> r 02 <len> s`, and nothing else.
     *
     * Strict, because a lenient parser is how a client ends up signing one thing
     * and transmitting another. Specifically refused: a wrong outer tag, a
     * length that does not describe the buffer, trailing bytes after the
     * SEQUENCE, an empty INTEGER, a NEGATIVE INTEGER (top bit set with no `0x00`
     * prefix), and a non-minimal INTEGER (`0x00` followed by a byte under
     * `0x80`). None of these can come out of a conforming AndroidKeyStore
     * provider; if one does, that is a fact worth failing on rather than
     * papering over.
     */
    fun parseDerSignature(der: ByteArray): Scalars {
        var cursor = 0

        fun demand(condition: Boolean, message: String) {
            if (!condition) throw MalformedSignature(message)
        }

        fun readByte(what: String): Int {
            demand(cursor < der.size, "truncated DER while reading $what")
            val value = der[cursor].toInt() and 0xFF
            cursor += 1
            return value
        }

        fun readLength(what: String): Int {
            val first = readByte("$what length")
            if (first < 0x80) return first
            val byteCount = first and 0x7F
            demand(byteCount in 1..2, "unsupported DER long-form length for $what")
            var length = 0
            for (index in 0 until byteCount) {
                length = (length shl 8) or readByte("$what length")
            }
            // DER requires the shortest length encoding.
            demand(byteCount == 1 || length > 0xFF, "non-minimal DER length for $what")
            demand(length >= 0x80, "non-minimal DER length for $what")
            return length
        }

        fun readInteger(): BigInteger {
            demand(readByte("INTEGER tag") == 0x02, "expected a DER INTEGER")
            val length = readLength("INTEGER")
            demand(length > 0, "empty DER INTEGER")
            demand(cursor + length <= der.size, "truncated DER INTEGER")
            val first = der[cursor].toInt() and 0xFF
            demand(first < 0x80, "negative DER INTEGER in an ECDSA signature")
            if (first == 0x00) {
                demand(length > 1, "DER INTEGER encoded as a bare zero pad")
                val second = der[cursor + 1].toInt() and 0xFF
                demand(second >= 0x80, "non-minimal DER INTEGER")
            }
            val content = ByteArray(length)
            System.arraycopy(der, cursor, content, 0, length)
            cursor += length
            return BigInteger(1, content)
        }

        demand(readByte("SEQUENCE tag") == 0x30, "expected a DER SEQUENCE")
        val sequenceLength = readLength("SEQUENCE")
        val contentStart = cursor
        demand(contentStart + sequenceLength == der.size, "DER SEQUENCE length does not describe the buffer")

        val r = readInteger()
        val s = readInteger()
        demand(cursor == der.size, "trailing bytes after the DER SEQUENCE")

        // Range, before anything downstream can treat these as scalars. Zero is
        // refused here rather than by the server, which would answer with an
        // indistinguishable refusal and no reason.
        demand(r >= BigInteger.ONE && r < P256_CURVE_ORDER, "r is outside the P-256 scalar range")
        demand(s >= BigInteger.ONE && s < P256_CURVE_ORDER, "s is outside the P-256 scalar range")
        return Scalars(r, s)
    }
}
