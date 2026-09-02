package com.sentinel.field.security

import java.math.BigInteger
import java.security.MessageDigest
import java.util.Base64

/**
 * ============================================================================
 * THE ONE ACCEPTED P-256 PUBLIC KEY REPRESENTATION, AND THE DERIVED THUMBPRINT.
 *
 * C15-02 defines exactly one form: the uncompressed SEC1 point
 * `0x04 || X(32) || Y(32)`, 65 bytes, canonical unpadded base64url. A
 * COMPRESSED point names the same key with different bytes, so admitting both
 * would give one key two thumbprints and let a device present whichever one the
 * registry was not looking for; DER/SPKI and PEM are worse, because each admits
 * several encodings of one key. The server refuses all of them structurally, by
 * prefix and by length. This produces the accepted form and nothing else.
 *
 * `Signature.getInstance("SHA256withECDSA")` never sees this — it signs with the
 * keystore handle. What this exists for is the ENROLLMENT REQUEST's
 * `public_key` field and the `public_key_thumbprint` bound into the possession
 * statement, both of which the phone must produce in the server's exact bytes
 * before any signature it makes can be checked against the right key.
 *
 * THE THUMBPRINT IS COMPUTED, NEVER BELIEVED — on this side too. The contract
 * recomputes it from the key and refuses on disagreement, so a client that
 * derived it any other way simply fails; deriving it here from the same 65
 * bytes is the only way the two agree.
 *
 * Pure Kotlin: `BigInteger`, `MessageDigest` and `Base64` are all JDK types
 * present on Android since API 26 (`Base64`, `java.time`) or forever
 * (`MessageDigest`). Nothing here imports `android.*`, so the JVM tests cover
 * it exactly as it runs on a phone.
 * ============================================================================
 */
object CanonicalPublicKey {

    const val UNCOMPRESSED_PREFIX: Byte = 0x04
    const val COORDINATE_BYTES = 32
    const val PUBLIC_KEY_BYTES = 1 + COORDINATE_BYTES * 2

    /** 65 bytes encode to exactly 87 base64url characters with no padding. */
    const val PUBLIC_KEY_BASE64URL_LENGTH = 87

    /** The P-256 field prime. A coordinate is a field element, so it is `< p`. */
    val P256_FIELD_PRIME: BigInteger =
        BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)

    class MalformedPublicKey(message: String) : IllegalArgumentException(message)

    /** The canonical 65 bytes for an affine point. */
    fun uncompressedPointBytes(x: BigInteger, y: BigInteger): ByteArray {
        if (x.signum() < 0 || y.signum() < 0) {
            throw MalformedPublicKey("a coordinate is negative")
        }
        if (x >= P256_FIELD_PRIME || y >= P256_FIELD_PRIME) {
            throw MalformedPublicKey("a coordinate is not a P-256 field element")
        }
        if (x.signum() == 0 && y.signum() == 0) {
            // The point at infinity has no uncompressed encoding and (0, 0) is
            // not on the curve. The server refuses it; so does this.
            throw MalformedPublicKey("(0, 0) is not a P-256 point")
        }
        val bytes = ByteArray(PUBLIC_KEY_BYTES)
        bytes[0] = UNCOMPRESSED_PREFIX
        writeCoordinate(x, bytes, 1)
        writeCoordinate(y, bytes, 1 + COORDINATE_BYTES)
        return bytes
    }

    /** The canonical wire form of an affine point. */
    fun encode(x: BigInteger, y: BigInteger): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(uncompressedPointBytes(x, y))

    /**
     * SHA-256, lowercase hex, over the canonical 65 key bytes.
     *
     * The input is the WIRE STRING rather than the point, so this derives the
     * thumbprint from precisely the value that was transmitted — a thumbprint
     * computed from a differently-encoded copy of the same key would be a second
     * opinion about the key's name.
     */
    fun thumbprint(canonicalPublicKey: String): String {
        val bytes = decode(canonicalPublicKey)
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return toLowercaseHex(digest)
    }

    /** Decodes and structurally validates a canonical wire public key. */
    fun decode(canonicalPublicKey: String): ByteArray {
        if (canonicalPublicKey.length != PUBLIC_KEY_BASE64URL_LENGTH) {
            throw MalformedPublicKey("a canonical public key is $PUBLIC_KEY_BASE64URL_LENGTH characters")
        }
        for (c in canonicalPublicKey) {
            val ok = (c in 'A'..'Z') || (c in 'a'..'z') || (c in '0'..'9') || c == '-' || c == '_'
            if (!ok) throw MalformedPublicKey("a canonical public key is unpadded base64url")
        }
        val bytes = try {
            Base64.getUrlDecoder().decode(canonicalPublicKey)
        } catch (error: IllegalArgumentException) {
            throw MalformedPublicKey("a canonical public key is unpadded base64url")
        }
        if (bytes.size != PUBLIC_KEY_BYTES) {
            throw MalformedPublicKey("a canonical public key is $PUBLIC_KEY_BYTES bytes")
        }
        if (bytes[0] != UNCOMPRESSED_PREFIX) {
            throw MalformedPublicKey("a canonical public key is an uncompressed SEC1 point")
        }
        return bytes
    }

    /** SHA-256 hex over arbitrary bytes, in the one hex shape the platform uses. */
    fun sha256Hex(input: ByteArray): String =
        toLowercaseHex(MessageDigest.getInstance("SHA-256").digest(input))

    /** SHA-256 hex over the UTF-8 bytes of a canonical statement. */
    fun sha256HexUtf8(input: String): String =
        sha256Hex(input.toByteArray(Charsets.UTF_8))

    private const val HEX = "0123456789abcdef"

    private fun toLowercaseHex(bytes: ByteArray): String {
        val out = StringBuilder(bytes.size * 2)
        for (byte in bytes) {
            val value = byte.toInt() and 0xFF
            out.append(HEX[value shr 4]).append(HEX[value and 0x0F])
        }
        return out.toString()
    }

    private fun writeCoordinate(value: BigInteger, out: ByteArray, offset: Int) {
        val raw = value.toByteArray()
        var start = 0
        var length = raw.size
        if (length > COORDINATE_BYTES) {
            val excess = length - COORDINATE_BYTES
            for (index in 0 until excess) {
                if (raw[index] != 0.toByte()) {
                    throw MalformedPublicKey("coordinate does not fit in $COORDINATE_BYTES bytes")
                }
            }
            start = excess
            length = COORDINATE_BYTES
        }
        System.arraycopy(raw, start, out, offset + (COORDINATE_BYTES - length), length)
    }
}
