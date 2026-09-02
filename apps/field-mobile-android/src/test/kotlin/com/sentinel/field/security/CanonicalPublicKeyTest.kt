package com.sentinel.field.security

import java.math.BigInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * ============================================================================
 * C15-02: ONE REPRESENTATION, ONE BYTE IDENTITY, ONE THUMBPRINT.
 *
 * The vectors are the P-256 BASE POINT G, whose coordinates are published in
 * SEC 2 and FIPS 186-4 and are therefore checkable by a reviewer without
 * running anything, plus a synthetic point that exercises left-padding. The
 * expected encodings and digests were computed by the contract's own recipe.
 * ============================================================================
 */
class CanonicalPublicKeyTest {

    private val gx = BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16)
    private val gy = BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)

    private val gEncoded =
        "BGsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
    private val gThumbprint = "698bea63dc44a344663ff1429aea10842df27b6b991ef25866b2c6c02cdcc5be"

    @Test
    fun `the base point encodes to the canonical uncompressed form`() {
        assertEquals(gEncoded, CanonicalPublicKey.encode(gx, gy))
        assertEquals(CanonicalPublicKey.PUBLIC_KEY_BASE64URL_LENGTH, gEncoded.length)
        assertEquals(CanonicalPublicKey.PUBLIC_KEY_BYTES, CanonicalPublicKey.decode(gEncoded).size)
        assertEquals(0x04.toByte(), CanonicalPublicKey.decode(gEncoded)[0])
    }

    @Test
    fun `the thumbprint is SHA-256 over the canonical 65 bytes, in lowercase hex`() {
        assertEquals(gThumbprint, CanonicalPublicKey.thumbprint(gEncoded))
        assertEquals(64, gThumbprint.length)
        assertTrue(gThumbprint.all { it in '0'..'9' || it in 'a'..'f' })
    }

    @Test
    fun `small coordinates are LEFT-PADDED to 32 bytes each`() {
        // x = 1, y = 2. A naive right-aligned copy would emit a shorter point,
        // or the same key under different bytes — which is exactly the
        // "one key, two thumbprints" failure C15-02 exists to prevent.
        val encoded = CanonicalPublicKey.encode(BigInteger.ONE, BigInteger.valueOf(2))
        assertEquals(
            "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI",
            encoded,
        )
        assertEquals(
            "dd35e3ee66ab959f257120c7125d48a15e690be558d55e744ba18e60999f2ebb",
            CanonicalPublicKey.thumbprint(encoded),
        )
    }

    @Test
    fun `the encoding is unpadded base64url and never standard base64`() {
        val encoded = CanonicalPublicKey.encode(gx, gy)
        assertTrue(encoded.none { it == '=' || it == '+' || it == '/' })
    }

    @Test
    fun `degenerate and out-of-range coordinates are refused`() {
        refuse("(0, 0)") { CanonicalPublicKey.encode(BigInteger.ZERO, BigInteger.ZERO) }
        refuse("x >= p") { CanonicalPublicKey.encode(CanonicalPublicKey.P256_FIELD_PRIME, gy) }
        refuse("y >= p") { CanonicalPublicKey.encode(gx, CanonicalPublicKey.P256_FIELD_PRIME) }
        refuse("negative x") { CanonicalPublicKey.encode(BigInteger.ONE.negate(), gy) }
    }

    @Test
    fun `a COMPRESSED point is not an alternate accepted input`() {
        // 33 bytes, prefix 0x02: the SAME key, DIFFERENT bytes. Admitting it
        // would give one key two thumbprints, and a device could then present
        // whichever the registry was not looking for.
        val compressed = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
            ByteArray(33) { if (it == 0) 0x02.toByte() else 0x11.toByte() },
        )
        refuse("a compressed point") { CanonicalPublicKey.decode(compressed) }
    }

    @Test
    fun `padded, non-base64url and wrong-length encodings are refused`() {
        refuse("padded") { CanonicalPublicKey.decode(gEncoded.dropLast(1) + "=") }
        refuse("standard base64 alphabet") { CanonicalPublicKey.decode(gEncoded.dropLast(1) + "+") }
        refuse("too short") { CanonicalPublicKey.decode(gEncoded.dropLast(1)) }
        refuse("too long") { CanonicalPublicKey.decode(gEncoded + "A") }
    }

    @Test
    fun `a point with a wrong prefix byte is refused`() {
        val bytes = CanonicalPublicKey.decode(gEncoded)
        bytes[0] = 0x03
        val wrongPrefix = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        refuse("prefix 0x03 at 65 bytes") { CanonicalPublicKey.decode(wrongPrefix) }
    }

    @Test
    fun `sha256HexUtf8 hashes UTF-8 bytes, which is what the contract does`() {
        // `createHash('sha256').update(input, 'utf8')`.
        assertEquals(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            CanonicalPublicKey.sha256HexUtf8("hello"),
        )
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            CanonicalPublicKey.sha256HexUtf8(""),
        )
    }

    private fun refuse(what: String, block: () -> Unit) {
        try {
            block()
            fail("expected $what to be refused")
        } catch (expected: CanonicalPublicKey.MalformedPublicKey) {
            assertTrue(expected.message!!.isNotEmpty())
        }
    }
}
