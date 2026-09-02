package com.sentinel.field.security

import java.math.BigInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * ============================================================================
 * THE SINGLE MOST LIKELY PLACE TO GET WP-26 WRONG, TESTED HARD.
 *
 * Two independent mistakes both produce signatures that are mathematically
 * valid and that the contract refuses:
 *
 *   1. transmitting DER instead of IEEE P1363 — refused `WRONG_LENGTH`, every
 *      time, deterministically;
 *   2. transmitting a high-S value — refused `S_NOT_LOW`, roughly HALF the
 *      time, which is far worse because it looks like flakiness.
 *
 * Both are fully testable on the JVM, and this file tests both, including the
 * exact boundary `s == floor(n/2)` — which is LOW-S and must be left alone —
 * and `floor(n/2) + 1`, the smallest value that must be flipped.
 *
 * THE FIXTURES ARE NOT INVENTED. The two `SAMPLE_*` vectors are real
 * `SHA256withECDSA` signatures produced by Node's OpenSSL over a P-256 key, and
 * their expected wire forms were computed by the same algorithm the contract
 * uses. The synthetic boundary vectors were computed the same way.
 * ============================================================================
 */
class CanonicalSignatureTest {

    private val n = CanonicalSignature.P256_CURVE_ORDER
    private val half = CanonicalSignature.P256_HALF_CURVE_ORDER

    // -----------------------------------------------------------------------
    // The curve constants themselves
    // -----------------------------------------------------------------------

    @Test
    fun `the half order is exactly floor of n over 2`() {
        assertEquals(n, half.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE))
        assertEquals(n.shiftRight(1), half)
    }

    // -----------------------------------------------------------------------
    // Real platform signatures
    // -----------------------------------------------------------------------

    /** A genuine ECDSA/SHA-256 DER signature whose `s` is ALREADY low. */
    private val sampleLowDer = hex(
        "3045022100ad7d021d8678b564e051cc15cfe15869a4eb9e6ca3a4cd731193dd9b27556de7" +
            "022013ffcbb811d9218acf518111cf97644288d57ededb369bcc51bd94a2270fb889",
    )
    private val sampleLowWire =
        "rX0CHYZ4tWTgUcwVz-FYaaTrnmyjpM1zEZPdmydVbecT_8u4Edkhis9RgRHPl2RCiNV-3ts2m8xRvZSiJw-4iQ"

    /** A genuine ECDSA/SHA-256 DER signature whose `s` is HIGH and must flip. */
    private val sampleHighDer = hex(
        "3046022100fb71a51096c7d3fe946410d6658cc616b9122c463a596c1ca22b9f86b72d8577" +
            "0221008e589df0a561448a7f0f0b9f02e2ae40025e5483261f4777144b21a91a577e32",
    )
    private val sampleHighWire =
        "-3GlEJbH0_6UZBDWZYzGFrkSLEY6WWwcoiufhrcthXdxp2IOWp67doDw9GD9HVG_uoimKoD4Vw3fbqkZ4gunHw"

    @Test
    fun `an already-low real signature converts to the contract wire form`() {
        assertEquals(sampleLowWire, CanonicalSignature.canonicalWireSignature(sampleLowDer))
    }

    @Test
    fun `a high-S real signature is flipped, and the flip changes the bytes`() {
        val scalars = CanonicalSignature.parseDerSignature(sampleHighDer)
        assertTrue("the fixture must actually be high-S", scalars.s > half)
        val wire = CanonicalSignature.canonicalWireSignature(sampleHighDer)
        assertEquals(sampleHighWire, wire)
        // The naive answer — concatenating the platform's own r and s without
        // flipping — is a DIFFERENT 86-character value, and it is the one the
        // contract refuses `S_NOT_LOW`. Roughly half of all real signatures
        // take this branch, which is why skipping the flip reads as flakiness.
        assertNotEquals(unflipped(scalars.r, scalars.s), wire)
        assertEquals(CanonicalSignature.P256_SIGNATURE_BASE64URL_LENGTH, unflipped(scalars.r, scalars.s).length)
    }

    @Test
    fun `every produced signature is 86 unpadded base64url characters`() {
        for (der in listOf(sampleLowDer, sampleHighDer)) {
            val wire = CanonicalSignature.canonicalWireSignature(der)
            assertEquals(CanonicalSignature.P256_SIGNATURE_BASE64URL_LENGTH, wire.length)
            assertTrue(wire.none { it == '=' })
            assertTrue(wire.all { it.isLetterOrDigit() || it == '-' || it == '_' })
            // The contract additionally refuses `+` and `/`; base64url must not
            // emit them, and a mistaken `getEncoder()` would.
            assertTrue(wire.none { it == '+' || it == '/' })
        }
    }

    // -----------------------------------------------------------------------
    // The low-S boundary — the one that is easy to get wrong by one
    // -----------------------------------------------------------------------

    @Test
    fun `s equal to floor n over 2 is LOW-S and is left untouched`() {
        assertTrue(CanonicalSignature.isLowS(half))
        assertEquals(half, CanonicalSignature.lowSCanonicaliseForSigning(half))
        assertEquals(
            "_____wAAAAD__________7zm-q2nF56E87nKwvxjJVB_____gAAAAH__________3nN9VtOLz0J53OVhfjGSqA",
            CanonicalSignature.canonicalWireSignature(der(n.subtract(BigInteger.ONE), half)),
        )
    }

    @Test
    fun `s one above the boundary is the smallest high-S value and flips back to the boundary`() {
        val justHigh = half.add(BigInteger.ONE)
        assertTrue(justHigh > half)
        assertEquals(half, CanonicalSignature.lowSCanonicaliseForSigning(justHigh))
        assertEquals(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJ_____gAAAAH__________3nN9VtOLz0J53OVhfjGSqA",
            CanonicalSignature.canonicalWireSignature(der(BigInteger.valueOf(2), justHigh)),
        )
    }

    @Test
    fun `s equal to n minus one flips to one`() {
        assertEquals(BigInteger.ONE, CanonicalSignature.lowSCanonicaliseForSigning(n.subtract(BigInteger.ONE)))
        assertEquals(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ",
            CanonicalSignature.canonicalWireSignature(der(BigInteger.valueOf(3), n.subtract(BigInteger.ONE))),
        )
    }

    @Test
    fun `minimal scalars are left-padded to 32 bytes each`() {
        assertEquals(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ",
            CanonicalSignature.canonicalWireSignature(der(BigInteger.ONE, BigInteger.ONE)),
        )
    }

    @Test
    fun `low-S canonicalisation is idempotent`() {
        for (s in listOf(BigInteger.ONE, half, half.add(BigInteger.ONE), n.subtract(BigInteger.ONE))) {
            val once = CanonicalSignature.lowSCanonicaliseForSigning(s)
            assertEquals(once, CanonicalSignature.lowSCanonicaliseForSigning(once))
            assertTrue(CanonicalSignature.isLowS(once))
        }
    }

    // -----------------------------------------------------------------------
    // Out-of-range scalars
    // -----------------------------------------------------------------------

    @Test
    fun `zero and out-of-range scalars are refused`() {
        expectMalformed("r = 0") { CanonicalSignature.parseDerSignature(der(BigInteger.ZERO, BigInteger.ONE)) }
        expectMalformed("s = 0") { CanonicalSignature.parseDerSignature(der(BigInteger.ONE, BigInteger.ZERO)) }
        expectMalformed("r = n") { CanonicalSignature.parseDerSignature(der(n, BigInteger.ONE)) }
        expectMalformed("s = n") { CanonicalSignature.parseDerSignature(der(BigInteger.ONE, n)) }
        expectMalformed("s below 1") { CanonicalSignature.lowSCanonicaliseForSigning(BigInteger.ZERO) }
        expectMalformed("s at n") { CanonicalSignature.lowSCanonicaliseForSigning(n) }
    }

    @Test
    fun `encodeP1363 refuses a high-S value rather than silently fixing it`() {
        // The asymmetry is the point: canonicalisation is an explicit signer-side
        // decision, and the encoder does not make it on somebody's behalf.
        expectMalformed("high S at the encoder") {
            CanonicalSignature.encodeP1363(BigInteger.ONE, half.add(BigInteger.ONE))
        }
    }

    // -----------------------------------------------------------------------
    // Malformed DER
    // -----------------------------------------------------------------------

    @Test
    fun `malformed DER is refused rather than half-interpreted`() {
        val good = der(BigInteger.valueOf(2), BigInteger.valueOf(3))

        expectMalformed("empty") { CanonicalSignature.parseDerSignature(ByteArray(0)) }

        val wrongOuterTag = good.copyOf()
        wrongOuterTag[0] = 0x31
        expectMalformed("wrong SEQUENCE tag") { CanonicalSignature.parseDerSignature(wrongOuterTag) }

        val wrongInnerTag = good.copyOf()
        wrongInnerTag[2] = 0x04
        expectMalformed("wrong INTEGER tag") { CanonicalSignature.parseDerSignature(wrongInnerTag) }

        expectMalformed("truncated") { CanonicalSignature.parseDerSignature(good.copyOf(good.size - 1)) }
        expectMalformed("trailing bytes") { CanonicalSignature.parseDerSignature(good + byteArrayOf(0x00)) }

        val lyingLength = good.copyOf()
        lyingLength[1] = (lyingLength[1] + 1).toByte()
        expectMalformed("SEQUENCE length disagrees with the buffer") {
            CanonicalSignature.parseDerSignature(lyingLength)
        }

        // 30 06 02 00 02 01 03 — an EMPTY INTEGER.
        expectMalformed("empty INTEGER") {
            CanonicalSignature.parseDerSignature(hex("3005020002010"+"3"))
        }

        // 30 07 02 02 00 02 02 01 03 — `00 02` is non-minimal (the leading zero
        // is unnecessary because 0x02 < 0x80).
        expectMalformed("non-minimal INTEGER") {
            CanonicalSignature.parseDerSignature(hex("3007020200020201" + "03"))
        }

        // A NEGATIVE INTEGER: 0x81 with no 0x00 prefix.
        expectMalformed("negative INTEGER") {
            CanonicalSignature.parseDerSignature(hex("3006020181020103"))
        }
    }

    @Test
    fun `a 33-byte DER integer with a leading zero round-trips to 32 bytes`() {
        // Any scalar whose top bit is set gets a `0x00` sign prefix in DER; both
        // real fixtures above have one for `r`, which is why they are 71 and 72
        // bytes rather than 70.
        val topBitSet = BigInteger(1, ByteArray(32) { if (it == 0) 0xF0.toByte() else 0x11.toByte() })
        val encoded = der(topBitSet, BigInteger.ONE)
        assertEquals(0x00.toByte(), encoded[4])
        val scalars = CanonicalSignature.parseDerSignature(encoded)
        assertEquals(topBitSet, scalars.r)
        assertEquals(
            CanonicalSignature.P256_SIGNATURE_BASE64URL_LENGTH,
            CanonicalSignature.encodeP1363(scalars.r, scalars.s).length,
        )
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private fun expectMalformed(what: String, block: () -> Unit) {
        try {
            block()
            fail("expected $what to be refused")
        } catch (expected: CanonicalSignature.MalformedSignature) {
            // The refusal this test exists to demand.
            assertTrue(expected.message!!.isNotEmpty())
        }
    }

    /**
     * Builds an X9.62 DER signature for arbitrary scalars.
     *
     * `BigInteger.toByteArray()` on a non-negative value is already the minimal
     * two's-complement big-endian encoding a DER INTEGER's content must be, so
     * this needs no padding logic of its own — which is what makes it a usable
     * independent check on the parser.
     */
    private fun der(r: BigInteger, s: BigInteger): ByteArray {
        val content = derInteger(r) + derInteger(s)
        check(content.size < 0x80) { "the test builder only emits short-form lengths" }
        return byteArrayOf(0x30, content.size.toByte()) + content
    }

    private fun derInteger(value: BigInteger): ByteArray {
        val magnitude = value.toByteArray()
        return byteArrayOf(0x02, magnitude.size.toByte()) + magnitude
    }

    /** The wire form WITHOUT the low-S step: what a naive client would send. */
    private fun unflipped(r: BigInteger, s: BigInteger): String {
        val bytes = ByteArray(CanonicalSignature.P256_SIGNATURE_BYTES)
        pad(r).copyInto(bytes, 0)
        pad(s).copyInto(bytes, CanonicalSignature.P256_SCALAR_BYTES)
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    private fun pad(value: BigInteger): ByteArray {
        val raw = value.toByteArray()
        val out = ByteArray(CanonicalSignature.P256_SCALAR_BYTES)
        val source = if (raw.size > out.size) raw.copyOfRange(raw.size - out.size, raw.size) else raw
        source.copyInto(out, out.size - source.size)
        return out
    }

    private fun hex(text: String): ByteArray {
        require(text.length % 2 == 0)
        val out = ByteArray(text.length / 2)
        for (index in out.indices) {
            out[index] = text.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
        return out
    }
}
