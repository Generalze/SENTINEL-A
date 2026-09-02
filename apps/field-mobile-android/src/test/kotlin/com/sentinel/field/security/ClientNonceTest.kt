package com.sentinel.field.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The two client-minted, non-authority values.
 *
 * A nonce that fell outside `DeviceNonceSchema`'s 16..256 bound, or a timestamp
 * that carried a local offset instead of `Z`, would be refused by the contract's
 * parse before any verifier was reached — and the refusal would be the same
 * opaque 403 as everything else, with nothing to debug from.
 */
class ClientNonceTest {

    @Test
    fun `a nonce is unpadded base64url inside the contract length bound`() {
        val nonce = ClientNonce.next()
        assertEquals(32, nonce.length)
        assertTrue(nonce.length in 16..256)
        assertTrue(nonce.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' })
        assertTrue(nonce.none { it == '=' || it == '+' || it == '/' })
    }

    @Test
    fun `nonces do not repeat`() {
        val seen = HashSet<String>()
        repeat(512) { seen.add(ClientNonce.next()) }
        assertEquals(512, seen.size)
    }

    @Test
    fun `the timestamp is the UTC shape the contract accepts`() {
        val now = ClientNonce.nowIso()
        // `z.string().datetime()` accepts `YYYY-MM-DDTHH:MM:SS(.fraction)?Z` and
        // REFUSES a local offset such as `+01:00`.
        assertTrue(now, Regex("""^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$""").matches(now))
    }
}
