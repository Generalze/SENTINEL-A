package com.sentinel.field.net

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The explicit, by-name response readers.
 *
 * Every value this client goes on to SIGN is read out by name through these, and
 * never by re-serialising a parsed response. The cases below are the ones that
 * would otherwise turn a missing or null field into a plausible-looking string:
 * `JsonNull.content` is the four characters `null`, so a reader that reached for
 * `content` directly would put the WORD "null" into a signed statement and the
 * server would refuse a signature over bytes nobody could explain.
 */
class ResponseReaderTest {

    private fun parse(text: String) = Json.parseToJsonElement(text).jsonObject

    @Test
    fun `text reads a string field`() {
        assertEquals("v", parse("""{"k":"v"}""").text("k"))
    }

    @Test
    fun `a JSON null is null, not the word null`() {
        val body = parse("""{"k":null}""")
        assertNull(body.textOrNull("k"))
        assertNull(body.intOrNull("k"))
    }

    @Test
    fun `an absent field is null`() {
        assertNull(parse("""{}""").textOrNull("k"))
    }

    @Test
    fun `text throws rather than inventing a value`() {
        try {
            parse("""{}""").text("k")
            throw AssertionError("expected a missing field to throw")
        } catch (expected: IllegalStateException) {
            assertTrue(expected.message!!.contains("k"))
        }
    }

    @Test
    fun `int reads a JSON number and refuses a non-number`() {
        assertEquals(7, parse("""{"n":7}""").intOrNull("n"))
        assertNull(parse("""{"n":"seven"}""").intOrNull("n"))
        assertNull(parse("""{"n":1.5}""").intOrNull("n"))
    }

    @Test
    fun `an object or array field does not masquerade as a string`() {
        assertNull(parse("""{"k":{"a":1}}""").textOrNull("k"))
        assertNull(parse("""{"k":[1,2]}""").textOrNull("k"))
    }
}
