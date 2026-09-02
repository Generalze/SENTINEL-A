package com.sentinel.field.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * ============================================================================
 * BYTE-IDENTICAL TO THE CONTRACT'S CANONICALISER.
 *
 * Every expected string in this file was produced by running the contract's own
 * algorithm — `JSON.stringify(sortKeysDeep(value))`, exactly as
 * `canonicalDeviceJson` defines it — on V8, and pasted here verbatim. They are
 * not what this implementation happens to output; that is the whole point of a
 * fixture. If a future edit changes this canonicaliser's behaviour, these fail.
 *
 * The escaping cases were checked against V8 code point by code point, which is
 * how the two surprising rules below were confirmed rather than assumed:
 *
 *   * 0x7F (DEL) is NOT escaped by `JSON.stringify`, even though it is a
 *     control character;
 *   * the six-character escape uses LOWERCASE hex.
 *
 * Every non-ASCII and control character in this file is written as a `\\u`
 * escape rather than as a literal, so no fixture here can be broken by a
 * file-encoding accident on somebody's checkout.
 * ============================================================================
 */
class CanonicalJsonTest {

    // -----------------------------------------------------------------------
    // Ordering
    // -----------------------------------------------------------------------

    @Test
    fun `object keys sort recursively and insertion order is irrelevant`() {
        assertEquals(
            """{"":5,"A":3,"_":4,"a":2,"b":1}""",
            CanonicalJson.encode(linkedMapOf("b" to 1, "a" to 2, "A" to 3, "_" to 4, "" to 5)),
        )
        // The same statement, built in a different order, is the same statement.
        assertEquals(
            CanonicalJson.encode(linkedMapOf("a" to 1, "b" to 2)),
            CanonicalJson.encode(linkedMapOf("b" to 2, "a" to 1)),
        )
    }

    @Test
    fun `ARRAY ORDER IS PRESERVED, and nested objects still sort`() {
        assertEquals(
            """{"arr":[3,1,2,{"a":2,"b":1}],"empty":{},"emptyArr":[],"f":false,"n":null,"t":true}""",
            CanonicalJson.encode(
                linkedMapOf(
                    "arr" to listOf(3, 1, 2, linkedMapOf("b" to 1, "a" to 2)),
                    "empty" to emptyMap<String, Any?>(),
                    "emptyArr" to emptyList<Any?>(),
                    "t" to true,
                    "f" to false,
                    "n" to null,
                ),
            ),
        )
    }

    @Test
    fun `sorting is by UTF-16 code unit, which is what JS does`() {
        // Uppercase sorts before lowercase, digits before letters, and `_`
        // (0x5F) falls between `Z` (0x5A) and `a` (0x61). A locale-aware
        // comparator would disagree, and a signature scheme cannot survive a
        // locale.
        assertEquals(
            """{"0":0,"Z":0,"_":0,"a":0,"z":0}""",
            CanonicalJson.encode(linkedMapOf("z" to 0, "a" to 0, "_" to 0, "Z" to 0, "0" to 0)),
        )
    }

    // -----------------------------------------------------------------------
    // Escaping
    // -----------------------------------------------------------------------

    @Test
    fun `string escaping matches JSON stringify exactly`() {
        val value = "\"" + "\\" +
            "\b" + "\t" + "\n" + "\u000C" + "\r" +
            "\u0001" + "\u001F" +
            "\u007F" +
            "\u00E9" + "\u4E2D"

        val expected = "{\"a\":\"" +
            "\\\"" +
            "\\\\" +
            "\\b" + "\\t" + "\\n" + "\\f" + "\\r" +
            "\\u0001" + "\\u001f" +
            "\u007F" +
            "\u00E9" + "\u4E2D" +
            "\"}"

        assertEquals(expected, CanonicalJson.encode(linkedMapOf("a" to value)))
    }

    @Test
    fun `keys are escaped by the same rules as values`() {
        assertEquals(
            """{"a\"b":1}""",
            CanonicalJson.encode(linkedMapOf("a\"b" to 1)),
        )
    }

    @Test
    fun `a lone surrogate takes the well-formed escape rather than corrupting the bytes`() {
        assertEquals(
            """{"a":"\ud800"}""",
            CanonicalJson.encode(linkedMapOf("a" to "\uD800")),
        )
        assertEquals(
            """{"a":"\udc00"}""",
            CanonicalJson.encode(linkedMapOf("a" to "\uDC00")),
        )
        // A genuine surrogate PAIR is emitted as the pair, not as two escapes.
        assertEquals(
            "{\"a\":\"\uD83D\uDE00\"}",
            CanonicalJson.encode(linkedMapOf("a" to "\uD83D\uDE00")),
        )
    }

    // -----------------------------------------------------------------------
    // Refusals
    // -----------------------------------------------------------------------

    @Test
    fun `values the contract refuses are refused here too`() {
        refuse("a Double") { CanonicalJson.encode(linkedMapOf("n" to 1.5)) }
        refuse("an integral Double") { CanonicalJson.encode(linkedMapOf("n" to 1.0)) }
        refuse("a Float") { CanonicalJson.encode(linkedMapOf("n" to 1.0f)) }
        refuse("NaN") { CanonicalJson.encode(linkedMapOf("n" to Double.NaN)) }
        refuse("a Date") { CanonicalJson.encode(linkedMapOf("d" to java.util.Date(0))) }
        refuse("a Set") { CanonicalJson.encode(linkedMapOf("s" to setOf(1))) }
        refuse("a non-string key") { CanonicalJson.encode(mapOf(1 to "a")) }
    }

    @Test
    fun `a cycle is refused rather than overflowing the stack`() {
        val cyclic = HashMap<String, Any?>()
        cyclic["self"] = cyclic
        refuse("a cycle") { CanonicalJson.encode(cyclic) }

        val cyclicList = ArrayList<Any?>()
        cyclicList.add(cyclicList)
        refuse("a cyclic list") { CanonicalJson.encode(cyclicList) }
    }

    @Test
    fun `two references to the same object are NOT a cycle`() {
        val shared = linkedMapOf("a" to 1)
        assertEquals(
            """{"x":{"a":1},"y":{"a":1}}""",
            CanonicalJson.encode(linkedMapOf("x" to shared, "y" to shared)),
        )
    }

    // -----------------------------------------------------------------------
    // Integers
    // -----------------------------------------------------------------------

    @Test
    fun `integers print exactly as JS prints them`() {
        assertEquals(
            """{"a":0,"b":-1,"c":1000000,"d":9007199254740991}""",
            CanonicalJson.encode(
                linkedMapOf("a" to 0, "b" to -1, "c" to 1_000_000, "d" to 9007199254740991L),
            ),
        )
    }

    @Test
    fun `top-level scalars encode without a wrapper`() {
        assertEquals("null", CanonicalJson.encode(null))
        assertEquals("\"x\"", CanonicalJson.encode("x"))
        assertEquals("true", CanonicalJson.encode(true))
        assertEquals("7", CanonicalJson.encode(7))
    }

    private fun refuse(what: String, block: () -> Unit) {
        try {
            block()
            fail("expected $what to be refused")
        } catch (expected: CanonicalJson.NotCanonicallyRepresentable) {
            assertTrue(expected.message!!.isNotEmpty())
        }
    }
}
