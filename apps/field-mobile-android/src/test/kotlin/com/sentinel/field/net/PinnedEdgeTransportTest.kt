package com.sentinel.field.net

import com.sentinel.field.security.EdgeTransportDescriptor
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * M3B §5 — WHAT THE PIN MUST REFUSE.
 *
 * These are JVM unit tests. They exercise the descriptor rules and the
 * expiry/refusal behaviour without a network, because the parts worth
 * asserting here are decisions, not sockets. The TLS handshake itself is
 * exercised by the WP-30 harness against a real Edge.
 */
class PinnedEdgeTransportTest {

    private val validSpki = "a".repeat(64)

    private fun descriptor(
        endpoint: String = "https://edge-1.site-1.internal:8443",
        spki: String = validSpki,
        issued: String = "2026-09-07T00:00:00Z",
        expires: String = "2026-09-07T06:00:00Z",
    ): JsonObject = buildJsonObject {
        put("edge_id", kotlinx.serialization.json.JsonPrimitive("edge-1"))
        put("site_id", kotlinx.serialization.json.JsonPrimitive("site-1"))
        put("transport_identity_id", kotlinx.serialization.json.JsonPrimitive("ti-1"))
        put("transport_key_version", kotlinx.serialization.json.JsonPrimitive("1"))
        put("https_endpoint", kotlinx.serialization.json.JsonPrimitive(endpoint))
        put("tls_spki_sha256", kotlinx.serialization.json.JsonPrimitive(spki))
        put("issued_at", kotlinx.serialization.json.JsonPrimitive(issued))
        put("expires_at", kotlinx.serialization.json.JsonPrimitive(expires))
    }

    @Test
    fun `parses a well-formed descriptor`() {
        val parsed = EdgeTransportDescriptor.parse(descriptor())
        assertNotNull(parsed)
        assertEquals("edge-1", parsed.edgeId)
        assertEquals(validSpki, parsed.tlsSpkiSha256)
    }

    // The absence of an http alternative is the guarantee; this is the
    // client-side half of it.
    @Test
    fun `refuses a plaintext endpoint`() {
        assertNull(EdgeTransportDescriptor.parse(descriptor(endpoint = "http://edge-1.internal:8443")))
    }

    // A secret in an address leaks into every log that records a connection.
    @Test
    fun `refuses credentials or a query in the endpoint`() {
        assertNull(EdgeTransportDescriptor.parse(descriptor(endpoint = "https://u:p@edge-1.internal")))
        assertNull(EdgeTransportDescriptor.parse(descriptor(endpoint = "https://edge-1.internal/?token=abc")))
    }

    // A comparison against a differently-cased or truncated pin is a
    // comparison that can succeed by accident.
    @Test
    fun `refuses a pin that is not exactly 64 lower-case hex characters`() {
        assertNull(EdgeTransportDescriptor.parse(descriptor(spki = "A".repeat(64))))
        assertNull(EdgeTransportDescriptor.parse(descriptor(spki = "a".repeat(63))))
        assertNull(EdgeTransportDescriptor.parse(descriptor(spki = "a".repeat(65))))
        assertNull(EdgeTransportDescriptor.parse(descriptor(spki = "z".repeat(64))))
    }

    @Test
    fun `refuses a window that ends before it begins`() {
        assertNull(
            EdgeTransportDescriptor.parse(
                descriptor(issued = "2026-09-07T06:00:00Z", expires = "2026-09-07T00:00:00Z"),
            ),
        )
    }

    /**
     * AN EXPIRED DESCRIPTOR DOES NOT DEGRADE TO "PROBABLY FINE".
     *
     * It refuses without opening a connection, and it does not fall back to an
     * older pin. Retaining the operation locally is strictly better than
     * trusting a transport identity whose authority has lapsed.
     */
    @Test
    fun `refuses to open a connection on an expired descriptor`() {
        val parsed = assertNotNull(EdgeTransportDescriptor.parse(descriptor()))
        val expiredNow = java.time.Instant.parse("2026-09-07T07:00:00Z").toEpochMilli()

        var clientWasBuilt = false
        val transport = PinnedEdgeTransport(
            descriptor = parsed,
            nowMillis = { expiredNow },
            clientFactory = {
                clientWasBuilt = true
                okhttp3.OkHttpClient()
            },
        )

        val answer = transport.submit(Json.parseToJsonElement("{}") as JsonObject)

        assertEquals(0, answer.status)
        assertTrue(answer.text.contains("expired"))
        // It did not merely fail to connect -- it never tried.
        assertFalse(clientWasBuilt, "an expired descriptor must not build a client at all")
    }

    @Test
    fun `a live descriptor is not treated as expired`() {
        val parsed = assertNotNull(EdgeTransportDescriptor.parse(descriptor()))
        val duringWindow = java.time.Instant.parse("2026-09-07T03:00:00Z").toEpochMilli()
        val transport = PinnedEdgeTransport(
            descriptor = parsed,
            nowMillis = { duringWindow },
            // Unreachable host: proves we got PAST the expiry gate and actually
            // attempted a connection, which is the distinction being drawn.
            clientFactory = { okhttp3.OkHttpClient() },
        )

        val answer = transport.submit(Json.parseToJsonElement("{}") as JsonObject)

        assertEquals(0, answer.status)
        assertFalse(answer.text.contains("expired"))
    }
}
