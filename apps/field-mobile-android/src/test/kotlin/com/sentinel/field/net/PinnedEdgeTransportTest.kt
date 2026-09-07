package com.sentinel.field.net

import com.sentinel.field.security.EdgeTransportDescriptor
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

/**
 * M3B §5 — WHAT THE PIN MUST REFUSE.
 *
 * JVM unit tests, no network. The parts worth asserting here are DECISIONS --
 * which descriptors are admissible, and whether an expired one is even
 * attempted. The TLS handshake itself is exercised by the WP-30 harness
 * against a real Edge, because a handshake asserted against a mock proves only
 * that the mock was configured.
 */
class PinnedEdgeTransportTest {

    private val validSpki = "a".repeat(64)

    private fun descriptor(
        endpoint: String = "https://edge-1.site-1.internal:8443",
        spki: String = validSpki,
        issued: String = "2026-09-07T00:00:00Z",
        expires: String = "2026-09-07T06:00:00Z",
    ): JsonObject = buildJsonObject {
        put("edge_id", "edge-1")
        put("site_id", "site-1")
        put("transport_identity_id", "ti-1")
        put("transport_key_version", "1")
        put("https_endpoint", endpoint)
        put("tls_spki_sha256", spki)
        put("issued_at", issued)
        put("expires_at", expires)
    }

    private fun requireParsed(json: JsonObject): EdgeTransportDescriptor {
        val parsed = EdgeTransportDescriptor.parse(json)
        assertNotNull("descriptor should have parsed", parsed)
        return parsed!!
    }

    @Test
    fun `parses a well-formed descriptor`() {
        val parsed = requireParsed(descriptor())
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
     * It refuses without opening a connection and does not fall back to an
     * older pin. Retaining the operation locally is strictly better than
     * trusting a transport identity whose authority has lapsed.
     */
    @Test
    fun `refuses to open a connection on an expired descriptor`() {
        val parsed = requireParsed(descriptor())
        val afterWindow = Instant.parse("2026-09-07T07:00:00Z").toEpochMilli()

        var clientWasBuilt = false
        val transport = PinnedEdgeTransport(
            descriptor = parsed,
            nowMillis = { afterWindow },
            clientFactory = {
                clientWasBuilt = true
                OkHttpClient()
            },
        )

        val answer = transport.submit(buildJsonObject { })

        assertEquals(0, answer.status)
        assertTrue(answer.text.contains("expired"))
        // It did not merely fail to connect -- it never tried. The refusal is a
        // decision, not a network outcome.
        assertFalse("an expired descriptor must not build a client at all", clientWasBuilt)
    }

    @Test
    fun `a live descriptor gets past the expiry gate`() {
        val parsed = requireParsed(descriptor())
        val duringWindow = Instant.parse("2026-09-07T03:00:00Z").toEpochMilli()
        val transport = PinnedEdgeTransport(
            descriptor = parsed,
            nowMillis = { duringWindow },
            // An unreachable host, which is the point: reaching a transport
            // failure proves the expiry gate was passed rather than tripped.
            clientFactory = { OkHttpClient() },
        )

        val answer = transport.submit(buildJsonObject { })

        assertEquals(0, answer.status)
        assertFalse(answer.text.contains("expired"))
    }
}
