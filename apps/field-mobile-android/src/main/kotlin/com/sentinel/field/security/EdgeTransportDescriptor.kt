package com.sentinel.field.security

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * M3B §2 / §5 — THE DESCRIPTOR, AS THE HANDSET HOLDS IT.
 *
 * Central issues this over the authenticated device gateway. It carries the
 * endpoint to open and the exact SPKI digest to require, and it carries NO
 * credential of any kind — it says who to believe, and the device still
 * authenticates every request it then makes.
 *
 * WHY IT IS PARSED RATHER THAN DESERIALISED WHOLESALE
 * ---------------------------------------------------
 * Every rule the server-side schema enforces is enforced again here, on the
 * client, against the bytes that actually arrived. That is not distrust of
 * central; it is the recognition that this value is the ONLY thing standing
 * between a handset and whatever answers first on a site LAN. A descriptor
 * that reached storage malformed would be a pin nobody could match, or worse a
 * plaintext endpoint, and the failure would surface as "the Edge is
 * unreachable" rather than as the parse error it is.
 *
 * HTTPS ONLY, and there is no field in which an `http` endpoint could arrive.
 * A digest that is not exactly 64 lower-case hex characters is refused rather
 * than normalised: a comparison against a differently-cased or truncated pin
 * is a comparison that can succeed by accident.
 */
data class EdgeTransportDescriptor(
    val edgeId: String,
    val siteId: String,
    val transportIdentityId: String,
    val transportKeyVersion: Int,
    val httpsEndpoint: String,
    val tlsSpkiSha256: String,
    val issuedAtMillis: Long,
    val expiresAtMillis: Long,
) {
    companion object {
        private val SPKI_PATTERN = Regex("^[0-9a-f]{64}$")

        /**
         * Parses a descriptor, or returns `null`.
         *
         * `null` rather than an exception, and rather than a partially
         * populated object: the caller's correct response to an unparseable
         * descriptor is to have NO Edge transport, which is a state this client
         * already handles safely through `EdgeTransport.NotConfigured`.
         */
        fun parse(json: JsonObject): EdgeTransportDescriptor? {
            val endpoint = json["https_endpoint"]?.jsonPrimitive?.contentOrNullSafe() ?: return null
            // The absence of an http alternative is the guarantee; this is the
            // client-side half of it.
            if (!endpoint.startsWith("https://")) return null
            // A credential in an address leaks into every log that records a
            // connection, and a query string is somewhere a token would hide.
            if (endpoint.contains('@') || endpoint.contains('?') || endpoint.contains('#')) return null

            val spki = json["tls_spki_sha256"]?.jsonPrimitive?.contentOrNullSafe() ?: return null
            if (!SPKI_PATTERN.matches(spki)) return null

            val issuedAt = json["issued_at"]?.jsonPrimitive?.contentOrNullSafe()?.let(::parseInstantMillis) ?: return null
            val expiresAt = json["expires_at"]?.jsonPrimitive?.contentOrNullSafe()?.let(::parseInstantMillis) ?: return null
            // A window that ends before it begins is not a window. Refusing
            // here means the transport never has to reason about it.
            if (expiresAt <= issuedAt) return null

            return EdgeTransportDescriptor(
                edgeId = json["edge_id"]?.jsonPrimitive?.contentOrNullSafe() ?: return null,
                siteId = json["site_id"]?.jsonPrimitive?.contentOrNullSafe() ?: return null,
                transportIdentityId = json["transport_identity_id"]?.jsonPrimitive?.contentOrNullSafe() ?: return null,
                transportKeyVersion = json["transport_key_version"]?.jsonPrimitive?.contentOrNullSafe()?.toIntOrNull()
                    ?: return null,
                httpsEndpoint = endpoint,
                tlsSpkiSha256 = spki,
                issuedAtMillis = issuedAt,
                expiresAtMillis = expiresAt,
            )
        }

        private fun kotlinx.serialization.json.JsonPrimitive.contentOrNullSafe(): String? =
            runCatching { content }.getOrNull()?.takeIf { it.isNotBlank() }

        /** ISO-8601 UTC, as every instant on the wire in this system is. */
        private fun parseInstantMillis(value: String): Long? =
            runCatching { java.time.Instant.parse(value).toEpochMilli() }.getOrNull()
    }
}
