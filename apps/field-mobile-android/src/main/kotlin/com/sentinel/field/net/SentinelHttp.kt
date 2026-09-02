package com.sentinel.field.net

import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * ============================================================================
 * THE TRANSPORT, AND NOTHING ELSE.
 *
 * WHAT AUTHENTICATES A CALL FROM THIS CLIENT
 * ------------------------------------------
 * The HUMAN SESSION, and only the human session. Both surfaces WP-26 speaks to
 * are session-authenticated and neither is `@Public()`:
 *
 *   * the enrollment ingress is authenticated by the INTENDED USER's session
 *     plus the one-shot bootstrap grant. The device contributes evidence and
 *     NO authority — it has no registered key, which is the reason the ceremony
 *     exists rather than a gap in it.
 *
 *   * the WP-25 gateway is authenticated by the session AND a fresh
 *     hardware-signed possession proof AND a live re-read of the actor's
 *     authority. None of the three substitutes for another.
 *
 * D25-01 forbids a credential a DEVICE can hold and present as authority: a
 * device token, a device session cookie, an authenticated socket, a
 * per-connection exemption, a header a controller reads as a device credential.
 * THERE IS NO SUCH HEADER HERE. `x-dev-user-id` carries the HUMAN, and that is
 * the Milestone-1 dev-auth placeholder (`identity/dev-auth.guard.ts`), not a
 * device credential — the guard looks the id up and attaches that user's
 * principal, with no password, token or signature of any kind. It is the
 * server's stated placeholder and this client inherits its weakness exactly;
 * when real authentication (OIDC) replaces that guard, this one header is the
 * only thing in this file that changes.
 *
 * REST ONLY (D25-10). There is no device WebSocket path in WP-25 or WP-26, and
 * this client does not open one.
 * ============================================================================
 */
class SentinelHttp(
    /** e.g. `http://10.0.2.2:3000` — no trailing slash. */
    private val baseUrl: String,
    private val client: OkHttpClient = defaultClient(),
) {

    companion object {
        /** The Milestone-1 dev-auth header. THE HUMAN, never the device. */
        const val SESSION_HEADER = "x-dev-user-id"

        private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()

        /**
         * Lenient on the way IN only.
         *
         * `ignoreUnknownKeys` affects nothing security-relevant: this client
         * never verifies anything it parses, and every value it goes on to SIGN
         * is picked out by name in `DeviceStatements`. Signed bytes are never
         * produced by re-serialising a parsed response.
         */
        val JSON = Json {
            ignoreUnknownKeys = true
            isLenient = false
            encodeDefaults = true
        }

        fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .retryOnConnectionFailure(false)
            .build()
    }

    /**
     * One HTTP answer.
     *
     * `body` is null when the response was not a JSON object — which includes
     * every transport failure. The server's own refusal discipline (D25-13) is
     * that every refusal is byte-identical, so there is deliberately nothing to
     * branch on here beyond the status: a client that tried to distinguish
     * refusal reasons would be reading an oracle the server does not offer.
     */
    data class Answer(
        val status: Int,
        val body: JsonObject?,
        val text: String,
    ) {
        val ok: Boolean get() = status in 200..299
    }

    /** A POST with a JSON body, carrying the human session. */
    fun post(path: String, sessionUserId: String, body: JsonObject): Answer {
        val request = Request.Builder()
            .url(baseUrl.trimEnd('/') + path)
            .addHeader(SESSION_HEADER, sessionUserId)
            .addHeader("accept", "application/json")
            .post(body.toString().toRequestBody(JSON_MEDIA_TYPE))
            .build()
        return try {
            client.newCall(request).execute().use { response ->
                val text = response.body?.string() ?: ""
                Answer(response.code, parseObjectOrNull(text), text)
            }
        } catch (error: Exception) {
            // A transport failure and a malformed base URL are the same thing to
            // a caller: no answer arrived. `IOException` alone would let an
            // `IllegalArgumentException` from an unparseable URL escape into the
            // UI thread's generic handler with no context.
            Answer(0, null, "transport failure: ${error.javaClass.simpleName}: ${error.message ?: "no detail"}")
        }
    }

    private fun parseObjectOrNull(text: String): JsonObject? =
        try {
            JSON.parseToJsonElement(text).jsonObject
        } catch (error: Exception) {
            null
        }
}
