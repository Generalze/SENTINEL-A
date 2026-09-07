package com.sentinel.field.net

import com.sentinel.field.security.EdgeTransportDescriptor
import kotlinx.serialization.json.JsonObject
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.X509TrustManager

/**
 * ============================================================================
 * M3B §5 — THE FIELD -> EDGE TRANSPORT, PINNED TO ONE KEY.
 *
 * WHAT CHANGED, AND WHY THIS IS NOW BUILDABLE
 * -------------------------------------------
 * `EdgeTransport.NotConfigured` existed because there was "no channel that
 * distributes an Edge address and a pinned TLS trust anchor to a handset".
 * That channel now exists: central issues a `DeviceEdgeTransportDescriptor`
 * over the authenticated device gateway, carrying the endpoint and an exact
 * SPKI digest. So this implementation is possible without inventing trust,
 * which is the only reason it is here.
 *
 * WHAT IT REFUSES TO DO
 * ---------------------
 *   no accept-all TrustManager      that is not trust, it is the absence of it
 *   no hostname-only verification   proves a name resolved, not who answered
 *   no TOFU                         on a hostile site LAN, "first" is the
 *                                   attacker
 *   no plaintext fallback           the descriptor schema cannot even express
 *                                   an http endpoint
 *   no certificate-warning override there is no user-facing prompt, because a
 *                                   prompt is a decision an operative under
 *                                   pressure will always answer "yes"
 *
 * THE PIN IS THE ONLY TRUST INPUT
 * -------------------------------
 * The platform trust store is deliberately NOT consulted. A site Edge presents
 * a certificate no public CA issued and none should; requiring a public chain
 * would force either a real domain per site or a private CA whose compromise
 * is worth more than any single Edge. Instead the leaf's SubjectPublicKeyInfo
 * is digested and compared to the descriptor, in constant time, and everything
 * else about the certificate is irrelevant — including its expiry, its issuer
 * and its subject.
 *
 * That last point is deliberate and worth stating plainly: an EXPIRED
 * certificate on the pinned key is accepted. The pin is an identity check, not
 * a validity check, and a site Edge whose certificate lapses at 02:00 must not
 * take the site's offline capability down with it. What is NOT accepted is a
 * different key, whatever paperwork accompanies it.
 *
 * AN EXPIRED DESCRIPTOR DOES NOT DEGRADE TO "PROBABLY FINE"
 * ---------------------------------------------------------
 * `submit` refuses outright once the descriptor's window has passed. It does
 * not try the endpoint anyway, and it does not fall back to an older pin. The
 * caller refreshes from central if it can reach central, and otherwise retains
 * the operation locally — which is strictly better than trusting a transport
 * identity whose authority has lapsed.
 * ============================================================================
 */
class PinnedEdgeTransport(
    private val descriptor: EdgeTransportDescriptor,
    private val nowMillis: () -> Long = System::currentTimeMillis,
    clientFactory: (EdgeTransportDescriptor) -> OkHttpClient = ::pinnedClient,
) : EdgeTransport {

    private val client: OkHttpClient by lazy { clientFactory(descriptor) }

    /**
     * MUST NOT THROW — the interface says so, and the classifier depends on it.
     *
     * Every failure becomes a status 0 answer, which is how "no answer arrived"
     * is reported everywhere in this client. A thrown exception would leave
     * `EdgeSubmission` by exception rather than being classified, which is the
     * C18-R1A defect one layer down.
     */
    override fun submit(body: JsonObject): SentinelHttp.Answer {
        if (isExpired()) {
            return SentinelHttp.Answer(
                status = 0,
                body = null,
                text = "edge transport descriptor has expired: refusing to open a trusted " +
                    "connection on lapsed authority",
            )
        }

        val request = Request.Builder()
            .url(descriptor.httpsEndpoint.trimEnd('/') + EDGE_WITNESS_PATH)
            .post(body.toString().toRequestBody(JSON_MEDIA_TYPE))
            .build()

        return try {
            client.newCall(request).execute().use { response ->
                SentinelHttp.Answer(
                    status = response.code,
                    body = null,
                    // `Answer.text` is non-nullable. An empty body is an empty
                    // string, not a null the caller has to guard.
                    text = response.body?.string() ?: "",
                )
            }
        } catch (pinFailure: SSLPeerUnverifiedException) {
            // THE CASE THIS CLASS EXISTS FOR. Something answered on the site
            // LAN and it was not the Edge central told us to trust. The message
            // deliberately does not include the presented key: it is attacker
            // input, and it would end up in a log.
            SentinelHttp.Answer(
                status = 0,
                body = null,
                text = "edge TLS identity did not match the pinned key: refusing",
            )
        } catch (error: Exception) {
            // An unreachable Edge is the ORDINARY case during an outage, not an
            // error. Status 0, the entry stays queued.
            SentinelHttp.Answer(status = 0, body = null, text = "edge unreachable: ${error.javaClass.simpleName}")
        }
    }

    private fun isExpired(): Boolean = nowMillis() >= descriptor.expiresAtMillis

    companion object {
        private const val EDGE_WITNESS_PATH = "/edge/v1/field-operations"
        private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()

        /**
         * SHA-256 over the DER SubjectPublicKeyInfo, lower-case hex.
         *
         * SPKI rather than the whole certificate, so routine renewal on the
         * SAME keypair does not break the pin while a KEY change does — which
         * is the event anyone actually cares about.
         */
        fun spkiSha256(certificate: X509Certificate): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(certificate.publicKey.encoded)
            return digest.joinToString("") { byte -> "%02x".format(byte) }
        }

        /**
         * CONSTANT-TIME COMPARISON.
         *
         * A pin comparison is a secret-independent equality check on public
         * data, so the timing risk is small — but `MessageDigest.isEqual` is
         * the same length of code as `==`, and using it means nobody has to
         * reason about whether this particular comparison was the one that
         * mattered.
         */
        fun pinMatches(expectedHex: String, presented: X509Certificate): Boolean =
            MessageDigest.isEqual(expectedHex.toByteArray(Charsets.UTF_8), spkiSha256(presented).toByteArray(Charsets.UTF_8))

        /**
         * The client, trusting EXACTLY ONE key.
         *
         * The TrustManager below is not permissive — it is the opposite. It
         * ignores the platform trust store because a site Edge's certificate is
         * not publicly issued, and it accepts a chain if and only if the LEAF's
         * public key digests to the pinned value. `checkClientTrusted` throws
         * unconditionally: this client is never a TLS server, and a trust
         * manager that answered that question would be answering a question
         * nobody asked.
         */
        fun pinnedClient(descriptor: EdgeTransportDescriptor): OkHttpClient {
            val trustManager = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                    throw java.security.cert.CertificateException("this client never acts as a TLS server")
                }

                override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                    val leaf = chain?.firstOrNull()
                        ?: throw SSLPeerUnverifiedException("edge presented no certificate")
                    if (!pinMatches(descriptor.tlsSpkiSha256, leaf)) {
                        // No detail about what WAS presented. That value is
                        // attacker-controlled and must not reach a log.
                        throw SSLPeerUnverifiedException("edge TLS key does not match the pinned SPKI digest")
                    }
                }

                // EMPTY ON PURPOSE. Returning platform CAs here would invite a
                // future change to fall back to them.
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }

            val sslContext = SSLContext.getInstance("TLS").apply {
                init(null, arrayOf(trustManager), java.security.SecureRandom())
            }

            return OkHttpClient.Builder()
                .sslSocketFactory(sslContext.socketFactory, trustManager)
                // The pin IS the identity check, so hostname verification adds
                // nothing: a certificate for the wrong name on the RIGHT key is
                // still the Edge we were told to trust, and the right name on
                // the wrong key is refused above. Returning true here is safe
                // ONLY because the trust manager cannot be bypassed.
                .hostnameVerifier { _, _ -> true }
                // Short timeouts. A site LAN is fast or it is down; waiting
                // longer converts a quick, correct "queue it" into a stall.
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS)
                .writeTimeout(10, TimeUnit.SECONDS)
                .retryOnConnectionFailure(false)
                .build()
        }
    }
}
