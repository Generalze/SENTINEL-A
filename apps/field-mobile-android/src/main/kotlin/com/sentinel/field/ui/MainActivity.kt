package com.sentinel.field.ui

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.sentinel.field.R
import com.sentinel.field.net.EnrollmentCeremony
import com.sentinel.field.net.GatewaySession
import com.sentinel.field.net.SentinelHttp
import com.sentinel.field.security.StrongBoxKeyManager
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * ============================================================================
 * ONE ACTIVITY, A FEW BUTTONS AND A LOG.
 *
 * D26-06: "minimal is the operative word; this is a foundation for a proof, not
 * a product." The buttons are in the one order D26-04A permits and each says
 * plainly what it does, because the ordering IS the security property and a UI
 * that let a user do step 2 before step 1 would be hiding it.
 *
 * D26-05 — THE HUMAN PRINCIPAL STAYS INDEPENDENT.
 *
 * "Session user id" is a separate input from everything about the device, and it
 * is sent on EVERY call including the ones the hardware signs. A mobile client
 * is exactly the context in which "the device is right here, surely that is
 * enough" becomes tempting. The device credential is never an implicit login,
 * and the login is never an implicit device.
 *
 * THERE IS NO APPROVE BUTTON, AND THERE IS NO CODE PATH TO ONE.
 *
 * Between step 2 and step 3 an INDEPENDENT COMMANDER approves the exact request
 * fingerprint, in Command web. The log prints that fingerprint so a human can
 * compare it; this app cannot act on it.
 * ============================================================================
 */
class MainActivity : AppCompatActivity() {

    private lateinit var inputBaseUrl: EditText
    private lateinit var inputSessionUser: EditText
    private lateinit var inputOrganisation: EditText
    private lateinit var inputSite: EditText
    private lateinit var inputBootstrapToken: EditText
    private lateinit var inputDevice: EditText
    private lateinit var textLog: TextView

    private lateinit var keys: StrongBoxKeyManager
    private val worker: ExecutorService = Executors.newSingleThreadExecutor()

    /**
     * The ceremony's carried state.
     *
     * All of it is non-authority: a challenge id, a request id, a fingerprint, a
     * context id. Every one may be logged, and none confers anything without the
     * hardware key AND the live human session.
     */
    private var challenge: EnrollmentCeremony.AttestationChallenge? = null
    private var generated: StrongBoxKeyManager.GenerateOutcome.Generated? = null
    private var submitted: EnrollmentCeremony.SubmittedRequest? = null
    private var deviceContext: GatewaySession.DeviceContext? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        inputBaseUrl = findViewById(R.id.inputBaseUrl)
        inputSessionUser = findViewById(R.id.inputSessionUser)
        inputOrganisation = findViewById(R.id.inputOrganisation)
        inputSite = findViewById(R.id.inputSite)
        inputBootstrapToken = findViewById(R.id.inputBootstrapToken)
        inputDevice = findViewById(R.id.inputDevice)
        textLog = findViewById(R.id.textLog)

        keys = StrongBoxKeyManager(applicationContext)

        if (keys.strongBoxDeclared()) {
            log("StrongBox is declared by this device.")
        } else {
            log("StrongBox is NOT declared by this device. D26-03A: there is no fallback to TEE.")
        }

        findViewById<Button>(R.id.buttonChallengeAndGenerate).setOnClickListener { runChallengeAndGenerate() }
        findViewById<Button>(R.id.buttonSubmitRequest).setOnClickListener { runSubmitRequest() }
        findViewById<Button>(R.id.buttonProveAndCommit).setOnClickListener { runProveAndCommit() }
        findViewById<Button>(R.id.buttonEstablishContext).setOnClickListener { runEstablishContext() }
        findViewById<Button>(R.id.buttonFieldState).setOnClickListener { runFieldState() }
        findViewById<Button>(R.id.buttonDiscardKey).setOnClickListener { runDiscardKey() }
        findViewById<Button>(R.id.buttonClearLog).setOnClickListener { textLog.text = "" }
    }

    override fun onDestroy() {
        worker.shutdownNow()
        super.onDestroy()
    }

    // -----------------------------------------------------------------------
    // Step 1 — the server nonce, THEN the key
    // -----------------------------------------------------------------------

    private fun runChallengeAndGenerate() {
        val session = inputSessionUser.value()
        val organisation = inputOrganisation.value()
        val site = inputSite.value()
        val token = inputBootstrapToken.value()
        val ceremony = ceremony()

        background {
            log("POST attestation-challenge ...")
            val issued = ceremony.requestAttestationChallenge(
                sessionUserId = session,
                organisationId = organisation,
                siteId = site,
                // The intended user IS the operative holding this handset. The
                // server equality-binds it to the grant's own intended user
                // before anything enters Shield.
                intendedUserId = session,
                bootstrapToken = token,
            )
            if (!issued.isOk) {
                log(issued.describe())
                return@background
            }
            val attestationChallenge = issued.valueOrThrow()
            challenge = attestationChallenge
            log("challenge id ${attestationChallenge.attestationChallengeId}")
            log("expires ${attestationChallenge.expiresAt}")

            log("generating a StrongBox P-256 key against THAT challenge ...")
            val outcome = ceremony.generateKey(attestationChallenge)
            if (outcome.isDeviceUnsupported) {
                log(outcome.describe())
                log("D26-03A: the ceremony STOPS here. There is no TEE fallback, by design.")
                return@background
            }
            if (!outcome.isOk) {
                log("key generation failed: ${outcome.detail}")
                return@background
            }
            val key = outcome.valueOrThrow()
            generated = key
            log("key generated. thumbprint ${key.thumbprint}")
            log("attestation chain: ${key.certificateChainBase64.size} certificates")
        }
    }

    // -----------------------------------------------------------------------
    // Step 2 — crossing A
    // -----------------------------------------------------------------------

    private fun runSubmitRequest() {
        val currentChallenge = challenge
        val currentKey = generated
        if (currentChallenge == null || currentKey == null) {
            log("run step 1 first: the key must be generated against a server challenge.")
            return
        }
        val session = inputSessionUser.value()
        val organisation = inputOrganisation.value()
        val site = inputSite.value()
        val token = inputBootstrapToken.value()
        val ceremony = ceremony()

        background {
            log("POST requests ...")
            val result = ceremony.submitEnrollmentRequest(
                sessionUserId = session,
                organisationId = organisation,
                siteId = site,
                intendedUserId = session,
                bootstrapToken = token,
                attestationChallengeId = currentChallenge.attestationChallengeId,
                generated = currentKey,
            )
            if (!result.isOk) {
                log(result.describe())
                return@background
            }
            val request = result.valueOrThrow()
            submitted = request
            log("enrollment request ${request.enrollmentRequestId}")
            log("REQUEST FINGERPRINT ${request.requestFingerprint}")
            log("server attestation verdict: ${request.attestationOutcome}")
            log("server-derived key storage: ${request.keyStorage}")
            log("An INDEPENDENT COMMANDER must now match that exact fingerprint in Command web.")
        }
    }

    // -----------------------------------------------------------------------
    // Step 3 — crossing B, then the commit
    // -----------------------------------------------------------------------

    private fun runProveAndCommit() {
        val request = submitted
        if (request == null) {
            log("run step 2 first.")
            return
        }
        val session = inputSessionUser.value()
        val organisation = inputOrganisation.value()
        val ceremony = ceremony()

        background {
            log("POST possession-challenge ...")
            val issued = ceremony.requestPossessionChallenge(session, organisation, request.enrollmentRequestId)
            if (!issued.isOk) {
                log(issued.describe())
                log("(a refusal here usually means the ceremony has not been signed off yet)")
                return@background
            }
            val possessionChallenge = issued.valueOrThrow()

            log("signing the possession statement with the hardware key ...")
            val possession = ceremony.submitPossession(
                sessionUserId = session,
                organisationId = organisation,
                enrollmentRequestId = request.enrollmentRequestId,
                requestFingerprint = request.requestFingerprint,
                challenge = possessionChallenge,
            )
            if (!possession.isOk) {
                log(possession.describe())
                return@background
            }
            log("possession outcome: ${possession.valueOrThrow()}")

            log("POST commit ...")
            val committed = ceremony.commit(
                sessionUserId = session,
                organisationId = organisation,
                enrollmentRequestId = request.enrollmentRequestId,
                challengeId = possessionChallenge.challengeId,
            )
            if (!committed.isOk) {
                log(committed.describe())
                return@background
            }
            val device = committed.valueOrThrow()
            log("commit ${device.outcome}, device ${device.deviceId}")
            log("registry-concluded trust: ${device.trust ?: "(converged retry)"}")
            runOnUiThread { inputDevice.setText(device.deviceId) }
        }
    }

    // -----------------------------------------------------------------------
    // Step 4 — WP-25 context establishment
    // -----------------------------------------------------------------------

    private fun runEstablishContext() {
        val session = inputSessionUser.value()
        val organisation = inputOrganisation.value()
        val site = inputSite.value()
        val deviceId = inputDevice.value()
        if (deviceId.isEmpty()) {
            log("no device id: complete the enrollment first, or paste a registered device id.")
            return
        }
        val gateway = gateway()

        background {
            log("POST contexts/establishment ...")
            val issued = gateway.requestEstablishment(session, organisation, deviceId, site)
            if (!issued.isOk) {
                log(issued.describe())
                return@background
            }
            val establishmentChallenge = issued.valueOrThrow()
            log("establishment ${establishmentChallenge.establishmentId}")
            log("proposed context ${establishmentChallenge.proposedContextId}")

            log("signing the challenge digest with the hardware key ...")
            val completed = gateway.completeEstablishment(session, establishmentChallenge)
            if (!completed.isOk) {
                log(completed.describe())
                return@background
            }
            val issuedContext = completed.valueOrThrow()
            deviceContext = issuedContext
            log("context ${issuedContext.contextId}, trust ${issuedContext.deviceTrust}")
            log("expires ${issuedContext.expiresAt}")
        }
    }

    // -----------------------------------------------------------------------
    // Step 5 — one Field operation, signed by the hardware key
    // -----------------------------------------------------------------------

    private fun runFieldState() {
        val currentContext = deviceContext
        if (currentContext == null) {
            log("establish a context first.")
            return
        }
        val session = inputSessionUser.value()
        val site = currentContext.authorisedSiteIds.firstOrNull() ?: inputSite.value()
        val gateway = gateway()

        background {
            log("POST operations/field-state (a FRESH proof, over a FRESH one-shot nonce) ...")
            val result = gateway.updateFieldState(
                sessionUserId = session,
                context = currentContext,
                siteId = site,
                state = "AVAILABLE",
            )
            if (!result.isOk) {
                log(result.describe())
                return@background
            }
            log("operation: ${result.valueOrThrow()}")
        }
    }

    // -----------------------------------------------------------------------

    private fun runDiscardKey() {
        background {
            keys.deleteKey()
            challenge = null
            generated = null
            submitted = null
            deviceContext = null
            log("device key discarded. A new ceremony needs a NEW server challenge and a NEW key.")
        }
    }

    private fun ceremony(): EnrollmentCeremony = EnrollmentCeremony(SentinelHttp(inputBaseUrl.value()), keys)

    private fun gateway(): GatewaySession = GatewaySession(SentinelHttp(inputBaseUrl.value()), keys)

    private fun EditText.value(): String = text.toString().trim()

    /**
     * Network and keystore work off the main thread, on a SINGLE-threaded
     * executor so two ceremony steps cannot interleave.
     */
    private fun background(block: () -> Unit) {
        worker.execute {
            try {
                block()
            } catch (error: Exception) {
                log("client error: ${error.javaClass.simpleName}: ${error.message ?: "no detail"}")
            }
        }
    }

    /**
     * The log holds ids, fingerprints, outcomes and refusals.
     *
     * D23-14/D25-13: it never holds a private key (there is none to hold), a
     * session credential, a bootstrap token or a raw signature. Everything
     * printed here is safe to print — a context id authorises nothing, and a
     * request fingerprint is a digest a commander is MEANT to compare.
     */
    private fun log(line: String) {
        runOnUiThread { textLog.append(line + "\n") }
    }
}
