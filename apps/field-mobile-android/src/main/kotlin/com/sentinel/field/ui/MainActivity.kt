package com.sentinel.field.ui

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.sentinel.field.R
import com.sentinel.field.net.EnrollmentCeremony
import com.sentinel.field.net.FieldReads
import com.sentinel.field.net.GatewaySession
import com.sentinel.field.net.SentinelHttp
import com.sentinel.field.security.StrongBoxKeyManager
import com.sentinel.field.store.ClientStateStore
import com.sentinel.field.store.EncryptedClientState
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * ============================================================================
 * ONE ACTIVITY, A FEW BUTTONS AND A LOG.
 *
 * D26-06: "minimal is the operative word; this is a foundation for a proof, not
 * a product." The ceremony buttons are in the one order D26-04A permits and
 * each says plainly what it does, because the ordering IS the security property
 * and a UI that let a user do step 2 before step 1 would be hiding it.
 *
 * THE TWO KINDS OF BUTTON, AND WHY THE SCREEN IS SPLIT ALONG THAT LINE
 * -------------------------------------------------------------------
 * READS go to the ORDINARY AUTHENTICATED HUMAN ROUTES and carry the session and
 * nothing else — see `FieldReads` for the four routes and where their shapes
 * were read from. They produce no effect, so there is nothing to attribute to a
 * device and no signature to make.
 *
 * OPERATIONS go through the WP-25 gateway, and each one mints a FRESH hardware
 * signature over a FRESH one-shot nonce over the digest of that exact
 * operation. There are exactly three, because WP-25 exposes exactly three:
 * field state, assignment accept/decline, message acknowledgement. Patrol is
 * READ ONLY in this client — the gateway has no patrol write, and a client that
 * invented one would be inventing platform surface from the handset.
 *
 * THERE IS NO OFFLINE QUEUE, DELIBERATELY. WP-29 owns queueing. If the network
 * fails here, the operation fails and the operative presses the button again.
 * No outbox, no retry store, no "will send later" that quietly becomes "never
 * sent" — the one failure mode a Field client must not have is believing it
 * reported something it did not.
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
 * Between step 2 and step 3 an INDEPENDENT COMMANDER signs off the exact request
 * fingerprint, in Command web. The log prints that fingerprint so a human can
 * compare it; this app cannot act on it.
 *
 * THE BOOTSTRAP GRANT IS THE ONE SECRET ON THIS SCREEN.
 *
 * It is masked in the layout, excluded from view-state save/restore, never
 * written to any persistence API, and cleared by [clearBootstrapToken] as soon
 * as it has been presented for the last time or the ceremony fails terminally.
 * `BootstrapTokenNeverPersistedSourceTest` fails the build if any of that stops
 * being true.
 *
 * C18-R1 QUALIFIES "PRESENTED FOR THE LAST TIME", AND NOTHING ELSE. When the
 * submission's outcome cannot be PROVEN — the server's own `409`, a transport
 * failure, a 5xx, an unreadable success — the grant, the attestation challenge
 * and the generated key are RETAINED IN MEMORY so the exact submission can be
 * retried and converge. Retention is in memory for the life of the ceremony and
 * nothing else changes: the grant still never reaches persistent storage, and
 * the source scan above still proves it.
 * ============================================================================
 */
class MainActivity : AppCompatActivity() {

    private lateinit var inputBaseUrl: EditText
    private lateinit var inputSessionUser: EditText
    private lateinit var inputOrganisation: EditText
    private lateinit var inputSite: EditText
    private lateinit var inputBootstrapToken: EditText
    private lateinit var inputDevice: EditText
    private lateinit var inputIncident: EditText
    private lateinit var inputAssignment: EditText
    private lateinit var inputMessage: EditText
    private lateinit var textLog: TextView

    private lateinit var keys: StrongBoxKeyManager
    private val worker: ExecutorService = Executors.newSingleThreadExecutor()

    /**
     * Secure local storage, or null when the platform could not produce the
     * encrypted store.
     *
     * NULLABLE, AND NEVER SUBSTITUTED. If `EncryptedSharedPreferences` cannot be
     * opened, this app remembers nothing for the rest of the session — it does
     * NOT fall back to plain preferences. Persistence here is a convenience over
     * non-authority ids; plaintext storage that appears when encryption fails is
     * a guarantee that depends on the weather.
     */
    private var store: ClientStateStore? = null

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
        inputIncident = findViewById(R.id.inputIncident)
        inputAssignment = findViewById(R.id.inputAssignment)
        inputMessage = findViewById(R.id.inputMessage)
        textLog = findViewById(R.id.textLog)

        keys = StrongBoxKeyManager(applicationContext)

        if (keys.strongBoxDeclared()) {
            log("StrongBox is declared by this device.")
        } else {
            log("StrongBox is NOT declared by this device. D26-03A: there is no fallback to TEE.")
        }

        restoreClientState()

        findViewById<Button>(R.id.buttonChallengeAndGenerate).setOnClickListener { runChallengeAndGenerate() }
        findViewById<Button>(R.id.buttonSubmitRequest).setOnClickListener { runSubmitRequest() }
        findViewById<Button>(R.id.buttonProveAndCommit).setOnClickListener { runProveAndCommit() }
        findViewById<Button>(R.id.buttonEstablishContext).setOnClickListener { runEstablishContext() }
        findViewById<Button>(R.id.buttonIdentity).setOnClickListener { runIdentity() }
        findViewById<Button>(R.id.buttonAssignments).setOnClickListener { runAssignments() }
        findViewById<Button>(R.id.buttonMessages).setOnClickListener { runMessages() }
        findViewById<Button>(R.id.buttonPatrolRuns).setOnClickListener { runPatrolRuns() }
        findViewById<Button>(R.id.buttonFieldState).setOnClickListener { runFieldState() }
        findViewById<Button>(R.id.buttonAcceptAssignment).setOnClickListener { runAssignmentAction(true) }
        findViewById<Button>(R.id.buttonDeclineAssignment).setOnClickListener { runAssignmentAction(false) }
        findViewById<Button>(R.id.buttonAcknowledgeMessage).setOnClickListener { runAcknowledgeMessage() }
        findViewById<Button>(R.id.buttonDiscardKey).setOnClickListener { runDiscardKey() }
        findViewById<Button>(R.id.buttonClearLog).setOnClickListener { textLog.text = "" }
    }

    override fun onDestroy() {
        worker.shutdownNow()
        super.onDestroy()
    }

    // -----------------------------------------------------------------------
    // Secure local storage — client state only, and only non-authority ids
    // -----------------------------------------------------------------------

    /**
     * Opens the encrypted store and pre-fills what is safe to pre-fill.
     *
     * A remembered CONTEXT ID does NOT resume a context. Operating through the
     * gateway needs the whole issued context — key id, key version, authorised
     * sites, the actor the server resolved — and this client will not
     * reconstruct that from a stored id and its own assumptions. The remembered
     * values are shown so the operative can see what the last session did; step
     * 4 is what makes a context usable again.
     */
    private fun restoreClientState() {
        val opened = try {
            EncryptedClientState.open(applicationContext)
        } catch (error: Exception) {
            log("secure local storage is unavailable (${error.javaClass.simpleName}); nothing will be remembered.")
            log("no fallback to plaintext storage is attempted, by design.")
            null
        }
        store = opened
        val remembered = opened?.read() ?: return
        log(remembered.describe())
        remembered.deviceId?.let { inputDevice.setText(it) }
        remembered.organisationId?.let { inputOrganisation.setText(it) }
        remembered.userId?.let { inputSessionUser.setText(it) }
        remembered.siteId?.let { inputSite.setText(it) }
        if (remembered.contextId != null) {
            log("a context was established previously; re-establish it (step 4) before operating.")
        }
    }

    // -----------------------------------------------------------------------
    // Step 1 — the server nonce, THEN the key
    // -----------------------------------------------------------------------

    private fun runChallengeAndGenerate() {
        val session = inputSessionUser.value()
        val organisation = inputOrganisation.value()
        val site = inputSite.value()
        val bootstrapToken = inputBootstrapToken.value()
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
                bootstrapToken = bootstrapToken,
            )
            if (issued.isCompletionUnknown) {
                // C18-R3: PHASE 0 PROBES THE GRANT; IT DOES NOT SPEND IT.
                //
                // A transport failure, a 5xx or an unreadable success says
                // nothing authoritative about the grant, and clearing it here
                // destroyed a commander-issued credential for no security gain.
                // A challenge that was issued just before a lost response
                // confers no device authority and simply expires.
                log(issued.describe())
                log("CHALLENGE OUTCOME UNKNOWN: the grant is NOT spent by this step.")
                log("the bootstrap grant is RETAINED. press step 1 again to obtain a fresh challenge.")
                return@background
            }
            if (!issued.isOk) {
                log(issued.describe())
                // An AUTHORITATIVE refusal is terminal for this grant: the
                // server was reached and answered, and a wrong-context probe
                // burns the grant server-side (D24-03a). Nothing is gained by
                // keeping the secret on screen.
                clearBootstrapToken()
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
                clearBootstrapToken()
                return@background
            }
            if (!outcome.isOk) {
                log("key generation failed: ${outcome.detail}")
                clearBootstrapToken()
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
        val bootstrapToken = inputBootstrapToken.value()
        val ceremony = ceremony()

        background {
            log("POST requests ...")
            val result = ceremony.submitEnrollmentRequest(
                sessionUserId = session,
                organisationId = organisation,
                siteId = site,
                intendedUserId = session,
                bootstrapToken = bootstrapToken,
                attestationChallengeId = currentChallenge.attestationChallengeId,
                generated = currentKey,
            )
            // ============================================================
            // C18-R1 — THE GRANT IS RELEASED ONLY ON AN AUTHORITATIVE ANSWER.
            // ============================================================
            //
            // THE DEFECT THIS REPLACES. This step used to clear the grant
            // UNCONDITIONALLY, before the result was even inspected. That is
            // wrong for one specific and entirely ordinary case: the POST
            // reached the server, the server created the enrollment request,
            // and the RESPONSE was lost on the way back. `SentinelHttp` reports
            // that as status 0, exactly as it reports a request that never
            // left. Clearing there destroys the grant, and the grant is one of
            // the three things — with the challenge and the generated key —
            // that the server's convergence path requires in order to hand this
            // client back the request id and fingerprint it already earned. A
            // client that discards them turns a SUCCEEDED ceremony into an
            // unfinishable one.
            //
            // THE RULE:
            //
            //   OK (REQUESTED or CONVERGED)  the server named the request.
            //                                Release the grant; nothing after
            //                                this point in the ceremony needs
            //                                it.
            //
            //   TERMINAL REFUSAL             the server evaluated this
            //                                submission and declined it.
            //                                Release the grant: it is spent,
            //                                and nothing is gained by leaving a
            //                                secret on screen.
            //
            //   COMPLETION UNKNOWN           RETAIN the grant, the challenge and
            //   (409, status 0, 5xx,         the generated key, in memory, and
            //    an unreadable 2xx)          tell the operative to retry THE
            //                                EXACT SAME submission.
            //
            // RETENTION IS IN LIVE MEMORY ONLY, AND THAT PART OF C18-05 STAYS
            // CLOSED. The grant is held where it already was — the masked,
            // save-disabled, autofill-excluded input — for the life of this
            // ceremony. It reaches no persistence API here or anywhere else,
            // and `BootstrapTokenNeverPersistedSourceTest` fails the build if
            // that ever stops being true. `challenge` and `generated` are
            // likewise ordinary in-memory fields and are deliberately NOT
            // cleared on this path.
            //
            // Honest about the limit, unchanged: a Kotlin String cannot be
            // wiped, only dereferenced, so clearing achieves that no live
            // reference to the secret is held by the UI or by this closure.
            // Zeroing would need a CharArray all the way through OkHttp, which
            // is not a promise this harness can keep.
            if (result.isCompletionUnknown) {
                log(result.describe())
                // C18-R1B: DO NOT PROMISE THAT A RETRY CONVERGES.
                //
                // The server answers UNKNOWN whenever the submission
                // fingerprint matches but the receipt is incomplete, and that
                // state can also come from a process death immediately after
                // the fenced consume — not only from a worker still finishing.
                // The resolver deliberately performs no recovery work, so such
                // an UNKNOWN can PERSIST. Telling the operative it converges
                // would send them into a silent retry loop.
                log("COMPLETION UNKNOWN: the server may already have created this enrollment request.")
                log("the bootstrap grant, the challenge and the generated key are RETAINED in memory.")
                log("press step 2 again to retry the EXACT same submission.")
                log("if it stays UNKNOWN: STOP and escalate. do NOT discard this material,")
                log("and do NOT start a replacement ceremony, until server state is resolved.")
                return@background
            }
            // Authoritative from here: a parsed success, or a terminal refusal.
            clearBootstrapToken()
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
            log("registry-concluded standing: ${device.trust ?: "(converged retry)"}")
            store?.rememberDevice(device.deviceId)
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
            log("context ${issuedContext.contextId}, standing ${issuedContext.deviceTrust}")
            log("expires ${issuedContext.expiresAt}")
            store?.rememberContext(issuedContext.contextId, issuedContext.expiresAt)
            store?.rememberIdentity(
                issuedContext.organisationId,
                issuedContext.actorUserId,
                issuedContext.authorisedSiteIds.firstOrNull(),
            )
        }
    }

    // -----------------------------------------------------------------------
    // READS — the ordinary authenticated human routes
    // -----------------------------------------------------------------------

    /**
     * Who is signed in, as the SERVER reports it.
     *
     * WHAT THIS CANNOT SHOW, AND WHY THAT IS SAID OUT LOUD RATHER THAN FAKED.
     * The core API has no `/me` route: the principal is assembled by the
     * DevAuthGuard and never serialised back to the caller, and every route that
     * would list users, sites or organisations is gated on an admin action a
     * `field.operative` does not hold. So ROLES are simply not readable by this
     * client, and this screen says so instead of printing a role list it
     * inferred locally — an app that displayed a role it decided for itself
     * would be displaying a claim, not an identity.
     *
     * What IS server-reported and shown: the organisation, user, site and device
     * on `GET /api/v1/field/state/mine`, and — when a context has been
     * established — the SITE SCOPE the gateway granted, in the form of the
     * context's own `authorised_site_ids`.
     */
    private fun runIdentity() {
        val session = inputSessionUser.value()
        if (session.isEmpty()) {
            log("enter the session user id first: it is the only thing that says who you are.")
            return
        }
        val reads = reads()
        val context = deviceContext

        background {
            log("GET ${FieldReads.ROUTE_OWN_STATE} (ordinary authenticated route, session only) ...")
            val result = reads.ownState(session)
            if (!result.isOk) {
                log(result.describe())
                return@background
            }
            val state = result.valueOrThrow()
            log("IDENTITY, as the server reports it:")
            log("  " + state.describe())
            store?.rememberIdentity(state.organisationId, state.userId, state.siteId)

            if (context == null) {
                log("  site scope: unknown until a device context is established (step 4).")
            } else {
                val scope = context.authorisedSiteIds.joinToString(", ").ifEmpty { "(none)" }
                log("  site scope, as the gateway granted it: $scope")
                log("  device ${context.deviceId}, standing ${context.deviceTrust}, context expires ${context.expiresAt}")
            }
            log("  roles: not exposed to this client by any route it may call (see the code comment).")
        }
    }

    private fun runAssignments() {
        val session = inputSessionUser.value()
        val reads = reads()

        background {
            log("GET ${FieldReads.ROUTE_OWN_ASSIGNMENTS} ...")
            val result = reads.ownAssignments(session)
            if (!result.isOk) {
                log(result.describe())
                return@background
            }
            val assignments = result.valueOrThrow()
            if (assignments.isEmpty()) {
                log("no assignments.")
                return@background
            }
            log("${assignments.size} assignment(s):")
            for (assignment in assignments) log("  " + assignment.describe())
            val first = assignments.first().id
            runOnUiThread {
                if (inputAssignment.value().isEmpty()) inputAssignment.setText(first)
            }
        }
    }

    private fun runMessages() {
        val session = inputSessionUser.value()
        val incidentId = inputIncident.value()
        if (!FieldReads.isSafePathId(incidentId)) {
            log("enter an incident id: the server scopes every recipient message read to ONE incident.")
            return
        }
        val reads = reads()

        background {
            log("GET ${FieldReads.routeIncidentMessages(incidentId)} ...")
            val result = reads.incidentMessages(session, incidentId)
            if (!result.isOk) {
                log(result.describe())
                return@background
            }
            val messages = result.valueOrThrow()
            if (messages.isEmpty()) {
                log("no messages on that incident for you.")
                return@background
            }
            log("${messages.size} message(s):")
            for (message in messages) log("  " + message.describe())
            val unacknowledged = messages.firstOrNull { it.awaitingOwnAcknowledgement }?.id
            if (unacknowledged != null) {
                runOnUiThread {
                    if (inputMessage.value().isEmpty()) inputMessage.setText(unacknowledged)
                }
            }
        }
    }

    /**
     * Patrol, READ ONLY.
     *
     * There is no patrol button on the operations side of this screen and there
     * is no code path to one: WP-25 exposes no patrol write through the device
     * gateway, so there is no signed patrol operation to make. Starting a run,
     * abandoning one or verifying a checkpoint remain Command-side REST surfaces
     * this client does not call.
     */
    private fun runPatrolRuns() {
        val session = inputSessionUser.value()
        val reads = reads()

        background {
            log("GET ${FieldReads.ROUTE_PATROL_RUNS} ...")
            val result = reads.patrolRuns(session)
            if (!result.isOk) {
                log(result.describe())
                return@background
            }
            val runs = result.valueOrThrow()
            if (runs.isEmpty()) {
                log("no patrol runs.")
                return@background
            }
            log("${runs.size} patrol run(s):")
            for (run in runs) log("  " + run.describe())
        }
    }

    // -----------------------------------------------------------------------
    // OPERATIONS — the WP-25 gateway, each one hardware-signed
    // -----------------------------------------------------------------------

    private fun runFieldState() {
        val currentContext = establishedContext() ?: return
        val session = inputSessionUser.value()
        val site = operatingSite(currentContext)
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

    /**
     * Accept or decline one assignment, through the gateway.
     *
     * `expected_status` is left at `GatewaySession`'s default. It is the
     * client's statement of the status it BELIEVES the assignment is in, and the
     * server refuses the operation if reality has moved on — which is how a
     * stale list on a handset fails loudly instead of silently overwriting a
     * newer decision.
     */
    private fun runAssignmentAction(accept: Boolean) {
        val currentContext = establishedContext() ?: return
        val assignmentId = inputAssignment.value()
        if (!FieldReads.isSafePathId(assignmentId)) {
            log("enter an assignment id (list them first).")
            return
        }
        val session = inputSessionUser.value()
        val site = operatingSite(currentContext)
        val gateway = gateway()
        val verb = if (accept) "accept" else "decline"

        background {
            log("POST operations/assignments/$assignmentId/$verb (FRESH hardware proof) ...")
            val result = gateway.actOnAssignment(
                sessionUserId = session,
                context = currentContext,
                siteId = site,
                assignmentId = assignmentId,
                accept = accept,
            )
            if (!result.isOk) {
                log(result.describe())
                return@background
            }
            log("operation: ${result.valueOrThrow()}")
        }
    }

    private fun runAcknowledgeMessage() {
        val currentContext = establishedContext() ?: return
        val messageId = inputMessage.value()
        if (!FieldReads.isSafePathId(messageId)) {
            log("enter a message id (list them first).")
            return
        }
        val session = inputSessionUser.value()
        val site = operatingSite(currentContext)
        val gateway = gateway()

        background {
            log("POST operations/messages/$messageId/acknowledge (FRESH hardware proof) ...")
            val result = gateway.acknowledgeMessage(
                sessionUserId = session,
                context = currentContext,
                siteId = site,
                messageId = messageId,
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
            store?.forgetAll()
            log("device key discarded and client state forgotten. A new ceremony needs a NEW server challenge and a NEW key.")
        }
    }

    /**
     * Clears the bootstrap grant from the input.
     *
     * Called from the worker thread, so it hops to the UI thread like every
     * other view touch here.
     */
    private fun clearBootstrapToken() {
        runOnUiThread { inputBootstrapToken.setText("") }
    }

    /** The established context, or a log line explaining why there is none. */
    private fun establishedContext(): GatewaySession.DeviceContext? {
        val current = deviceContext
        if (current == null) {
            log("establish a device context first (step 4): every operation is signed against it.")
        }
        return current
    }

    /**
     * The site an operation is signed against.
     *
     * The context's OWN authorised sites come first: the server decided that
     * list, and signing against a site the context does not carry is a refusal
     * waiting to happen. The typed site is a fallback for the case where the
     * server returned none.
     */
    private fun operatingSite(context: GatewaySession.DeviceContext): String =
        context.authorisedSiteIds.firstOrNull() ?: inputSite.value()

    private fun ceremony(): EnrollmentCeremony = EnrollmentCeremony(SentinelHttp(inputBaseUrl.value()), keys)

    private fun gateway(): GatewaySession = GatewaySession(SentinelHttp(inputBaseUrl.value()), keys)

    private fun reads(): FieldReads = FieldReads(SentinelHttp(inputBaseUrl.value()))

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
     * session credential, a bootstrap grant or a raw signature. Everything
     * printed here is safe to print — a context id authorises nothing, and a
     * request fingerprint is a digest a commander is MEANT to compare.
     */
    private fun log(line: String) {
        runOnUiThread { textLog.append(line + "\n") }
    }
}
