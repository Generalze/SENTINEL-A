package com.sentinel.field.net

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject

/**
 * ============================================================================
 * THE READ SURFACES — ORDINARY AUTHENTICATED HUMAN ROUTES, NOT THE GATEWAY.
 *
 * D26-06 locks a client that covers identity, assignments, state, messaging and
 * patrol, "with read surfaces through ordinary authenticated routes". This
 * class is those routes and nothing else.
 *
 * WHY READS DO NOT GO THROUGH THE WP-25 GATEWAY
 * --------------------------------------------
 * The gateway exists to make an EFFECT attributable to a physical device: a
 * fresh hardware signature, over a fresh one-shot nonce, over the digest of the
 * exact operation. Reading changes nothing, produces no effect to attribute,
 * and — decisively — WP-25 exposes no read operation at all. A client that
 * invented one would be inventing platform surface from the handset, which is
 * the exact failure D26-01 exists to prevent. So a read carries the HUMAN
 * SESSION and is answered according to that person's §62 authority, exactly as
 * it would be for the same person in Command web.
 *
 * THE FOUR ROUTES, AND WHERE THEIR SHAPES WERE READ FROM
 * -----------------------------------------------------
 *   GET /api/v1/field/state/mine
 *       field.controller.ts `getOwnState`, guarded on `field.state.write`
 *       (the operative's own state read-back; `field.state.read` is the
 *       authority to read SOMEBODY ELSE and the operative does not hold it).
 *
 *   GET /api/v1/field/assignments/mine
 *       field.controller.ts `listOwnAssignments`, guarded on
 *       `field.assignment.act`. The service narrows to the caller's own
 *       assignee rows; the dispatcher's wider `assignments` route is a
 *       different route with a different action and this client never calls it.
 *
 *   GET /api/v1/field-messages/incidents/{incidentId}/mine
 *       field-messaging.controller.ts `listMine`, guarded on
 *       `field.message.read`. Messages on that incident the caller sent or was
 *       addressed in — nothing else. The `oversight/...` routes are a
 *       commander's surface and are deliberately absent from this client.
 *
 *   GET /api/v1/patrol/runs
 *       patrol.controller.ts `listRuns`, guarded on `patrol.run.read`. The
 *       service applies the C9-05 visibility split for us: a holder of
 *       `patrol.run.manage` sees command reach, and an operative — who holds
 *       read/act/verify only — is narrowed to their OWN runs. This client asks
 *       for no filter and receives whichever the server decides.
 *
 * PATROL IS READ ONLY HERE, AND THAT IS NOT AN OVERSIGHT. WP-25 exposes no
 * patrol write through the device gateway. There is therefore no signed patrol
 * operation to make, and this client does not invent one — no start, no
 * abandon, no checkpoint verification. `patrol/routes` is not read either: an
 * operative does not hold `patrol.route.read`, so calling it would only ever
 * produce a refusal.
 * ============================================================================
 */
class FieldReads(private val http: SentinelHttp) {

    companion object {
        const val ROUTE_OWN_STATE = "/api/v1/field/state/mine"
        const val ROUTE_OWN_ASSIGNMENTS = "/api/v1/field/assignments/mine"
        const val ROUTE_PATROL_RUNS = "/api/v1/patrol/runs"

        private const val MESSAGES_PREFIX = "/api/v1/field-messages/incidents/"
        private const val MESSAGES_SUFFIX = "/mine"

        /**
         * Server ids are UUIDs (`@default(uuid())` throughout the Prisma
         * schema). The character class below is wider than that on purpose — it
         * is not trying to validate an id, only to make sure a value typed into
         * a text box cannot carry a path segment or a query string into a URL
         * this client builds by concatenation.
         */
        private val SAFE_PATH_ID = Regex("^[A-Za-z0-9._~-]{1,200}$")

        /**
         * True when [id] is safe to interpolate into a path segment.
         *
         * The dot is allowed because some id schemes use it, so `.` and `..`
         * would otherwise slip through the character class — and a `..` segment
         * is normalised away by the URL parser before the request leaves,
         * silently turning `/incidents/../mine` into a different route. An id
         * that is nothing but dots is therefore refused outright.
         */
        fun isSafePathId(id: String): Boolean =
            SAFE_PATH_ID.matches(id) && !id.all { it == '.' }

        fun routeIncidentMessages(incidentId: String): String {
            require(isSafePathId(incidentId)) {
                "'$incidentId' is not a usable id: it would change the shape of the URL"
            }
            return MESSAGES_PREFIX + incidentId + MESSAGES_SUFFIX
        }
    }

    /** The operative's own current Field state, as the server holds it. */
    fun ownState(sessionUserId: String): CeremonyStep<OperativeState> =
        readObject(ROUTE_OWN_STATE, sessionUserId) { OperativeState.from(it) }

    /** The operative's own assignments. */
    fun ownAssignments(sessionUserId: String): CeremonyStep<List<AssignmentSummary>> =
        readList(ROUTE_OWN_ASSIGNMENTS, sessionUserId) { AssignmentSummary.from(it) }

    /**
     * The messages on one incident that this operative sent or was addressed
     * in.
     *
     * The incident is a PARAMETER because the server has no "all my messages"
     * route: `field-messaging.controller.ts` scopes every recipient read to one
     * incident, so the client asks per incident rather than pretending to a
     * surface that does not exist.
     */
    fun incidentMessages(sessionUserId: String, incidentId: String): CeremonyStep<List<MessageSummary>> =
        readList(routeIncidentMessages(incidentId), sessionUserId) {
            MessageSummary.from(it, sessionUserId)
        }

    /** The operative's current and scheduled patrol runs. READ ONLY. */
    fun patrolRuns(sessionUserId: String): CeremonyStep<List<PatrolRunSummary>> =
        readList(ROUTE_PATROL_RUNS, sessionUserId) { PatrolRunSummary.from(it) }

    // -----------------------------------------------------------------------

    private fun <T> readObject(
        path: String,
        sessionUserId: String,
        mapper: (JsonObject) -> T,
    ): CeremonyStep<T> {
        val reply = http.get(path, sessionUserId)
        val element = reply.element
        if (!reply.ok || element == null) return CeremonyStep.refused(reply.status, reply.text)
        val view = element as? JsonObject
            ?: return CeremonyStep.refused(reply.status, "$path did not answer with a JSON object")
        return CeremonyStep.ok(mapper(view))
    }

    /**
     * The list routes answer with a BARE JSON array, which is why
     * [SentinelHttp.get] returns an element rather than an object. An element
     * that is not an array is a refusal, not an empty list: "the server sent
     * something else" and "you have nothing" are different answers and a client
     * that collapsed them would show an operative an empty assignment list when
     * the truth was a broken response.
     */
    private fun <T> readList(
        path: String,
        sessionUserId: String,
        mapper: (JsonObject) -> T,
    ): CeremonyStep<List<T>> {
        val reply = http.get(path, sessionUserId)
        val element = reply.element
        if (!reply.ok || element == null) return CeremonyStep.refused(reply.status, reply.text)
        val array = element as? JsonArray
            ?: return CeremonyStep.refused(reply.status, "$path did not answer with a JSON array")
        return CeremonyStep.ok(array.mapNotNull { it as? JsonObject }.map(mapper))
    }
}
