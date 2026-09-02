package com.sentinel.field.net

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject

/**
 * ============================================================================
 * THE READ SURFACES, READ OUT BY NAME.
 *
 * Four server views, mapped field by field, in the same explicit style
 * `EnrollmentCeremony` and `GatewaySession` use for the signing path. The
 * shapes below are transcribed from the SERVER's own mappers — they are not
 * guessed and they are not inferred from a sample response:
 *
 *   * `services/core-api/src/modules/field/field.types.ts` and
 *     `field.mapper.ts`            -> AssignmentSummary, OperativeState
 *   * `.../field-messaging/field-messaging.types.ts` and `.mapper.ts`
 *                                  -> MessageSummary
 *   * `.../patrol/patrol.types.ts` and `patrol.mapper.ts`
 *                                  -> PatrolRunSummary
 *
 * Every wire name is snake_case because every one of those mappers emits
 * snake_case. Timestamps arrive as ISO-8601 strings and are kept as strings:
 * this client does no clock arithmetic on server time, and a client that parsed
 * and re-rendered a server instant would eventually render its own timezone as
 * though it were the server's.
 *
 * NOTHING HERE IS EVER SIGNED. These are display values. The values this client
 * signs are built in `DeviceStatements` from the WP-25 context, never from a
 * parsed read.
 * ============================================================================
 */

/** `GET /api/v1/field/assignments/mine` — one element. */
data class AssignmentSummary(
    val id: String,
    val organisationId: String,
    val siteId: String,
    val incidentId: String?,
    val assigneeUserId: String,
    val assignmentType: String,
    val priority: String,
    val status: String,
    val deliveryState: String,
    val needToKnowSummary: String,
    val expiresAt: String?,
) {

    fun describe(): String =
        "$id  [$status/$deliveryState]  $priority  $assignmentType  site $siteId" +
            (incidentId?.let { "  incident $it" } ?: "") +
            (expiresAt?.let { "  expires $it" } ?: "") +
            "\n      $needToKnowSummary"

    companion object {
        fun from(view: JsonObject): AssignmentSummary = AssignmentSummary(
            id = view.text("id"),
            organisationId = view.text("organisation_id"),
            siteId = view.text("site_id"),
            incidentId = view.textOrNull("incident_id"),
            assigneeUserId = view.text("assignee_user_id"),
            assignmentType = view.text("assignment_type"),
            priority = view.text("priority"),
            status = view.text("status"),
            deliveryState = view.text("delivery_state"),
            needToKnowSummary = view.textOrNull("need_to_know_summary") ?: "",
            expiresAt = view.textOrNull("expires_at"),
        )
    }
}

/** `GET /api/v1/field/state/mine` — the whole body. */
data class OperativeState(
    val organisationId: String,
    val siteId: String,
    val userId: String,
    val deviceId: String,
    val state: String,
    val sourceAt: String,
    val receivedAt: String,
) {

    fun describe(): String =
        "state $state  |  org $organisationId  |  site $siteId  |  user $userId  |  device $deviceId" +
            "\n      device clock said $sourceAt, server received $receivedAt"

    companion object {
        fun from(view: JsonObject): OperativeState = OperativeState(
            organisationId = view.text("organisation_id"),
            siteId = view.text("site_id"),
            userId = view.text("user_id"),
            deviceId = view.text("device_id"),
            state = view.text("state"),
            sourceAt = view.text("source_at"),
            receivedAt = view.text("received_at"),
        )
    }
}

/** `GET /api/v1/field-messages/incidents/{incidentId}/mine` — one element. */
data class MessageSummary(
    val id: String,
    val organisationId: String,
    val siteId: String,
    val incidentId: String,
    val senderUserId: String,
    val body: String?,
    val sentAt: String,
    val expiresAt: String?,
    /** The caller's OWN recipient row, or null when the caller only sent this. */
    val ownDeliveryState: String?,
    val ownAcknowledgedAt: String?,
) {

    /** True when the caller is a named recipient who has not acknowledged yet. */
    val awaitingOwnAcknowledgement: Boolean
        get() = ownDeliveryState != null && ownAcknowledgedAt == null

    fun describe(): String =
        "$id  from $senderUserId  $sentAt" +
            (ownDeliveryState?.let { "  [$it]" } ?: "  [sent by you]") +
            (ownAcknowledgedAt?.let { "  acknowledged $it" } ?: "") +
            "\n      " + (body ?: "(no body)")

    companion object {
        /**
         * `recipientUserId` is the SESSION user — the person this client is
         * signed in as. It selects the caller's own recipient row out of the
         * `recipients` array, because "has this been acknowledged" is a
         * per-recipient fact and a message with four recipients has four
         * different answers.
         */
        fun from(view: JsonObject, recipientUserId: String): MessageSummary {
            val own = (view["recipients"] as? JsonArray)
                ?.mapNotNull { it as? JsonObject }
                ?.firstOrNull { it.textOrNull("recipient_user_id") == recipientUserId }
            return MessageSummary(
                id = view.text("id"),
                organisationId = view.text("organisation_id"),
                siteId = view.text("site_id"),
                incidentId = view.text("incident_id"),
                senderUserId = view.text("sender_user_id"),
                body = view.textOrNull("body"),
                sentAt = view.text("sent_at"),
                expiresAt = view.textOrNull("expires_at"),
                ownDeliveryState = own?.textOrNull("delivery_state"),
                ownAcknowledgedAt = own?.textOrNull("acknowledged_at"),
            )
        }
    }
}

/** `GET /api/v1/patrol/runs` — one element. READ ONLY; see `FieldReads`. */
data class PatrolRunSummary(
    val id: String,
    val organisationId: String,
    val siteId: String,
    val patrolRouteId: String,
    val routeVersion: Int,
    val assignedOperativeUserId: String,
    val incidentId: String?,
    val status: String,
    val scheduledStartAt: String,
    val startedAt: String?,
    val endedAt: String?,
    val checkpointCount: Int,
    /** How many checkpoints are still `PENDING` (the contract's own word). */
    val pendingCheckpointCount: Int,
) {

    fun describe(): String =
        "$id  [$status]  route $patrolRouteId v$routeVersion  site $siteId" +
            "\n      scheduled $scheduledStartAt" +
            (startedAt?.let { "  started $it" } ?: "") +
            (endedAt?.let { "  ended $it" } ?: "") +
            "\n      checkpoints: $pendingCheckpointCount pending of $checkpointCount"

    companion object {
        /** `PatrolRunCheckpointStateSchema` in `packages/contracts/src/field.ts`. */
        const val CHECKPOINT_PENDING = "PENDING"

        fun from(view: JsonObject): PatrolRunSummary {
            val checkpoints = (view["checkpoints"] as? JsonArray)
                ?.mapNotNull { it as? JsonObject }
                ?: emptyList()
            return PatrolRunSummary(
                id = view.text("id"),
                organisationId = view.text("organisation_id"),
                siteId = view.text("site_id"),
                patrolRouteId = view.text("patrol_route_id"),
                routeVersion = view.intOrNull("route_version") ?: 0,
                assignedOperativeUserId = view.text("assigned_operative_user_id"),
                incidentId = view.textOrNull("incident_id"),
                status = view.text("status"),
                scheduledStartAt = view.text("scheduled_start_at"),
                startedAt = view.textOrNull("started_at"),
                endedAt = view.textOrNull("ended_at"),
                checkpointCount = checkpoints.size,
                pendingCheckpointCount = checkpoints.count {
                    it.textOrNull("state") == CHECKPOINT_PENDING
                },
            )
        }
    }
}
