package com.sentinel.field.net

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ============================================================================
 * THE READ SURFACES, MAPPED FROM THE SERVER'S OWN SHAPES.
 *
 * Every fixture below is transcribed from the mapper that produces it — not
 * from a captured response and not from memory:
 *
 *   `field.mapper.ts`            -> mapFieldAssignment, mapFieldState
 *   `field-messaging.mapper.ts`  -> mapMessage, mapRecipient
 *   `patrol.mapper.ts`           -> mapRun, mapRunCheckpoint
 *
 * Fields this client does not use are LEFT IN the fixtures on purpose. The
 * mappers emit them, so a client that broke when they were present would break
 * against the real server; keeping them here means these tests exercise the
 * same JSON the handset will actually receive.
 * ============================================================================
 */
class FieldViewsTest {

    private fun parse(text: String) = Json.parseToJsonElement(text).jsonObject

    // -----------------------------------------------------------------------
    // GET /api/v1/field/assignments/mine
    // -----------------------------------------------------------------------

    private val assignmentJson = """
        {
          "id": "11111111-1111-1111-1111-111111111111",
          "organisation_id": "org-1",
          "site_id": "site-1",
          "incident_id": "22222222-2222-2222-2222-222222222222",
          "assignee_user_id": "user-1",
          "assignment_type": "RESPOND",
          "priority": "HIGH",
          "status": "REQUESTED",
          "delivery_state": "DELIVERED",
          "need_to_know_summary": "North gate, door held open",
          "expires_at": "2026-01-01T00:10:00.000Z",
          "accepted_at": null,
          "started_at": null,
          "completed_at": null,
          "cancelled_at": null,
          "declined_at": null,
          "created_by_user_id": "user-9",
          "updated_by_user_id": "user-9",
          "accepted_by_user_id": null,
          "created_at": "2026-01-01T00:00:00.000Z",
          "updated_at": "2026-01-01T00:00:00.000Z"
        }
    """.trimIndent()

    @Test
    fun `an assignment maps field by field`() {
        val assignment = AssignmentSummary.from(parse(assignmentJson))
        assertEquals("11111111-1111-1111-1111-111111111111", assignment.id)
        assertEquals("org-1", assignment.organisationId)
        assertEquals("site-1", assignment.siteId)
        assertEquals("22222222-2222-2222-2222-222222222222", assignment.incidentId)
        assertEquals("user-1", assignment.assigneeUserId)
        assertEquals("RESPOND", assignment.assignmentType)
        assertEquals("HIGH", assignment.priority)
        assertEquals("REQUESTED", assignment.status)
        assertEquals("DELIVERED", assignment.deliveryState)
        assertEquals("North gate, door held open", assignment.needToKnowSummary)
        assertEquals("2026-01-01T00:10:00.000Z", assignment.expiresAt)
    }

    @Test
    fun `a null incident and a null expiry stay null, never the word null`() {
        val assignment = AssignmentSummary.from(
            parse(assignmentJson.replace("\"22222222-2222-2222-2222-222222222222\"", "null")
                .replace("\"2026-01-01T00:10:00.000Z\"", "null")),
        )
        assertNull(assignment.incidentId)
        assertNull(assignment.expiresAt)
        assertFalse(assignment.describe().contains("incident null"))
    }

    @Test
    fun `an assignment describes itself with its status and its summary`() {
        val described = AssignmentSummary.from(parse(assignmentJson)).describe()
        assertTrue(described.contains("REQUESTED/DELIVERED"))
        assertTrue(described.contains("North gate, door held open"))
    }

    // -----------------------------------------------------------------------
    // GET /api/v1/field/state/mine
    // -----------------------------------------------------------------------

    @Test
    fun `the own-state body maps field by field`() {
        val state = OperativeState.from(
            parse(
                """
                {
                  "id": "33333333-3333-3333-3333-333333333333",
                  "organisation_id": "org-1",
                  "site_id": "site-1",
                  "user_id": "user-1",
                  "device_id": "device-1",
                  "state": "AVAILABLE",
                  "location": null,
                  "source_at": "2026-01-01T00:00:00.000Z",
                  "received_at": "2026-01-01T00:00:01.000Z",
                  "client_freshness_ms": 0,
                  "authoritative_freshness_ms": 1000,
                  "trace_id": "trace-1",
                  "updated_at": "2026-01-01T00:00:01.000Z"
                }
                """.trimIndent(),
            ),
        )
        assertEquals("org-1", state.organisationId)
        assertEquals("site-1", state.siteId)
        assertEquals("user-1", state.userId)
        assertEquals("device-1", state.deviceId)
        assertEquals("AVAILABLE", state.state)
        assertEquals("2026-01-01T00:00:00.000Z", state.sourceAt)
        assertEquals("2026-01-01T00:00:01.000Z", state.receivedAt)
    }

    // -----------------------------------------------------------------------
    // GET /api/v1/field-messages/incidents/{incidentId}/mine
    // -----------------------------------------------------------------------

    private val messageJson = """
        {
          "id": "44444444-4444-4444-4444-444444444444",
          "organisation_id": "org-1",
          "site_id": "site-1",
          "incident_id": "22222222-2222-2222-2222-222222222222",
          "sender_user_id": "user-9",
          "body": "Hold position at the north gate.",
          "media_refs": [],
          "retention_class": "OPERATIONAL",
          "sent_at": "2026-01-01T00:00:00.000Z",
          "expires_at": null,
          "trace_id": "trace-2",
          "recipients": [
            {
              "recipient_user_id": "user-1",
              "delivery_state": "DELIVERED",
              "delivered_at": "2026-01-01T00:00:02.000Z",
              "acknowledged_at": null
            },
            {
              "recipient_user_id": "user-2",
              "delivery_state": "ACKNOWLEDGED",
              "delivered_at": "2026-01-01T00:00:02.000Z",
              "acknowledged_at": "2026-01-01T00:00:30.000Z"
            }
          ]
        }
    """.trimIndent()

    @Test
    fun `a message maps field by field and picks the CALLER's own recipient row`() {
        val message = MessageSummary.from(parse(messageJson), "user-1")
        assertEquals("44444444-4444-4444-4444-444444444444", message.id)
        assertEquals("22222222-2222-2222-2222-222222222222", message.incidentId)
        assertEquals("user-9", message.senderUserId)
        assertEquals("Hold position at the north gate.", message.body)
        assertEquals("2026-01-01T00:00:00.000Z", message.sentAt)
        assertNull(message.expiresAt)
        assertEquals("DELIVERED", message.ownDeliveryState)
        assertNull(message.ownAcknowledgedAt)
        assertTrue(message.awaitingOwnAcknowledgement)
    }

    /**
     * The same message, read by a DIFFERENT recipient, is a different answer.
     * "Has this been acknowledged" is per-recipient, and a client that read the
     * first row in the array would tell one operative about another's state.
     */
    @Test
    fun `a second recipient sees their OWN acknowledgement, not the first row`() {
        val message = MessageSummary.from(parse(messageJson), "user-2")
        assertEquals("ACKNOWLEDGED", message.ownDeliveryState)
        assertEquals("2026-01-01T00:00:30.000Z", message.ownAcknowledgedAt)
        assertFalse(message.awaitingOwnAcknowledgement)
    }

    @Test
    fun `the SENDER has no recipient row and is not shown as awaiting anything`() {
        val message = MessageSummary.from(parse(messageJson), "user-9")
        assertNull(message.ownDeliveryState)
        assertNull(message.ownAcknowledgedAt)
        assertFalse(message.awaitingOwnAcknowledgement)
        assertTrue(message.describe().contains("sent by you"))
    }

    @Test
    fun `a null body renders as an absence, not as the word null`() {
        val message = MessageSummary.from(
            parse(messageJson.replace("\"Hold position at the north gate.\"", "null")),
            "user-1",
        )
        assertNull(message.body)
        assertTrue(message.describe().contains("(no body)"))
    }

    // -----------------------------------------------------------------------
    // GET /api/v1/patrol/runs
    // -----------------------------------------------------------------------

    private val runJson = """
        {
          "id": "55555555-5555-5555-5555-555555555555",
          "organisation_id": "org-1",
          "site_id": "site-1",
          "patrol_route_id": "66666666-6666-6666-6666-666666666666",
          "route_version": 3,
          "assigned_operative_user_id": "user-1",
          "incident_id": null,
          "status": "IN_PROGRESS",
          "scheduled_start_at": "2026-01-01T00:00:00.000Z",
          "started_at": "2026-01-01T00:01:00.000Z",
          "ended_at": null,
          "abandon_reason": null,
          "created_by_user_id": "user-9",
          "created_at": "2026-01-01T00:00:00.000Z",
          "updated_at": "2026-01-01T00:01:00.000Z",
          "trace_id": "trace-3",
          "checkpoints": [
            { "id": "c1", "sequence_number": 1, "state": "VERIFIED" },
            { "id": "c2", "sequence_number": 2, "state": "PENDING" },
            { "id": "c3", "sequence_number": 3, "state": "PENDING" }
          ]
        }
    """.trimIndent()

    @Test
    fun `a patrol run maps field by field`() {
        val run = PatrolRunSummary.from(parse(runJson))
        assertEquals("55555555-5555-5555-5555-555555555555", run.id)
        assertEquals("site-1", run.siteId)
        assertEquals("66666666-6666-6666-6666-666666666666", run.patrolRouteId)
        assertEquals(3, run.routeVersion)
        assertEquals("user-1", run.assignedOperativeUserId)
        assertNull(run.incidentId)
        assertEquals("IN_PROGRESS", run.status)
        assertEquals("2026-01-01T00:00:00.000Z", run.scheduledStartAt)
        assertEquals("2026-01-01T00:01:00.000Z", run.startedAt)
        assertNull(run.endedAt)
    }

    @Test
    fun `checkpoints are counted, and only PENDING counts as outstanding`() {
        val run = PatrolRunSummary.from(parse(runJson))
        assertEquals(3, run.checkpointCount)
        assertEquals(2, run.pendingCheckpointCount)
        assertTrue(run.describe().contains("2 pending of 3"))
    }

    @Test
    fun `a run with no checkpoints array counts zero rather than throwing`() {
        val run = PatrolRunSummary.from(
            parse(runJson.replaceAfter("\"checkpoints\":", " [] }")),
        )
        assertEquals(0, run.checkpointCount)
        assertEquals(0, run.pendingCheckpointCount)
    }

    // -----------------------------------------------------------------------
    // Route construction
    // -----------------------------------------------------------------------

    @Test
    fun `the four read routes are the ones the server declares`() {
        assertEquals("/api/v1/field/state/mine", FieldReads.ROUTE_OWN_STATE)
        assertEquals("/api/v1/field/assignments/mine", FieldReads.ROUTE_OWN_ASSIGNMENTS)
        assertEquals("/api/v1/patrol/runs", FieldReads.ROUTE_PATROL_RUNS)
        assertEquals(
            "/api/v1/field-messages/incidents/22222222-2222-2222-2222-222222222222/mine",
            FieldReads.routeIncidentMessages("22222222-2222-2222-2222-222222222222"),
        )
    }

    @Test
    fun `an id that would change the shape of the URL is refused, not encoded away`() {
        assertTrue(FieldReads.isSafePathId("22222222-2222-2222-2222-222222222222"))
        assertFalse(FieldReads.isSafePathId(""))
        assertFalse(FieldReads.isSafePathId(".."))
        assertFalse(FieldReads.isSafePathId("a/b"))
        assertFalse(FieldReads.isSafePathId("a?b=c"))
        assertFalse(FieldReads.isSafePathId("a#b"))
        assertFalse(FieldReads.isSafePathId("a b"))
        try {
            FieldReads.routeIncidentMessages("../oversight/incidents/other")
            throw AssertionError("expected an unusable id to be refused")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message!!.contains("not a usable id"))
        }
    }

    /**
     * The dot is legal inside an id, so the character class alone would let a
     * bare `..` through — and a `..` segment is normalised away by the URL
     * parser, quietly turning the message route into a different one. An id
     * that is nothing but dots is refused for that reason and no other.
     */
    @Test
    fun `a dot inside an id is legal, but an id that is only dots is not`() {
        assertTrue(FieldReads.isSafePathId("a.b"))
        assertTrue(FieldReads.isSafePathId("1.0.0"))
        assertFalse(FieldReads.isSafePathId("."))
        assertFalse(FieldReads.isSafePathId("..."))
        assertFalse(FieldReads.isSafePathId("a/../b"))
    }
}
