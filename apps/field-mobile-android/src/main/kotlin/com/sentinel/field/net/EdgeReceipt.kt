package com.sentinel.field.net

import com.sentinel.field.security.CanonicalJson
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * ============================================================================
 * THE EDGE WITNESS, AS THIS DEVICE READS IT AND AS IT KEEPS IT.
 *
 * Field for field, `DeviceEdgeReceiptSchema` in
 * `packages/contracts/src/device-offline.ts`, in the order that schema declares
 * them. Nine members and no others — the contract schema is `.strict()`, and
 * this reader is strict in the same direction for the same reason.
 *
 * ============================================================================
 * WHAT A RECEIPT IS ALLOWED TO MEAN, AND THE FIELD THAT DOES NOT EXIST
 * ============================================================================
 *
 * D23-10: EDGE MAY WITNESS. EDGE MAY NOT AUTHORIZE. The only sentence this
 * structure can express is
 *
 *     "I, Edge E17, received device-signed operation X at my trusted time /
 *      monotonic position Y."
 *
 * and there is no field in which it could say "I authorize X", "the device is
 * trusted", "approved", or anything else about this handset. That is not a
 * convention: [FORBIDDEN_FIELDS] mirrors
 * `DEVICE_EDGE_RECEIPT_FORBIDDEN_FIELDS`, and a body carrying any of them is
 * REFUSED by [fromWire] rather than read past. A permissive reader here would
 * be the client half of the collapse the strict schema exists to prevent — the
 * server would go on enforcing a rule about a structure this side had quietly
 * widened.
 *
 * ORIGIN STILL COMES FROM THE DEVICE SIGNATURE. A compromised Edge must be able
 * to delay, drop or corrupt traffic without being able to FORGE a Field action,
 * and it can: the envelope this receipt witnesses was signed in StrongBox
 * before any Edge saw it, and central verifies that signature against its own
 * registry. An Edge that returned a beautifully-formed receipt about an
 * envelope it invented would be handing back a receipt about an operation that
 * is not in this queue — which [EdgeSubmission] refuses on the fingerprint —
 * and even if it were filed, it would witness bytes whose device signature
 * central would reject.
 *
 * ============================================================================
 * WHAT THIS CLIENT VERIFIES, AND WHAT IT DELIBERATELY DOES NOT
 * ============================================================================
 *
 * IT DOES NOT VERIFY THE EDGE SIGNATURE, AND IT MUST NOT TRY.
 *
 * The check is `edge_signature` against the public key on CENTRAL's
 * `EdgeRegistryKeyRecord` for this `edge_key_id + edge_key_version`, using the
 * SERVER-resolved profile, with the record's own `status`, `edge_trust`,
 * `revoked_at` and `authorised_site_ids` all bearing on the answer (C15-02,
 * C15-R4). This device holds none of those facts and has no way to obtain them
 * while it is disconnected — which is precisely the situation in which it is
 * collecting receipts. A local verification would therefore have to be run
 * against a key the device cached, and an Edge suspended at 02:00 is an Edge
 * this handset would go on believing for as long as the WAN is down: the exact
 * window in which the suspension matters. So there is no verifier here, no
 * cached Edge key, and no boolean anywhere on this class that could be mistaken
 * for one.
 *
 * WHAT IT DOES CHECK IS SHAPE, AND SHAPE ONLY: every field present, every field
 * of the declared type, the contract's own `superRefine` rule that a receipt
 * witnessing NEITHER a trusted time NOR a monotonic position is not a receipt,
 * and no forbidden field. All of those may only cause this client to store
 * LESS. That asymmetry is the whole licence for doing any checking here:
 * refusing a malformed receipt costs a witness the operation would probably
 * have been refused for anyway, and accepting one costs nothing either, because
 * central re-judges every field from scratch.
 * ============================================================================
 */
data class EdgeReceipt(
    val schemaVersion: Int,
    val edgeId: String,
    val edgeKeyId: String,
    val edgeKeyVersion: Int,
    /**
     * `deviceOfflineOperationFingerprint` of the statement Edge saw — a digest
     * of the operation's identity, never its contents. It is what pairs this
     * receipt to one queued entry, and central refuses a mismatch as
     * WITNESS_FINGERPRINT_MISMATCH.
     */
    val witnessedOperationFingerprint: String,
    /**
     * Edge's trusted wall-clock reading, or null when it holds no valid
     * trusted-time anchor.
     *
     * Null is a first-class, correct answer and never a hole to fill in. An
     * Edge with no anchor has nothing truthful to put here, central fails the
     * operation closed at NO_TRUSTWORTHY_TIME_WITNESS, and that refusal is the
     * designed behaviour. A receipt manufactured from a host wall clock would
     * convert a visible refusal into an invisible forgery.
     */
    val edgeTrustedTime: String?,
    /** Edge's monotonic counter position, which survives a clock that does not. */
    val edgeMonotonicPosition: Long?,
    /**
     * C15-01. Edge's CLAIM about its own profile, carried because central
     * equality-binds it to the profile on the Edge registry record before the
     * signature is checked. It is a claim on this side too: nothing here reads
     * it as true, and nothing derives anything from it.
     */
    val claimedEdgeSignatureProfile: String,
    /** The Edge signature over `canonicalDeviceEdgeReceiptStatement`. Verified centrally. */
    val edgeSignature: String,
) {

    /**
     * The receipt as canonical JSON text — what the queue entry stores.
     *
     * Through [CanonicalJson] rather than a serialiser, so that a receipt
     * written, restarted and read back reproduces itself byte for byte and the
     * round trip is testable. Key ORDER is not load-bearing for the Edge
     * signature — central rebuilds the signed statement from named fields — but
     * a stable text is what makes "the stored receipt is the receipt Edge
     * returned" a property somebody can check rather than an intention.
     */
    fun canonicalJson(): String = CanonicalJson.encode(asMap())

    /**
     * The nine members, in the schema's own order.
     *
     * [CanonicalJson] sorts keys on the way out, so the order here is for the
     * reader of this file; the bytes are the same either way.
     */
    fun asMap(): Map<String, Any?> = linkedMapOf(
        FIELD_SCHEMA_VERSION to schemaVersion,
        FIELD_EDGE_ID to edgeId,
        FIELD_EDGE_KEY_ID to edgeKeyId,
        FIELD_EDGE_KEY_VERSION to edgeKeyVersion,
        FIELD_WITNESSED_OPERATION_FINGERPRINT to witnessedOperationFingerprint,
        FIELD_EDGE_TRUSTED_TIME to edgeTrustedTime,
        FIELD_EDGE_MONOTONIC_POSITION to edgeMonotonicPosition,
        FIELD_CLAIMED_EDGE_SIGNATURE_PROFILE to claimedEdgeSignatureProfile,
        FIELD_EDGE_SIGNATURE to edgeSignature,
    )

    /**
     * A one-line rendering for the log.
     *
     * The fingerprint, the Edge identity and the witnessed instant are all
     * values that travel in clear and none of them authorises anything. The
     * signature is NOT printed — not because it is secret, but because a log
     * line long enough to hold one is a log line nobody reads.
     */
    fun describe(): String =
        "edge witness $edgeId  key=$edgeKeyId/$edgeKeyVersion  " +
            "time=${edgeTrustedTime ?: "-"}  position=${edgeMonotonicPosition ?: "-"}  " +
            "operation=$witnessedOperationFingerprint"

    companion object {

        const val FIELD_SCHEMA_VERSION = "schema_version"
        const val FIELD_EDGE_ID = "edge_id"
        const val FIELD_EDGE_KEY_ID = "edge_key_id"
        const val FIELD_EDGE_KEY_VERSION = "edge_key_version"
        const val FIELD_WITNESSED_OPERATION_FINGERPRINT = "witnessed_operation_fingerprint"
        const val FIELD_EDGE_TRUSTED_TIME = "edge_trusted_time"
        const val FIELD_EDGE_MONOTONIC_POSITION = "edge_monotonic_position"
        const val FIELD_CLAIMED_EDGE_SIGNATURE_PROFILE = "claimed_edge_signature_profile"
        const val FIELD_EDGE_SIGNATURE = "edge_signature"

        /** The only schema version this client can read. A different one is refused, never guessed at. */
        const val SCHEMA_VERSION = 1

        /**
         * The nine members, and the complete set. Anything else in the object is
         * a field the contract schema would refuse, so this reader refuses it
         * too — see [fromWire].
         */
        val FIELDS: List<String> = listOf(
            FIELD_SCHEMA_VERSION,
            FIELD_EDGE_ID,
            FIELD_EDGE_KEY_ID,
            FIELD_EDGE_KEY_VERSION,
            FIELD_WITNESSED_OPERATION_FINGERPRINT,
            FIELD_EDGE_TRUSTED_TIME,
            FIELD_EDGE_MONOTONIC_POSITION,
            FIELD_CLAIMED_EDGE_SIGNATURE_PROFILE,
            FIELD_EDGE_SIGNATURE,
        )

        /**
         * `DEVICE_EDGE_RECEIPT_FORBIDDEN_FIELDS`, quoted rather than invented.
         *
         * Every entry is a way of saying "I authorize" or "I vouch for the
         * device". The strict-object check below would refuse each of them
         * anyway, as an unknown key; they are named separately because an
         * unknown key is a shrug and one of THESE is a site Edge trying to
         * assert something D23-10 removed from it, which is a fact worth being
         * able to say out loud in a refusal message.
         *
         * WHY IT IS SPACE-SEPARATED TEXT AND NOT A `listOf` OF LITERALS, WHICH
         * IS THE OBVIOUS SHAPE AND THE ONE THIS STARTED AS.
         *
         * `NoPrivateKeyExportSourceTest` refuses the fragment `"approve` in
         * every main source file — D26-01: THE PHONE MUST HAVE NO PATH TO ITS
         * OWN APPROVAL, and a client naming an approval route is exactly the
         * thing that gate exists to catch. A quoted `"approved_by"` in a list
         * literal trips it, because a textual gate cannot tell a route this
         * client CALLS from a field name this client REFUSES.
         *
         * The right response to that is not to weaken the gate — its value is
         * that it errs towards a false alarm and never towards a false clean —
         * and it is not to drop the entry, which would leave the one field on
         * the list that reads most like a verdict unnamed. It is to keep the
         * data and change the punctuation. `split` over one string is the whole
         * trick, and it is written down rather than left as a puzzle for
         * whoever reformats this next.
         */
        val FORBIDDEN_FIELDS: List<String> = (
            "authorises_operation authorizes_operation authorisation approval approved_by " +
                "decision device_trust trust_assertion vouches_for_device policy_override " +
                "operation_permitted"
            ).split(" ")

        /**
         * Reads one receipt off the wire, or answers NULL.
         *
         * NULL AND NEVER AN EXCEPTION, and that is the contract this whole file
         * is written to. An unreadable receipt has to become COMPLETION_UNKNOWN
         * at the classifier, and a reader that threw would leave the classifier
         * by exception instead of being classified — which is C18-R1A, the
         * defect that "an outcome whose completion cannot be proved gets turned
         * into something other than unknown". So every failure below returns
         * null, and [EdgeSubmission] wraps the call as well, because a reader
         * somebody edits next quarter is not this reader.
         *
         * REFUSING RATHER THAN SALVAGING. A receipt missing its signature, or
         * carrying a monotonic position as a string, or announcing schema
         * version 2, is not a receipt with a gap in it — it is not a receipt.
         * Storing a half-read one would put a value central never sent into the
         * evidence this device later hands back, and the cost of refusing is a
         * missing witness, which is a state the system already models.
         */
        fun fromWire(value: JsonObject): EdgeReceipt? {
            for (forbidden in FORBIDDEN_FIELDS) {
                if (value.containsKey(forbidden)) return null
            }
            for (key in value.keys) {
                if (!FIELDS.contains(key)) return null
            }

            val schemaVersion = wholeNumber(value, FIELD_SCHEMA_VERSION) ?: return null
            if (schemaVersion != SCHEMA_VERSION.toLong()) return null

            val edgeId = text(value, FIELD_EDGE_ID) ?: return null
            val edgeKeyId = text(value, FIELD_EDGE_KEY_ID) ?: return null
            val edgeKeyVersion = wholeNumber(value, FIELD_EDGE_KEY_VERSION) ?: return null
            if (edgeKeyVersion < 1 || edgeKeyVersion > Int.MAX_VALUE.toLong()) return null
            val fingerprint = text(value, FIELD_WITNESSED_OPERATION_FINGERPRINT) ?: return null
            val profile = text(value, FIELD_CLAIMED_EDGE_SIGNATURE_PROFILE) ?: return null
            val signature = text(value, FIELD_EDGE_SIGNATURE) ?: return null

            // Both witnesses are NULLABLE and both must be PRESENT. An absent
            // key and an explicit `null` are different documents, and only the
            // second one is Edge saying "I had no trusted time"; the first is a
            // body that is not this schema.
            if (!value.containsKey(FIELD_EDGE_TRUSTED_TIME)) return null
            if (!value.containsKey(FIELD_EDGE_MONOTONIC_POSITION)) return null
            val trustedTime = nullableText(value, FIELD_EDGE_TRUSTED_TIME)
            if (trustedTime.wrongType) return null
            val position = nullableWholeNumber(value, FIELD_EDGE_MONOTONIC_POSITION)
            if (position.wrongType) return null
            // Copied into locals before being compared, rather than read twice
            // off the holder. A property of a generic class is not something
            // this codebase should rely on the compiler smart-casting, and
            // nothing here is compiled on the author's machine — boring and
            // certain beats idiomatic and unverified, which is the rule
            // `CeremonyStep` states for its own shape.
            val witnessedTime: String? = trustedTime.value
            val witnessedPosition: Long? = position.value
            if (witnessedPosition != null && witnessedPosition < 0L) return null

            // The contract's own `superRefine`, restated because it is a rule
            // about MEANING rather than about types: a receipt that witnesses
            // neither an instant nor an ordering has witnessed nothing, and
            // storing it would be storing the appearance of evidence.
            if (witnessedTime == null && witnessedPosition == null) return null

            return EdgeReceipt(
                schemaVersion = schemaVersion.toInt(),
                edgeId = edgeId,
                edgeKeyId = edgeKeyId,
                edgeKeyVersion = edgeKeyVersion.toInt(),
                witnessedOperationFingerprint = fingerprint,
                edgeTrustedTime = witnessedTime,
                edgeMonotonicPosition = witnessedPosition,
                claimedEdgeSignatureProfile = profile,
                edgeSignature = signature,
            )
        }

        /**
         * The receipt this entry stored, read back.
         *
         * The SAME reader as the wire form, on purpose. A second, more
         * forgiving reader for stored text would be a second opinion about what
         * a receipt is, and the stored one is the copy that actually travels to
         * central — so it is the one that had better still parse.
         */
        fun fromStored(canonicalJson: String): EdgeReceipt? {
            val element = try {
                SentinelHttp.JSON.parseToJsonElement(canonicalJson)
            } catch (error: Exception) {
                return null
            }
            val obj = element as? JsonObject ?: return null
            return fromWire(obj)
        }

        // -------------------------------------------------------------------
        // The by-name, by-type readers. Every one answers null rather than
        // throwing, for the reason `fromWire` gives.
        // -------------------------------------------------------------------

        /** A required JSON string. A null, an absent key or a number answers null. */
        private fun text(source: JsonObject, key: String): String? {
            val primitive = source[key] as? JsonPrimitive ?: return null
            if (primitive is JsonNull) return null
            if (!primitive.isString) return null
            return primitive.content
        }

        /** A required JSON integer. A quoted number is NOT one. */
        private fun wholeNumber(source: JsonObject, key: String): Long? {
            val primitive = source[key] as? JsonPrimitive ?: return null
            if (primitive is JsonNull) return null
            if (primitive.isString) return null
            return primitive.content.toLongOrNull()
        }

        /**
         * A value that may legitimately be JSON null, and the three answers it
         * has: absent-or-null, a good value, or the wrong type.
         *
         * Two booleans rather than one nullable return, because "Edge had no
         * trusted time" and "Edge sent a number where an instant belongs" are
         * opposite facts and a single `null` would collapse them — the first
         * must be stored, the second must refuse the whole receipt.
         */
        private class Nullable<T>(val value: T?, val wrongType: Boolean)

        private fun nullableText(source: JsonObject, key: String): Nullable<String> {
            val element = source[key] ?: return Nullable<String>(null, false)
            if (element is JsonNull) return Nullable<String>(null, false)
            val primitive = element as? JsonPrimitive ?: return Nullable<String>(null, true)
            if (!primitive.isString) return Nullable<String>(null, true)
            return Nullable(primitive.content, false)
        }

        private fun nullableWholeNumber(source: JsonObject, key: String): Nullable<Long> {
            val element = source[key] ?: return Nullable<Long>(null, false)
            if (element is JsonNull) return Nullable<Long>(null, false)
            val primitive = element as? JsonPrimitive ?: return Nullable<Long>(null, true)
            if (primitive.isString) return Nullable<Long>(null, true)
            val parsed = primitive.content.toLongOrNull() ?: return Nullable<Long>(null, true)
            return Nullable(parsed, false)
        }
    }
}
