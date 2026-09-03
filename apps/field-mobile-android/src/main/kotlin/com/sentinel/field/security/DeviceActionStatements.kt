package com.sentinel.field.security

/**
 * ============================================================================
 * WP-27 — THE v2 DEVICE-ACTION STATEMENT, AS THIS CLIENT MUST PRODUCE IT.
 *
 * It mirrors ONE server-side object literal:
 *
 *   `whisperDeviceActionV2StatementObject`
 *   packages/contracts/src/whisper-device-action-v2.ts
 *   domain: sentinel.whisper.device-action.v2
 *
 * and its claim half mirrors `whisperDeviceActionV2ClaimsShape` in the same
 * file. Both are listed field by field, in the server's own file order, for the
 * reason `DeviceStatements` gives for the other four: a field added to a
 * statement must not slip into the signed bytes without somebody deciding it
 * should be there.
 *
 * FIELD ORDER IS DOCUMENTATION, NOT MECHANISM. `canonicalDeviceJson` sorts keys
 * recursively, so what decides the bytes is the SET of keys and their values,
 * never the order they were written in. The order here matches the contract's
 * so a reviewer can read the two side by side.
 *
 * A COMMITTED FIXTURE DECIDES WHETHER THIS IS RIGHT.
 * `services/core-api/src/modules/whisper-device-action/fixtures/
 * whisper-device-action-v2.interop.json` carries the canonical statement and
 * its SHA-256 as the server produced them. `DeviceActionStatementsInteropTest`
 * reproduces both from the fields in that same file and asserts byte equality.
 * That test, and not this comment, is the evidence.
 *
 * WHY THERE ARE TWO BUILDERS AND WHAT SEPARATES THEM
 * --------------------------------------------------
 * [statement] is what the HARDWARE KEY SIGNS. [claims] is what goes ON THE
 * WIRE. They are deliberately different sets:
 *
 *   * the statement carries the SERVER-RESOLVED IDENTITY — `context_id`,
 *     `organisation_id`, `site_id`, `actor_user_id`, `device_id` — which the
 *     claims must NOT carry. `WhisperDeviceActionV2ClaimsSchema` is `.strict()`
 *     and the server assembles the identity from the persisted context, so a
 *     claim that proposed one would be refused. The device signs those values
 *     so the signature is bound to whose action it is; it does not get to SAY
 *     them.
 *
 *   * the statement carries `signature_profile`; the claims must NOT. C11-04 —
 *     the algorithm is the REGISTRY's answer for the resolved key. There is no
 *     client field for it, and `.strict()` makes `signature_algorithm`,
 *     `signature_profile`, `curve`, `hash_algorithm` and any public key parse
 *     failures rather than ignored extras.
 *
 *   * the statement excludes `signature`, because it is the output. The claims
 *     carry it, because it is what is being delivered.
 *
 * THE PROFILE THIS CLIENT PUTS IN THE SIGNED BYTES
 * ------------------------------------------------
 * The statement's `signature_profile` is the SERVER's answer, and the client
 * must nevertheless produce the same bytes before it can sign them. It uses
 * `DeviceStatements.SIGNATURE_PROFILE` — the one approved profile, and the only
 * one StrongBox can produce — exactly as the other four statements do. If a
 * registry record ever resolved to something else, this client's signature
 * would fail to verify, LOUDLY, rather than quietly signing a different claim.
 * That is the correct failure: the client is not entitled to be told what the
 * registry holds, and it is not entitled to negotiate it either.
 * ============================================================================
 */
object DeviceActionStatements {

    /**
     * Domain separator, DISTINCT from v1's `sentinel.whisper.device-action.v1`
     * and from every WP-23..26 statement this client already produces.
     */
    const val DOMAIN = "sentinel.whisper.device-action.v2"

    /** A literal on both sides, and the reason dispatch is deterministic. */
    const val SCHEMA_VERSION = 2

    /** Pinned, as v1 pins it: DEVICE_ACTION is the only modality M3 admits. */
    const val MODALITY = "DEVICE_ACTION"

    /** The gateway operation kind whose route carries this statement. */
    const val OPERATION_KIND = "DEVICE_ACTION"

    /**
     * The confidence value, as a canonical JSON number.
     *
     * WHOLE HUNDREDTHS, AND NOTHING ELSE. `confidence` is the one non-integer
     * in any Sentinel statement, and a floating-point value printed by Kotlin
     * is not guaranteed to be the same digits V8 prints for the double the
     * server parses — see the long note in [CanonicalJson]. So this client can
     * only express 0.00 to 1.00 in steps of 0.01, the signed digits are built
     * from that integer, and a value outside the range is refused rather than
     * clamped.
     *
     * It narrows what this client can claim. It does not narrow what the SERVER
     * accepts, and it must never be read as a contract change: the contract's
     * bound is still `z.number().min(0).max(1)`.
     */
    fun confidence(hundredths: Int): CanonicalJson.JsonNumber =
        CanonicalJson.JsonNumber.ofHundredths(hundredths)

    /**
     * EXACTLY what the hardware key signs.
     *
     * Every field, and why it is bound, is set out in the contract's own note
     * above `whisperDeviceActionV2StatementObject`. The two that are easiest to
     * mistake for decoration are the two that make the statement unportable:
     * `actor_user_id`, so one operative's statement cannot be presented as
     * another's on a signal both are authorised for, and `context_id`, which no
     * device can mint — so a statement cannot be pre-computed for a ceremony the
     * server never issued, nor outlive it.
     */
    fun statement(
        contextId: String,
        organisationId: String,
        siteId: String,
        actorUserId: String,
        deviceId: String,
        keyId: String,
        keyVersion: Int,
        whisperSignalId: String,
        whisperSignalVersion: Int,
        deviceActionId: String,
        recognisedAt: String,
        confidenceHundredths: Int,
        antiReplayNonce: String,
        signatureProfile: String = DeviceStatements.SIGNATURE_PROFILE,
    ): String = CanonicalJson.encode(
        linkedMapOf<String, Any?>(
            "domain" to DOMAIN,
            "schema_version" to SCHEMA_VERSION,
            "context_id" to contextId,
            "organisation_id" to organisationId,
            "site_id" to siteId,
            "actor_user_id" to actorUserId,
            "device_id" to deviceId,
            "key_id" to keyId,
            "key_version" to keyVersion,
            "whisper_signal_id" to whisperSignalId,
            "whisper_signal_version" to whisperSignalVersion,
            "modality" to MODALITY,
            "device_action_id" to deviceActionId,
            "recognised_at" to recognisedAt,
            "confidence" to confidence(confidenceHundredths),
            "anti_replay_nonce" to antiReplayNonce,
            "signature_profile" to signatureProfile,
        ),
    )

    /**
     * SHA-256 over the canonical statement — the server's
     * `whisperDeviceActionV2Fingerprint`.
     *
     * The client never sends it. It exists so the interop fixture's recorded
     * digest can be asserted against these bytes, and so a human comparing a
     * handset's log with a server audit row is comparing one recipe.
     */
    fun fingerprint(
        contextId: String,
        organisationId: String,
        siteId: String,
        actorUserId: String,
        deviceId: String,
        keyId: String,
        keyVersion: Int,
        whisperSignalId: String,
        whisperSignalVersion: Int,
        deviceActionId: String,
        recognisedAt: String,
        confidenceHundredths: Int,
        antiReplayNonce: String,
        signatureProfile: String = DeviceStatements.SIGNATURE_PROFILE,
    ): String = CanonicalPublicKey.sha256HexUtf8(
        statement(
            contextId = contextId,
            organisationId = organisationId,
            siteId = siteId,
            actorUserId = actorUserId,
            deviceId = deviceId,
            keyId = keyId,
            keyVersion = keyVersion,
            whisperSignalId = whisperSignalId,
            whisperSignalVersion = whisperSignalVersion,
            deviceActionId = deviceActionId,
            recognisedAt = recognisedAt,
            confidenceHundredths = confidenceHundredths,
            antiReplayNonce = antiReplayNonce,
            signatureProfile = signatureProfile,
        ),
    )

    /**
     * The CLAIM half — what this device actually sends, and nothing more.
     *
     * ELEVEN FIELDS. NOTE WHAT IS ABSENT, AND THAT IT IS ABSENT BY
     * CONSTRUCTION: no `signature_algorithm`, no `signature_profile`, no
     * `curve`, no `hash_algorithm`, no public key, no trust word, no serialized
     * context, no identity the server owns. There is no parameter here through
     * which any of them could be supplied, so the absence is not a check
     * somebody could delete.
     *
     * ONE MAP, TWO USES. The value returned here is both the semantic payload
     * the gateway envelope digest is computed over AND the body that is posted.
     * Building it twice is how the signed digest and the sent bytes come to
     * disagree, which is the same reason the contract builds its statement and
     * its fingerprint from one object literal.
     */
    fun claims(
        keyId: String,
        keyVersion: Int,
        whisperSignalId: String,
        whisperSignalVersion: Int,
        deviceActionId: String,
        recognisedAt: String,
        confidenceHundredths: Int,
        antiReplayNonce: String,
        signature: String,
    ): Map<String, Any?> = linkedMapOf<String, Any?>(
        "schema_version" to SCHEMA_VERSION,
        "key_id" to keyId,
        "key_version" to keyVersion,
        "whisper_signal_id" to whisperSignalId,
        "whisper_signal_version" to whisperSignalVersion,
        "modality" to MODALITY,
        "device_action_id" to deviceActionId,
        "recognised_at" to recognisedAt,
        "confidence" to confidence(confidenceHundredths),
        "anti_replay_nonce" to antiReplayNonce,
        "signature" to signature,
    )
}
