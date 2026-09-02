package com.sentinel.field.store

/**
 * ============================================================================
 * THE CLIENT STATE THIS APP IS ALLOWED TO REMEMBER, AND NOTHING ELSE.
 *
 * D26-06 scopes secure local storage to CLIENT STATE. Every field here is a
 * NON-AUTHORITY fact:
 *
 *   * [deviceId] names a device the SERVER registered. Knowing it confers
 *     nothing — every operation still needs the hardware key and a live human
 *     session, and the server resolves the device's standing for itself.
 *
 *   * [contextId] / [contextExpiresAt] record which WP-25 context this client
 *     last established and when the server said it stops being valid. A context
 *     id is not a credential: replaying one without a fresh hardware-signed
 *     proof over a fresh one-shot nonce buys nothing (D25-01).
 *
 *   * [organisationId] / [userId] / [siteId] are the LAST KNOWN identity as the
 *     SERVER reported it, kept so the app can render something honest before
 *     the first read of the session comes back. They are a cache of a server
 *     answer, never an assertion to the server: nothing in this app sends them
 *     as a claim about who the caller is. The human session header is the only
 *     thing that answers that, and it is typed in, never stored.
 *
 * WHAT IS NOT HERE, ON PURPOSE
 * ----------------------------
 *   * THE BOOTSTRAP GRANT TOKEN. It is the ceremony secret. It is never written
 *     to this store, to plain preferences, to a file or to saved instance
 *     state, and `BootstrapTokenNeverPersistedSourceTest` fails the build if a
 *     future edit changes that.
 *   * Any session credential, key material, key handle or signature.
 *   * Any queued operation. WP-29 owns the offline queue; there is no outbox
 *     here and no retry-later store. A failed operation fails, and the operative
 *     tries again.
 * ============================================================================
 */
data class ClientState(
    val deviceId: String? = null,
    val contextId: String? = null,
    val contextExpiresAt: String? = null,
    val organisationId: String? = null,
    val userId: String? = null,
    val siteId: String? = null,
) {

    /** True when nothing at all has been remembered yet. */
    val isEmpty: Boolean
        get() = deviceId == null &&
            contextId == null &&
            contextExpiresAt == null &&
            organisationId == null &&
            userId == null &&
            siteId == null

    /**
     * A one-line rendering for the log. Safe to print in full: see the class
     * comment for why every field here authorises nothing.
     */
    fun describe(): String = if (isEmpty) {
        "remembered client state: (nothing yet)"
    } else {
        "remembered client state: device=${deviceId ?: "-"} context=${contextId ?: "-"} " +
            "expires=${contextExpiresAt ?: "-"} org=${organisationId ?: "-"} " +
            "user=${userId ?: "-"} site=${siteId ?: "-"}"
    }
}
