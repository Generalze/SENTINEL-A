package com.sentinel.field.store

/**
 * ============================================================================
 * THE ONE WAY THE OFFLINE QUEUE REACHES DISK.
 *
 * A two-method interface over a single protected document, and the exact
 * counterpart of [KeyValueStore]: the RULES about the queue — sequence
 * allocation, duplicate refusal, depth bounding, what "terminal" means — live
 * in [OfflineOutbox], which is pure Kotlin the JVM unit tests can execute,
 * while the Android binding ([EncryptedOutboxFile]) stays a thin adapter with
 * no policy in it at all.
 *
 * WHY ONE DOCUMENT AND NOT A KEY PER ENTRY
 * ----------------------------------------
 * The queue and its NEXT-SEQUENCE COUNTER must move together or not at all. If
 * the counter were a separate key, a crash between "counter incremented" and
 * "entry appended" would burn a position that no operation ever occupies — a
 * permanent gap in the per-device sequence, which is precisely what the WP-20
 * cursor refuses to skip past. One document, written whole, makes that window
 * structurally impossible rather than merely unlikely.
 *
 * There is deliberately no `append`, no `delete` and no partial update. A
 * partial update is the shape through which half a queue reaches disk.
 * ============================================================================
 */
interface ProtectedFileStore {

    /** The whole stored document, or null when nothing has ever been written. */
    fun read(): String?

    /**
     * Replaces the whole document with [text].
     *
     * The implementation MUST be all-or-nothing: after this returns, either the
     * complete new document is readable or the complete previous one still is.
     * A truncated document is not an acceptable third outcome — it is a queue
     * with operations missing, and a missing queued acknowledgement is lost
     * forever.
     *
     * Throwing is the correct behaviour when the write cannot be completed. The
     * caller treats a throw as "nothing changed", which is only true because
     * this contract says the previous document survives.
     */
    fun write(text: String)
}
