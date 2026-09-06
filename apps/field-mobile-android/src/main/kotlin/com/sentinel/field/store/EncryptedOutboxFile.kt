package com.sentinel.field.store

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * ============================================================================
 * THE DURABLE OFFLINE QUEUE — THE ANDROID HALF.
 *
 * A thin adapter and NOTHING ELSE, exactly as [EncryptedClientState] is for the
 * client-state store. Every rule about what may be queued, how a sequence is
 * allocated and when an entry may leave lives in [OfflineOutbox], where the JVM
 * tests can execute it; this file only says WHERE the bytes go and HOW they are
 * replaced.
 *
 * WHY `EncryptedFile` AND NOT A HAND-ROLLED WRAP
 * ---------------------------------------------
 * The same argument [EncryptedClientState] makes, and it has not weakened: a
 * hand-rolled keystore wrap would put `Cipher.getInstance` and a second
 * `KeyGenParameterSpec` into this application, both of which
 * `NoPrivateKeyExportSourceTest` refuses on sight. That test earns its keep
 * precisely because the app holds ONE key generation spec and no cipher
 * primitives, so a private-key export path cannot be assembled quietly.
 * `EncryptedFile` keeps the primitives inside a reviewed library, behind the
 * same keystore-held [MasterKey] scheme the preference store already uses.
 *
 * A FILE RATHER THAN PREFERENCES, and that is a deliberate difference from the
 * client-state store. `EncryptedSharedPreferences` is a map of small values;
 * the queue is one document that must be replaced ATOMICALLY AND WHOLE, and a
 * preference edit gives no such guarantee across many keys.
 *
 * ============================================================================
 * THE ATOMIC WRITE, AND THE DEFECT IT PREVENTS
 * ============================================================================
 *
 * A write that truncates the queue is worse than a write that fails. A failed
 * write is visible and the previous queue survives; a truncated one silently
 * destroys operations an operative already performed and already believes were
 * recorded — and, because the sequence counter lives in the same document, it
 * can also wind the counter backwards and cause the device to re-use positions
 * the server has already settled.
 *
 * So the bytes never go to the live file. They go to a TEMPORARY file, which is
 * closed and complete before anything else happens, and only then does the
 * temporary file REPLACE the live one by rename. A crash before the rename
 * leaves the previous queue intact and a stale temporary file, which the next
 * write deletes. A crash after the rename leaves the new queue intact. There is
 * no third state, because rename(2) has no partial outcome.
 *
 * `Files.move(..., ATOMIC_MOVE)` is used rather than `File.renameTo`, which
 * answers a boolean nobody is obliged to read and whose behaviour over an
 * existing destination is platform-dependent. `java.nio.file` is available from
 * API 26 and this application requires API 28, so the call is unconditional.
 *
 * THE STAGING FILE HAS THE SAME NAME, IN A DIFFERENT DIRECTORY, AND THAT IS NOT
 * A STYLE CHOICE
 * ----------------------------------------------------------------------------
 * `EncryptedFile` passes `file.getName()` to Tink as the AEAD ASSOCIATED DATA,
 * on both the encrypting and the decrypting stream. So a document encrypted as
 * `...outbox.writing` and then renamed to `...outbox` authenticates against the
 * wrong associated data and CANNOT BE DECRYPTED AGAIN — the rename would
 * destroy the queue rather than replace it, and it would do so silently, on the
 * first write, leaving a file that looks present and reads as corrupt. Staging
 * in a subdirectory under the SAME name keeps the associated data identical
 * across the move, which is the only arrangement in which temp-then-rename is
 * usable with this library at all.
 *
 * WHAT THIS DOES NOT ESTABLISH, STATED PLAINLY. The rename is atomic with
 * respect to a reader and with respect to a process crash. It is NOT a durability
 * guarantee against sudden power loss: that also wants the file and its directory
 * to be flushed to the medium, and `EncryptedFile` exposes no file descriptor
 * through which this application could do it. The property claimed here is the
 * one the mechanism actually provides — never a truncated queue — and the wider
 * durability question belongs to the Edge and reconnect work, where a witness
 * outside this handset is what closes it.
 * ============================================================================
 */
object EncryptedOutboxFile {

    /**
     * The live queue document. One file, one purpose.
     *
     * It sits beside the client-state preference file rather than inside it,
     * because the two have different write shapes and different failure modes,
     * and a store that mixed them would have to be as careful as the more
     * careful of the two everywhere.
     */
    const val FILE_NAME = "sentinel-field-offline-outbox"

    /**
     * The directory the next document is built in, under [FILE_NAME] again.
     *
     * A DIRECTORY and not a differently-named file, because the file name is the
     * AEAD associated data — see the class comment. Nothing ever reads the
     * staging copy as the queue.
     */
    const val STAGING_DIRECTORY_NAME = "outbox-staging"

    /**
     * Opens the queue.
     *
     * Throws if the platform cannot produce the master key — deliberately NOT
     * caught here and NOT quietly downgraded to a plaintext file. A queue that
     * fell back to unencrypted storage when encryption was unavailable would be
     * a queue whose confidentiality depends on the weather, and it holds the
     * operational content of everything the operative did while disconnected.
     */
    fun open(context: Context, maxDepth: Int = OfflineOutbox.DEFAULT_MAX_DEPTH): OfflineOutbox =
        OfflineOutbox(EncryptedProtectedFileStore(context.applicationContext), maxDepth)
}

/** The adapter. No policy, no sequencing, no decisions. */
private class EncryptedProtectedFileStore(
    private val context: Context,
) : ProtectedFileStore {

    private val liveFile: File get() = File(context.filesDir, EncryptedOutboxFile.FILE_NAME)

    /**
     * The same base name, one directory down, so the AEAD associated data is
     * unchanged by the move that follows.
     */
    private val stagingFile: File
        get() {
            val directory = File(context.filesDir, EncryptedOutboxFile.STAGING_DIRECTORY_NAME)
            if (!directory.isDirectory && !directory.mkdirs()) {
                throw java.io.IOException("could not create the staging directory at ${directory.absolutePath}")
            }
            return File(directory, EncryptedOutboxFile.FILE_NAME)
        }

    override fun read(): String? {
        val file = liveFile
        // A file that has never been written is an EMPTY QUEUE. A file that
        // exists and cannot be decrypted is not, and the exception is allowed
        // out: `OfflineOutbox` states why answering "empty" to an unreadable
        // queue is the one recovery that must never be offered.
        if (!file.isFile) return null
        return encrypted(file).openFileInput().use { input ->
            input.readBytes().toString(Charsets.UTF_8)
        }
    }

    override fun write(text: String) {
        val staging = stagingFile
        // `EncryptedFile.openFileOutput` refuses to open a file that already
        // exists, so a leftover staging file from an interrupted write is
        // removed first. It is never read, so discarding it loses nothing: the
        // live file is still the previous complete queue.
        if (staging.exists() && !staging.delete()) {
            throw java.io.IOException("could not clear the staging file at ${staging.absolutePath}")
        }
        encrypted(staging).openFileOutput().use { output ->
            output.write(text.toByteArray(Charsets.UTF_8))
            output.flush()
        }
        // The single instant at which the queue changes.
        Files.move(
            staging.toPath(),
            liveFile.toPath(),
            StandardCopyOption.REPLACE_EXISTING,
            StandardCopyOption.ATOMIC_MOVE,
        )
    }

    /**
     * The same master key scheme the client-state store uses.
     *
     * Built per call rather than cached: `MasterKey.Builder` resolves an
     * existing keystore entry rather than creating a second one, and a cached
     * handle in a long-lived object is a handle that outlives the reason it was
     * obtained.
     */
    private fun encrypted(file: File): EncryptedFile {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedFile.Builder(
            context,
            file,
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
        ).build()
    }
}
