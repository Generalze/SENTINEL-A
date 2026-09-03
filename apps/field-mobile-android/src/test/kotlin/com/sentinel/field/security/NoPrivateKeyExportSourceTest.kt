package com.sentinel.field.security

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * ============================================================================
 * D26-02, AS A SOURCE FACT.
 *
 *     "The app must have no code path that can produce the private key as
 *      bytes. This is a property to be proven by the client's own tests and by
 *      review, not asserted in a README."
 *
 * WHY A SOURCE SCAN AND NOT ONLY A BEHAVIOURAL TEST
 * -------------------------------------------------
 * A behavioural test can prove that the methods it calls do not return key
 * material. It cannot prove anything about the method somebody adds next
 * quarter. The server side takes exactly this position for exactly this reason —
 * `device-enrollment-ingress-boundary.architecture.spec.ts` asserts the ABSENCE
 * of `@Public()` as a source fact, because "a behavioural test can prove that the
 * routes it calls require a session, and cannot prove that the sixth route
 * somebody adds next quarter does". This file is the client's equivalent, and it
 * scans EVERY main source file rather than only the security package.
 *
 * WHAT A SOURCE SCAN IS, AND WHAT IT IS NOT
 * -----------------------------------------
 * It is a REVIEW AID WITH TEETH: a named set of export primitives cannot appear
 * without the build going red, so adding one is a deliberate, visible act rather
 * than an accident inside a refactor. It is NOT a proof of impossibility —
 * reflection, a new dependency or a native call could evade any textual rule,
 * and this file does not pretend otherwise. The properties that genuinely cannot
 * be evaded come from the platform: an AndroidKeyStore private key's encoding is
 * unavailable because the material is not in this process, and a StrongBox key's
 * material never leaves the secure element. Those are established by PHYSICAL
 * DEVICE ACCEPTANCE (D26-10) and by nothing in this file.
 *
 * COMMENTS ARE EXEMPT, CODE IS NOT. Whole-line comments are stripped before any
 * scan, so the source may DISCUSS the primitives it must not call — which the
 * files here do, at length, because a rule nobody can read is a rule nobody
 * keeps. A trailing comment on a line of code is deliberately NOT stripped: this
 * scan errs towards a false alarm, never towards a false clean.
 * ============================================================================
 */
class NoPrivateKeyExportSourceTest {

    /**
     * The export primitives, each one something a person would have to write ON
     * PURPOSE in order to move key material out of the keystore or into a
     * serialisable form.
     */
    private val forbiddenSubstrings = listOf(
        // Serialising a key to bytes. On AndroidKeyStore this returns null; the
        // point is that no code should be ASKING.
        "getEncoded",
        "PKCS8EncodedKeySpec",
        "ECPrivateKeySpec",
        "RSAPrivateKeySpec",
        // Reconstructing or exporting a key through the JCA factories.
        "KeyFactory",
        "KeyStore.SecretKeyEntry",
        "setEntry(",
        // Wrapping a key with another key — export, with a straight face.
        "WRAP_MODE",
        "UNWRAP_MODE",
        "Cipher.getInstance",
        "PURPOSE_WRAP",
        // The private half of a generated pair, named through the getter.
        "getPrivate(",
        // Java serialisation, of anything, anywhere in this application.
        "ObjectOutputStream",
        "Serializable",
    )

    /**
     * `keyPair.private` — the Kotlin property form of `getPrivate()`.
     *
     * `entry.privateKey` is a different thing and is governed by the per-line
     * rule below, so the lookahead excludes it rather than the rule being
     * dropped.
     */
    private val privatePropertyAccess = Regex("""\.private(?!Key)""")

    @Test
    fun `no main source file contains a private-key export primitive`() {
        val violations = mutableListOf<String>()
        for (file in mainSources()) {
            val code = codeOf(file)
            for (forbidden in forbiddenSubstrings) {
                if (code.contains(forbidden)) violations.add("${file.name}: contains '$forbidden'")
            }
            if (privatePropertyAccess.containsMatchIn(code)) {
                violations.add("${file.name}: reads the private half of a key pair")
            }
        }
        if (violations.isNotEmpty()) {
            fail("D26-02 violation — private-key export primitives found:\n" + violations.joinToString("\n"))
        }
    }

    /**
     * A private key may be NAMED on exactly one kind of line: the one that
     * resolves the keystore entry, and the one that hands its handle straight to
     * `Signature.initSign`. Assigning it to a field, returning it, logging it or
     * passing it anywhere else fails here.
     */
    @Test
    fun `every mention of a private key hands it directly to initSign`() {
        val violations = mutableListOf<String>()
        for (file in mainSources()) {
            codeLines(file).forEach { (number, line) ->
                val mentions = line.contains("privateKey", ignoreCase = true) || line.contains("PrivateKey")
                if (!mentions) return@forEach
                val allowed = line.contains("initSign") || line.contains("KeyStore.PrivateKeyEntry")
                if (!allowed) violations.add("${file.name}:$number: ${line.trim()}")
            }
        }
        if (violations.isNotEmpty()) {
            fail(
                "D26-02 violation — a private key is named outside the single initSign path:\n" +
                    violations.joinToString("\n"),
            )
        }
    }

    @Test
    fun `no declaration exposes a key type`() {
        val exposesKey = Regex("""(?::|->)\s*(PrivateKey|KeyPair|SecretKey)\b""")
        val violations = mutableListOf<String>()
        for (file in mainSources()) {
            codeLines(file).forEach { (number, line) ->
                if (exposesKey.containsMatchIn(line)) violations.add("${file.name}:$number: ${line.trim()}")
            }
        }
        if (violations.isNotEmpty()) {
            fail("D26-02 violation — a declaration exposes a key type:\n" + violations.joinToString("\n"))
        }
    }

    // -----------------------------------------------------------------------
    // D26-03A — StrongBox, and no fallback, as a source fact
    // -----------------------------------------------------------------------

    @Test
    fun `StrongBox is requested exactly once and is never requested as false`() {
        val allCode = mainSources().joinToString("\n") { codeOf(it) }
        assertEquals(
            "there must be exactly ONE key generation spec in the whole application",
            1,
            occurrences(allCode, "KeyGenParameterSpec.Builder("),
        )
        assertEquals(
            "StrongBox must be requested exactly once",
            1,
            occurrences(allCode, "setIsStrongBoxBacked(true)"),
        )
        assertEquals(
            "there must be NO code path that requests a non-StrongBox key",
            0,
            occurrences(allCode, "setIsStrongBoxBacked(false)"),
        )
    }

    @Test
    fun `StrongBoxUnavailableException is caught and reports the device UNSUPPORTED`() {
        val keyManager = codeOf(mainSources().single { it.name == "StrongBoxKeyManager.kt" })
        assertTrue(
            "the unavailable exception must be handled explicitly, by type",
            keyManager.contains("catch (unavailable: StrongBoxUnavailableException)"),
        )
        assertTrue(
            "the handler must report the device unsupported",
            keyManager.contains("GenerateOutcome.DeviceUnsupported("),
        )
    }

    // -----------------------------------------------------------------------
    // D26-01 — the phone cannot cause its own approval
    // -----------------------------------------------------------------------

    @Test
    fun `no source file names a Command-side or approval route`() {
        val violations = mutableListOf<String>()
        for (file in mainSources()) {
            val code = codeOf(file)
            // `/api/v1/device-enrollment/command` is the COMMANDER's surface,
            // reached from Command web by a different human. There is no route
            // fragment for it here and no call that could construct one.
            for (fragment in listOf("/command", "/approve", "approve\"", "\"approve")) {
                if (code.contains(fragment)) violations.add("${file.name}: names '$fragment'")
            }
        }
        if (violations.isNotEmpty()) {
            fail(
                "D26-01 violation — the client must have no path to its own approval:\n" +
                    violations.joinToString("\n"),
            )
        }
    }

    // -----------------------------------------------------------------------
    // D26-02 — the client never CLAIMS a hardware or trust verdict
    // -----------------------------------------------------------------------

    @Test
    fun `the client never SENDS a storage, trust or attestation verdict`() {
        val violations = mutableListOf<String>()
        // The server has no such request field, on any of its routes. A client
        // that started sending one would be a client asking to be believed about
        // its own hardware — and one that can claim HARDWARE_BACKED can claim
        // TRUSTED. Reading these names OUT of a response is fine and happens
        // through `text(...)`; only `put(...)` is forbidden.
        val forbidden = listOf("key_storage", "trust", "attestation_outcome", "device_trust")
        for (file in mainSources()) {
            val code = codeOf(file)
            for (field in forbidden) {
                if (code.contains("put(\"$field\"")) violations.add("${file.name}: sends '$field'")
            }
        }
        if (violations.isNotEmpty()) {
            fail("D26-02 violation — the client claims a server-owned verdict:\n" + violations.joinToString("\n"))
        }
    }

    // -----------------------------------------------------------------------
    // Locating and reading the sources
    // -----------------------------------------------------------------------

    private fun occurrences(text: String, token: String): Int = text.split(token).size - 1

    /** Code lines only: whole-line comments are dropped, blank lines with them. */
    private fun codeLines(file: File): List<Pair<Int, String>> {
        val out = mutableListOf<Pair<Int, String>>()
        file.readLines().forEachIndexed { index, line ->
            val trimmed = line.trim()
            val isComment = trimmed.startsWith("//") ||
                trimmed.startsWith("*") ||
                trimmed.startsWith("/*")
            if (!isComment && trimmed.isNotEmpty()) out.add((index + 1) to line)
        }
        return out
    }

    private fun codeOf(file: File): String = codeLines(file).joinToString("\n") { it.second }

    /**
     * Every `.kt` file under the app's main source tree.
     *
     * If no source tree is found the test FAILS rather than passing vacuously.
     * `scripts/security-source-gate.sh` records what the alternative costs: a
     * scanner that could not tell "found nothing" from "never ran" reported
     * success while scanning nothing, for the whole life of that pipeline. A
     * security gate that cannot tell those apart is worse than no gate, because
     * it manufactures evidence.
     */
    private fun mainSources(): List<File> {
        val root = locateMainSourceRoot()
        val files = root.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        assertTrue("the source scan found no Kotlin files under $root", files.isNotEmpty())
        assertTrue("the source scan found suspiciously few files under $root", files.size >= 8)
        return files
    }

    private fun locateMainSourceRoot(): File {
        val candidates = listOf(
            "src/main/kotlin",
            "app/src/main/kotlin",
            "apps/field-mobile-android/app/src/main/kotlin",
        )
        var directory: File? = File(System.getProperty("user.dir")).absoluteFile
        var depth = 0
        while (directory != null && depth < 8) {
            for (candidate in candidates) {
                val resolved = File(directory, candidate)
                if (resolved.isDirectory) return resolved
            }
            directory = directory.parentFile
            depth += 1
        }
        throw AssertionError(
            "could not locate the app main source tree from ${System.getProperty("user.dir")}; " +
                "a source scan must never pass without scanning anything",
        )
    }
}
