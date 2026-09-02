package com.sentinel.field.security

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * ============================================================================
 * THE BOOTSTRAP GRANT IS THE CEREMONY SECRET, AS A SOURCE FACT.
 *
 * It is the one value on this client's screen whose disclosure would let
 * somebody else start an enrollment as this operative. It is one-shot, it is
 * issued by a commander, and it has NO business surviving the ceremony that
 * consumes it.
 *
 * WHY A SOURCE SCAN AND NOT ONLY A BEHAVIOURAL TEST — the same argument
 * `NoPrivateKeyExportSourceTest` makes, and this file follows its shape and
 * borrows its file-walking helpers deliberately, so the two read alike. A
 * behavioural test could show that the persistence calls it makes do not carry
 * the grant. It could say nothing about the call somebody adds next quarter.
 *
 * WHAT THIS PROVES, AND WHAT IT DOES NOT. It proves that no line of this
 * application both names the grant and touches a persistence primitive, that
 * only two files may name the grant at all, that the persistence layer cannot
 * name it, that the activity clears it on every path that consumes it, and that
 * the input is masked and excluded from view-state save/restore. It does NOT
 * prove that the JVM has no copy of the string in heap memory — a Kotlin String
 * is immutable and cannot be wiped, only dereferenced. That limit is stated in
 * `MainActivity` rather than papered over here.
 *
 * COMMENTS ARE EXEMPT, CODE IS NOT — again as in the sibling file, so that the
 * sources may DISCUSS the secret they must not store. They do, at length.
 * ============================================================================
 */
class BootstrapTokenNeverPersistedSourceTest {

    /** Anything that names the ceremony secret. */
    private val secretWords = listOf("token", "bootstrap", "secret", "passphrase")

    /**
     * Anything that puts a value somewhere it outlives the call — disk,
     * preferences, saved view state, or a parcel handed to another component.
     */
    private val persistencePrimitives = listOf(
        "SharedPreferences",
        "MasterKey",
        "putString",
        "putStringSet",
        "putExtra",
        "Bundle",
        "onSaveInstanceState",
        "outState",
        "openFileOutput",
        "FileOutputStream",
        "FileWriter",
        "writeText",
        "writeBytes",
        "ClientStateStore",
        "KeyValueStore",
        "EncryptedClientState",
        "writeString",
        "readString",
        "rememberDevice",
        "rememberContext",
        "rememberIdentity",
        "forgetAll",
        "forgetContext",
    )

    /**
     * The ONLY two files permitted to name the grant at all: the ceremony that
     * presents it to the server, and the activity that reads it out of the
     * input and clears it again.
     */
    private val filesAllowedToNameTheGrant = setOf("EnrollmentCeremony.kt", "MainActivity.kt")

    // -----------------------------------------------------------------------
    // The grant never reaches a persistence call
    // -----------------------------------------------------------------------

    @Test
    fun `no line both names the grant and touches a persistence primitive`() {
        val violations = mutableListOf<String>()
        for (file in mainSources()) {
            codeLines(file).forEach { (number, line) ->
                val namesSecret = secretWords.any { line.contains(it, ignoreCase = true) }
                if (!namesSecret) return@forEach
                val persists = persistencePrimitives.firstOrNull { line.contains(it) } ?: return@forEach
                violations.add("${file.name}:$number: names the grant beside '$persists': ${line.trim()}")
            }
        }
        if (violations.isNotEmpty()) {
            fail("the bootstrap grant must never reach a persistence API:\n" + violations.joinToString("\n"))
        }
    }

    @Test
    fun `only the ceremony and the activity may name the grant at all`() {
        val violations = mutableListOf<String>()
        for (file in mainSources()) {
            if (file.name in filesAllowedToNameTheGrant) continue
            codeLines(file).forEach { (number, line) ->
                val word = secretWords.firstOrNull { line.contains(it, ignoreCase = true) } ?: return@forEach
                violations.add("${file.name}:$number: names '$word': ${line.trim()}")
            }
        }
        if (violations.isNotEmpty()) {
            fail(
                "a file outside the ceremony and the activity names the ceremony secret:\n" +
                    violations.joinToString("\n"),
            )
        }
    }

    /**
     * Stated separately from the rule above because it is the sharper claim: the
     * storage layer cannot name the secret even in a string literal, so there is
     * no key it could be filed under.
     */
    @Test
    fun `the secure-storage layer cannot name the grant`() {
        val storeSources = mainSources().filter { it.parentFile.name == "store" }
        assertTrue("the store package was not found by the scan", storeSources.size >= 3)
        for (file in storeSources) {
            for (word in secretWords) {
                assertFalse(
                    "${file.name} names '$word'",
                    codeOf(file).contains(word, ignoreCase = true),
                )
            }
        }
    }

    @Test
    fun `the application never opens plain unencrypted preferences`() {
        val forbidden = listOf("getSharedPreferences(", "getDefaultSharedPreferences", "PreferenceManager")
        val violations = mutableListOf<String>()
        for (file in mainSources()) {
            val code = codeOf(file)
            for (call in forbidden) {
                if (code.contains(call)) violations.add("${file.name}: calls '$call'")
            }
        }
        if (violations.isNotEmpty()) {
            fail(
                "client state is stored through EncryptedSharedPreferences or not at all:\n" +
                    violations.joinToString("\n"),
            )
        }
    }

    @Test
    fun `no source file participates in view-state save or restore`() {
        for (file in mainSources()) {
            assertFalse(
                "${file.name} implements onSaveInstanceState; the grant field must not be saved by anything",
                codeOf(file).contains("onSaveInstanceState"),
            )
        }
    }

    // -----------------------------------------------------------------------
    // The grant is cleared once it has been presented
    // -----------------------------------------------------------------------

    @Test
    fun `the activity has one clearing helper and it empties the input`() {
        val activity = codeOf(mainActivity())
        assertTrue(
            "there must be a single named clearing helper",
            activity.contains("private fun clearBootstrapToken()"),
        )
        assertTrue(
            "the helper must empty the input itself, not merely log about it",
            activity.contains("inputBootstrapToken.setText(\"\")"),
        )
    }

    @Test
    fun `every ceremony step that presents the grant also clears it`() {
        for (step in listOf("runChallengeAndGenerate", "runSubmitRequest")) {
            val body = functionBody(mainActivity(), step)
            assertTrue(
                "$step reads the grant but never clears it",
                body.contains("clearBootstrapToken()"),
            )
        }
    }

    /**
     * The submit step clears UNCONDITIONALLY — before the response is even
     * inspected — because the grant is one-shot and the server has seen it
     * either way. A clear that only ran on success would leave the secret on
     * screen in exactly the case where something has already gone wrong.
     */
    @Test
    fun `the submit step clears the grant before it branches on the result`() {
        val body = functionBody(mainActivity(), "runSubmitRequest")
        val cleared = body.indexOf("clearBootstrapToken()")
        val branched = body.indexOf("if (!result.isOk)")
        assertTrue("runSubmitRequest does not clear the grant", cleared >= 0)
        assertTrue("runSubmitRequest does not branch on the result", branched >= 0)
        assertTrue("the grant is cleared only on one branch", cleared < branched)
    }

    @Test
    fun `the clearing helper is called from more than one place`() {
        val calls = codeLines(mainActivity())
            .count { (_, line) -> line.trim() == "clearBootstrapToken()" }
        assertTrue("expected at least three call sites, found $calls", calls >= 3)
    }

    // -----------------------------------------------------------------------
    // The input itself
    // -----------------------------------------------------------------------

    @Test
    fun `the grant input is masked and excluded from saved view state`() {
        val field = tokenInputDeclaration()
        assertTrue(
            "the grant input must be masked: $field",
            field.contains("android:inputType=\"textPassword\""),
        )
        assertTrue(
            "the grant input must be excluded from view-state save and restore: $field",
            field.contains("android:saveEnabled=\"false\""),
        )
        assertTrue(
            "the grant input must be excluded from autofill: $field",
            field.contains("android:importantForAutofill=\"no\""),
        )
        assertFalse(
            "the grant input must not carry a hardcoded value: $field",
            field.contains("android:text="),
        )
    }

    // -----------------------------------------------------------------------
    // Locating and reading the sources
    // -----------------------------------------------------------------------

    private fun mainActivity(): File = mainSources().single { it.name == "MainActivity.kt" }

    /**
     * The text of one function, from its declaration to the next top-level
     * declaration in the file. Crude on purpose: it needs to be obviously
     * correct by reading, not clever.
     */
    private fun functionBody(file: File, name: String): String {
        val code = codeOf(file)
        val start = code.indexOf("private fun $name(")
        if (start < 0) throw AssertionError("${file.name} has no function named '$name'")
        val next = code.indexOf("\n    private fun ", start + 1)
        return if (next < 0) code.substring(start) else code.substring(start, next)
    }

    /** The `inputBootstrapToken` element of the layout, as written. */
    private fun tokenInputDeclaration(): String {
        val layout = File(mainSourceRoot().parentFile, "res/layout/activity_main.xml")
        assertTrue("the layout was not found at $layout", layout.isFile)
        val text = layout.readText()
        val anchor = text.indexOf("@+id/inputBootstrapToken")
        assertTrue("the layout declares no inputBootstrapToken", anchor >= 0)
        val open = text.lastIndexOf("<EditText", anchor)
        val close = text.indexOf("/>", anchor)
        assertTrue("the inputBootstrapToken element is not a well-formed EditText", open in 0 until close)
        return text.substring(open, close + 2)
    }

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

    private fun mainSources(): List<File> {
        val root = mainSourceRoot()
        val files = root.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        assertTrue("the source scan found no Kotlin files under $root", files.isNotEmpty())
        assertTrue("the source scan found suspiciously few files under $root", files.size >= 8)
        return files
    }

    /**
     * If no source tree is found this FAILS rather than passing vacuously — the
     * same rule the sibling scan states, for the same reason: a security gate
     * that cannot tell "found nothing" from "never ran" manufactures evidence.
     */
    private fun mainSourceRoot(): File {
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
