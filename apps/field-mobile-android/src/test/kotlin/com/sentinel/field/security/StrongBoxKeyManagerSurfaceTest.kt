package com.sentinel.field.security

import java.lang.reflect.Modifier
import java.security.Key
import java.security.KeyPair
import java.security.KeyStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ============================================================================
 * THE KEY MANAGER'S SURFACE, READ OFF THE COMPILED CLASS.
 *
 * `NoPrivateKeyExportSourceTest` reads the source; this reads the BYTECODE's
 * declared members. The two catch different things: a source scan can be evaded
 * by an unusual spelling, and a member whose type is a key cannot be — whatever
 * it is called, `java.security.Key` is assignable from it and this test fails.
 *
 * It also pins the exact set of PUBLIC method names, so that adding anything to
 * this class is a visible, deliberate diff in a test file that says why the set
 * is closed, rather than a quiet addition to a security-critical surface.
 *
 * This is still not a proof about the KEY. It is a proof about the CLASS. That
 * the material lives in a physical StrongBox and never leaves it is established
 * by D26-10's physical device acceptance, on real hardware, and by nothing that
 * runs on a JVM.
 * ============================================================================
 */
class StrongBoxKeyManagerSurfaceTest {

    private val type: Class<*> = StrongBoxKeyManager::class.java

    /**
     * The complete public surface. Closed on purpose.
     *
     * Nothing here returns key material: three of them return the canonical
     * PUBLIC key or its digest, one returns the attestation chain (public
     * certificates), two return a SIGNATURE, and the rest are lifecycle.
     */
    private val expectedPublicMethods = setOf(
        "strongBoxDeclared",
        "generate",
        "hasKey",
        "deleteKey",
        "readCanonicalPublicKey",
        "readPublicKeyThumbprint",
        "readCertificateChainBase64",
        "signCanonical",
        "signCanonicalStatement",
    )

    @Test
    fun `the public surface is exactly the closed set`() {
        val actual = type.declaredMethods
            .filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic && !it.name.contains('$') }
            .map { it.name }
            .toSet()
        assertEquals(
            "the public surface of the key manager changed; if that is intended, " +
                "change it here too and say why in review",
            expectedPublicMethods,
            actual,
        )
    }

    @Test
    fun `no declared method returns a key, a key pair or a keystore entry`() {
        for (method in type.declaredMethods) {
            val returned = method.returnType
            assertTrue(
                "${method.name} returns ${returned.name}, which is a key type",
                !Key::class.java.isAssignableFrom(returned),
            )
            assertTrue(
                "${method.name} returns a KeyPair",
                !KeyPair::class.java.isAssignableFrom(returned),
            )
            assertTrue(
                "${method.name} returns a KeyStore entry",
                !KeyStore.Entry::class.java.isAssignableFrom(returned),
            )
        }
    }

    @Test
    fun `no declared field holds a key, a key pair or a keystore entry`() {
        // The private key handle is obtained inside `sign`, handed to
        // `initSign`, and goes out of scope. It is never cached, so there is
        // nowhere for a later refactor to read it back out of.
        for (field in type.declaredFields) {
            if (field.isSynthetic) continue
            val held = field.type
            assertTrue(
                "${field.name} holds ${held.name}, which is a key type",
                !Key::class.java.isAssignableFrom(held),
            )
            assertTrue("${field.name} holds a KeyPair", !KeyPair::class.java.isAssignableFrom(held))
            assertTrue("${field.name} holds a KeyStore entry", !KeyStore.Entry::class.java.isAssignableFrom(held))
        }
    }

    @Test
    fun `the generate outcome carries the public key and the chain, and nothing else`() {
        val generated = StrongBoxKeyManager.GenerateOutcome.Generated::class.java
        val names = generated.declaredFields.filter { !it.isSynthetic }.map { it.name }.toSet()
        assertEquals(setOf("publicKey", "thumbprint", "certificateChainBase64"), names)
        for (field in generated.declaredFields) {
            assertTrue(
                "${field.name} holds ${field.type.name}",
                !Key::class.java.isAssignableFrom(field.type),
            )
        }
    }

    @Test
    fun `the unsupported outcome exists and is distinct from a generic failure`() {
        // D26-03A: reporting the device UNSUPPORTED must be its own outcome. If
        // it collapsed into a generic error, the next person to "make it work"
        // would add the TEE fallback the directive forbids.
        val unsupported = StrongBoxKeyManager.GenerateOutcome.DeviceUnsupported::class.java
        val failed = StrongBoxKeyManager.GenerateOutcome.Failed::class.java
        assertTrue(unsupported != failed)
        assertTrue(StrongBoxKeyManager.GenerateOutcome::class.java.isAssignableFrom(unsupported))
        assertTrue(StrongBoxKeyManager.GenerateOutcome::class.java.isAssignableFrom(failed))
    }
}
