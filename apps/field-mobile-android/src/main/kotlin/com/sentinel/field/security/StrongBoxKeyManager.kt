package com.sentinel.field.security

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * ============================================================================
 * THE ONLY FILE IN THIS CLIENT THAT TOUCHES THE ANDROID KEYSTORE.
 *
 * D26-02 — WHAT "PROTECTED" MUST MEAN
 * -----------------------------------
 *     generated ON the device, in hardware-backed storage
 *     NEVER exportable — not to Sentinel, not to the server, not to app
 *                        storage, not to a backup, not to a log
 *     signing happens IN PLACE; the app holds a HANDLE, never key material
 *
 * There is no method here that returns a private key, and no method anywhere in
 * this application that could construct one. That is asserted three ways, on
 * purpose, because "we didn't write one" is not a property:
 *
 *   1. `NoPrivateKeyExportSourceTest` scans EVERY main source file for the
 *      export primitives — `getEncoded`, `KeyFactory`, `PKCS8EncodedKeySpec`,
 *      `ECPrivateKey`, a declared `PrivateKey` return type — and for any use of
 *      `privateKey` on a line that is not the `initSign` call below.
 *   2. `StrongBoxKeyManagerSurfaceTest` reflects over this class's declared
 *      members and asserts nothing exposes a key type or key bytes.
 *   3. The private key handle is never stored in a field. It is obtained inside
 *      `sign`, handed straight to `Signature.initSign`, and goes out of scope.
 *
 * D26-03A — STRONGBOX, WITH NO SILENT FALLBACK
 * --------------------------------------------
 * `setIsStrongBoxBacked(true)` appears EXACTLY ONCE in this application and
 * `setIsStrongBoxBacked(false)` appears nowhere. A `StrongBoxUnavailableException`
 * is caught and reported as [GenerateOutcome.DeviceUnsupported] — the ceremony
 * STOPS. It does not retry without StrongBox, and there is no second
 * `KeyGenParameterSpec.Builder` in the codebase for it to retry with.
 *
 *     "A device without usable StrongBox is reported UNSUPPORTED for the WP-26
 *      reference path. It never quietly becomes equivalent hardware, and a
 *      certificate saying TEE is never promoted into the StrongBox profile."
 *
 * The last sentence is the server's job and the server does it: the verifier
 * derives `HARDWARE_BACKED` from its own reading of the attestation, and this
 * client has no field anywhere through which it could claim otherwise.
 *
 * D26-04A — THE CHALLENGE COMES FIRST, AND IT IS NOT OPTIONAL
 * ----------------------------------------------------------
 * [generate] takes the server's challenge bytes as a REQUIRED parameter and
 * puts them in `setAttestationChallenge`. Android Key Attestation is produced
 * when the key is generated, which is the whole reason the server issues a nonce
 * before the phone has a key: a server that hands out nothing first cannot tell
 * a certificate minted seconds ago from one minted last year. There is no
 * overload that generates without a challenge, so the ordering is enforced by
 * the signature of the only method that exists.
 *
 * WHAT THIS FILE CANNOT PROVE, AND WHERE THAT PROOF COMES FROM
 * -----------------------------------------------------------
 * None of the above is established by the JVM unit tests. They can only show
 * that the source contains no export path and that the surface exposes none.
 * That a private key actually lived in a physical StrongBox is established by
 * D26-10's PHYSICAL DEVICE ACCEPTANCE, on genuine hardware, and by nothing else.
 * An emulator would not establish it either, which is why this project has no
 * instrumented tests at all.
 * ============================================================================
 */
class StrongBoxKeyManager(
    private val context: Context,
    private val alias: String = DEFAULT_KEY_ALIAS,
) {

    companion object {
        const val DEFAULT_KEY_ALIAS = "sentinel.field.device.v1"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        private const val CURVE = "secp256r1"
    }

    /**
     * The result of a generation attempt.
     *
     * `DeviceUnsupported` is a first-class outcome and not an error string,
     * because the caller has to tell its operative something true and specific:
     * this handset cannot take part in the WP-26 reference path. Collapsing it
     * into a generic failure is how a fallback gets added later "to make it
     * work".
     */
    sealed class GenerateOutcome {
        /**
         * A StrongBox-backed P-256 key exists under [alias], attested against
         * the server's challenge.
         *
         * [publicKey] is the canonical uncompressed SEC1 point in unpadded
         * base64url; [thumbprint] is derived from those exact bytes;
         * [certificateChainBase64] is standard base64 DER, LEAF FIRST, which is
         * what `EnrollmentRequestSchema.certificate_chain` expects.
         */
        data class Generated(
            val publicKey: String,
            val thumbprint: String,
            val certificateChainBase64: List<String>,
        ) : GenerateOutcome()

        /** D26-03A. StrongBox is absent or refused the request. The ceremony stops. */
        data class DeviceUnsupported(val detail: String) : GenerateOutcome()

        /** Anything else. Never a reason to retry without StrongBox. */
        data class Failed(val detail: String) : GenerateOutcome()
    }

    /**
     * Does this handset even declare StrongBox?
     *
     * Advisory only. `FEATURE_STRONGBOX_KEYSTORE` being present does not
     * guarantee a generation request will succeed, and its absence is not the
     * check that matters — [generate] catching `StrongBoxUnavailableException`
     * is. This exists so the UI can say "unsupported" before asking a server for
     * a challenge it is going to waste.
     */
    fun strongBoxDeclared(): Boolean =
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    /**
     * Generates the device key, in StrongBox, bound to the SERVER's challenge.
     *
     * Any existing key under [alias] is deleted first. A half-finished ceremony
     * leaves a key that no enrollment request will ever name, and D26-04A's own
     * words for the expired-challenge case are that the phone "discards the
     * unfinished key and restarts" — a fresh challenge and a fresh key, not
     * another go with the old one.
     */
    fun generate(serverChallenge: ByteArray): GenerateOutcome {
        if (serverChallenge.isEmpty()) {
            return GenerateOutcome.Failed("the server attestation challenge is empty")
        }
        return try {
            deleteKey()
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE)
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec(CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(serverChallenge)
                .setIsStrongBoxBacked(true)
                .build()
            generator.initialize(spec)
            // The returned KeyPair is DELIBERATELY DISCARDED. Reading its
            // `private` half is the one thing this class must never do, and the
            // public half and the chain are read back out of the keystore
            // below, so the word does not need to appear in this file at all.
            generator.generateKeyPair()

            val publicKey = readCanonicalPublicKey()
            GenerateOutcome.Generated(
                publicKey = publicKey,
                thumbprint = CanonicalPublicKey.thumbprint(publicKey),
                certificateChainBase64 = readCertificateChainBase64(),
            )
        } catch (unavailable: StrongBoxUnavailableException) {
            // D26-03A. NO FALLBACK. There is no `else` branch that tries again
            // without StrongBox, and adding one would be a change to the
            // security contract, not a bug fix.
            GenerateOutcome.DeviceUnsupported(
                "StrongBox is unavailable on this device: ${unavailable.javaClass.simpleName}",
            )
        } catch (error: Exception) {
            GenerateOutcome.Failed("${error.javaClass.simpleName}: ${error.message ?: "no detail"}")
        }
    }

    /** True when a key exists under [alias]. */
    fun hasKey(): Boolean = loadKeyStore().containsAlias(alias)

    /** Removes the key. The material is destroyed by the keystore, not by this process. */
    fun deleteKey() {
        val store = loadKeyStore()
        if (store.containsAlias(alias)) store.deleteEntry(alias)
    }

    /**
     * The canonical uncompressed SEC1 public key, from the keystore certificate.
     *
     * Read from the keystore rather than remembered from generation, so the
     * value transmitted is the value the keystore actually holds.
     */
    fun readCanonicalPublicKey(): String {
        val certificate = loadKeyStore().getCertificate(alias)
            ?: throw IllegalStateException("no device key exists under alias $alias")
        val ecPublicKey = certificate.publicKey as? ECPublicKey
            ?: throw IllegalStateException("the device key is not an EC key")
        val point = ecPublicKey.w
        return CanonicalPublicKey.encode(point.affineX, point.affineY)
    }

    /** SHA-256 hex over the canonical public key bytes. Computed, never believed. */
    fun readPublicKeyThumbprint(): String = CanonicalPublicKey.thumbprint(readCanonicalPublicKey())

    /**
     * The Android Key Attestation chain, standard base64 DER, LEAF FIRST.
     *
     * This is EVIDENCE, not a verdict (D26-04). The client transports it and
     * says nothing about what it means; the server's verifier decides, against
     * trust anchors the server pins and a revocation snapshot the server owns.
     * A client that could interpret its own attestation could claim
     * `HARDWARE_BACKED`, and a client that can claim `HARDWARE_BACKED` can claim
     * `TRUSTED`.
     */
    fun readCertificateChainBase64(): List<String> {
        val chain = loadKeyStore().getCertificateChain(alias)
            ?: throw IllegalStateException("no attestation chain exists under alias $alias")
        val encoder = Base64.getEncoder()
        return chain.map { encoder.encodeToString(it.encoded) }
    }

    /**
     * Signs [payload] with the hardware key and returns the CONTRACT's wire form.
     *
     * The platform hands back DER; [CanonicalSignature] converts it to IEEE
     * P1363 `r || s` and canonicalises `s` low. That conversion is pure Kotlin
     * and fully unit-tested, which is exactly why it is not done here.
     *
     * The private key handle is obtained, used and dropped inside this method.
     * It is not returned, not cached in a field, and not passed to any other
     * object.
     */
    fun signCanonical(payload: ByteArray): String =
        CanonicalSignature.canonicalWireSignature(signToDer(payload))

    /** Signs the UTF-8 bytes of a canonical statement. */
    fun signCanonicalStatement(statement: String): String =
        signCanonical(statement.toByteArray(Charsets.UTF_8))

    /**
     * The raw platform signature, in DER.
     *
     * `private` so the only way out of this class is through [signCanonical],
     * which cannot forget the low-S step.
     */
    private fun signToDer(payload: ByteArray): ByteArray {
        val entry = loadKeyStore().getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("no device key entry exists under alias $alias")
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
        signature.initSign(entry.privateKey)
        signature.update(payload)
        return signature.sign()
    }

    private fun loadKeyStore(): KeyStore {
        val store = KeyStore.getInstance(ANDROID_KEY_STORE)
        store.load(null)
        return store
    }

}
