/*
 * WP-26 Field Mobile Foundation — the Android client.
 *
 * A CONVENTIONAL single-project Android build. Three CI attempts failed on
 * plugin resolution, and they shared one cause: Gradle named the root project
 * after the DIRECTORY, which is what it does when the settings file is not
 * applied — so `pluginManagement { repositories { google() } }` never applied
 * either, and the very first failure (an unresolvable AGP plugin MARKER) was
 * that same bug wearing a different message. The settings file is now Groovy,
 * the most broadly handled form, and everything here is the ordinary shape an
 * Android project has: `plugins {}` first, versions pinned, repositories in
 * settings.
 *
 * Every version is an exact, published coordinate. Nothing resolves a range, a
 * `+` or a snapshot: this machine has no JDK, no Gradle and no Android SDK, so
 * hosted CI is the only verification this project gets, and a build that
 * resolves differently on two days is a build that cannot be audited.
 *
 *   Gradle 8.7 · AGP 8.3.2 (needs Gradle >= 8.4, JDK 17) · Kotlin 1.9.24
 */
plugins {
    id("com.android.application") version "8.3.2"
    id("org.jetbrains.kotlin.android") version "1.9.24"
    id("org.jetbrains.kotlin.plugin.serialization") version "1.9.24"
}

/**
 * One piece of signing material, from a Gradle property or the environment.
 *
 * Neither source is a file in this repository, and that is the point: the
 * keystore, its passwords and the alias are supplied by whoever performs the
 * acceptance run and are never committed. `.gitignore` refuses the keystore
 * shapes as a second line of defence.
 */
fun signingMaterial(gradleProperty: String, environmentVariable: String): String? =
    (project.findProperty(gradleProperty) as String?) ?: System.getenv(environmentVariable)

android {
    namespace = "com.sentinel.field"
    compileSdk = 34

    defaultConfig {
        /*
         * `com.sentinel.field` is the package name the server's Android Key
         * Attestation verifier compares the leaf's attestationApplicationId
         * against (`expectedPackageName` in `android-attestation.trust-material.ts`,
         * and `TEST_PACKAGE_NAME` in the server's own test support). The
         * SERVER owns that expectation as configuration — an app identity a
         * device could choose is not an app identity — so this value must be
         * kept equal to the deployment's configured one, and changing it here
         * alone silently produces APPLICATION_PACKAGE_UNEXPECTED at enrollment.
         */
        applicationId = "com.sentinel.field"

        /*
         * D26-03A: StrongBox arrived in API 28 and WP-26 requires it with NO
         * silent fallback, so a device that cannot even express the request is
         * out of scope for the reference path rather than quietly served a TEE
         * key. minSdk 28 makes that a build fact rather than a runtime hope.
         */
        minSdk = 28
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0-wp26"
    }

    /*
     * THE ACCEPTANCE SIGNING IDENTITY.
     *
     * The physical-device acceptance proves, among other things, that the app
     * holding the StrongBox key IS Sentinel Field — by package name AND by the
     * SHA-256 of the certificate that signed the APK. That check is only worth
     * anything if the signing identity is STABLE and DELIBERATE.
     *
     * A debug APK is signed with an auto-generated debug keystore. Its
     * fingerprint differs between machines and can be regenerated at any time,
     * so configuring the server to trust it would either fail on the next build
     * or pin a key nobody controls. Neither is acceptable for the identity that
     * decides whether hardware is trusted.
     *
     * So the material is supplied at BUILD TIME and never committed: a Gradle
     * property or an environment variable, resolved below. Absent, there is no
     * `acceptance` config at all and `assembleDebug` is unaffected — which is
     * what hosted CI builds, and CI holds no signing key.
     *
     * The private key never reaches Sentinel. The server is configured with the
     * PUBLIC certificate fingerprint only.
     */
    val acceptanceStoreFile = signingMaterial("sentinelAcceptanceStoreFile", "SENTINEL_ACCEPTANCE_STORE_FILE")
    val acceptanceStorePassword = signingMaterial("sentinelAcceptanceStorePassword", "SENTINEL_ACCEPTANCE_STORE_PASSWORD")
    val acceptanceKeyAlias = signingMaterial("sentinelAcceptanceKeyAlias", "SENTINEL_ACCEPTANCE_KEY_ALIAS")
    val acceptanceKeyPassword = signingMaterial("sentinelAcceptanceKeyPassword", "SENTINEL_ACCEPTANCE_KEY_PASSWORD")
    val acceptanceSigningConfigured =
        acceptanceStoreFile != null &&
            acceptanceStorePassword != null &&
            acceptanceKeyAlias != null &&
            acceptanceKeyPassword != null

    signingConfigs {
        if (acceptanceSigningConfigured) {
            create("acceptance") {
                storeFile = file(acceptanceStoreFile!!)
                storePassword = acceptanceStorePassword
                keyAlias = acceptanceKeyAlias
                keyPassword = acceptanceKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Only when the material is present. There is deliberately NO
            // fallback to the debug key: an acceptance APK signed by a key the
            // server was not configured for would fail the identity check for a
            // reason that looks like a device fault, and one silently signed by
            // a debug key is worse — it would be a build nobody could vouch for.
            if (acceptanceSigningConfigured) {
                signingConfig = signingConfigs.getByName("acceptance")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        buildConfig = true
    }

    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/kotlin")
        }
        getByName("test") {
            java.srcDirs("src/test/kotlin")
        }
    }

    testOptions {
        unitTests {
            /*
             * The security-critical LOGIC in `security/` is pure Kotlin and
             * imports nothing from `android.*` — that is asserted as a source
             * fact by `NoPrivateKeyExportSourceTest`. This flag exists only so
             * that the reflective surface test can LOAD `StrongBoxKeyManager`,
             * whose signatures mention Android types, without the stubbed
             * android.jar throwing on class initialisation.
             */
            isReturnDefaultValues = true
        }
    }

    lint {
        abortOnError = true
        warningsAsErrors = false
        checkDependencies = false
    }

    /*
     * D26-10: there are NO instrumented tests and no emulator in this project,
     * and there is not going to be one. "An emulator is not a hardware test.
     * It cannot establish that a private key lived in a physical StrongBox, and
     * WP-26 will not present one as if it could." The evidence class that
     * covers StrongBox is PHYSICAL DEVICE ACCEPTANCE, performed by a human on
     * genuine hardware, and no CI job can stand in for it.
     */
}

dependencies {
    // Kept deliberately small. Every entry is an exact, published coordinate.
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")

    /*
     * D26-06 secure local storage. `EncryptedSharedPreferences` and its
     * keystore-held master key, and NOTHING hand-rolled.
     *
     * The alternative — plain preferences wrapped by an AndroidKeystore AES/GCM
     * key of our own — would put `Cipher.getInstance` and a second
     * `KeyGenParameterSpec` into this application, both of which
     * `NoPrivateKeyExportSourceTest` refuses on sight. That test's value is
     * precisely that the app holds ONE key spec and no cipher primitives, so a
     * private-key export path cannot be assembled quietly; weakening it to make
     * room for hand-rolled storage encryption would trade a proven property for
     * an unproven one.
     *
     * IT IS AN ALPHA AND THAT IS STATED PLAINLY. `1.1.0-alpha06` is the version
     * in general use for this class and the first line to carry the `MasterKey`
     * API used here (the 1.0.0 line predates it). Verified published on Google's
     * Maven: the .pom, .aar and .module all resolve, and its three transitive
     * dependencies — androidx.annotation 1.1.0, androidx.collection 1.1.0 and
     * com.google.crypto.tink:tink-android 1.8.0 — resolve from the repositories
     * already declared in `settings.gradle`. Pinned exactly, like everything
     * else here.
     */
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    testImplementation("junit:junit:4.13.2")
}


/*
 * A RELEASE BUILD WITHOUT AN ACCEPTANCE IDENTITY FAILS LOUDLY.
 *
 * Without this, `assembleRelease` would quietly produce an UNSIGNED APK, and an
 * unsigned APK cannot be installed or attested — the failure would surface much
 * later, on the phone, as something that looks unrelated. Failing here names
 * the actual cause.
 *
 * `assembleDebug` is untouched, so hosted CI, which holds no signing key,
 * builds exactly as before.
 */
tasks.matching { it.name.startsWith("assemble") && it.name.contains("Release") }.configureEach {
    doFirst {
        val configured =
            signingMaterial("sentinelAcceptanceStoreFile", "SENTINEL_ACCEPTANCE_STORE_FILE") != null &&
                signingMaterial("sentinelAcceptanceStorePassword", "SENTINEL_ACCEPTANCE_STORE_PASSWORD") != null &&
                signingMaterial("sentinelAcceptanceKeyAlias", "SENTINEL_ACCEPTANCE_KEY_ALIAS") != null &&
                signingMaterial("sentinelAcceptanceKeyPassword", "SENTINEL_ACCEPTANCE_KEY_PASSWORD") != null
        if (!configured) {
            throw GradleException(
                "A release build needs the Sentinel acceptance signing identity. " +
                    "Set sentinelAcceptanceStoreFile / StorePassword / KeyAlias / KeyPassword " +
                    "(or SENTINEL_ACCEPTANCE_STORE_FILE / _STORE_PASSWORD / _KEY_ALIAS / _KEY_PASSWORD). " +
                    "See README.md, 'Physical-device acceptance'. Refusing to produce an unsigned APK.",
            )
        }
    }
}
