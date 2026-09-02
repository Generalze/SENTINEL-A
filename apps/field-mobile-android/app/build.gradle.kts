plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
}

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

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
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

    testImplementation("junit:junit:4.13.2")
}
