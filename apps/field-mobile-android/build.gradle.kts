/*
 * Root build script.
 *
 * Every plugin version is PINNED to an exact, published coordinate. Nothing
 * here resolves a range, a `+`, or a snapshot: this machine has no JDK, no
 * Gradle and no Android SDK, so the only verification this project gets is
 * hosted CI, and a build that resolves differently on two days is a build that
 * cannot be audited.
 *
 *   Gradle                       8.7        (gradle/wrapper/gradle-wrapper.properties)
 *   Android Gradle Plugin        8.3.2      (requires Gradle >= 8.4, JDK 17)
 *   Kotlin                       1.9.24
 *   kotlinx-serialization        1.6.3      (matches Kotlin 1.9.x)
 */
/*
 * WP-26 CI FIX: `buildscript` classpath rather than the plugins DSL.
 *
 * The first CI run failed resolving the plugin MARKER artifact
 * `com.android.application:com.android.application.gradle.plugin:8.3.2`,
 * even though `google()` is declared in `pluginManagement`. The marker is a
 * tiny redirect POM and is a separate coordinate from the plugin itself.
 * Declaring the real library on the buildscript classpath resolves
 * `com.android.tools.build:gradle`, which is unambiguously published on
 * `google()`, and removes the marker from the picture entirely.
 *
 * The versions are still pinned to the exact same values; only the resolution
 * path changed.
 */
buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("com.android.tools.build:gradle:8.3.2")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.24")
        classpath("org.jetbrains.kotlin:kotlin-serialization:1.9.24")
    }
}
