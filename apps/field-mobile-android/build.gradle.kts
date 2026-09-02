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
plugins {
    id("com.android.application") version "8.3.2" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "1.9.24" apply false
}
