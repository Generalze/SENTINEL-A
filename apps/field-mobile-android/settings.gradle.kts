/*
 * WP-26 Field Mobile Foundation — the Android client, deliberately OUTSIDE the
 * pnpm workspace.
 *
 * D26-10 / gate ruling "Option B, tightened": the Android project stays in the
 * monorepo so the single-boundary discipline holds, but it is not a pnpm
 * package. This directory carries NO `package.json`, so `pnpm-workspace.yaml`'s
 * `apps/*` glob does not match it, `pnpm -r typecheck` and `pnpm -r lint` do not
 * see it, and the workspace test count therefore stops being a complete measure
 * of the system. The gate reads TWO numbers: Sentinel's CI and `android.yml`.
 */
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

// Single project (see build.gradle.kts): there is no `include` to honour,
// so a settings file that is ignored costs nothing.
rootProject.name = "sentinel-field-mobile"
