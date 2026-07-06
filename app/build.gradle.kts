import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ksp)
    alias(libs.plugins.hilt)
    alias(libs.plugins.rust.android)
}

android {
    namespace = "com.adwarden"
    compileSdk = 36
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "com.adwarden"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0-p1"
        vectorDrawables { useSupportLibrary = true }

        ksp {
            // Persist Room schemas so migrations can be diffed in review.
            arg("room.schemaLocation", "$projectDir/schemas")
            arg("room.generateKotlin", "true")
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            isDebuggable = true
        }
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }

    packaging {
        resources { excludes += "/META-INF/{AL2.0,LGPL2.1}" }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

// Cross-compile the Rust native core into per-ABI .so files and fold them into
// the app's jniLibs. Requires the Android std targets:
//   sudo rustup target add aarch64-linux-android armv7-linux-androideabi \
//                          i686-linux-android x86_64-linux-android
cargo {
    module = "../rust"
    libname = "adwarden_core"
    targets = listOf("arm64", "arm", "x86_64", "x86")
    profile = "release"
    prebuiltToolchains = true
}

// Build the native libraries before they are merged into the APK. This is
// deliberately hung off the jniLib merge (packaging), NOT preBuild, so that
// `compileDebugKotlin` stays runnable on a host without the Android Rust
// targets installed.
//
// `outputs.upToDateWhen { false }` is load-bearing: `cargoBuild` rewrites the
// per-ABI .so files in build/rustJniLibs on every rebuild, but the folder-merge
// task's input snapshot does NOT reliably detect that content change, so it
// would stay UP-TO-DATE and silently repackage a stale .so (shipping old native
// code in the APK). Forcing it to always re-merge fixes the whole chain — the
// downstream mergeNativeLibs/strip/package tasks still short-circuit on
// byte-identical output, so this only costs a quick copy when nothing changed.
tasks.matching { it.name.matches(Regex("merge.*JniLibFolders")) }.configureEach {
    dependsOn("cargoBuild")
    outputs.upToDateWhen { false }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.extended)
    implementation(libs.androidx.navigation.compose)

    // DI
    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)
    implementation(libs.androidx.hilt.navigation.compose)
    implementation(libs.androidx.hilt.work)
    ksp(libs.androidx.hilt.compiler)

    // Persistence
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)
    implementation(libs.androidx.datastore.preferences)

    // Background work
    implementation(libs.androidx.work.runtime.ktx)

    // Networking
    implementation(libs.okhttp)

    debugImplementation(libs.androidx.ui.tooling)

    // Test
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.turbine)
    testImplementation(libs.mockk)
    testImplementation(libs.androidx.room.testing)
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.test.core)
    testImplementation(libs.androidx.test.ext.junit)
}
