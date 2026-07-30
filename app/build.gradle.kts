import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ksp)
}

// Optional release signing: present only if keystore.properties exists.
val keystorePropsFile = rootProject.file("keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) keystorePropsFile.inputStream().use { load(it) }
}

// Build metadata for the About screen. Derived from git so the values only change when
// HEAD or the working tree changes — a wall-clock timestamp would change every build and
// make generateBuildConfig (and everything downstream) never UP-TO-DATE, defeating
// incremental builds. Stable inputs keep `assemble` cacheable.
fun gitOutput(vararg args: String): String? = runCatching {
    providers.exec { commandLine("git", *args) }.standardOutput.asText.get().trim()
}.getOrNull()?.ifEmpty { null }

val gitSha: String = run {
    val sha = gitOutput("rev-parse", "--short", "HEAD") ?: "unknown"
    val dirty = gitOutput("status", "--porcelain")?.isNotEmpty() == true
    if (dirty) "$sha-dirty" else sha
}
val gitCommitTime: String =
    gitOutput("log", "-1", "--format=%cd", "--date=format:%Y-%m-%d %H:%M") ?: "unknown"

android {
    namespace = "com.example.tlswatchdog"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.example.tlswatchdog"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "0.1"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        buildConfigField("String", "GIT_SHA", "\"$gitSha\"")
        buildConfigField("String", "GIT_COMMIT_TIME", "\"$gitCommitTime\"")

        externalNativeBuild {
            cmake {
                // arm64/arm for phones; x86_64 so the native lib runs on ChromeOS
                // Android (ARCVM) on an x86_64 Chromebook.
                abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
                arguments += "-DANDROID_STL=none"
            }
        }
    }

    signingConfigs {
        if (keystorePropsFile.exists()) {
            create("release") {
                storeFile = file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            if (keystorePropsFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
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
        compose = true
        buildConfig = true
    }
}

// Export Room schemas (see FlowDatabase exportSchema = true) so future versions
// can ship real migrations instead of destroying recorded history.
ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.extended)
    debugImplementation(libs.androidx.ui.tooling)

    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)

    implementation(libs.androidx.datastore.preferences)

    testImplementation(libs.junit)
}
