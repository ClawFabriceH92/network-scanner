import java.io.File
import java.util.Base64

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.fabrice.network.scanner"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.fabrice.network.scanner"
        minSdk = 26
        targetSdk = 35
        versionCode = 25
        versionName = "1.5.3"
    }

    signingConfigs {
        create("release") {
            val b64 = System.getenv("NETWORK_SCANNER_KEYSTORE_B64")
            if (!b64.isNullOrBlank()) {
                val tmp = System.getenv("RUNNER_TEMP") ?: System.getProperty("java.io.tmpdir") ?: "/tmp"
                val ks = File(tmp, "network-scanner-release.keystore")
                ks.writeBytes(Base64.getDecoder().decode(b64))
                storeFile = ks
                storePassword = System.getenv("NETWORK_SCANNER_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("NETWORK_SCANNER_KEY_ALIAS")
                keyPassword = System.getenv("NETWORK_SCANNER_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = if (System.getenv("NETWORK_SCANNER_KEYSTORE_B64").isNullOrBlank()) null
                else signingConfigs.getByName("release")
        }
        debug {
            isMinifyEnabled = false
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

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.10.01"))
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    // Client SMB (partages réseau) — pure Java, compatible Android
    implementation("com.hierynomus:smbj:0.13.0")
    implementation("org.slf4j:slf4j-nop:2.0.13")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
