import java.io.File
import java.util.Base64

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// ---------------------------------------------------------------------------
// Signature release (auto-update GitHub Releases)
//
// CI (GitHub Actions) : le keystore arrive en base64 via NETWORK_SCANNER_KEYSTORE_B64
// et est décodé dans RUNNER_TEMP. Build local : le keystore est lu directement
// depuis /root/.secrets/keystores-android/. Les mots de passe sont lus depuis les
// variables d'environnement si présentes, sinon depuis les fichiers d'environnement
// locaux (network-scanner-release.env ou passwords.env).
// ---------------------------------------------------------------------------
val localKeystore = File("/root/.secrets/keystores-android/network-scanner-release.keystore")
val localEnvFiles = listOf(
    File("/root/.secrets/keystores-android/network-scanner-release.env"),
    File("/root/.secrets/keystores-android/passwords.env")
)

fun secret(envName: String, key: String): String? {
    val fromEnv = System.getenv(envName)
    if (!fromEnv.isNullOrBlank()) return fromEnv
    for (f in localEnvFiles) {
        if (!f.exists()) continue
        f.readLines().forEach { line ->
            val idx = line.indexOf('=')
            if (idx > 0 && line.substring(0, idx).trim() == key) {
                return line.substring(idx + 1).trim()
            }
        }
    }
    return null
}

val releaseKeystoreB64 = System.getenv("NETWORK_SCANNER_KEYSTORE_B64")
val releaseStorePassword = secret("NETWORK_SCANNER_KEYSTORE_PASSWORD", "NETWORK_SCANNER_KEYSTORE_PASSWORD")
val releaseKeyAlias = secret("NETWORK_SCANNER_KEY_ALIAS", "NETWORK_SCANNER_KEY_ALIAS") ?: "scanner"
// PKCS12 : storePassword == keyPassword (un seul mot de passe pour store + clé).
val releaseKeyPassword = secret("NETWORK_SCANNER_KEY_PASSWORD", "NETWORK_SCANNER_KEY_PASSWORD")
    ?: releaseStorePassword

// Fichier keystore effectif : décodé depuis le B64 (CI) ou fichier local (dev).
var releaseKeystoreFile: File? = null
if (!releaseKeystoreB64.isNullOrBlank()) {
    val runnerTemp = System.getenv("RUNNER_TEMP") ?: System.getProperty("java.io.tmpdir")
    val f = File(runnerTemp, "network-scanner-release.keystore")
    f.parentFile?.mkdirs()
    f.writeBytes(Base64.getDecoder().decode(releaseKeystoreB64.trim()))
    releaseKeystoreFile = f
} else if (localKeystore.exists()) {
    releaseKeystoreFile = localKeystore
}

// La signature release n'est active que si le keystore ET le mot de passe sont
// disponibles (le CI a toujours les secrets ; le build local a le keystore).
val hasReleaseSigning = releaseKeystoreFile != null && !releaseStorePassword.isNullOrBlank()

android {
    namespace = "com.fabrice.network.scanner"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.fabrice.network.scanner"
        minSdk = 26
        targetSdk = 35
        versionCode = 32
        versionName = "1.9.3"
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = releaseKeystoreFile
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
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
    // Surveillance continue (v1.9.0) : scan planifié en arrière-plan
    implementation("androidx.work:work-runtime-ktx:2.9.1")
    // Verrouillage biométrique (v1.9.0) : BiometricPrompt androidx
    implementation("androidx.biometric:biometric:1.1.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
