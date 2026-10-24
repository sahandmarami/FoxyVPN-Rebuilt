import java.util.Base64
buildscript {
    repositories { mavenCentral() }
    dependencies {
        // Ed25519 on the build-script classpath so the signing-key check below
        // can derive the public key at build time and fail a bad .sec early
        classpath("org.bouncycastle:bcprov-jdk18on:1.78.1")
    }
}
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

// ---------------------------------------------------------------------------
// Ed25519 quota-signing key (v6 pipeline — the old one silently shipped a
// broken key from v3 to v5 and minting always failed with "خودآزمایی امضا").
//
// signing/signing-key.sec is PLAIN base64 of the 32-byte Ed25519 seed. At
// build time the public key is derived here and MUST match the key embedded
// in the FoxyVPN client below — a mismatch now FAILS THE BUILD instead of
// producing a keygen that cannot sign anything.
// ---------------------------------------------------------------------------
val EXPECTED_SIGNING_PUB_B64 = "7TLb/pjKRJ2vBHqQt8Y5kZ8XTs7uUj9ThtkRu/C8YGI="

val foxyPrivateKey: String = (project.findProperty("FOXY_PRIVATE_KEY") as String?)
    ?: run {
        val secFile = rootProject.file("signing/signing-key.sec")
        require(secFile.exists()) { "signing/signing-key.sec یافت نشد — کلید امضا گم شده است" }
        val seedB64 = secFile.readText().trim()
        val seed = try {
            Base64.getDecoder().decode(seedB64)
        } catch (e: IllegalArgumentException) {
            throw IllegalStateException("signing-key.sec فرمت درست ندارد (باید base64 خالص ۳۲ بایت باشد): ${e.message}")
        }
        require(seed.size == 32) { "signing-key.sec باید ۳۲ بایت باشد (الان ${seed.size} بایت است)" }
        val derivedPub = org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(seed, 0)
            .generatePublicKey().getEncoded()
        val expectedPub = Base64.getDecoder().decode(EXPECTED_SIGNING_PUB_B64)
        require(derivedPub.contentEquals(expectedPub)) {
            "کلید امضا با کلید عمومی برنامهٔ اصلی هم‌خوانی ندارد — فایل signing-key.sec را بازسازی کنید"
        }
        seedB64
    }

android {
    namespace = "com.foxy.keygen"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.foxy.keygen"
        minSdk = 26
        targetSdk = 34
        versionCode = 6
        versionName = "2.0.0"
        buildConfigField("String", "FOXY_PRIVATE_KEY", "\"$foxyPrivateKey\"")
    }

    signingConfigs {
        create("release") {
            storeFile = rootProject.file("release-keystore.jks")
            storePassword = System.getenv("SIGNING_STORE_PASSWORD") ?: "foxyvpn"
            keyAlias = System.getenv("SIGNING_KEY_ALIAS") ?: "foxyvpn"
            keyPassword = System.getenv("SIGNING_KEY_PASSWORD") ?: "foxyvpn"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs += listOf(
            "-opt-in=androidx.compose.material3.ExperimentalMaterial3Api",
        )
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    lint {
        checkReleaseBuilds = false
        abortOnError = false
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2025.01.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")

    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
}
