plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.example.pqbdh_7816"
    compileSdk {
        version = release(36)
    }

    defaultConfig {
        applicationId = "com.example.pqbdh_7816"
        minSdk = 24
        targetSdk = 36
        versionCode = 7
        versionName = "1.4"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += listOf("x86_64", "arm64-v8a", "armeabi-v7a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    buildFeatures {
        viewBinding = true
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/emptyJniLibs")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("../../BOD_Terminal/app/src/main/cpp/CMakeLists.txt")
        }
    }

}

dependencies {
    implementation(libs.appcompat)
    implementation(libs.material)
    implementation(libs.constraintlayout)
    implementation(libs.bcprov)
    implementation(libs.bcpkix)
    testImplementation(libs.junit)
    androidTestImplementation(libs.ext.junit)
    androidTestImplementation(libs.espresso.core)
}
