# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html.
# For more examples on how to use CMake, see https://github.com/android/ndk-samples.

# Sets the minimum CMake version required for this project.
cmake_minimum_required(VERSION 3.22.1)

# Declares the project name. The project name can be accessed via ${ PROJECT_NAME},
# Since this is the top level CMakeLists.txt, the project name is also accessible
# with ${CMAKE_PROJECT_NAME} (both CMake variables are in-sync within the top level
# build script scope).
project("bod_terminal")

# Setup liboqs (The PQC Algorithms)
set(OQS_BUILD_ONLY_LIB ON)
set(OQS_DIST_BUILD ON)
set(OQS_USE_OPENSSL OFF) # Simpler for Android (avoids compiling OpenSSL)
set(OQS_ENABLE_KEM_ML_KEM_512 ON) # Enable Kyber-512
set(OQS_ENABLE_SIG_ML_DSA_44 ON)  # Enable Dilithium-2 (ML-DSA-44)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.
#
# In this top level CMakeLists.txt, ${CMAKE_PROJECT_NAME} is used to define
# the target library name; in the sub-module's CMakeLists.txt, ${PROJECT_NAME}
# is preferred for the same purpose.
#
# In order to load a library into your app from Java/Kotlin, you must call
# System.loadLibrary() and pass the name of the library defined here;
# for GameActivity/NativeActivity derived applications, the same library name must be
# used in the AndroidManifest.xml file.
add_subdirectory(liboqs)

# Setup the JNI Bridge (The Java Wrapper)
# This includes the C files that let Java talk to C
add_library(
        oqs-jni-runtime
        SHARED
        jni/c/KeyEncapsulation.c
        jni/c/KEMs.c
        jni/c/Rand.c
        jni/c/Signature.c
        jni/c/Sigs.c
        jni/c/handle.c
        jni/jni.c # Legacy bridge helpers (Common)
)

# Include Directories
target_include_directories(oqs-jni-runtime PRIVATE
        liboqs/src/common
        liboqs/src
        ${CMAKE_CURRENT_BINARY_DIR}/liboqs/include
        jni
)

# Connect the JNI bridge to the algorithms and standard android logs
target_link_libraries(
        oqs-jni-runtime
        oqs
        android
        log
)
