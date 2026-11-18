cmake_minimum_required(VERSION 3.22.1)
project(pakebdh_chic C)

get_filename_component(EMV_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../../.." ABSOLUTE)
# Keep the existing ML-KEM/certificate provider for the outer protocol.
add_subdirectory("${EMV_ROOT}/BOD_Terminal/app/src/main/cpp" "${CMAKE_CURRENT_BINARY_DIR}/oqs-runtime")
# CHIC uses its authors' complete, pinned Kyber/HIC construction independently.
add_subdirectory("${EMV_ROOT}/third_party/chic" "${CMAKE_CURRENT_BINARY_DIR}/chic-ref")
add_library(chic-jni SHARED chic_jni.c chic_randombytes.c)
target_link_libraries(chic-jni PRIVATE chic_ref)
target_compile_features(chic-jni PRIVATE c_std_11)
