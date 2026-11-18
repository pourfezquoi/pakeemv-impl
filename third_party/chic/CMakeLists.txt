cmake_minimum_required(VERSION 3.18)
project(chic_reference C)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    include(CTest)
endif()

add_library(chic_ref STATIC
    chic.c
    src/chic_ref_pake.c
    src/chic_ref_hic.c
    src/chic_ref_rijndael.c
    src/chic_ref_tables.c
    src/chic_ref_kem.c
    src/chic_ref_indcpa.c
    src/chic_ref_rej_uniform.c
    src/chic_ref_polyvec.c
    src/chic_ref_poly.c
    src/chic_ref_ntt.c
    src/chic_ref_cbd.c
    src/chic_ref_reduce.c
    src/chic_ref_verify.c
    src/chic_ref_fips202.c
    src/chic_ref_symmetric_shake.c
)
target_include_directories(chic_ref PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/upstream/kyber
            ${CMAKE_CURRENT_SOURCE_DIR}/compat)
set_target_properties(chic_ref PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED YES POSITION_INDEPENDENT_CODE ON)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    # Upstream Rijndael accesses byte arrays through 32-bit word pointers.
    target_compile_options(chic_ref PRIVATE -fno-strict-aliasing)
endif()
if(BUILD_TESTING AND NOT ANDROID)
    add_executable(chic_tests tests/test_chic.c)
    target_link_libraries(chic_tests PRIVATE chic_ref)
    add_test(NAME chic_reference_and_negative COMMAND chic_tests)
endif()
