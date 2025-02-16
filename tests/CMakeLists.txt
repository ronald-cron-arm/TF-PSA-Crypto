set(libs
    ${tfpsacrypto_target}
    ${CMAKE_THREAD_LIBS_INIT}
)

if(NOT TF_PSA_CRYPTO_PYTHON_EXECUTABLE)
    message(FATAL_ERROR "Cannot build test suites without Python 3")
endif()

# Get paths relative to the current binary directory of the generated data files
# Paths are of the form "suites/test_suite*.data" as the data files are
# generated in the "./suites" directory.
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/suites)
execute_process(
    COMMAND
        ${TF_PSA_CRYPTO_PYTHON_EXECUTABLE}
        ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/generate_bignum_tests.py
        --list-for-cmake
    WORKING_DIRECTORY
        ${CMAKE_CURRENT_SOURCE_DIR}/..
    OUTPUT_VARIABLE
        bignum_generated_data_files)
string(REPLACE "tests/" ""
       bignum_generated_data_files "${bignum_generated_data_files}")

execute_process(
    COMMAND
        ${TF_PSA_CRYPTO_PYTHON_EXECUTABLE}
        ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/generate_config_tests.py
        --list-for-cmake
    WORKING_DIRECTORY
        ${CMAKE_CURRENT_SOURCE_DIR}/..
    OUTPUT_VARIABLE
        config_generated_data_files)
string(REPLACE "tests/" ""
       config_generated_data_files "${config_generated_data_files}")

execute_process(
    COMMAND
        ${TF_PSA_CRYPTO_PYTHON_EXECUTABLE}
        ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/generate_ecp_tests.py
        --list-for-cmake
    WORKING_DIRECTORY
        ${CMAKE_CURRENT_SOURCE_DIR}/..
    OUTPUT_VARIABLE
        ecp_generated_data_files)
string(REPLACE "tests/" ""
       ecp_generated_data_files "${ecp_generated_data_files}")

execute_process(
    COMMAND
        ${TF_PSA_CRYPTO_PYTHON_EXECUTABLE}
        ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/generate_psa_tests.py
        --list-for-cmake
    WORKING_DIRECTORY
        ${CMAKE_CURRENT_SOURCE_DIR}/..
    OUTPUT_VARIABLE
        psa_generated_data_files)
string(REPLACE "tests/" ""
       psa_generated_data_files "${psa_generated_data_files}")

set(all_generated_data_files
    ${bignum_generated_data_files} ${config_generated_data_files}
    ${ecp_generated_data_files} ${psa_generated_data_files})

if(GEN_FILES)
    add_custom_command(
        OUTPUT
            ${bignum_generated_data_files}
        WORKING_DIRECTORY
            ${CMAKE_CURRENT_SOURCE_DIR}/..
        COMMAND
            ${TF_PSA_CRYPTO_PYTHON_EXECUTABLE}
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/generate_bignum_tests.py
            --directory ${CMAKE_CURRENT_BINARY_DIR}/suites
        DEPENDS
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/generate_bignum_tests.py
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/mbedtls_framework/bignum_common.py
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/mbedtls_framework/bignum_core.py
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/mbedtls_framework/bignum_mod_raw.py
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/mbedtls_framework/bignum_mod.py
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/mbedtls_framework/test_case.py
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/mbedtls_framework/test_data_generation.py
    )
    add_custom_command(
        OUTPUT
            ${config_generated_data_files}
        WORKING_DIRECTORY
            ${CMAKE_CURRENT_SOURCE_DIR}/..
        COMMAND
            ${TF_PSA_CRYPTO_PYTHON_EXECUTABLE}
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/generate_config_tests.py
            --directory ${CMAKE_CURRENT_BINARY_DIR}/suites
            ${config_generated_data_files}
        DEPENDS
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/generate_config_tests.py
            # Do not declare the configuration files as dependencies: they
            # change too often in ways that don't affect the result
            # ((un)commenting some options).
    )
    add_custom_command(
        OUTPUT
            ${ecp_generated_data_files}
        WORKING_DIRECTORY
            ${CMAKE_CURRENT_SOURCE_DIR}/..
        COMMAND
            ${TF_PSA_CRYPTO_PYTHON_EXECUTABLE}
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/generate_ecp_tests.py
            --directory ${CMAKE_CURRENT_BINARY_DIR}/suites
        DEPENDS
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/generate_ecp_tests.py
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/mbedtls_framework/bignum_common.py
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/mbedtls_framework/ecp.py
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/mbedtls_framework/test_case.py
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/mbedtls_framework/test_data_generation.py
    )
    add_custom_command(
        OUTPUT
            ${psa_generated_data_files}
        WORKING_DIRECTORY
            ${CMAKE_CURRENT_SOURCE_DIR}/..
        COMMAND
            ${TF_PSA_CRYPTO_PYTHON_EXECUTABLE}
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/generate_psa_tests.py
            --directory ${CMAKE_CURRENT_BINARY_DIR}/suites
        DEPENDS
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/generate_psa_tests.py
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/mbedtls_framework/crypto_data_tests.py
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/mbedtls_framework/crypto_knowledge.py
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/mbedtls_framework/macro_collector.py
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/mbedtls_framework/psa_information.py
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/mbedtls_framework/psa_storage.py
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/mbedtls_framework/psa_test_case.py
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/mbedtls_framework/test_case.py
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/mbedtls_framework/test_data_generation.py
            ${CMAKE_CURRENT_SOURCE_DIR}/../include/psa/crypto_config.h
            ${CMAKE_CURRENT_SOURCE_DIR}/../include/psa/crypto_values.h
            ${CMAKE_CURRENT_SOURCE_DIR}/../include/psa/crypto_extra.h
    )
else()
    foreach(file ${all_generated_data_files})
        link_to_source(${file})
    endforeach()
endif()
# A separate target is created for each test data generation script. Each test
# suite executable that depends on a generated test data file is then set to
# depend on the corresponding target. This ensures that a generation script
# is not executed concurrently for different test suite executables,
# preventing simultaneous generation of the same files.
# This precaution is necessary for scripts that generate multiple files. As of
# this writing, only generate_bignum_tests.py and generate_psa_tests.py fall
# into this category. However, we apply this approach to all generation scripts
# to future-proof the system, anticipating that they may eventually generate
# multiple files.
add_custom_target(test_suite_bignum_generated_data DEPENDS ${bignum_generated_data_files})
add_custom_target(test_suite_tf_psa_crypto_config_generated_data DEPENDS ${config_generated_data_files})
add_custom_target(test_suite_ecp_generated_data DEPENDS ${ecp_generated_data_files})
add_custom_target(test_suite_psa_generated_data DEPENDS ${psa_generated_data_files})
register_generated_files("tests/" "${bignum_generated_data_files}")
register_generated_files("tests/" "${config_generated_data_files}")
register_generated_files("tests/" "${ecp_generated_data_files}")
register_generated_files("tests/" "${psa_generated_data_files}")

# If SKIP_TEST_SUITES is not defined with -D, get it from the environment.
if((NOT DEFINED SKIP_TEST_SUITES) AND (DEFINED ENV{SKIP_TEST_SUITES}))
    set(SKIP_TEST_SUITES $ENV{SKIP_TEST_SUITES})
endif()
# Test suites caught by SKIP_TEST_SUITES are built but not executed.
# "foo" as a skip pattern skips "test_suite_foo" and "test_suite_foo.bar"
# but not "test_suite_foobar".
string(REGEX REPLACE "[ ,;]" "|" SKIP_TEST_SUITES_REGEX "${SKIP_TEST_SUITES}")
string(REPLACE "." "\\." SKIP_TEST_SUITES_REGEX "${SKIP_TEST_SUITES_REGEX}")
set(SKIP_TEST_SUITES_REGEX "^(${SKIP_TEST_SUITES_REGEX})(\$|\\.)")

function(add_test_suite function_name data_name data_file_path)
    set(data_file "${data_file_path}/test_suite_${data_name}.data")

    add_custom_command(
        OUTPUT
            # The output filename of generate_test_code.py is derived from the -d
            # input argument.
            test_suite_${data_name}.c
        COMMAND
            ${TF_PSA_CRYPTO_PYTHON_EXECUTABLE}
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/generate_test_code.py
            -f ${CMAKE_CURRENT_SOURCE_DIR}/suites/test_suite_${function_name}.function
            -d ${data_file}
            -t ${CMAKE_CURRENT_SOURCE_DIR}/suites/main_test.function
            -p ${CMAKE_CURRENT_SOURCE_DIR}/suites/host_test.function
            -s ${CMAKE_CURRENT_SOURCE_DIR}/suites
            --helpers-file ${CMAKE_CURRENT_SOURCE_DIR}/suites/helpers.function
            -o .
        DEPENDS
            ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/scripts/generate_test_code.py
            ${CMAKE_CURRENT_SOURCE_DIR}/suites/test_suite_${function_name}.function
            ${data_file}
            ${CMAKE_CURRENT_SOURCE_DIR}/suites/main_test.function
            ${CMAKE_CURRENT_SOURCE_DIR}/suites/host_test.function
            ${CMAKE_CURRENT_SOURCE_DIR}/suites/helpers.function
            ${tfpsacrypto_target}
        BYPRODUCTS
            test_suite_${data_name}.datax
    )

    add_executable(test_suite_${data_name} test_suite_${data_name}.c
                   $<TARGET_OBJECTS:tf_psa_crypto_test>)
    set_base_compile_options(test_suite_${data_name})
    target_compile_options(test_suite_${data_name} PRIVATE ${TEST_C_FLAGS})

    if("suites/test_suite_${data_name}.data" IN_LIST bignum_generated_data_files)
        add_dependencies(test_suite_${data_name} test_suite_bignum_generated_data)
    elseif("suites/test_suite_${data_name}.data" IN_LIST config_generated_data_files)
        add_dependencies(test_suite_${data_name} test_suite_tf_psa_crypto_config_generated_data)
    elseif("suites/test_suite_${data_name}.data" IN_LIST ecp_generated_data_files)
        add_dependencies(test_suite_${data_name} test_suite_ecp_generated_data)
    elseif("suites/test_suite_${data_name}.data" IN_LIST psa_generated_data_files)
        add_dependencies(test_suite_${data_name} test_suite_psa_generated_data)
    endif()

    target_link_libraries(test_suite_${data_name} ${libs})
    # Include test-specific header files from ./include and private header
    # files (used by some invasive tests) from ../library. Public header
    # files are automatically included because the library targets declare
    # them as PUBLIC.
    target_include_directories(test_suite_${data_name}
        PRIVATE ${TF_PSA_CRYPTO_FRAMEWORK_DIR}/tests/include
        PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/include
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../core
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../drivers/builtin/src)
    # Request C11, which is needed for memory poisoning tests
    set_target_properties(test_suite_${data_name} PROPERTIES C_STANDARD 11)

    if(${data_name} MATCHES ${SKIP_TEST_SUITES_REGEX})
        message(STATUS "The test suite ${data_name} will not be executed.")
    else()
        add_test(${data_name}-suite test_suite_${data_name} --verbose)
    endif()
endfunction(add_test_suite)

# Enable definition of various functions used throughout the testsuite
# (gethostname, strdup, fileno...) even when compiling with -std=c99. Harmless
# on non-POSIX platforms.
add_definitions("-D_POSIX_C_SOURCE=200809L")

if(CMAKE_COMPILER_IS_CLANG)
    set(TEST_C_FLAGS -Wdocumentation -Wno-documentation-deprecated-sync -Wunreachable-code)
endif(CMAKE_COMPILER_IS_CLANG)

if(MSVC)
    # If a warning level has been defined, suppress all warnings for test code
    set(TEST_C_FLAGS /W0 /WX-)
endif(MSVC)

file(GLOB test_suites RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" suites/*.data)
list(APPEND test_suites ${all_generated_data_files})
# If the generated .data files are present in the source tree, we just added
# them twice, both through GLOB and through ${all_generated_data_files}.
list(REMOVE_DUPLICATES test_suites)
list(SORT test_suites)
foreach(test_suite ${test_suites})
    get_filename_component(data_name ${test_suite} NAME)
    string(REGEX REPLACE "\\.data\$" "" data_name "${data_name}")
    string(REPLACE "test_suite_" "" data_name "${data_name}")
    string(REGEX MATCH "[^.]*" function_name "${data_name}")

    if(test_suite IN_LIST all_generated_data_files)
        set(data_file_path "${CMAKE_CURRENT_BINARY_DIR}/suites")
    else()
        set(data_file_path "${CMAKE_CURRENT_SOURCE_DIR}/suites")
    endif()

    add_test_suite(${function_name} ${data_name} "${data_file_path}")
endforeach(test_suite)

# Make scripts and data files needed for testing available in an
# out-of-source build.
if (NOT ${CMAKE_CURRENT_BINARY_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/seedfile")
        link_to_source(seedfile)
    endif()
    link_to_source(Descriptions.txt)
    link_to_source(../framework/data_files)
endif()
