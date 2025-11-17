# CMake module for building built-in and generated test drivers.
# This file is meant to be included from `builtin/CMakeLists.txt` or
# `libtestdriver1/CMakeLists.txt`.
#
# The following variables must be defined by the caller before including this
# module:
# - tf_psa_crypto_driver: the driver name (e.g. "builtin", "libtestdriver1")
# - ${tf_psa_crypto_driver}_src_files: the list of source files for the driver

if(CMAKE_COMPILER_IS_GNUCC)
    set(LIBS_C_FLAGS -Wmissing-declarations -Wmissing-prototypes)
endif(CMAKE_COMPILER_IS_GNUCC)

if(CMAKE_COMPILER_IS_CLANG)
    set(LIBS_C_FLAGS -Wmissing-declarations -Wmissing-prototypes -Wdocumentation -Wno-documentation-deprecated-sync -Wunreachable-code)
endif(CMAKE_COMPILER_IS_CLANG)

set(${tf_psa_crypto_driver}_target ${TF_PSA_CRYPTO_TARGET_PREFIX}${tf_psa_crypto_driver})
if (USE_STATIC_TF_PSA_CRYPTO_LIBRARY)
    set(${tf_psa_crypto_driver}_static_target ${${tf_psa_crypto_driver}_target})
endif()
set(target_libraries ${${tf_psa_crypto_driver}_target})
if(USE_STATIC_TF_PSA_CRYPTO_LIBRARY AND USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    string(APPEND ${tf_psa_crypto_driver}_static_target "_static")
    list(APPEND target_libraries ${${tf_psa_crypto_driver}_static_target})
endif()

foreach (target IN LISTS target_libraries)
    add_library(${target} OBJECT ${${tf_psa_crypto_driver}_src_files})
    tf_psa_crypto_set_base_compile_options(${target})
    target_compile_options(${target} PRIVATE ${LIBS_C_FLAGS})

    target_include_directories(${target}
      PUBLIC include
      PRIVATE ${TF_PSA_CRYPTO_DIR}/drivers/${tf_psa_crypto_driver}/include
              ${TF_PSA_CRYPTO_DIR}/drivers/${tf_psa_crypto_driver}/src
              ${TF_PSA_CRYPTO_DIR}/include
              ${TF_PSA_CRYPTO_DIR}/core
              ${TF_PSA_CRYPTO_DRIVERS_INCLUDE_DIRS})
    tf_psa_crypto_set_config_files_compile_definitions(${target})
    if(TF_PSA_CRYPTO_TEST_DRIVER)
        add_dependencies(${target} tf_psa_crypto_test_driver_src)
    endif()
endforeach(target)

if(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    set_property(TARGET ${${tf_psa_crypto_driver}_target} PROPERTY POSITION_INDEPENDENT_CODE ON)
endif(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)

if(INSTALL_TF_PSA_CRYPTO_HEADERS)
  install(DIRECTORY "include/"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h")
endif(INSTALL_TF_PSA_CRYPTO_HEADERS)
