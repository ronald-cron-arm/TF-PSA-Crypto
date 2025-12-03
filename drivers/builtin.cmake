
if(CMAKE_COMPILER_IS_GNUCC)
    set(LIBS_C_FLAGS -Wmissing-declarations -Wmissing-prototypes)
endif(CMAKE_COMPILER_IS_GNUCC)

if(CMAKE_COMPILER_IS_CLANG)
    set(LIBS_C_FLAGS -Wmissing-declarations -Wmissing-prototypes -Wdocumentation -Wno-documentation-deprecated-sync -Wunreachable-code)
endif(CMAKE_COMPILER_IS_CLANG)

if(CMAKE_COMPILER_IS_MSVC)
    option(MSVC_STATIC_RUNTIME "Build the libraries with /MT compiler flag" OFF)
    if(MSVC_STATIC_RUNTIME)
        foreach(flag_var
            CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
            CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO
            CMAKE_C_FLAGS_CHECK)
            string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
        endforeach(flag_var)
    endif()
endif()

if(CMAKE_C_COMPILER_ID MATCHES "AppleClang")
    set(CMAKE_C_ARCHIVE_CREATE   "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_C_ARCHIVE_FINISH   "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "AppleClang")
    set(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_CXX_ARCHIVE_FINISH "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
endif()

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
      PRIVATE ${TF_PSA_CRYPTO_DIR}/drivers/${tf_psa_crypto_driver}/include
              ${TF_PSA_CRYPTO_DIR}/drivers/${tf_psa_crypto_driver}/src
              ${TF_PSA_CRYPTO_DIR}/include
              ${TF_PSA_CRYPTO_DIR}/core
              ${TF_PSA_CRYPTO_DRIVERS_INCLUDE_DIRS})
    tf_psa_crypto_set_config_files_compile_definitions(${target})
endforeach(target)

if(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
    set_property(TARGET ${${tf_psa_crypto_driver}_target} PROPERTY POSITION_INDEPENDENT_CODE ON)
endif(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)

if(INSTALL_TF_PSA_CRYPTO_HEADERS)
  install(DIRECTORY "include/${tf_psa_crypto_driver_include_dir}"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h")
endif(INSTALL_TF_PSA_CRYPTO_HEADERS)
