set(drivers_dirs "builtin;everest;p256-m")
set(TF_PSA_CRYPTO_DRIVERS_INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/builtin/include
        ${CMAKE_CURRENT_SOURCE_DIR}/everest/include
        ${CMAKE_CURRENT_SOURCE_DIR}/p256-m)

if(TF_PSA_CRYPTO_TEST_DRIVER)
    list(APPEND drivers_dirs libtestdriver1)
    list(APPEND TF_PSA_CRYPTO_DRIVERS_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libtestdriver1/include)

    execute_process(
        COMMAND ${TF_PSA_CRYPTO_PYTHON_EXECUTABLE} ./scripts/generate_test_driver.py --list-vars-for-cmake --dst-dir ${CMAKE_CURRENT_BINARY_DIR}
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        RESULT_VARIABLE result)
    if(result)
        message(FATAL_ERROR "Generation of list-vars.cmake failed: ${result}")
    endif()

    include(${CMAKE_CURRENT_BINARY_DIR}/libtestdriver1-list-vars.cmake)

    add_custom_command(
        OUTPUT ${libtestdriver1_output_files}
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        COMMAND
            ${TF_PSA_CRYPTO_PYTHON_EXECUTABLE}
                ./scripts/generate_test_driver.py --dst-dir ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS ${PROJECT_SOURCE_DIR}/scripts/generate_test_driver.py
        COMMENT "Generating test driver libtestdriver1 tree"
    )

    add_custom_target(tf_psa_crypto_test_driver_src
        DEPENDS ${libtestdriver1_output_files})

    set(libtestdriver1_target ${TF_PSA_CRYPTO_TARGET_PREFIX}libtestdriver1)
    if (USE_STATIC_TF_PSA_CRYPTO_LIBRARY)
        set(libtestdriver1_static_target ${libtestdriver1_target})
    endif()
    set(target_libraries ${libtestdriver1_target})
    if(USE_STATIC_TF_PSA_CRYPTO_LIBRARY AND USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
        string(APPEND libtestdriver1_static_target "_static")
        list(APPEND target_libraries ${libtestdriver1_static_target})
    endif()

    foreach (target IN LISTS target_libraries)
        add_library(${target} OBJECT ${libtestdriver1_output_c_files})
        tf_psa_crypto_set_base_compile_options(${target})
        target_compile_options(${target} PRIVATE ${LIBS_C_FLAGS})

        target_include_directories(${target}
          PRIVATE src include
                  ${TF_PSA_CRYPTO_DIR}/include
                  ${TF_PSA_CRYPTO_DIR}/core
                  ${TF_PSA_CRYPTO_DRIVERS_INCLUDE_DIRS})
        tf_psa_crypto_set_config_files_compile_definitions(${target})
        add_dependencies(${target} tf_psa_crypto_test_driver_src)
    endforeach(target)

    if(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
        set_property(TARGET ${libtestdriver1_target} PROPERTY POSITION_INDEPENDENT_CODE ON)
    endif(USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
endif()

set(TF_PSA_CRYPTO_DRIVERS_DIRS "${drivers_dirs}" PARENT_SCOPE)
set(TF_PSA_CRYPTO_DRIVERS_INCLUDE_DIRS "${TF_PSA_CRYPTO_DRIVERS_INCLUDE_DIRS}" PARENT_SCOPE)

add_subdirectory(everest)
add_subdirectory(p256-m)
add_subdirectory(builtin)
