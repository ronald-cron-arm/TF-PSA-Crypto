set(drivers
    builtin
    everest
    p256-m
)
set(TF_PSA_CRYPTO_DRIVERS "${drivers}" PARENT_SCOPE)

# Drivers currently depend on each other indirectly through the inclusion
# `crypto_driver_contexts_*.h` headers, so all driver include paths
# must be visible when building each driver.
set(TF_PSA_CRYPTO_DRIVERS_INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/builtin/include
        ${CMAKE_CURRENT_SOURCE_DIR}/everest/include
        ${CMAKE_CURRENT_SOURCE_DIR}/p256-m
)

# Lists of driver targets.
# TF_PSA_CRYPTO_DRIVER_STATIC_TARGETS: the list of driver targets to use to
# build the static library if the build of the static library is enabled, not
# defined otherwise.
# TF_PSA_CRYPTO_DRIVER_TARGETS: the list of driver targets to use to build
# the shared library if the build of the shared library is enabled. Equal to
# TF_PSA_CRYPTO_DRIVER_STATIC_TARGETS otherwise.
set(driver_targets "")
foreach(driver ${drivers})
    list(APPEND driver_targets "${TF_PSA_CRYPTO_TARGET_PREFIX}${driver}")
endforeach()

if (USE_STATIC_TF_PSA_CRYPTO_LIBRARY)
    if(NOT USE_SHARED_TF_PSA_CRYPTO_LIBRARY)
        set(driver_static_targets ${driver_targets})
    else()
        set(driver_static_targets "")
        foreach(target ${driver_targets})
            list(APPEND driver_static_targets "${target}_static")
        endforeach()
    endif()
endif()
set(TF_PSA_CRYPTO_DRIVER_STATIC_TARGETS "${driver_static_targets}" PARENT_SCOPE)
set(TF_PSA_CRYPTO_DRIVER_TARGETS "${driver_targets}" PARENT_SCOPE)

add_subdirectory(everest)
add_subdirectory(p256-m)
add_subdirectory(builtin)
