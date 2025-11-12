set(drivers "builtin;everest;p256-m")
# Directories containing the headers exposed by drivers
set(TF_PSA_CRYPTO_DRIVERS_INCLUDE_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/builtin/include
        ${CMAKE_CURRENT_SOURCE_DIR}/everest/include
        ${CMAKE_CURRENT_SOURCE_DIR}/p256-m)

set(TF_PSA_CRYPTO_DRIVERS "${drivers}" PARENT_SCOPE)
set(TF_PSA_CRYPTO_DRIVERS_INCLUDE_DIRS "${TF_PSA_CRYPTO_DRIVERS_INCLUDE_DIRS}" PARENT_SCOPE)

add_subdirectory(everest)
add_subdirectory(p256-m)
add_subdirectory(builtin)
