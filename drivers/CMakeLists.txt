set(drivers_dirs "builtin;everest;p256-m")
set(TF_PSA_CRYPTO_DRIVERS_DIRS "${drivers_dirs}" PARENT_SCOPE)

add_subdirectory(everest)
add_subdirectory(p256-m)
add_subdirectory(builtin)
