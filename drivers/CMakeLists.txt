set(drivers "builtin;everest;p256-m")
set(TF_PSA_CRYPTO_DRIVERS "${drivers}" PARENT_SCOPE)

add_subdirectory(everest)
add_subdirectory(p256-m)
add_subdirectory(builtin)
