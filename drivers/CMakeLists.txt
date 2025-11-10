file(GLOB subdirs RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/*")
set(drivers_dirs "")
foreach(entry ${subdirs})
    if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/${entry}")
        list(APPEND drivers_dirs "${entry}")
    endif()
endforeach()

set(TF_PSA_CRYPTO_DRIVERS_DIRS "${drivers_dirs}" PARENT_SCOPE)

foreach(entry ${drivers_dirs})
    add_subdirectory("${entry}")
endforeach()
