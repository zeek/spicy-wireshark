
if (NOT CMAKE_BUILD_TYPE)
    # CMake doesn't set build type by default.
    set(CMAKE_BUILD_TYPE "Debug")
endif ()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/plugin-config.h.in" plugin-config.h)

set(AUTOGEN_H "${CMAKE_CURRENT_BINARY_DIR}/autogen")
file(MAKE_DIRECTORY "${AUTOGEN_H}")

add_custom_command(
    OUTPUT "${AUTOGEN_H}/wireshark.h"
    COMMAND ${SPICYC} -P '' "${CMAKE_SOURCE_DIR}/lib/wireshark.spicy" -o "${AUTOGEN_H}/wireshark.h"
    DEPENDS ${SPICYC} "${CMAKE_SOURCE_DIR}/lib/wireshark.spicy"
    COMMENT "Generating wireshark.h"
)

add_custom_target(update_version
    COMMAND ${CMAKE_SOURCE_DIR}/cmake/project-version.sh --update "${AUTOGEN_H}/version.h"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_custom_target(generate_header ALL DEPENDS "${AUTOGEN_H}/wireshark.h" update_version)
set_target_properties(generate_header PROPERTIES ADDITIONAL_CLEAN_FILES "${AUTOGEN_H}/wireshark.h")
set_target_properties(generate_header PROPERTIES ADDITIONAL_CLEAN_FILES "${AUTOGEN_H}/version.h")

add_library(ws-spicy MODULE plugin.cc tree-builder.cc)
add_dependencies(ws-spicy generate_header)
set_target_properties(ws-spicy PROPERTIES OUTPUT_NAME "spicy")
set_target_properties(ws-spicy PROPERTIES PREFIX "")
set_target_properties(ws-spicy PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugin/${WS_PLUGIN_INSTALL_DIR_POSTFIX}/epan")
target_compile_options(ws-spicy PRIVATE "-Wall")

target_include_directories(ws-spicy PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(ws-spicy PRIVATE ${Wireshark_INCLUDE_DIR})
target_include_directories(ws-spicy PRIVATE "${AUTOGEN_H}")
target_link_libraries(ws-spicy PRIVATE PkgConfig::deps)

# We do *not* link against the Wireshark library. If we did, the path to the
# library would be hardcoded into the plugin, which would then prevent us from
# loading it into different Wireshark installations. (It might subtly fail if
# we do. For example, with the two Homebrew versions (UI vs non-UI), the plugin
# initialization didn't quite work if loaded with the one not build against,
# even if the two Wireshark versions matched.)
#
# target_link_directories(ws-spicy PRIVATE ${Wireshark_LIB_DIR})
# target_link_libraries(ws-spicy PRIVATE wireshark)

target_compile_options(ws-spicy PRIVATE ${SPICY_CXX_FLAGS} "-Wno-deprecated-volatile")
target_link_options(ws-spicy PRIVATE ${SPICY_LD_FLAGS})
target_include_directories(ws-spicy PRIVATE ${SPICY_INCLUDE_DIRS_RUNTIME})
target_link_directories(ws-spicy PRIVATE ${SPICY_LIBRARY_DIRS_RUNTIME})

if (APPLE)
    set_target_properties(ws-spicy PROPERTIES LINK_FLAGS "-undefined dynamic_lookup")
endif ()

if (Wireshark_PLUGIN_INSTALL_DIR)
    install(TARGETS ws-spicy DESTINATION "${Wireshark_PLUGIN_INSTALL_DIR}/epan")
endif ()
