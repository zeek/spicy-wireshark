cmake_minimum_required(VERSION 3.15.0)

execute_process(
    COMMAND cmake/project-version.sh --print
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE PLUGIN_VERSION_NUMBER
    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)

string(REGEX MATCH "([0-9]*)\.([0-9]*)\.([0-9]*).*" _ ${PLUGIN_VERSION_NUMBER})
set(PLUGIN_VERSION_NUMBER_MAIN "${CMAKE_MATCH_1}" CACHE STRING "")

project(WiresharkPlugin VERSION "${PLUGIN_VERSION_NUMBER_MAIN}" LANGUAGES CXX)

option(USE_CCACHE "" "no")
option(SPICY_ROOT_DIR "" "")
option(WS_ROOT "" "")
option(WS_INCLUDE_DIR "" "")
option(WS_PLUGIN_DIR "" "")

if (USE_CCACHE)
    find_program(CCACHE_PROGRAM ccache)
    if (CCACHE_PROGRAM)
        set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
        set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
    else ()
        set(USE_CCACHE "no (error: could not find ccache)")
    endif ()
endif ()

include(GNUInstallDirs)

list(PREPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

### Wireshark

if (WS_ROOT)
    set(Wireshark_ROOT "${WS_ROOT}" CACHE PATH "" FORCE)
endif ()

find_package(Wireshark REQUIRED)

set(WIRESHARK_MIN_VERSION "4.2" CACHE STRING "Minimum required Wireshark version")

if (Wireshark_VERSION VERSION_LESS "${WIRESHARK_MIN_VERSION}")
    message(
        FATAL_ERROR
            "Wireshark ${WIRESHARK_MIN_VERSION} or newer is required; found ${Wireshark_VERSION}")
endif ()

string(REGEX MATCH "^([0-9]+)\\.([0-9]+)" _ "${WIRESHARK_MIN_VERSION}")
set(WIRESHARK_MIN_VERSION_MAJOR "${CMAKE_MATCH_1}")
set(WIRESHARK_MIN_VERSION_MINOR "${CMAKE_MATCH_2}")

###

find_package(PkgConfig REQUIRED)
pkg_check_modules(deps REQUIRED IMPORTED_TARGET glib-2.0)

find_package(Spicy REQUIRED)
spicy_require_version("1.14.0")

if (WS_INCLUDE_DIR)
    set(Wireshark_INCLUDE_DIR "${WS_INCLUDE_DIR}" CACHE PATH "" FORCE)
endif ()

if (WS_USE_PERSONAL_PLUGIN_DIR)
    set(Wireshark_PLUGIN_INSTALL_DIR "${Wireshark_PERSONAL_PLUGIN_INSTALL_DIR}")
elseif (WS_PLUGIN_DIR)
    set(Wireshark_PLUGIN_INSTALL_DIR "${WS_PLUGIN_DIR}" CACHE PATH "" FORCE)
endif ()

get_filename_component(WS_PLUGIN_INSTALL_DIR_POSTFIX "${Wireshark_PLUGIN_INSTALL_DIR}" NAME)
add_subdirectory(src)

spicy_print_summary()

if (Wireshark_FOUND)
    set(Wireshark_FOUND yes)
else ()
    set(Wireshark_FOUND no)
endif ()

message(
    "\n====================|  Wireshark Installation Summary |===================="
    "\n"
    "\nFound Wireshark:       ${Wireshark_FOUND}"
    "\n"
    "\nVersion:               ${Wireshark_VERSION}"
    "\nInclude directory:     ${Wireshark_INCLUDE_DIR}"
    "\nLibrary directory:     ${Wireshark_LIB_DIR}"
    "\nPlugin directory:      ${Wireshark_PLUGIN_INSTALL_DIR}"
    "\n"
    "\n========================================================================\n"
    "\n"
    "\n====================|  Spicy Wireshark Plugin  |===================="
    "\n"
    "\nVersion:               ${PLUGIN_VERSION_NUMBER}"
    "\nBuild type:            ${CMAKE_BUILD_TYPE}"
    "\nBuild directory:       ${PROJECT_BINARY_DIR}"
    "\nspicy-config:          ${SPICY_CONFIG}"
    "\n"
    "\n========================================================================\n")
