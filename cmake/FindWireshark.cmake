# Locate the Wireshark library.
#
# This file is meant to be copied into projects that want to use Wireshark.
# It will search for WiresharkConfig.cmake, which ships with Wireshark
# and will provide up-to-date buildsystem changes. Thus there should not be
# any need to update FindWiresharkVc.cmake again after you integrated it into
# your project.
#
# This module defines the following variables:
# Wireshark_FOUND
# Wireshark_VERSION_MAJOR
# Wireshark_VERSION_MINOR
# Wireshark_VERSION_PATCH
# Wireshark_VERSION
# Wireshark_VERSION_STRING
# Wireshark_INSTALL_DIR
# Wireshark_PLUGIN_INSTALL_DIR
# Wireshark_LIB_DIR
# Wireshark_LIBRARY
# Wireshark_INCLUDE_DIR
# Wireshark_CMAKE_MODULES_DIR

find_package(
    Wireshark
    ${Wireshark_FIND_VERSION}
    QUIET
    NO_MODULE
    PATHS
    $ENV{HOME}
    /opt/Wireshark)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Wireshark CONFIG_MODE)

# Run tshark with to get the user plugin directory.
if (Wireshark_FOUND)
    find_program(_tshark NAME tshark HINTS "${Wireshark_INSTALL_DIR}/bin")
    if (_tshark)
        message(STATUS "Found tshark: ${_tshark}")

        # AI! Clear the WIRESHARK_PLUGIN_DIR environment variable when running the following command.
        execute_process(
            COMMAND env WIRESHARK_PLUGIN_DIR= tshark -G folders
            OUTPUT_VARIABLE _tshark_folders
            ERROR_VARIABLE _tshark_error
            RESULT_VARIABLE _tshark_result
            OUTPUT_STRIP_TRAILING_WHITESPACE)

        if (_tshark_result EQUAL 0)
            string(REGEX MATCH "Personal Plugins:[ \t]+(/[^\n]+)" _tshark_match
                         "${_tshark_folders}")
            set(Wireshark_PERSONAL_PLUGIN_INSTALL_DIR "${CMAKE_MATCH_1}")
            message(
                STATUS
                    "Wireshark personal plugin directory: ${Wireshark_PERSONAL_PLUGIN_INSTALL_DIR}")
        else ()
            message(WARNING "Failed to run tshark: ${_tshark_error}")
            set(Wireshark_PERSONAL_PLUGIN_INSTALL_DIR "")
        endif ()
    endif ()
endif ()
