# Compare the CMake source manifest with the Makefile.
#
# Usage (script mode):
#   cmake -DMAKEFILE=<path to Makefile> -DSOURCE_DIR=<cpp dir>
#         [-DSOURCES_CMAKE=<GhidraDecompSources.cmake>]
#         -P CheckMakefileManifest.cmake
#
# Parses the CORE, DECCORE, SLEIGH, GHIDRA, SLACOMP and SPECIAL variables
# from the Makefile (joining backslash continuations and dropping $(...)
# references), computes EXTRA the way the Makefile does (every *.cc in
# SOURCE_DIR that is in none of the other sets), and compares each set with
# the lists in GhidraDecompSources.cmake.  Exits with an error and prints
# the only-in-Makefile and only-in-CMake names when they differ.
#
# Also usable as an include from CMakeLists.txt: call
# ghidra_decomp_check_manifest(<makefile> <source dir>) after including
# GhidraDecompSources.cmake.

function(_ghidra_decomp_parse_makefile_var makefile_text var out_var)
  # Match "VAR=" or "VAR =" at the start of a line.
  string(REGEX MATCH "(^|\n)${var}[ \t]*=[ \t]*([^\n]*)" _m "${makefile_text}")
  if(NOT _m)
    message(FATAL_ERROR "manifest check: variable ${var} not found in Makefile")
  endif()
  set(_value "${CMAKE_MATCH_2}")
  # Drop $(...) references such as $(COREEXT_NAMES).
  string(REGEX REPLACE "\\$\\([^)]*\\)" "" _value "${_value}")
  string(REGEX REPLACE "[ \t]+" ";" _list "${_value}")
  list(REMOVE_ITEM _list "")
  set(${out_var} "${_list}" PARENT_SCOPE)
endfunction()

function(_ghidra_decomp_compare_set name makefile_list cmake_list result_var)
  set(_mk ${makefile_list})
  set(_cm ${cmake_list})
  list(SORT _mk)
  list(SORT _cm)
  set(_only_mk ${_mk})
  if(_cm)
    list(REMOVE_ITEM _only_mk ${_cm})
  endif()
  set(_only_cm ${_cm})
  if(_mk)
    list(REMOVE_ITEM _only_cm ${_mk})
  endif()
  set(_ok TRUE)
  if(_only_mk)
    string(REPLACE ";" " " _s "${_only_mk}")
    message(SEND_ERROR "manifest check: ${name}: only-in-Makefile: ${_s}")
    set(_ok FALSE)
  endif()
  if(_only_cm)
    string(REPLACE ";" " " _s "${_only_cm}")
    message(SEND_ERROR "manifest check: ${name}: only-in-CMake: ${_s}")
    set(_ok FALSE)
  endif()
  # Duplicates inside the CMake list mean two object libraries compile the
  # same translation unit.
  set(_dedup ${_cm})
  list(REMOVE_DUPLICATES _dedup)
  list(LENGTH _cm _n1)
  list(LENGTH _dedup _n2)
  if(NOT _n1 EQUAL _n2)
    message(SEND_ERROR "manifest check: ${name}: duplicate names in the CMake list")
    set(_ok FALSE)
  endif()
  list(LENGTH _mk _count)
  message(STATUS "manifest check: ${name}: ${_count} names, match=${_ok}")
  set(${result_var} ${_ok} PARENT_SCOPE)
endfunction()

function(ghidra_decomp_check_manifest makefile source_dir)
  if(NOT EXISTS "${makefile}")
    message(FATAL_ERROR "manifest check: Makefile not found: ${makefile}")
  endif()
  file(READ "${makefile}" _text)
  # Join backslash-newline continuations.
  string(REGEX REPLACE "\\\\[ \t]*\r?\n" " " _text "${_text}")
  string(REPLACE "\r\n" "\n" _text "${_text}")

  foreach(_var CORE DECCORE SLEIGH GHIDRA SLACOMP SPECIAL)
    _ghidra_decomp_parse_makefile_var("${_text}" ${_var} _MK_${_var})
  endforeach()

  # EXTRA = $(filter-out CORE DECCORE SLEIGH GHIDRA SLACOMP SPECIAL, ALL_NAMES)
  file(GLOB _all_cc RELATIVE "${source_dir}" "${source_dir}/*.cc")
  set(_MK_ALL "")
  foreach(_f IN LISTS _all_cc)
    string(REGEX REPLACE "\\.cc$" "" _n "${_f}")
    list(APPEND _MK_ALL "${_n}")
  endforeach()
  set(_MK_EXTRA ${_MK_ALL})
  foreach(_var CORE DECCORE SLEIGH GHIDRA SLACOMP SPECIAL)
    if(_MK_${_var})
      list(REMOVE_ITEM _MK_EXTRA ${_MK_${_var}})
    endif()
  endforeach()

  set(_all_ok TRUE)
  _ghidra_decomp_compare_set(CORE    "${_MK_CORE}"    "${GHIDRA_DECOMP_CORE_SOURCES}"        _ok)
  if(NOT _ok)
    set(_all_ok FALSE)
  endif()
  _ghidra_decomp_compare_set(DECCORE "${_MK_DECCORE}" "${GHIDRA_DECOMP_DECCORE_ALL_SOURCES}" _ok)
  if(NOT _ok)
    set(_all_ok FALSE)
  endif()
  _ghidra_decomp_compare_set(SLEIGH  "${_MK_SLEIGH}"  "${GHIDRA_DECOMP_SLEIGH_SOURCES}"      _ok)
  if(NOT _ok)
    set(_all_ok FALSE)
  endif()
  _ghidra_decomp_compare_set(GHIDRA  "${_MK_GHIDRA}"  "${GHIDRA_DECOMP_GHIDRA_SOURCES}"      _ok)
  if(NOT _ok)
    set(_all_ok FALSE)
  endif()
  _ghidra_decomp_compare_set(SLACOMP "${_MK_SLACOMP}" "${GHIDRA_DECOMP_SLACOMP_SOURCES}"     _ok)
  if(NOT _ok)
    set(_all_ok FALSE)
  endif()
  _ghidra_decomp_compare_set(SPECIAL "${_MK_SPECIAL}" "${GHIDRA_DECOMP_SPECIAL_SOURCES}"     _ok)
  if(NOT _ok)
    set(_all_ok FALSE)
  endif()
  _ghidra_decomp_compare_set(EXTRA   "${_MK_EXTRA}"   "${GHIDRA_DECOMP_EXTRA_SOURCES}"       _ok)
  if(NOT _ok)
    set(_all_ok FALSE)
  endif()

  # Every listed source must exist.
  foreach(_n IN LISTS GHIDRA_DECOMP_CORE_SOURCES GHIDRA_DECOMP_DECCORE_ALL_SOURCES
                      GHIDRA_DECOMP_SLEIGH_SOURCES GHIDRA_DECOMP_SLACOMP_SOURCES
                      GHIDRA_DECOMP_EXTRA_SOURCES GHIDRA_DECOMP_SPECIAL_SOURCES)
    if(NOT EXISTS "${source_dir}/${_n}.cc")
      message(SEND_ERROR "manifest check: listed source does not exist: ${_n}.cc")
      set(_all_ok FALSE)
    endif()
  endforeach()

  if(NOT _all_ok)
    message(FATAL_ERROR "manifest check: GhidraDecompSources.cmake differs from ${makefile}")
  endif()
  message(STATUS "manifest check: GhidraDecompSources.cmake matches ${makefile}")
endfunction()

if(CMAKE_SCRIPT_MODE_FILE AND CMAKE_SCRIPT_MODE_FILE STREQUAL CMAKE_CURRENT_LIST_FILE)
  if(NOT MAKEFILE)
    message(FATAL_ERROR "usage: cmake -DMAKEFILE=<Makefile> -DSOURCE_DIR=<cpp dir> -P CheckMakefileManifest.cmake")
  endif()
  if(NOT SOURCE_DIR)
    get_filename_component(SOURCE_DIR "${MAKEFILE}" DIRECTORY)
  endif()
  if(NOT SOURCES_CMAKE)
    set(SOURCES_CMAKE "${CMAKE_CURRENT_LIST_DIR}/GhidraDecompSources.cmake")
  endif()
  include("${SOURCES_CMAKE}")
  ghidra_decomp_check_manifest("${MAKEFILE}" "${SOURCE_DIR}")
endif()
