# Isolation checks, run through ctest in script mode.
#
#   cmake -DMODE=linkage -DBINARIES=<a;b;c> -P NoJvmCheck.cmake
#       Every binary's dynamic dependencies (ldd, or otool -L on macOS) must
#       not match libjvm|libjava|libjli|libjawt.
#
#   cmake -DMODE=runtime -DBINARY=<exe> -DARGS=<a;b> [-DSTRACE=<path>]
#         [-DWORKDIR=<dir>] -P NoJvmCheck.cmake
#       Run the binary with an empty environment (env -i PATH=/usr/bin
#       HOME=/nonexistent LANG=C).  With STRACE set, also record execve
#       calls and require exactly one: the program never starts another
#       process.
#
#   cmake -DMODE=symbols -DNM=<nm> -DARCHIVE=<lib.a> -DPATTERN=<regex>
#         -P NoJvmCheck.cmake
#       The archive must define no symbol matching PATTERN.  Used to prove
#       ghidra_process.cc (GhidraCapability, GhidraCommand) is not linked.

if(NOT MODE)
  message(FATAL_ERROR "NoJvmCheck: MODE is required (linkage|runtime|symbols)")
endif()

set(_jvm_regex "libjvm|libjava|libjli|libjawt")

if(MODE STREQUAL "linkage")
  if(NOT BINARIES)
    message(FATAL_ERROR "NoJvmCheck: BINARIES is required")
  endif()
  find_program(_ldd ldd)
  find_program(_otool otool)
  find_program(_readelf readelf)
  set(_failed FALSE)
  foreach(_bin IN LISTS BINARIES)
    if(NOT EXISTS "${_bin}")
      message(SEND_ERROR "NoJvmCheck: missing binary ${_bin}")
      set(_failed TRUE)
      continue()
    endif()
    if(_ldd)
      execute_process(COMMAND "${_ldd}" "${_bin}" OUTPUT_VARIABLE _out ERROR_VARIABLE _err RESULT_VARIABLE _rc)
      # ldd fails on static executables; that is a pass.
      if(NOT _rc EQUAL 0 AND _readelf)
        execute_process(COMMAND "${_readelf}" -d "${_bin}" OUTPUT_VARIABLE _out ERROR_QUIET)
      endif()
    elseif(_otool)
      execute_process(COMMAND "${_otool}" -L "${_bin}" OUTPUT_VARIABLE _out ERROR_QUIET)
    elseif(_readelf)
      execute_process(COMMAND "${_readelf}" -d "${_bin}" OUTPUT_VARIABLE _out ERROR_QUIET)
    else()
      message(FATAL_ERROR "NoJvmCheck: no ldd, otool or readelf found")
    endif()
    if(_out MATCHES "${_jvm_regex}")
      message(SEND_ERROR "NoJvmCheck: ${_bin} links a JVM library:\n${_out}")
      set(_failed TRUE)
    else()
      get_filename_component(_name "${_bin}" NAME)
      message(STATUS "NoJvmCheck: ${_name}: no JVM library")
    endif()
  endforeach()
  if(_failed)
    message(FATAL_ERROR "NoJvmCheck: linkage check failed")
  endif()

elseif(MODE STREQUAL "runtime")
  if(NOT BINARY)
    message(FATAL_ERROR "NoJvmCheck: BINARY is required")
  endif()
  # Do not inherit a shadow command from the caller's PATH.  This test
  # deliberately constructs its own minimal environment, so /usr/bin/env is
  # the portable system utility we mean to execute.
  find_program(_env env PATHS /usr/bin /bin NO_DEFAULT_PATH)
  if(NOT _env)
    message(FATAL_ERROR "NoJvmCheck: env not found")
  endif()
  if(NOT WORKDIR)
    set(WORKDIR "${CMAKE_CURRENT_BINARY_DIR}")
  endif()
  set(_clean_env "${_env}" -i PATH=/usr/bin HOME=/nonexistent LANG=C)
  if(STRACE)
    set(_trace_file "${WORKDIR}/no_jvm_runtime.strace")
    file(REMOVE "${_trace_file}")
    execute_process(
      COMMAND ${_clean_env} "${STRACE}" -f -e trace=execve -o "${_trace_file}" "${BINARY}" ${ARGS}
      WORKING_DIRECTORY "${WORKDIR}"
      OUTPUT_VARIABLE _out ERROR_VARIABLE _err RESULT_VARIABLE _rc)
  else()
    execute_process(
      COMMAND ${_clean_env} "${BINARY}" ${ARGS}
      WORKING_DIRECTORY "${WORKDIR}"
      OUTPUT_VARIABLE _out ERROR_VARIABLE _err RESULT_VARIABLE _rc)
  endif()
  if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "NoJvmCheck: ${BINARY} failed under an empty environment (rc=${_rc})\n${_err}")
  endif()
  if(_out MATCHES "${_jvm_regex}" OR _err MATCHES "${_jvm_regex}")
    message(FATAL_ERROR "NoJvmCheck: output mentions a JVM library")
  endif()
  if(STRACE)
    file(STRINGS "${_trace_file}" _lines REGEX "execve\\(")
    list(LENGTH _lines _n)
    if(NOT _n EQUAL 1)
      message(FATAL_ERROR "NoJvmCheck: expected exactly one execve, saw ${_n}:\n${_lines}")
    endif()
    message(STATUS "NoJvmCheck: one execve, no child process")
  endif()
  message(STATUS "NoJvmCheck: ${BINARY} ran with an empty environment")

elseif(MODE STREQUAL "symbols")
  if(NOT NM OR NOT ARCHIVE OR NOT PATTERN)
    message(FATAL_ERROR "NoJvmCheck: NM, ARCHIVE and PATTERN are required")
  endif()
  execute_process(COMMAND "${NM}" -C --defined-only "${ARCHIVE}"
    OUTPUT_VARIABLE _out ERROR_VARIABLE _err RESULT_VARIABLE _rc)
  if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "NoJvmCheck: nm failed: ${_err}")
  endif()
  string(REGEX MATCHALL "[^\n]*(${PATTERN})[^\n]*" _hits "${_out}")
  if(_hits)
    list(LENGTH _hits _n)
    string(REPLACE ";" "\n" _hits "${_hits}")
    message(FATAL_ERROR "NoJvmCheck: ${_n} symbol(s) matching ${PATTERN} in ${ARCHIVE}:\n${_hits}")
  endif()
  message(STATUS "NoJvmCheck: no symbol matching ${PATTERN} in ${ARCHIVE}")

else()
  message(FATAL_ERROR "NoJvmCheck: unknown MODE ${MODE}")
endif()
