# ghidra_sleigh_compile_specs: compile processor specifications into a
# "sleigh home" directory tree.
#
#   ghidra_sleigh_compile_specs(
#     TARGET <name>                 custom target that builds every .sla
#     PROCESSORS <p1;p2;...>        directory names under PROCESSORS_ROOT
#     OUTPUT_DIR <dir>              root of the generated tree
#     [PROCESSORS_ROOT <dir>]       default: Ghidra/Processors of this checkout
#     [COMPILER <target-or-path>]   default: sleigh_compiler target
#     [OUT_VAR <var>]               receives the list of generated .sla files
#   )
#
# Layout produced, which SleighArchitecture::scanForSleighDirectories walks:
#
#   <OUTPUT_DIR>/Ghidra/Processors/<P>/data/languages/<spec>.sla
#   <OUTPUT_DIR>/Ghidra/Processors/<P>/data/languages/<support files>
#
# Only .slaspec files that some .ldefs in the same directory names in a
# slafile="..." attribute are compiled.  Support files are every regular file
# in data/languages that is not .slaspec, .sinc or .sla (that is: .ldefs,
# .pspec, .cspec, .opinion, .dwarf, .gdis, .register.info, ...).
#
# Per-processor compiler options come from sleighCompileOptions in
# <PROCESSORS_ROOT>/<P>/build.gradle, the same source the Gradle build uses.
#
# Each .slaspec is compiled in single-file mode with an explicit output path,
# so @include resolves against the source tree and the source tree stays
# clean.  Compilation runs in the Ninja job pool named `sleigh_specs`
# (property JOB_POOLS on the global scope); set it before calling this
# function to bound parallelism.  x86-64 and AARCH64 each take minutes and
# more than 1 GB of memory.

function(ghidra_sleigh_compile_specs)
  set(_opts)
  set(_one TARGET OUTPUT_DIR PROCESSORS_ROOT COMPILER OUT_VAR)
  set(_multi PROCESSORS)
  cmake_parse_arguments(ARG "${_opts}" "${_one}" "${_multi}" ${ARGN})

  if(NOT ARG_TARGET)
    message(FATAL_ERROR "ghidra_sleigh_compile_specs: TARGET is required")
  endif()
  if(NOT ARG_OUTPUT_DIR)
    message(FATAL_ERROR "ghidra_sleigh_compile_specs: OUTPUT_DIR is required")
  endif()
  if(NOT ARG_PROCESSORS_ROOT)
    get_filename_component(ARG_PROCESSORS_ROOT
      "${CMAKE_CURRENT_LIST_DIR}/../../../../../Processors" ABSOLUTE)
  endif()
  if(NOT ARG_COMPILER)
    set(ARG_COMPILER sleigh_compiler)
  endif()
  if(TARGET "${ARG_COMPILER}")
    set(_compiler_cmd "$<TARGET_FILE:${ARG_COMPILER}>")
    set(_compiler_dep "${ARG_COMPILER}")
  else()
    set(_compiler_cmd "${ARG_COMPILER}")
    set(_compiler_dep "")
  endif()

  get_property(_pools GLOBAL PROPERTY JOB_POOLS)
  set(_pool_arg)
  if(_pools MATCHES "(^|;)sleigh_specs=")
    set(_pool_arg JOB_POOL sleigh_specs)
  endif()

  set(_all_sla)
  set(_all_stamps)
  foreach(_proc IN LISTS ARG_PROCESSORS)
    set(_langdir "${ARG_PROCESSORS_ROOT}/${_proc}/data/languages")
    if(NOT IS_DIRECTORY "${_langdir}")
      message(FATAL_ERROR "ghidra_sleigh_compile_specs: no such processor directory: ${_langdir}")
    endif()
    set(_outdir "${ARG_OUTPUT_DIR}/Ghidra/Processors/${_proc}/data/languages")

    # Options from build.gradle: sleighCompileOptions = [ '-l', "-t" ]
    set(_options)
    set(_gradle "${ARG_PROCESSORS_ROOT}/${_proc}/build.gradle")
    if(EXISTS "${_gradle}")
      file(READ "${_gradle}" _gradle_text)
      string(REGEX MATCH "sleighCompileOptions[ \t]*=[ \t]*\\[([^]]*)\\]" _m "${_gradle_text}")
      if(_m)
        string(REGEX MATCHALL "[\"']([^\"']*)[\"']" _quoted "${CMAKE_MATCH_1}")
        foreach(_q IN LISTS _quoted)
          string(REGEX REPLACE "^[\"']|[\"']$" "" _q "${_q}")
          list(APPEND _options "${_q}")
        endforeach()
      endif()
    endif()

    # Which .sla files do the .ldefs ask for?
    file(GLOB _ldefs "${_langdir}/*.ldefs")
    set(_wanted_sla)
    foreach(_ld IN LISTS _ldefs)
      file(READ "${_ld}" _ld_text)
      string(REGEX MATCHALL "slafile=\"[^\"]*\"" _refs "${_ld_text}")
      foreach(_r IN LISTS _refs)
        string(REGEX REPLACE "^slafile=\"|\"$" "" _r "${_r}")
        list(APPEND _wanted_sla "${_r}")
      endforeach()
    endforeach()
    list(REMOVE_DUPLICATES _wanted_sla)

    file(GLOB _slaspecs "${_langdir}/*.slaspec")
    file(GLOB _sincs "${_langdir}/*.sinc")
    set(_proc_sla)
    foreach(_spec IN LISTS _slaspecs)
      get_filename_component(_name "${_spec}" NAME_WE)
      if(NOT "${_name}.sla" IN_LIST _wanted_sla)
        message(STATUS "sleigh specs: ${_proc}/${_name}.slaspec is not referenced by an .ldefs, skipped")
        continue()
      endif()
      set(_out "${_outdir}/${_name}.sla")
      add_custom_command(
        OUTPUT "${_out}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${_outdir}"
        COMMAND "${_compiler_cmd}" ${_options} "${_spec}" "${_out}"
        DEPENDS "${_spec}" ${_sincs} ${_compiler_dep}
        COMMENT "sleigh ${_proc}/${_name}.slaspec"
        ${_pool_arg}
        VERBATIM
      )
      list(APPEND _proc_sla "${_out}")
    endforeach()
    if(NOT _proc_sla)
      message(FATAL_ERROR "ghidra_sleigh_compile_specs: ${_proc}: no .slaspec is referenced by an .ldefs")
    endif()
    list(APPEND _all_sla ${_proc_sla})

    # Support files next to the .sla files.
    file(GLOB _support LIST_DIRECTORIES false "${_langdir}/*")
    list(FILTER _support EXCLUDE REGEX "\\.(slaspec|sinc|sla)$")
    set(_stamp "${_outdir}/.support-files.stamp")
    add_custom_command(
      OUTPUT "${_stamp}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${_outdir}"
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different ${_support} "${_outdir}"
      COMMAND "${CMAKE_COMMAND}" -E touch "${_stamp}"
      DEPENDS ${_support}
      COMMENT "sleigh specs: copy ${_proc} support files"
      VERBATIM
    )
    list(APPEND _all_stamps "${_stamp}")
    list(LENGTH _proc_sla _n)
    string(REPLACE ";" " " _opt_str "${_options}")
    message(STATUS "sleigh specs: ${_proc}: ${_n} spec(s), options: ${_opt_str}")
  endforeach()

  add_custom_target(${ARG_TARGET} ALL DEPENDS ${_all_sla} ${_all_stamps})
  set_property(TARGET ${ARG_TARGET} PROPERTY GHIDRA_SLEIGH_HOME "${ARG_OUTPUT_DIR}")
  if(ARG_OUT_VAR)
    set(${ARG_OUT_VAR} "${_all_sla}" PARENT_SCOPE)
  endif()
endfunction()
