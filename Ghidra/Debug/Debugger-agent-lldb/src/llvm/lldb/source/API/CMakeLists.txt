/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
if ( CMAKE_SYSTEM_NAME MATCHES "Windows" )
  add_definitions( -DEXPORT_LIBLLDB )
endif()

get_property(LLDB_ALL_PLUGINS GLOBAL PROPERTY LLDB_PLUGINS)

if(LLDB_BUILD_FRAMEWORK)
  set(option_install_prefix INSTALL_PREFIX ${LLDB_FRAMEWORK_INSTALL_DIR})
  set(option_framework FRAMEWORK)
endif()

if(LLDB_ENABLE_PYTHON)
  get_target_property(python_bindings_dir swig_wrapper_python BINARY_DIR)
  set(lldb_python_wrapper ${python_bindings_dir}/LLDBWrapPython.cpp)
endif()

if(LLDB_ENABLE_LUA)
  get_target_property(lua_bindings_dir swig_wrapper_lua BINARY_DIR)
  set(lldb_lua_wrapper ${lua_bindings_dir}/LLDBWrapLua.cpp)
endif()

if(LLDB_ENABLE_JAVA)
  get_target_property(java_bindings_dir swig_wrapper_java BINARY_DIR)
  set(lldb_java_wrapper ${java_bindings_dir}/LLDBWrapJava.cpp)
endif()

add_lldb_library(liblldb SHARED ${option_framework}
  SBAddress.cpp
  SBAttachInfo.cpp
  SBBlock.cpp
  SBBreakpoint.cpp
  SBBreakpointLocation.cpp
  SBBreakpointName.cpp
  SBBreakpointOptionCommon.cpp
  SBBroadcaster.cpp
  SBCommandInterpreter.cpp
  SBCommandInterpreterRunOptions.cpp
  SBCommandReturnObject.cpp
  SBCommunication.cpp
  SBCompileUnit.cpp
  SBData.cpp
  SBDebugger.cpp
  SBDeclaration.cpp
  SBEnvironment.cpp
  SBError.cpp
  SBEvent.cpp
  SBExecutionContext.cpp
  SBExpressionOptions.cpp
  SBFileSpec.cpp
  SBFile.cpp
  SBFileSpecList.cpp
  SBFrame.cpp
  SBFunction.cpp
  SBHostOS.cpp
  SBInstruction.cpp
  SBInstructionList.cpp
  SBLanguageRuntime.cpp
  SBLaunchInfo.cpp
  SBLineEntry.cpp
  SBListener.cpp
  SBMemoryRegionInfo.cpp
  SBMemoryRegionInfoList.cpp
  SBModule.cpp
  SBModuleSpec.cpp
  SBPlatform.cpp
  SBProcess.cpp
  SBProcessInfo.cpp
  SBQueue.cpp
  SBQueueItem.cpp
  SBReproducer.cpp
  SBSection.cpp
  SBSourceManager.cpp
  SBStream.cpp
  SBStringList.cpp
  SBStructuredData.cpp
  SBSymbol.cpp
  SBSymbolContext.cpp
  SBSymbolContextList.cpp
  SBTarget.cpp
  SBThread.cpp
  SBThreadCollection.cpp
  SBThreadPlan.cpp
  SBTrace.cpp
  SBTraceOptions.cpp
  SBType.cpp
  SBTypeCategory.cpp
  SBTypeEnumMember.cpp
  SBTypeFilter.cpp
  SBTypeFormat.cpp
  SBTypeNameSpecifier.cpp
  SBTypeSummary.cpp
  SBTypeSynthetic.cpp
  SBValue.cpp
  SBValueList.cpp
  SBVariablesOptions.cpp
  SBWatchpoint.cpp
  SBUnixSignals.cpp
  SystemInitializerFull.cpp
  ${lldb_python_wrapper}
  ${lldb_lua_wrapper}
  ${lldb_java_wrapper}

  LINK_LIBS
    lldbBase
    lldbBreakpoint
    lldbCore
    lldbDataFormatters
    lldbExpression
    lldbHost
    lldbInitialization
    lldbInterpreter
    lldbSymbol
    lldbTarget
    lldbUtility
    ${LLDB_ALL_PLUGINS}
  LINK_COMPONENTS
    Support

  ${option_install_prefix}
)

# lib/pythonX.Y/dist-packages/lldb/_lldb.so is a symlink to lib/liblldb.so,
# which depends on lib/libLLVM*.so (BUILD_SHARED_LIBS) or lib/libLLVM-10git.so
# (LLVM_LINK_LLVM_DYLIB). Add an additional rpath $ORIGIN/../../../../lib so
# that _lldb.so can be loaded from Python.
if(LLDB_ENABLE_PYTHON AND (BUILD_SHARED_LIBS OR LLVM_LINK_LLVM_DYLIB) AND UNIX AND NOT APPLE)
  set_property(TARGET liblldb APPEND PROPERTY INSTALL_RPATH "\$ORIGIN/../../../../lib${LLVM_LIBDIR_SUFFIX}")
endif()

if(Python3_RPATH)
  set_property(TARGET liblldb APPEND PROPERTY INSTALL_RPATH "${Python3_RPATH}")
  set_property(TARGET liblldb APPEND PROPERTY BUILD_RPATH   "${Python3_RPATH}")
endif()


if(LLDB_ENABLE_PYTHON)
  add_dependencies(liblldb swig_wrapper_python)

  if (MSVC)
    set_property(SOURCE ${lldb_python_wrapper} APPEND_STRING PROPERTY COMPILE_FLAGS " /W0")
  else()
    set_property(SOURCE ${lldb_python_wrapper} APPEND_STRING PROPERTY COMPILE_FLAGS " -w")
  endif()

  set_source_files_properties(${lldb_python_wrapper} PROPERTIES GENERATED ON)
  if (CLANG_CL)
    set_property(SOURCE ${lldb_python_wrapper} APPEND_STRING
      PROPERTY COMPILE_FLAGS " -Wno-unused-function")
  endif()
  if (LLVM_COMPILER_IS_GCC_COMPATIBLE AND
      NOT "${CMAKE_SYSTEM_NAME}" MATCHES "Darwin")
    set_property(SOURCE ${lldb_python_wrapper} APPEND_STRING
      PROPERTY COMPILE_FLAGS " -Wno-sequence-point -Wno-cast-qual")
  endif ()
endif()

if(LLDB_ENABLE_LUA)
  add_dependencies(liblldb swig_wrapper_lua)
  target_include_directories(liblldb PRIVATE ${LUA_INCLUDE_DIR})

  if (MSVC)
    set_property(SOURCE ${lldb_lua_wrapper} APPEND_STRING PROPERTY COMPILE_FLAGS " /W0")
  else()
    set_property(SOURCE ${lldb_lua_wrapper} APPEND_STRING PROPERTY COMPILE_FLAGS " -w")
  endif()

  set_source_files_properties(${lldb_lua_wrapper} PROPERTIES GENERATED ON)
endif()

if(LLDB_ENABLE_JAVA)
  add_dependencies(liblldb swig_wrapper_java)
  target_include_directories(liblldb PRIVATE ${JAVA_INCLUDE_DIR})
  target_include_directories(liblldb PRIVATE ${JAVA_INCLUDE_DIR}/darwin)

  if (MSVC)
    set_property(SOURCE ${lldb_java_wrapper} APPEND_STRING PROPERTY COMPILE_FLAGS " /W0")
  else()
    set_property(SOURCE ${lldb_java_wrapper} APPEND_STRING PROPERTY COMPILE_FLAGS " ")
  endif()

  set_source_files_properties(${lldb_java_wrapper} PROPERTIES GENERATED ON)
endif()


set_target_properties(liblldb
  PROPERTIES
  VERSION ${LLDB_VERSION}
)

if (NOT CMAKE_SYSTEM_NAME MATCHES "Windows")
  if (NOT LLDB_EXPORT_ALL_SYMBOLS)
    # If we're not exporting all symbols, we'll want to explicitly set
    # the exported symbols here.  This prevents 'log enable --stack ...'
    # from working on some systems but limits the liblldb size.
    MESSAGE("-- Symbols (liblldb): exporting all symbols from the lldb namespace")
    add_llvm_symbol_exports(liblldb ${CMAKE_CURRENT_SOURCE_DIR}/liblldb.exports)
  else()
    # Don't use an explicit export.  Instead, tell the linker to
    # export all symbols.
    MESSAGE("-- Symbols (liblldb): exporting all symbols from the lldb and lldb_private namespaces")
    add_llvm_symbol_exports(liblldb ${CMAKE_CURRENT_SOURCE_DIR}/liblldb-private.exports)
  endif()
  set_target_properties(liblldb_exports PROPERTIES FOLDER "lldb misc")
endif()

if (MSVC)
  # Only MSVC has the ABI compatibility problem and avoids using FindPythonLibs,
  # so only it needs to explicitly link against ${Python3_LIBRARIES}
  if (LLDB_ENABLE_PYTHON)
    target_link_libraries(liblldb PRIVATE ${Python3_LIBRARIES})
  endif()
else()
  set_target_properties(liblldb
    PROPERTIES
    OUTPUT_NAME lldb
  )
endif()

# The Clang expression parser in LLDB requires the Clang resource directory to function.
if (TARGET clang-resource-headers)
  # If building alongside Clang, just add a dependency to ensure it is build together with liblldb.
  add_dependencies(liblldb clang-resource-headers)
else()
  # In a standalone build create a symlink from the LLDB library directory that points to the
  # resource directory in the Clang library directory. LLDB searches relative to its install path,
  # and the symlink is created in the same relative path as the resource directory of Clang when
  # building alongside Clang.
  # When building the LLDB framework, this isn't necessary as there we copy everything we need into
  # the framework (including the Clang resourece directory).
  if(NOT LLDB_BUILD_FRAMEWORK)
    set(LLDB_CLANG_RESOURCE_DIR_PARENT "$<TARGET_FILE_DIR:liblldb>/clang")
    file(MAKE_DIRECTORY "${LLDB_CLANG_RESOURCE_DIR_PARENT}")
    add_custom_command(TARGET liblldb POST_BUILD
      COMMENT "Linking Clang resource dir into LLDB build directory: ${LLDB_CLANG_RESOURCE_DIR_PARENT}"
      COMMAND ${CMAKE_COMMAND} -E make_directory "${LLDB_CLANG_RESOURCE_DIR_PARENT}"
      COMMAND ${CMAKE_COMMAND} -E create_symlink "${LLDB_EXTERNAL_CLANG_RESOURCE_DIR}"
              "${LLDB_CLANG_RESOURCE_DIR_PARENT}/${LLDB_CLANG_RESOURCE_DIR_NAME}"
    )
  endif()
endif()

if(LLDB_BUILD_FRAMEWORK)
  include(LLDBFramework)
endif()
