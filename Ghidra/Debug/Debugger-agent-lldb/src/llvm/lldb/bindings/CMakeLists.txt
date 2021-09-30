/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
file(GLOB SWIG_INTERFACES interface/*.i)
file(GLOB_RECURSE SWIG_SOURCES *.swig)
file(GLOB SWIG_HEADERS
  ${LLDB_SOURCE_DIR}/include/lldb/API/*.h
  ${LLDB_SOURCE_DIR}/include/lldb/*.h
)
file(GLOB SWIG_PRIVATE_HEADERS
  ${LLDB_SOURCE_DIR}/include/lldb/lldb-private*.h
)
foreach(private_header ${SWIG_PRIVATE_HEADERS})
  list(REMOVE_ITEM SWIG_HEADERS ${private_header})
endforeach()

if(LLDB_BUILD_FRAMEWORK)
  set(framework_arg --framework --target-platform Darwin)
endif()

if(APPLE)
  set(DARWIN_EXTRAS "-D__APPLE__")
else()
  set(DARWIN_EXTRAS "")
endif()

set(SWIG_COMMON_FLAGS
  -c++
  -features autodoc
  -I${LLDB_SOURCE_DIR}/include
  -I${CMAKE_CURRENT_SOURCE_DIR}
  -D__STDC_LIMIT_MACROS
  -D__STDC_CONSTANT_MACROS
  ${DARWIN_EXTRAS}
)

if (LLDB_ENABLE_PYTHON)
  add_subdirectory(python)
endif()

if (LLDB_ENABLE_LUA)
  add_subdirectory(lua)
endif()

if (LLDB_ENABLE_JAVA)
  add_subdirectory(java)
endif()

