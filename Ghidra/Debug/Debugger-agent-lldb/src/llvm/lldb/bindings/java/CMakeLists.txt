/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/LLDBWrapJava.cpp
  DEPENDS ${SWIG_SOURCES}
  DEPENDS ${SWIG_INTERFACES}
  DEPENDS ${SWIG_HEADERS}
  COMMAND ${SWIG_EXECUTABLE}
      ${SWIG_COMMON_FLAGS}
      -I${CMAKE_CURRENT_SOURCE_DIR}
      -java
      -package SWIG
      -c++
      -outdir ${CMAKE_CURRENT_BINARY_DIR}
      -o ${CMAKE_CURRENT_BINARY_DIR}/LLDBWrapJava.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/java.swig
  VERBATIM
  COMMENT "Building LLDB Java wrapper")

add_custom_target(swig_wrapper_java ALL DEPENDS
  ${CMAKE_CURRENT_BINARY_DIR}/LLDBWrapJava.cpp
)
