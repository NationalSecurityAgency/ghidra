/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
find_package(Lua REQUIRED)

add_lldb_library(lldbPluginScriptInterpreterJava PLUGIN
  Java.cpp
  ScriptInterpreterJava.cpp

  LINK_LIBS
    lldbCore
    lldbInterpreter
  )

target_include_directories(lldbPluginScriptInterpreterJava PUBLIC ${JAVA_INCLUDE_DIR})
target_link_libraries(lldbPluginScriptInterpreterJava INTERFACE ${JAVA_LIBRARIES})
