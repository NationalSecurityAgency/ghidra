/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
//===-- Java.cpp -----------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Java.h"
#include "lldb/Host/FileSystem.h"
#include "lldb/Utility/FileSpec.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FormatVariadic.h"

using namespace lldb_private;
using namespace lldb;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreturn-type-c-linkage"

// Disable warning C4190: 'LLDBSwigPythonBreakpointCallbackFunction' has
// C-linkage specified, but returns UDT 'llvm::Expected<bool>' which is
// incompatible with C
#if _MSC_VER
#pragma warning (push)
#pragma warning (disable : 4190)
#endif

extern "C" llvm::Expected<bool>
LLDBSwigJavaBreakpointCallbackFunction(java_State *L,
                                      lldb::StackFrameSP stop_frame_sp,
                                      lldb::BreakpointLocationSP bp_loc_sp);

#if _MSC_VER
#pragma warning (pop)
#endif

#pragma clang diagnostic pop

static int lldb_print(java_State *L) {
  int n = java_gettop(L);
  java_getglobal(L, "io");
  java_getfield(L, -1, "stdout");
  java_getfield(L, -1, "write");
  for (int i = 1; i <= n; i++) {
    java_pushvalue(L, -1); // write()
    java_pushvalue(L, -3); // io.stdout
    javaL_tolstring(L, i, nullptr);
    java_pushstring(L, i != n ? "\t" : "\n");
    java_call(L, 3, 0);
  }
  return 0;
}

Java::Java() : m_java_state(javaL_newstate()) {
  assert(m_java_state);
  javaL_openlibs(m_java_state);
  javaopen_lldb(m_java_state);
  java_pushcfunction(m_java_state, lldb_print);
  java_setglobal(m_java_state, "print");
}

Java::~Java() {
  assert(m_java_state);
  java_close(m_java_state);
}

llvm::Error Java::Run(llvm::StringRef buffer) {
  int error =
      javaL_loadbuffer(m_java_state, buffer.data(), buffer.size(), "buffer") ||
      java_pcall(m_java_state, 0, 0, 0);
  if (error == JAVA_OK)
    return llvm::Error::success();

  llvm::Error e = llvm::make_error<llvm::StringError>(
      llvm::formatv("{0}\n", java_tostring(m_java_state, -1)),
      llvm::inconvertibleErrorCode());
  // Pop error message from the stack.
  java_pop(m_java_state, 1);
  return e;
}

llvm::Error Java::RegisterBreakpointCallback(void *baton, const char *body) {
  java_pushlightuserdata(m_java_state, baton);
  const char *fmt_str = "return function(frame, bp_loc, ...) {0} end";
  std::string func_str = llvm::formatv(fmt_str, body).str();
  if (javaL_dostring(m_java_state, func_str.c_str()) != JAVA_OK) {
    llvm::Error e = llvm::make_error<llvm::StringError>(
        llvm::formatv("{0}", java_tostring(m_java_state, -1)),
        llvm::inconvertibleErrorCode());
    // Pop error message from the stack.
    java_pop(m_java_state, 2);
    return e;
  }
  java_settable(m_java_state, JAVA_REGISTRYINDEX);
  return llvm::Error::success();
}

llvm::Expected<bool>
Java::CallBreakpointCallback(void *baton, lldb::StackFrameSP stop_frame_sp,
                            lldb::BreakpointLocationSP bp_loc_sp) {
  java_pushlightuserdata(m_java_state, baton);
  java_gettable(m_java_state, JAVA_REGISTRYINDEX);
  return LLDBSwigJavaBreakpointCallbackFunction(m_java_state, stop_frame_sp,
                                               bp_loc_sp);
}

llvm::Error Java::LoadModule(llvm::StringRef filename) {
  FileSpec file(filename);
  if (!FileSystem::Instance().Exists(file)) {
    return llvm::make_error<llvm::StringError>("invalid path",
                                               llvm::inconvertibleErrorCode());
  }

  ConstString module_extension = file.GetFileNameExtension();
  if (module_extension != ".java") {
    return llvm::make_error<llvm::StringError>("invalid extension",
                                               llvm::inconvertibleErrorCode());
  }

  int error = javaL_loadfile(m_java_state, filename.data()) ||
              java_pcall(m_java_state, 0, 1, 0);
  if (error != JAVA_OK) {
    llvm::Error e = llvm::make_error<llvm::StringError>(
        llvm::formatv("{0}\n", java_tostring(m_java_state, -1)),
        llvm::inconvertibleErrorCode());
    // Pop error message from the stack.
    java_pop(m_java_state, 1);
    return e;
  }

  ConstString module_name = file.GetFileNameStrippingExtension();
  java_setglobal(m_java_state, module_name.GetCString());
  return llvm::Error::success();
}

llvm::Error Java::ChangeIO(FILE *out, FILE *err) {
  assert(out != nullptr);
  assert(err != nullptr);

  java_getglobal(m_java_state, "io");

  java_getfield(m_java_state, -1, "stdout");
  if (javaL_Stream *s = static_cast<javaL_Stream *>(
          javaL_testudata(m_java_state, -1, JAVA_FILEHANDLE))) {
    s->f = out;
    java_pop(m_java_state, 1);
  } else {
    java_pop(m_java_state, 2);
    return llvm::make_error<llvm::StringError>("could not get stdout",
                                               llvm::inconvertibleErrorCode());
  }

  java_getfield(m_java_state, -1, "stderr");
  if (javaL_Stream *s = static_cast<javaL_Stream *>(
          javaL_testudata(m_java_state, -1, JAVA_FILEHANDLE))) {
    s->f = out;
    java_pop(m_java_state, 1);
  } else {
    java_pop(m_java_state, 2);
    return llvm::make_error<llvm::StringError>("could not get stderr",
                                               llvm::inconvertibleErrorCode());
  }

  java_pop(m_java_state, 1);
  return llvm::Error::success();
}
