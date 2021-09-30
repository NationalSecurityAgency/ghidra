/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
//===-- ScriptInterpreterJava.h ----------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_Java_h_
#define liblldb_Java_h_

#include "lldb/API/SBBreakpointLocation.h"
#include "lldb/API/SBFrame.h"
#include "lldb/lldb-types.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Error.h"

//#include "java.hpp"

#include <mutex>

namespace lldb_private {

extern "C" {
int javaopen_lldb(java_State *L);
}

class Java {
public:
  Java();
  ~Java();

  llvm::Error Run(llvm::StringRef buffer);
  llvm::Error RegisterBreakpointCallback(void *baton, const char *body);
  llvm::Expected<bool>
  CallBreakpointCallback(void *baton, lldb::StackFrameSP stop_frame_sp,
                         lldb::BreakpointLocationSP bp_loc_sp);
  llvm::Error LoadModule(llvm::StringRef filename);
  llvm::Error ChangeIO(FILE *out, FILE *err);

private:
  java_State *m_java_state;
};

} // namespace lldb_private

#endif // liblldb_Java_h_
