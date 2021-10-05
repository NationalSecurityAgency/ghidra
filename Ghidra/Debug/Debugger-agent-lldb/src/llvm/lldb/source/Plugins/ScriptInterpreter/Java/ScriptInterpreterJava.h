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

#ifndef liblldb_ScriptInterpreterJava_h_
#define liblldb_ScriptInterpreterJava_h_

#include "lldb/Interpreter/ScriptInterpreter.h"
#include "lldb/Utility/Status.h"
#include "lldb/lldb-enumerations.h"

namespace lldb_private {
class Java;
class ScriptInterpreterJava : public ScriptInterpreter {
public:
  class CommandDataJava : public BreakpointOptions::CommandData {
  public:
    CommandDataJava() : BreakpointOptions::CommandData() {
      interpreter = lldb::eScriptLanguageJava;
    }
  };

  ScriptInterpreterJava(Debugger &debugger);

  ~ScriptInterpreterJava() override;

  bool ExecuteOneLine(
      llvm::StringRef command, CommandReturnObject *result,
      const ExecuteScriptOptions &options = ExecuteScriptOptions()) override;

  void ExecuteInterpreterLoop() override;

  bool LoadScriptingModule(const char *filename, bool init_session,
                           lldb_private::Status &error,
                           StructuredData::ObjectSP *module_sp = nullptr,
                           FileSpec extra_search_dir = {}) override;

  // Static Functions
  static void Initialize();

  static void Terminate();

  static lldb::ScriptInterpreterSP CreateInstance(Debugger &debugger);

  static lldb_private::ConstString GetPluginNameStatic();

  static const char *GetPluginDescriptionStatic();

  static bool BreakpointCallbackFunction(void *baton,
                                         StoppointCallbackContext *context,
                                         lldb::user_id_t break_id,
                                         lldb::user_id_t break_loc_id);

  // PluginInterface protocol
  lldb_private::ConstString GetPluginName() override;

  uint32_t GetPluginVersion() override;

  Java &GetJava();

  llvm::Error EnterSession(lldb::user_id_t debugger_id);
  llvm::Error LeaveSession();

  Status SetBreakpointCommandCallback(BreakpointOptions *bp_options,
                                      const char *command_body_text) override;

private:
  std::unique_ptr<Java> m_java;
  bool m_session_is_active = false;
};

} // namespace lldb_private

#endif // liblldb_ScriptInterpreterJava_h_
