/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
//===-- ScriptInterpreterJava.cpp ------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "ScriptInterpreterJava.h"
#include "Java.h"
#include "lldb/Breakpoint/StoppointCallbackContext.h"
#include "lldb/Core/Debugger.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Core/StreamFile.h"
#include "lldb/Interpreter/CommandReturnObject.h"
#include "lldb/Target/ExecutionContext.h"
#include "lldb/Utility/Stream.h"
#include "lldb/Utility/StringList.h"
#include "lldb/Utility/Timer.h"
#include "llvm/Support/FormatAdapters.h"
#include <memory>

using namespace lldb;
using namespace lldb_private;

LLDB_PLUGIN_DEFINE(ScriptInterpreterJava)

class IOHandlerJavaInterpreter : public IOHandlerDelegate,
                                public IOHandlerEditline {
public:
  IOHandlerJavaInterpreter(Debugger &debugger,
                          ScriptInterpreterJava &script_interpreter)
      : IOHandlerEditline(debugger, IOHandler::Type::JavaInterpreter, "java",
                          ">>> ", "..> ", true, debugger.GetUseColor(), 0,
                          *this, nullptr),
        m_script_interpreter(script_interpreter) {
    llvm::cantFail(m_script_interpreter.GetJava().ChangeIO(
        debugger.GetOutputFile().GetStream(),
        debugger.GetErrorFile().GetStream()));
    llvm::cantFail(m_script_interpreter.EnterSession(debugger.GetID()));
  }

  ~IOHandlerJavaInterpreter() override {
    llvm::cantFail(m_script_interpreter.LeaveSession());
  }

  void IOHandlerInputComplete(IOHandler &io_handler,
                              std::string &data) override {
    if (llvm::StringRef(data).rtrim() == "quit") {
      io_handler.SetIsDone(true);
      return;
    }

    if (llvm::Error error = m_script_interpreter.GetJava().Run(data)) {
      *GetOutputStreamFileSP() << llvm::toString(std::move(error));
    }
  }

private:
  ScriptInterpreterJava &m_script_interpreter;
};

ScriptInterpreterJava::ScriptInterpreterJava(Debugger &debugger)
    : ScriptInterpreter(debugger, eScriptLanguageJava),
      m_java(std::make_unique<Java>()) {}

ScriptInterpreterJava::~ScriptInterpreterJava() {}

bool ScriptInterpreterJava::ExecuteOneLine(llvm::StringRef command,
                                          CommandReturnObject *result,
                                          const ExecuteScriptOptions &options) {
  if (command.empty()) {
    if (result)
      result->AppendError("empty command passed to java\n");
    return false;
  }

  llvm::Expected<std::unique_ptr<ScriptInterpreterIORedirect>>
      io_redirect_or_error = ScriptInterpreterIORedirect::Create(
          options.GetEnableIO(), m_debugger, result);
  if (!io_redirect_or_error) {
    if (result)
      result->AppendErrorWithFormatv(
          "failed to redirect I/O: {0}\n",
          llvm::fmt_consume(io_redirect_or_error.takeError()));
    else
      llvm::consumeError(io_redirect_or_error.takeError());
    return false;
  }

  ScriptInterpreterIORedirect &io_redirect = **io_redirect_or_error;

  if (llvm::Error e =
          m_java->ChangeIO(io_redirect.GetOutputFile()->GetStream(),
                          io_redirect.GetErrorFile()->GetStream())) {
    result->AppendErrorWithFormatv("java failed to redirect I/O: {0}\n",
                                   llvm::toString(std::move(e)));
    return false;
  }

  if (llvm::Error e = m_java->Run(command)) {
    result->AppendErrorWithFormatv(
        "java failed attempting to evaluate '{0}': {1}\n", command,
        llvm::toString(std::move(e)));
    return false;
  }

  io_redirect.Flush();
  return true;
}

void ScriptInterpreterJava::ExecuteInterpreterLoop() {
  static Timer::Category func_cat(LLVM_PRETTY_FUNCTION);
  Timer scoped_timer(func_cat, LLVM_PRETTY_FUNCTION);

  // At the moment, the only time the debugger does not have an input file
  // handle is when this is called directly from java, in which case it is
  // both dangerous and unnecessary (not to mention confusing) to try to embed
  // a running interpreter loop inside the already running java interpreter
  // loop, so we won't do it.
  if (!m_debugger.GetInputFile().IsValid())
    return;

  IOHandlerSP io_handler_sp(new IOHandlerJavaInterpreter(m_debugger, *this));
  m_debugger.RunIOHandlerAsync(io_handler_sp);
}

bool ScriptInterpreterJava::LoadScriptingModule(
    const char *filename, bool init_session, lldb_private::Status &error,
    StructuredData::ObjectSP *module_sp, FileSpec extra_search_dir) {

  FileSystem::Instance().Collect(filename);
  if (llvm::Error e = m_java->LoadModule(filename)) {
    error.SetErrorStringWithFormatv("java failed to import '{0}': {1}\n",
                                    filename, llvm::toString(std::move(e)));
    return false;
  }
  return true;
}

void ScriptInterpreterJava::Initialize() {
  static llvm::once_flag g_once_flag;

  llvm::call_once(g_once_flag, []() {
    PluginManager::RegisterPlugin(GetPluginNameStatic(),
                                  GetPluginDescriptionStatic(),
                                  lldb::eScriptLanguageJava, CreateInstance);
  });
}

void ScriptInterpreterJava::Terminate() {}

llvm::Error ScriptInterpreterJava::EnterSession(user_id_t debugger_id) {
  if (m_session_is_active)
    return llvm::Error::success();

  const char *fmt_str =
      "lldb.debugger = lldb.SBDebugger.FindDebuggerWithID({0}); "
      "lldb.target = lldb.debugger:GetSelectedTarget(); "
      "lldb.process = lldb.target:GetProcess(); "
      "lldb.thread = lldb.process:GetSelectedThread(); "
      "lldb.frame = lldb.thread:GetSelectedFrame()";
  return m_java->Run(llvm::formatv(fmt_str, debugger_id).str());
}

llvm::Error ScriptInterpreterJava::LeaveSession() {
  if (!m_session_is_active)
    return llvm::Error::success();

  m_session_is_active = false;

  llvm::StringRef str = "lldb.debugger = nil; "
                        "lldb.target = nil; "
                        "lldb.process = nil; "
                        "lldb.thread = nil; "
                        "lldb.frame = nil";
  return m_java->Run(str);
}

bool ScriptInterpreterJava::BreakpointCallbackFunction(
    void *baton, StoppointCallbackContext *context, user_id_t break_id,
    user_id_t break_loc_id) {
  assert(context);

  ExecutionContext exe_ctx(context->exe_ctx_ref);
  Target *target = exe_ctx.GetTargetPtr();
  if (target == nullptr)
    return true;

  StackFrameSP stop_frame_sp(exe_ctx.GetFrameSP());
  BreakpointSP breakpoint_sp = target->GetBreakpointByID(break_id);
  BreakpointLocationSP bp_loc_sp(breakpoint_sp->FindLocationByID(break_loc_id));

  Debugger &debugger = target->GetDebugger();
  ScriptInterpreterJava *java_interpreter = static_cast<ScriptInterpreterJava *>(
      debugger.GetScriptInterpreter(true, eScriptLanguageJava));
  Java &java = java_interpreter->GetJava();

  llvm::Expected<bool> BoolOrErr =
      java.CallBreakpointCallback(baton, stop_frame_sp, bp_loc_sp);
  if (llvm::Error E = BoolOrErr.takeError()) {
    debugger.GetErrorStream() << toString(std::move(E));
    return true;
  }

  return *BoolOrErr;
}

Status ScriptInterpreterJava::SetBreakpointCommandCallback(
    BreakpointOptions *bp_options, const char *command_body_text) {
  Status error;
  auto data_up = std::make_unique<CommandDataJava>();
  error = m_java->RegisterBreakpointCallback(data_up.get(), command_body_text);
  if (error.Fail())
    return error;
  auto baton_sp =
      std::make_shared<BreakpointOptions::CommandBaton>(std::move(data_up));
  bp_options->SetCallback(ScriptInterpreterJava::BreakpointCallbackFunction,
                          baton_sp);
  return error;
}

lldb::ScriptInterpreterSP
ScriptInterpreterJava::CreateInstance(Debugger &debugger) {
  return std::make_shared<ScriptInterpreterJava>(debugger);
}

lldb_private::ConstString ScriptInterpreterJava::GetPluginNameStatic() {
  static ConstString g_name("script-java");
  return g_name;
}

const char *ScriptInterpreterJava::GetPluginDescriptionStatic() {
  return "Java script interpreter";
}

lldb_private::ConstString ScriptInterpreterJava::GetPluginName() {
  return GetPluginNameStatic();
}

uint32_t ScriptInterpreterJava::GetPluginVersion() { return 1; }

Java &ScriptInterpreterJava::GetJava() { return *m_java; }
