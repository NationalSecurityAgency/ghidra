/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
//===-- SBDebugger.cpp ----------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "SBReproducerPrivate.h"
#include "SystemInitializerFull.h"

#include "lldb/API/SBDebugger.h"

#include "lldb/lldb-private.h"

#include "lldb/API/SBBroadcaster.h"
#include "lldb/API/SBCommandInterpreter.h"
#include "lldb/API/SBCommandInterpreterRunOptions.h"
#include "lldb/API/SBCommandReturnObject.h"
#include "lldb/API/SBError.h"
#include "lldb/API/SBEvent.h"
#include "lldb/API/SBFile.h"
#include "lldb/API/SBFrame.h"
#include "lldb/API/SBListener.h"
#include "lldb/API/SBProcess.h"
#include "lldb/API/SBSourceManager.h"
#include "lldb/API/SBStream.h"
#include "lldb/API/SBStringList.h"
#include "lldb/API/SBStructuredData.h"
#include "lldb/API/SBTarget.h"
#include "lldb/API/SBThread.h"
#include "lldb/API/SBTypeCategory.h"
#include "lldb/API/SBTypeFilter.h"
#include "lldb/API/SBTypeFormat.h"
#include "lldb/API/SBTypeNameSpecifier.h"
#include "lldb/API/SBTypeSummary.h"
#include "lldb/API/SBTypeSynthetic.h"

#include "lldb/Core/Debugger.h"
#include "lldb/Core/PluginManager.h"
#include "lldb/Core/Progress.h"
#include "lldb/Core/StreamFile.h"
#include "lldb/Core/StructuredDataImpl.h"
#include "lldb/DataFormatters/DataVisualization.h"
#include "lldb/Host/Config.h"
#include "lldb/Host/XML.h"
#include "lldb/Initialization/SystemLifetimeManager.h"
#include "lldb/Interpreter/CommandInterpreter.h"
#include "lldb/Interpreter/OptionArgParser.h"
#include "lldb/Interpreter/OptionGroupPlatform.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/TargetList.h"
#include "lldb/Utility/Args.h"
#include "lldb/Utility/State.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/DynamicLibrary.h"
#include "llvm/Support/ManagedStatic.h"

using namespace lldb;
using namespace lldb_private;

static llvm::sys::DynamicLibrary LoadPlugin(const lldb::DebuggerSP &debugger_sp,
                                            const FileSpec &spec,
                                            Status &error) {
  llvm::sys::DynamicLibrary dynlib =
      llvm::sys::DynamicLibrary::getPermanentLibrary(spec.GetPath().c_str());
  if (dynlib.isValid()) {
    typedef bool (*LLDBCommandPluginInit)(lldb::SBDebugger & debugger);

    lldb::SBDebugger debugger_sb(debugger_sp);
    // This calls the bool lldb::PluginInitialize(lldb::SBDebugger debugger)
    // function.
    // TODO: mangle this differently for your system - on OSX, the first
    // underscore needs to be removed and the second one stays
    LLDBCommandPluginInit init_func =
        (LLDBCommandPluginInit)(uintptr_t)dynlib.getAddressOfSymbol(
            "_ZN4lldb16PluginInitializeENS_10SBDebuggerE");
    if (init_func) {
      if (init_func(debugger_sb))
        return dynlib;
      else
        error.SetErrorString("plug-in refused to load "
                             "(lldb::PluginInitialize(lldb::SBDebugger) "
                             "returned false)");
    } else {
      error.SetErrorString("plug-in is missing the required initialization: "
                           "lldb::PluginInitialize(lldb::SBDebugger)");
    }
  } else {
    if (FileSystem::Instance().Exists(spec))
      error.SetErrorString("this file does not represent a loadable dylib");
    else
      error.SetErrorString("no such file");
  }
  return llvm::sys::DynamicLibrary();
}

static llvm::ManagedStatic<SystemLifetimeManager> g_debugger_lifetime;

SBError SBInputReader::Initialize(
    lldb::SBDebugger &sb_debugger,
    unsigned long (*callback)(void *, lldb::SBInputReader *,
                              lldb::InputReaderAction, char const *,
                              unsigned long),
    void *a, lldb::InputReaderGranularity b, char const *c, char const *d,
    bool e) {
  LLDB_RECORD_DUMMY(
      lldb::SBError, SBInputReader, Initialize,
      (lldb::SBDebugger &,
       unsigned long (*)(void *, lldb::SBInputReader *, lldb::InputReaderAction,
                         const char *, unsigned long),
       void *, lldb::InputReaderGranularity, const char *, const char *, bool),
      sb_debugger, callback, a, b, c, d, e);

  return SBError();
}

void SBInputReader::SetIsDone(bool b) {
  LLDB_RECORD_METHOD(void, SBInputReader, SetIsDone, (bool), b);
}

bool SBInputReader::IsActive() const {
  LLDB_RECORD_METHOD_CONST_NO_ARGS(bool, SBInputReader, IsActive);

  return false;
}

SBDebugger::SBDebugger() { LLDB_RECORD_CONSTRUCTOR_NO_ARGS(SBDebugger); }

SBDebugger::SBDebugger(const lldb::DebuggerSP &debugger_sp)
    : m_opaque_sp(debugger_sp) {
  LLDB_RECORD_CONSTRUCTOR(SBDebugger, (const lldb::DebuggerSP &), debugger_sp);
}

SBDebugger::SBDebugger(const SBDebugger &rhs) : m_opaque_sp(rhs.m_opaque_sp) {
  LLDB_RECORD_CONSTRUCTOR(SBDebugger, (const lldb::SBDebugger &), rhs);
}

SBDebugger::~SBDebugger() = default;

SBDebugger &SBDebugger::operator=(const SBDebugger &rhs) {
  LLDB_RECORD_METHOD(lldb::SBDebugger &,
                     SBDebugger, operator=,(const lldb::SBDebugger &), rhs);

  if (this != &rhs) {
    m_opaque_sp = rhs.m_opaque_sp;
  }
  return LLDB_RECORD_RESULT(*this);
}

const char *SBDebugger::GetBroadcasterClass() {
  LLDB_RECORD_STATIC_METHOD_NO_ARGS(const char *, SBDebugger,
                                    GetBroadcasterClass);

  return Debugger::GetStaticBroadcasterClass().AsCString();
}

const char *SBDebugger::GetProgressFromEvent(const lldb::SBEvent &event,
                                             uint64_t &progress_id,
                                             uint64_t &completed,
                                             uint64_t &total,
                                             bool &is_debugger_specific) {
  const Debugger::ProgressEventData *progress_data =
      Debugger::ProgressEventData::GetEventDataFromEvent(event.get());
  if (progress_data == nullptr)
    return nullptr;
  progress_id = progress_data->GetID();
  completed = progress_data->GetCompleted();
  total = progress_data->GetTotal();
  is_debugger_specific = progress_data->IsDebuggerSpecific();
  // We must record the static method _after_ the out parameters have been
  // filled in.
  LLDB_RECORD_STATIC_METHOD(
      const char *, SBDebugger, GetProgressFromEvent,
      (const lldb::SBEvent &, uint64_t &, uint64_t &, uint64_t &, bool &),
      event, progress_id, completed, total, is_debugger_specific);
  return LLDB_RECORD_RESULT(progress_data->GetMessage().c_str())
}

SBBroadcaster SBDebugger::GetBroadcaster() {
  LLDB_RECORD_METHOD_NO_ARGS(lldb::SBBroadcaster, SBDebugger, GetBroadcaster);
  SBBroadcaster broadcaster(&m_opaque_sp->GetBroadcaster(), false);
  return LLDB_RECORD_RESULT(broadcaster);
}

void SBDebugger::Initialize() {
  LLDB_RECORD_STATIC_METHOD_NO_ARGS(void, SBDebugger, Initialize);
  SBError ignored = SBDebugger::InitializeWithErrorHandling();
}

lldb::SBError SBDebugger::InitializeWithErrorHandling() {
  LLDB_RECORD_STATIC_METHOD_NO_ARGS(lldb::SBError, SBDebugger,
                                    InitializeWithErrorHandling);

  SBError error;
  if (auto e = g_debugger_lifetime->Initialize(
          std::make_unique<SystemInitializerFull>(), LoadPlugin)) {
    error.SetError(Status(std::move(e)));
  }
  return LLDB_RECORD_RESULT(error);
}

void SBDebugger::Terminate() {
  LLDB_RECORD_STATIC_METHOD_NO_ARGS(void, SBDebugger, Terminate);

  g_debugger_lifetime->Terminate();
}

void SBDebugger::Clear() {
  LLDB_RECORD_METHOD_NO_ARGS(void, SBDebugger, Clear);

  if (m_opaque_sp)
    m_opaque_sp->ClearIOHandlers();

  m_opaque_sp.reset();
}

SBDebugger SBDebugger::Create() {
  LLDB_RECORD_STATIC_METHOD_NO_ARGS(lldb::SBDebugger, SBDebugger, Create);

  return LLDB_RECORD_RESULT(SBDebugger::Create(false, nullptr, nullptr));
}

SBDebugger SBDebugger::Create(bool source_init_files) {
  LLDB_RECORD_STATIC_METHOD(lldb::SBDebugger, SBDebugger, Create, (bool),
                            source_init_files);

  return LLDB_RECORD_RESULT(
      SBDebugger::Create(source_init_files, nullptr, nullptr));
}

SBDebugger SBDebugger::Create(bool source_init_files,
                              lldb::LogOutputCallback callback, void *baton)

{
  LLDB_RECORD_DUMMY(lldb::SBDebugger, SBDebugger, Create,
                    (bool, lldb::LogOutputCallback, void *), source_init_files,
                    callback, baton);

  SBDebugger debugger;

  // Currently we have issues if this function is called simultaneously on two
  // different threads. The issues mainly revolve around the fact that the
  // lldb_private::FormatManager uses global collections and having two threads
  // parsing the .lldbinit files can cause mayhem. So to get around this for
  // now we need to use a mutex to prevent bad things from happening.
  static std::recursive_mutex g_mutex;
  std::lock_guard<std::recursive_mutex> guard(g_mutex);

  debugger.reset(Debugger::CreateInstance(callback, baton));

  SBCommandInterpreter interp = debugger.GetCommandInterpreter();
  if (source_init_files) {
    interp.get()->SkipLLDBInitFiles(false);
    interp.get()->SkipAppInitFiles(false);
    SBCommandReturnObject result;
    interp.SourceInitFileInHomeDirectory(result, false);
  } else {
    interp.get()->SkipLLDBInitFiles(true);
    interp.get()->SkipAppInitFiles(true);
  }
  return debugger;
}

void SBDebugger::Destroy(SBDebugger &debugger) {
  LLDB_RECORD_STATIC_METHOD(void, SBDebugger, Destroy, (lldb::SBDebugger &),
                            debugger);

  Debugger::Destroy(debugger.m_opaque_sp);

  if (debugger.m_opaque_sp.get() != nullptr)
    debugger.m_opaque_sp.reset();
}

void SBDebugger::MemoryPressureDetected() {
  LLDB_RECORD_STATIC_METHOD_NO_ARGS(void, SBDebugger, MemoryPressureDetected);

  // Since this function can be call asynchronously, we allow it to be non-
  // mandatory. We have seen deadlocks with this function when called so we
  // need to safeguard against this until we can determine what is causing the
  // deadlocks.

  const bool mandatory = false;

  ModuleList::RemoveOrphanSharedModules(mandatory);
}

bool SBDebugger::IsValid() const {
  LLDB_RECORD_METHOD_CONST_NO_ARGS(bool, SBDebugger, IsValid);
  return this->operator bool();
}
SBDebugger::operator bool() const {
  LLDB_RECORD_METHOD_CONST_NO_ARGS(bool, SBDebugger, operator bool);

  return m_opaque_sp.get() != nullptr;
}

void SBDebugger::SetAsync(bool b) {
  LLDB_RECORD_METHOD(void, SBDebugger, SetAsync, (bool), b);

  if (m_opaque_sp)
    m_opaque_sp->SetAsyncExecution(b);
}

bool SBDebugger::GetAsync() {
  LLDB_RECORD_METHOD_NO_ARGS(bool, SBDebugger, GetAsync);

  return (m_opaque_sp ? m_opaque_sp->GetAsyncExecution() : false);
}

void SBDebugger::SkipLLDBInitFiles(bool b) {
  LLDB_RECORD_METHOD(void, SBDebugger, SkipLLDBInitFiles, (bool), b);

  if (m_opaque_sp)
    m_opaque_sp->GetCommandInterpreter().SkipLLDBInitFiles(b);
}

void SBDebugger::SkipAppInitFiles(bool b) {
  LLDB_RECORD_METHOD(void, SBDebugger, SkipAppInitFiles, (bool), b);

  if (m_opaque_sp)
    m_opaque_sp->GetCommandInterpreter().SkipAppInitFiles(b);
}

void SBDebugger::SetInputFileHandle(FILE *fh, bool transfer_ownership) {
  LLDB_RECORD_METHOD(void, SBDebugger, SetInputFileHandle, (FILE *, bool), fh,
                     transfer_ownership);
  SetInputFile((FileSP)std::make_shared<NativeFile>(fh, transfer_ownership));
}

SBError SBDebugger::SetInputFile(FileSP file_sp) {
  LLDB_RECORD_METHOD(SBError, SBDebugger, SetInputFile, (FileSP), file_sp);
  return LLDB_RECORD_RESULT(SetInputFile(SBFile(file_sp)));
}

// Shouldn't really be settable after initialization as this could cause lots
// of problems; don't want users trying to switch modes in the middle of a
// debugging session.
SBError SBDebugger::SetInputFile(SBFile file) {
  LLDB_RECORD_METHOD(SBError, SBDebugger, SetInputFile, (SBFile), file);

  SBError error;
  if (!m_opaque_sp) {
    error.ref().SetErrorString("invalid debugger");
    return LLDB_RECORD_RESULT(error);
  }

  repro::DataRecorder *recorder = nullptr;
  if (repro::Generator *g = repro::Reproducer::Instance().GetGenerator())
    recorder = g->GetOrCreate<repro::CommandProvider>().GetNewRecorder();

  FileSP file_sp = file.m_opaque_sp;

  static std::unique_ptr<repro::MultiLoader<repro::CommandProvider>> loader =
      repro::MultiLoader<repro::CommandProvider>::Create(
          repro::Reproducer::Instance().GetLoader());
  if (loader) {
    llvm::Optional<std::string> nextfile = loader->GetNextFile();
    FILE *fh = nextfile ? FileSystem::Instance().Fopen(nextfile->c_str(), "r")
                        : nullptr;
    // FIXME Jonas Devlieghere: shouldn't this error be propagated out to the
    // reproducer somehow if fh is NULL?
    if (fh) {
      file_sp = std::make_shared<NativeFile>(fh, true);
    }
  }

  if (!file_sp || !file_sp->IsValid()) {
    error.ref().SetErrorString("invalid file");
    return LLDB_RECORD_RESULT(error);
  }

  m_opaque_sp->SetInputFile(file_sp, recorder);
  return LLDB_RECORD_RESULT(error);
}

SBError SBDebugger::SetOutputFile(FileSP file_sp) {
  LLDB_RECORD_METHOD(SBError, SBDebugger, SetOutputFile, (FileSP), file_sp);
  return LLDB_RECORD_RESULT(SetOutputFile(SBFile(file_sp)));
}

void SBDebugger::SetOutputFileHandle(FILE *fh, bool transfer_ownership) {
  LLDB_RECORD_METHOD(void, SBDebugger, SetOutputFileHandle, (FILE *, bool), fh,
                     transfer_ownership);
  SetOutputFile((FileSP)std::make_shared<NativeFile>(fh, transfer_ownership));
}

SBError SBDebugger::SetOutputFile(SBFile file) {
  LLDB_RECORD_METHOD(SBError, SBDebugger, SetOutputFile, (SBFile file), file);
  SBError error;
  if (!m_opaque_sp) {
    error.ref().SetErrorString("invalid debugger");
    return LLDB_RECORD_RESULT(error);
  }
  if (!file) {
    error.ref().SetErrorString("invalid file");
    return LLDB_RECORD_RESULT(error);
  }
  m_opaque_sp->SetOutputFile(file.m_opaque_sp);
  return LLDB_RECORD_RESULT(error);
}

void SBDebugger::SetErrorFileHandle(FILE *fh, bool transfer_ownership) {
  LLDB_RECORD_METHOD(void, SBDebugger, SetErrorFileHandle, (FILE *, bool), fh,
                     transfer_ownership);
  SetErrorFile((FileSP)std::make_shared<NativeFile>(fh, transfer_ownership));
}

SBError SBDebugger::SetErrorFile(FileSP file_sp) {
  LLDB_RECORD_METHOD(SBError, SBDebugger, SetErrorFile, (FileSP), file_sp);
  return LLDB_RECORD_RESULT(SetErrorFile(SBFile(file_sp)));
}

SBError SBDebugger::SetErrorFile(SBFile file) {
  LLDB_RECORD_METHOD(SBError, SBDebugger, SetErrorFile, (SBFile file), file);
  SBError error;
  if (!m_opaque_sp) {
    error.ref().SetErrorString("invalid debugger");
    return LLDB_RECORD_RESULT(error);
  }
  if (!file) {
    error.ref().SetErrorString("invalid file");
    return LLDB_RECORD_RESULT(error);
  }
  m_opaque_sp->SetErrorFile(file.m_opaque_sp);
  return LLDB_RECORD_RESULT(error);
}

FILE *SBDebugger::GetInputFileHandle() {
  LLDB_RECORD_METHOD_NO_ARGS(FILE *, SBDebugger, GetInputFileHandle);
  if (m_opaque_sp) {
    File &file_sp = m_opaque_sp->GetInputFile();
    return LLDB_RECORD_RESULT(file_sp.GetStream());
  }
  return LLDB_RECORD_RESULT(nullptr);
}

SBFile SBDebugger::GetInputFile() {
  LLDB_RECORD_METHOD_NO_ARGS(SBFile, SBDebugger, GetInputFile);
  if (m_opaque_sp) {
    return LLDB_RECORD_RESULT(SBFile(m_opaque_sp->GetInputFileSP()));
  }
  return LLDB_RECORD_RESULT(SBFile());
}

FILE *SBDebugger::GetOutputFileHandle() {
  LLDB_RECORD_METHOD_NO_ARGS(FILE *, SBDebugger, GetOutputFileHandle);
  if (m_opaque_sp) {
    StreamFile &stream_file = m_opaque_sp->GetOutputStream();
    return LLDB_RECORD_RESULT(stream_file.GetFile().GetStream());
  }
  return LLDB_RECORD_RESULT(nullptr);
}

SBFile SBDebugger::GetOutputFile() {
  LLDB_RECORD_METHOD_NO_ARGS(SBFile, SBDebugger, GetOutputFile);
  if (m_opaque_sp) {
    SBFile file(m_opaque_sp->GetOutputStream().GetFileSP());
    return LLDB_RECORD_RESULT(file);
  }
  return LLDB_RECORD_RESULT(SBFile());
}

FILE *SBDebugger::GetErrorFileHandle() {
  LLDB_RECORD_METHOD_NO_ARGS(FILE *, SBDebugger, GetErrorFileHandle);

  if (m_opaque_sp) {
    StreamFile &stream_file = m_opaque_sp->GetErrorStream();
    return LLDB_RECORD_RESULT(stream_file.GetFile().GetStream());
  }
  return LLDB_RECORD_RESULT(nullptr);
}

SBFile SBDebugger::GetErrorFile() {
  LLDB_RECORD_METHOD_NO_ARGS(SBFile, SBDebugger, GetErrorFile);
  SBFile file;
  if (m_opaque_sp) {
    SBFile file(m_opaque_sp->GetErrorStream().GetFileSP());
    return LLDB_RECORD_RESULT(file);
  }
  return LLDB_RECORD_RESULT(SBFile());
}

void SBDebugger::SaveInputTerminalState() {
  LLDB_RECORD_DUMMY_NO_ARGS(void, SBDebugger, SaveInputTerminalState);

  if (m_opaque_sp)
    m_opaque_sp->SaveInputTerminalState();
}

void SBDebugger::RestoreInputTerminalState() {
  LLDB_RECORD_DUMMY_NO_ARGS(void, SBDebugger, RestoreInputTerminalState);

  if (m_opaque_sp)
    m_opaque_sp->RestoreInputTerminalState();
}
SBCommandInterpreter SBDebugger::GetCommandInterpreter() {
  LLDB_RECORD_METHOD_NO_ARGS(lldb::SBCommandInterpreter, SBDebugger,
                             GetCommandInterpreter);

  SBCommandInterpreter sb_interpreter;
  if (m_opaque_sp)
    sb_interpreter.reset(&m_opaque_sp->GetCommandInterpreter());

  return LLDB_RECORD_RESULT(sb_interpreter);
}

void SBDebugger::HandleCommand(const char *command) {
  LLDB_RECORD_METHOD(void, SBDebugger, HandleCommand, (const char *), command);

  if (m_opaque_sp) {
    TargetSP target_sp(m_opaque_sp->GetSelectedTarget());
    std::unique_lock<std::recursive_mutex> lock;
    if (target_sp)
      lock = std::unique_lock<std::recursive_mutex>(target_sp->GetAPIMutex());

    SBCommandInterpreter sb_interpreter(GetCommandInterpreter());
    SBCommandReturnObject result;

    sb_interpreter.HandleCommand(command, result, false);

    result.PutError(m_opaque_sp->GetErrorStream().GetFileSP());
    result.PutOutput(m_opaque_sp->GetOutputStream().GetFileSP());

    if (!m_opaque_sp->GetAsyncExecution()) {
      SBProcess process(GetCommandInterpreter().GetProcess());
      ProcessSP process_sp(process.GetSP());
      if (process_sp) {
        EventSP event_sp;
        ListenerSP lldb_listener_sp = m_opaque_sp->GetListener();
        while (lldb_listener_sp->GetEventForBroadcaster(
            process_sp.get(), event_sp, std::chrono::seconds(0))) {
          SBEvent event(event_sp);
          HandleProcessEvent(process, event, GetOutputFile(), GetErrorFile());
        }
      }
    }
  }
}

SBListener SBDebugger::GetListener() {
  LLDB_RECORD_METHOD_NO_ARGS(lldb::SBListener, SBDebugger, GetListener);

  SBListener sb_listener;
  if (m_opaque_sp)
    sb_listener.reset(m_opaque_sp->GetListener());

  return LLDB_RECORD_RESULT(sb_listener);
}

void SBDebugger::HandleProcessEvent(const SBProcess &process,
                                    const SBEvent &event, SBFile out,
                                    SBFile err) {
  LLDB_RECORD_METHOD(
      void, SBDebugger, HandleProcessEvent,
      (const lldb::SBProcess &, const lldb::SBEvent &, SBFile, SBFile), process,
      event, out, err);

  return HandleProcessEvent(process, event, out.m_opaque_sp, err.m_opaque_sp);
}

void SBDebugger::HandleProcessEvent(const SBProcess &process,
                                    const SBEvent &event, FILE *out,
                                    FILE *err) {
  LLDB_RECORD_METHOD(
      void, SBDebugger, HandleProcessEvent,
      (const lldb::SBProcess &, const lldb::SBEvent &, FILE *, FILE *), process,
      event, out, err);

  FileSP outfile = std::make_shared<NativeFile>(out, false);
  FileSP errfile = std::make_shared<NativeFile>(err, false);
  return HandleProcessEvent(process, event, outfile, errfile);
}

void SBDebugger::HandleProcessEvent(const SBProcess &process,
                                    const SBEvent &event, FileSP out_sp,
                                    FileSP err_sp) {

  LLDB_RECORD_METHOD(
      void, SBDebugger, HandleProcessEvent,
      (const lldb::SBProcess &, const lldb::SBEvent &, FileSP, FileSP), process,
      event, out_sp, err_sp);

  if (!process.IsValid())
    return;

  TargetSP target_sp(process.GetTarget().GetSP());
  if (!target_sp)
    return;

  const uint32_t event_type = event.GetType();
  char stdio_buffer[1024];
  size_t len;

  std::lock_guard<std::recursive_mutex> guard(target_sp->GetAPIMutex());

  if (event_type &
      (Process::eBroadcastBitSTDOUT | Process::eBroadcastBitStateChanged)) {
    // Drain stdout when we stop just in case we have any bytes
    while ((len = process.GetSTDOUT(stdio_buffer, sizeof(stdio_buffer))) > 0)
      if (out_sp)
        out_sp->Write(stdio_buffer, len);
  }

  if (event_type &
      (Process::eBroadcastBitSTDERR | Process::eBroadcastBitStateChanged)) {
    // Drain stderr when we stop just in case we have any bytes
    while ((len = process.GetSTDERR(stdio_buffer, sizeof(stdio_buffer))) > 0)
      if (err_sp)
        err_sp->Write(stdio_buffer, len);
  }

  if (event_type & Process::eBroadcastBitStateChanged) {
    StateType event_state = SBProcess::GetStateFromEvent(event);

    if (event_state == eStateInvalid)
      return;

    bool is_stopped = StateIsStoppedState(event_state);
    if (!is_stopped)
      process.ReportEventState(event, out_sp);
  }
}

SBSourceManager SBDebugger::GetSourceManager() {
  LLDB_RECORD_METHOD_NO_ARGS(lldb::SBSourceManager, SBDebugger,
                             GetSourceManager);

  SBSourceManager sb_source_manager(*this);
  return LLDB_RECORD_RESULT(sb_source_manager);
}

bool SBDebugger::GetDefaultArchitecture(char *arch_name, size_t arch_name_len) {
  LLDB_RECORD_CHAR_PTR_STATIC_METHOD(bool, SBDebugger, GetDefaultArchitecture,
                                     (char *, size_t), arch_name, "",
                                     arch_name_len);

  if (arch_name && arch_name_len) {
    ArchSpec default_arch = Target::GetDefaultArchitecture();

    if (default_arch.IsValid()) {
      const std::string &triple_str = default_arch.GetTriple().str();
      if (!triple_str.empty())
        ::snprintf(arch_name, arch_name_len, "%s", triple_str.c_str());
      else
        ::snprintf(arch_name, arch_name_len, "%s",
                   default_arch.GetArchitectureName());
      return true;
    }
  }
  if (arch_name && arch_name_len)
    arch_name[0] = '\0';
  return false;
}

bool SBDebugger::SetDefaultArchitecture(const char *arch_name) {
  LLDB_RECORD_STATIC_METHOD(bool, SBDebugger, SetDefaultArchitecture,
                            (const char *), arch_name);

  if (arch_name) {
    ArchSpec arch(arch_name);
    if (arch.IsValid()) {
      Target::SetDefaultArchitecture(arch);
      return true;
    }
  }
  return false;
}

ScriptLanguage
SBDebugger::GetScriptingLanguage(const char *script_language_name) {
  LLDB_RECORD_METHOD(lldb::ScriptLanguage, SBDebugger, GetScriptingLanguage,
                     (const char *), script_language_name);

  if (!script_language_name)
    return eScriptLanguageDefault;
  return OptionArgParser::ToScriptLanguage(
      llvm::StringRef(script_language_name), eScriptLanguageDefault, nullptr);
}

const char *SBDebugger::GetVersionString() {
  LLDB_RECORD_STATIC_METHOD_NO_ARGS(const char *, SBDebugger, GetVersionString);

  return lldb_private::GetVersion();
}

const char *SBDebugger::StateAsCString(StateType state) {
  LLDB_RECORD_STATIC_METHOD(const char *, SBDebugger, StateAsCString,
                            (lldb::StateType), state);

  return lldb_private::StateAsCString(state);
}

static void AddBoolConfigEntry(StructuredData::Dictionary &dict,
                               llvm::StringRef name, bool value,
                               llvm::StringRef description) {
  auto entry_up = std::make_unique<StructuredData::Dictionary>();
  entry_up->AddBooleanItem("value", value);
  entry_up->AddStringItem("description", description);
  dict.AddItem(name, std::move(entry_up));
}

static void AddLLVMTargets(StructuredData::Dictionary &dict) {
  auto array_up = std::make_unique<StructuredData::Array>();
#define LLVM_TARGET(target)                                                    \
  array_up->AddItem(std::make_unique<StructuredData::String>(#target));
#include "llvm/Config/Targets.def"
  auto entry_up = std::make_unique<StructuredData::Dictionary>();
  entry_up->AddItem("value", std::move(array_up));
  entry_up->AddStringItem("description", "A list of configured LLVM targets.");
  dict.AddItem("targets", std::move(entry_up));
}

SBStructuredData SBDebugger::GetBuildConfiguration() {
  LLDB_RECORD_STATIC_METHOD_NO_ARGS(lldb::SBStructuredData, SBDebugger,
                                    GetBuildConfiguration);

  auto config_up = std::make_unique<StructuredData::Dictionary>();
  AddBoolConfigEntry(
      *config_up, "xml", XMLDocument::XMLEnabled(),
      "A boolean value that indicates if XML support is enabled in LLDB");
  AddBoolConfigEntry(
      *config_up, "curses", LLDB_ENABLE_CURSES,
      "A boolean value that indicates if curses support is enabled in LLDB");
  AddBoolConfigEntry(
      *config_up, "editline", LLDB_ENABLE_LIBEDIT,
      "A boolean value that indicates if editline support is enabled in LLDB");
  AddBoolConfigEntry(
      *config_up, "lzma", LLDB_ENABLE_LZMA,
      "A boolean value that indicates if lzma support is enabled in LLDB");
  AddBoolConfigEntry(
      *config_up, "python", LLDB_ENABLE_PYTHON,
      "A boolean value that indicates if python support is enabled in LLDB");
  AddBoolConfigEntry(
      *config_up, "lua", LLDB_ENABLE_LUA,
      "A boolean value that indicates if lua support is enabled in LLDB");
  AddBoolConfigEntry(
      *config_up, "java", LLDB_ENABLE_JAVA,
      "A boolean value that indicates if java support is enabled in LLDB");
  AddLLVMTargets(*config_up);

  SBStructuredData data;
  data.m_impl_up->SetObjectSP(std::move(config_up));
  return LLDB_RECORD_RESULT(data);
}

bool SBDebugger::StateIsRunningState(StateType state) {
  LLDB_RECORD_STATIC_METHOD(bool, SBDebugger, StateIsRunningState,
                            (lldb::StateType), state);

  const bool result = lldb_private::StateIsRunningState(state);

  return result;
}

bool SBDebugger::StateIsStoppedState(StateType state) {
  LLDB_RECORD_STATIC_METHOD(bool, SBDebugger, StateIsStoppedState,
                            (lldb::StateType), state);

  const bool result = lldb_private::StateIsStoppedState(state, false);

  return result;
}

lldb::SBTarget SBDebugger::CreateTarget(const char *filename,
                                        const char *target_triple,
                                        const char *platform_name,
                                        bool add_dependent_modules,
                                        lldb::SBError &sb_error) {
  LLDB_RECORD_METHOD(
      lldb::SBTarget, SBDebugger, CreateTarget,
      (const char *, const char *, const char *, bool, lldb::SBError &),
      filename, target_triple, platform_name, add_dependent_modules, sb_error);

  SBTarget sb_target;
  TargetSP target_sp;
  if (m_opaque_sp) {
    sb_error.Clear();
    OptionGroupPlatform platform_options(false);
    platform_options.SetPlatformName(platform_name);

    sb_error.ref() = m_opaque_sp->GetTargetList().CreateTarget(
        *m_opaque_sp, filename, target_triple,
        add_dependent_modules ? eLoadDependentsYes : eLoadDependentsNo,
        &platform_options, target_sp);

    if (sb_error.Success())
      sb_target.SetSP(target_sp);
  } else {
    sb_error.SetErrorString("invalid debugger");
  }

  Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_API));
  LLDB_LOGF(log,
            "SBDebugger(%p)::CreateTarget (filename=\"%s\", triple=%s, "
            "platform_name=%s, add_dependent_modules=%u, error=%s) => "
            "SBTarget(%p)",
            static_cast<void *>(m_opaque_sp.get()), filename, target_triple,
            platform_name, add_dependent_modules, sb_error.GetCString(),
            static_cast<void *>(target_sp.get()));

  return LLDB_RECORD_RESULT(sb_target);
}

SBTarget
SBDebugger::CreateTargetWithFileAndTargetTriple(const char *filename,
                                                const char *target_triple) {
  LLDB_RECORD_METHOD(lldb::SBTarget, SBDebugger,
                     CreateTargetWithFileAndTargetTriple,
                     (const char *, const char *), filename, target_triple);

  SBTarget sb_target;
  TargetSP target_sp;
  if (m_opaque_sp) {
    const bool add_dependent_modules = true;
    Status error(m_opaque_sp->GetTargetList().CreateTarget(
        *m_opaque_sp, filename, target_triple,
        add_dependent_modules ? eLoadDependentsYes : eLoadDependentsNo, nullptr,
        target_sp));
    sb_target.SetSP(target_sp);
  }

  Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_API));
  LLDB_LOGF(log,
            "SBDebugger(%p)::CreateTargetWithFileAndTargetTriple "
            "(filename=\"%s\", triple=%s) => SBTarget(%p)",
            static_cast<void *>(m_opaque_sp.get()), filename, target_triple,
            static_cast<void *>(target_sp.get()));

  return LLDB_RECORD_RESULT(sb_target);
}

SBTarget SBDebugger::CreateTargetWithFileAndArch(const char *filename,
                                                 const char *arch_cstr) {
  LLDB_RECORD_METHOD(lldb::SBTarget, SBDebugger, CreateTargetWithFileAndArch,
                     (const char *, const char *), filename, arch_cstr);

  Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_API));

  SBTarget sb_target;
  TargetSP target_sp;
  if (m_opaque_sp) {
    Status error;
    if (arch_cstr == nullptr) {
      // The version of CreateTarget that takes an ArchSpec won't accept an
      // empty ArchSpec, so when the arch hasn't been specified, we need to
      // call the target triple version.
      error = m_opaque_sp->GetTargetList().CreateTarget(*m_opaque_sp, filename, 
          arch_cstr, eLoadDependentsYes, nullptr, target_sp);
    } else {
      PlatformSP platform_sp = m_opaque_sp->GetPlatformList()
          .GetSelectedPlatform();
      ArchSpec arch = Platform::GetAugmentedArchSpec(platform_sp.get(), 
          arch_cstr);
      if (arch.IsValid())
        error = m_opaque_sp->GetTargetList().CreateTarget(*m_opaque_sp, filename, 
            arch, eLoadDependentsYes, platform_sp, target_sp);
      else
        error.SetErrorStringWithFormat("invalid arch_cstr: %s", arch_cstr);
    }
    if (error.Success())
      sb_target.SetSP(target_sp);
  }

  LLDB_LOGF(log,
            "SBDebugger(%p)::CreateTargetWithFileAndArch (filename=\"%s\", "
            "arch=%s) => SBTarget(%p)",
            static_cast<void *>(m_opaque_sp.get()),
            filename ? filename : "<unspecified>",
            arch_cstr ? arch_cstr : "<unspecified>",
            static_cast<void *>(target_sp.get()));

  return LLDB_RECORD_RESULT(sb_target);
}

SBTarget SBDebugger::CreateTarget(const char *filename) {
  LLDB_RECORD_METHOD(lldb::SBTarget, SBDebugger, CreateTarget, (const char *),
                     filename);

  SBTarget sb_target;
  TargetSP target_sp;
  if (m_opaque_sp) {
    Status error;
    const bool add_dependent_modules = true;
    error = m_opaque_sp->GetTargetList().CreateTarget(
        *m_opaque_sp, filename, "",
        add_dependent_modules ? eLoadDependentsYes : eLoadDependentsNo, nullptr,
        target_sp);

    if (error.Success())
      sb_target.SetSP(target_sp);
  }
  Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_API));
  LLDB_LOGF(log,
            "SBDebugger(%p)::CreateTarget (filename=\"%s\") => SBTarget(%p)",
            static_cast<void *>(m_opaque_sp.get()), filename,
            static_cast<void *>(target_sp.get()));
  return LLDB_RECORD_RESULT(sb_target);
}

SBTarget SBDebugger::GetDummyTarget() {
  LLDB_RECORD_METHOD_NO_ARGS(lldb::SBTarget, SBDebugger, GetDummyTarget);

  SBTarget sb_target;
  if (m_opaque_sp) {
    sb_target.SetSP(m_opaque_sp->GetDummyTarget().shared_from_this());
  }
  Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_API));
  LLDB_LOGF(log, "SBDebugger(%p)::GetDummyTarget() => SBTarget(%p)",
            static_cast<void *>(m_opaque_sp.get()),
            static_cast<void *>(sb_target.GetSP().get()));
  return LLDB_RECORD_RESULT(sb_target);
}

bool SBDebugger::DeleteTarget(lldb::SBTarget &target) {
  LLDB_RECORD_METHOD(bool, SBDebugger, DeleteTarget, (lldb::SBTarget &),
                     target);

  bool result = false;
  if (m_opaque_sp) {
    TargetSP target_sp(target.GetSP());
    if (target_sp) {
      // No need to lock, the target list is thread safe
      result = m_opaque_sp->GetTargetList().DeleteTarget(target_sp);
      target_sp->Destroy();
      target.Clear();
    }
  }

  Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_API));
  LLDB_LOGF(log, "SBDebugger(%p)::DeleteTarget (SBTarget(%p)) => %i",
            static_cast<void *>(m_opaque_sp.get()),
            static_cast<void *>(target.m_opaque_sp.get()), result);

  return result;
}

SBTarget SBDebugger::GetTargetAtIndex(uint32_t idx) {
  LLDB_RECORD_METHOD(lldb::SBTarget, SBDebugger, GetTargetAtIndex, (uint32_t),
                     idx);

  SBTarget sb_target;
  if (m_opaque_sp) {
    // No need to lock, the target list is thread safe
    sb_target.SetSP(m_opaque_sp->GetTargetList().GetTargetAtIndex(idx));
  }
  return LLDB_RECORD_RESULT(sb_target);
}

uint32_t SBDebugger::GetIndexOfTarget(lldb::SBTarget target) {
  LLDB_RECORD_METHOD(uint32_t, SBDebugger, GetIndexOfTarget, (lldb::SBTarget),
                     target);

  lldb::TargetSP target_sp = target.GetSP();
  if (!target_sp)
    return UINT32_MAX;

  if (!m_opaque_sp)
    return UINT32_MAX;

  return m_opaque_sp->GetTargetList().GetIndexOfTarget(target.GetSP());
}

SBTarget SBDebugger::FindTargetWithProcessID(lldb::pid_t pid) {
  LLDB_RECORD_METHOD(lldb::SBTarget, SBDebugger, FindTargetWithProcessID,
                     (lldb::pid_t), pid);

  SBTarget sb_target;
  if (m_opaque_sp) {
    // No need to lock, the target list is thread safe
    sb_target.SetSP(m_opaque_sp->GetTargetList().FindTargetWithProcessID(pid));
  }
  return LLDB_RECORD_RESULT(sb_target);
}

SBTarget SBDebugger::FindTargetWithFileAndArch(const char *filename,
                                               const char *arch_name) {
  LLDB_RECORD_METHOD(lldb::SBTarget, SBDebugger, FindTargetWithFileAndArch,
                     (const char *, const char *), filename, arch_name);

  SBTarget sb_target;
  if (m_opaque_sp && filename && filename[0]) {
    // No need to lock, the target list is thread safe
    ArchSpec arch = Platform::GetAugmentedArchSpec(
        m_opaque_sp->GetPlatformList().GetSelectedPlatform().get(), arch_name);
    TargetSP target_sp(
        m_opaque_sp->GetTargetList().FindTargetWithExecutableAndArchitecture(
            FileSpec(filename), arch_name ? &arch : nullptr));
    sb_target.SetSP(target_sp);
  }
  return LLDB_RECORD_RESULT(sb_target);
}

SBTarget SBDebugger::FindTargetWithLLDBProcess(const ProcessSP &process_sp) {
  SBTarget sb_target;
  if (m_opaque_sp) {
    // No need to lock, the target list is thread safe
    sb_target.SetSP(
        m_opaque_sp->GetTargetList().FindTargetWithProcess(process_sp.get()));
  }
  return sb_target;
}

uint32_t SBDebugger::GetNumTargets() {
  LLDB_RECORD_METHOD_NO_ARGS(uint32_t, SBDebugger, GetNumTargets);

  if (m_opaque_sp) {
    // No need to lock, the target list is thread safe
    return m_opaque_sp->GetTargetList().GetNumTargets();
  }
  return 0;
}

SBTarget SBDebugger::GetSelectedTarget() {
  LLDB_RECORD_METHOD_NO_ARGS(lldb::SBTarget, SBDebugger, GetSelectedTarget);

  Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_API));

  SBTarget sb_target;
  TargetSP target_sp;
  if (m_opaque_sp) {
    // No need to lock, the target list is thread safe
    target_sp = m_opaque_sp->GetTargetList().GetSelectedTarget();
    sb_target.SetSP(target_sp);
  }

  if (log) {
    SBStream sstr;
    sb_target.GetDescription(sstr, eDescriptionLevelBrief);
    LLDB_LOGF(log, "SBDebugger(%p)::GetSelectedTarget () => SBTarget(%p): %s",
              static_cast<void *>(m_opaque_sp.get()),
              static_cast<void *>(target_sp.get()), sstr.GetData());
  }

  return LLDB_RECORD_RESULT(sb_target);
}

void SBDebugger::SetSelectedTarget(SBTarget &sb_target) {
  LLDB_RECORD_METHOD(void, SBDebugger, SetSelectedTarget, (lldb::SBTarget &),
                     sb_target);

  Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_API));

  TargetSP target_sp(sb_target.GetSP());
  if (m_opaque_sp) {
    m_opaque_sp->GetTargetList().SetSelectedTarget(target_sp);
  }
  if (log) {
    SBStream sstr;
    sb_target.GetDescription(sstr, eDescriptionLevelBrief);
    LLDB_LOGF(log, "SBDebugger(%p)::SetSelectedTarget () => SBTarget(%p): %s",
              static_cast<void *>(m_opaque_sp.get()),
              static_cast<void *>(target_sp.get()), sstr.GetData());
  }
}

SBPlatform SBDebugger::GetSelectedPlatform() {
  LLDB_RECORD_METHOD_NO_ARGS(lldb::SBPlatform, SBDebugger, GetSelectedPlatform);

  Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_API));

  SBPlatform sb_platform;
  DebuggerSP debugger_sp(m_opaque_sp);
  if (debugger_sp) {
    sb_platform.SetSP(debugger_sp->GetPlatformList().GetSelectedPlatform());
  }
  LLDB_LOGF(log, "SBDebugger(%p)::GetSelectedPlatform () => SBPlatform(%p): %s",
            static_cast<void *>(m_opaque_sp.get()),
            static_cast<void *>(sb_platform.GetSP().get()),
            sb_platform.GetName());
  return LLDB_RECORD_RESULT(sb_platform);
}

void SBDebugger::SetSelectedPlatform(SBPlatform &sb_platform) {
  LLDB_RECORD_METHOD(void, SBDebugger, SetSelectedPlatform,
                     (lldb::SBPlatform &), sb_platform);

  Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_API));

  DebuggerSP debugger_sp(m_opaque_sp);
  if (debugger_sp) {
    debugger_sp->GetPlatformList().SetSelectedPlatform(sb_platform.GetSP());
  }

  LLDB_LOGF(log, "SBDebugger(%p)::SetSelectedPlatform (SBPlatform(%p) %s)",
            static_cast<void *>(m_opaque_sp.get()),
            static_cast<void *>(sb_platform.GetSP().get()),
            sb_platform.GetName());
}

uint32_t SBDebugger::GetNumPlatforms() {
  LLDB_RECORD_METHOD_NO_ARGS(uint32_t, SBDebugger, GetNumPlatforms);

  if (m_opaque_sp) {
    // No need to lock, the platform list is thread safe
    return m_opaque_sp->GetPlatformList().GetSize();
  }
  return 0;
}

SBPlatform SBDebugger::GetPlatformAtIndex(uint32_t idx) {
  LLDB_RECORD_METHOD(lldb::SBPlatform, SBDebugger, GetPlatformAtIndex,
                     (uint32_t), idx);

  SBPlatform sb_platform;
  if (m_opaque_sp) {
    // No need to lock, the platform list is thread safe
    sb_platform.SetSP(m_opaque_sp->GetPlatformList().GetAtIndex(idx));
  }
  return LLDB_RECORD_RESULT(sb_platform);
}

uint32_t SBDebugger::GetNumAvailablePlatforms() {
  LLDB_RECORD_METHOD_NO_ARGS(uint32_t, SBDebugger, GetNumAvailablePlatforms);

  uint32_t idx = 0;
  while (true) {
    if (!PluginManager::GetPlatformPluginNameAtIndex(idx)) {
      break;
    }
    ++idx;
  }
  // +1 for the host platform, which should always appear first in the list.
  return idx + 1;
}

SBStructuredData SBDebugger::GetAvailablePlatformInfoAtIndex(uint32_t idx) {
  LLDB_RECORD_METHOD(lldb::SBStructuredData, SBDebugger,
                     GetAvailablePlatformInfoAtIndex, (uint32_t), idx);

  SBStructuredData data;
  auto platform_dict = std::make_unique<StructuredData::Dictionary>();
  llvm::StringRef name_str("name"), desc_str("description");

  if (idx == 0) {
    PlatformSP host_platform_sp(Platform::GetHostPlatform());
    platform_dict->AddStringItem(
        name_str, host_platform_sp->GetPluginName().GetStringRef());
    platform_dict->AddStringItem(
        desc_str, llvm::StringRef(host_platform_sp->GetDescription()));
  } else if (idx > 0) {
    const char *plugin_name =
        PluginManager::GetPlatformPluginNameAtIndex(idx - 1);
    if (!plugin_name) {
      return LLDB_RECORD_RESULT(data);
    }
    platform_dict->AddStringItem(name_str, llvm::StringRef(plugin_name));

    const char *plugin_desc =
        PluginManager::GetPlatformPluginDescriptionAtIndex(idx - 1);
    if (!plugin_desc) {
      return LLDB_RECORD_RESULT(data);
    }
    platform_dict->AddStringItem(desc_str, llvm::StringRef(plugin_desc));
  }

  data.m_impl_up->SetObjectSP(
      StructuredData::ObjectSP(platform_dict.release()));
  return LLDB_RECORD_RESULT(data);
}

void SBDebugger::DispatchInput(void *baton, const void *data, size_t data_len) {
  LLDB_RECORD_DUMMY(void, SBDebugger, DispatchInput,
                    (void *, const void *, size_t), baton, data, data_len);

  DispatchInput(data, data_len);
}

void SBDebugger::DispatchInput(const void *data, size_t data_len) {
  LLDB_RECORD_DUMMY(void, SBDebugger, DispatchInput, (const void *, size_t),
                    data, data_len);

  //    Log *log(GetLogIfAllCategoriesSet (LIBLLDB_LOG_API));
  //
  //    if (log)
  //        LLDB_LOGF(log, "SBDebugger(%p)::DispatchInput (data=\"%.*s\",
  //        size_t=%" PRIu64 ")",
  //                     m_opaque_sp.get(),
  //                     (int) data_len,
  //                     (const char *) data,
  //                     (uint64_t)data_len);
  //
  //    if (m_opaque_sp)
  //        m_opaque_sp->DispatchInput ((const char *) data, data_len);
}

void SBDebugger::DispatchInputInterrupt() {
  LLDB_RECORD_DUMMY_NO_ARGS(void, SBDebugger, DispatchInputInterrupt);

  if (m_opaque_sp)
    m_opaque_sp->DispatchInputInterrupt();
}

void SBDebugger::DispatchInputEndOfFile() {
  LLDB_RECORD_METHOD_NO_ARGS(void, SBDebugger, DispatchInputEndOfFile);

  if (m_opaque_sp)
    m_opaque_sp->DispatchInputEndOfFile();
}

void SBDebugger::PushInputReader(SBInputReader &reader) {
  LLDB_RECORD_METHOD(void, SBDebugger, PushInputReader, (lldb::SBInputReader &),
                     reader);
}

void SBDebugger::RunCommandInterpreter(bool auto_handle_events,
                                       bool spawn_thread) {
  LLDB_RECORD_METHOD(void, SBDebugger, RunCommandInterpreter, (bool, bool),
                     auto_handle_events, spawn_thread);

  if (m_opaque_sp) {
    CommandInterpreterRunOptions options;
    options.SetAutoHandleEvents(auto_handle_events);
    options.SetSpawnThread(spawn_thread);
    m_opaque_sp->GetCommandInterpreter().RunCommandInterpreter(options);
  }
}

void SBDebugger::RunCommandInterpreter(bool auto_handle_events,
                                       bool spawn_thread,
                                       SBCommandInterpreterRunOptions &options,
                                       int &num_errors, bool &quit_requested,
                                       bool &stopped_for_crash)

{
  LLDB_RECORD_METHOD(void, SBDebugger, RunCommandInterpreter,
                     (bool, bool, lldb::SBCommandInterpreterRunOptions &, int &,
                      bool &, bool &),
                     auto_handle_events, spawn_thread, options, num_errors,
                     quit_requested, stopped_for_crash);

  if (m_opaque_sp) {
    options.SetAutoHandleEvents(auto_handle_events);
    options.SetSpawnThread(spawn_thread);
    CommandInterpreter &interp = m_opaque_sp->GetCommandInterpreter();
    CommandInterpreterRunResult result =
        interp.RunCommandInterpreter(options.ref());
    num_errors = result.GetNumErrors();
    quit_requested =
        result.IsResult(lldb::eCommandInterpreterResultQuitRequested);
    stopped_for_crash =
        result.IsResult(lldb::eCommandInterpreterResultInferiorCrash);
  }
}

SBCommandInterpreterRunResult SBDebugger::RunCommandInterpreter(
    const SBCommandInterpreterRunOptions &options) {
  LLDB_RECORD_METHOD(lldb::SBCommandInterpreterRunResult, SBDebugger,
                     RunCommandInterpreter,
                     (const lldb::SBCommandInterpreterRunOptions &), options);

  if (!m_opaque_sp)
    return LLDB_RECORD_RESULT(SBCommandInterpreterRunResult());

  CommandInterpreter &interp = m_opaque_sp->GetCommandInterpreter();
  CommandInterpreterRunResult result =
      interp.RunCommandInterpreter(options.ref());

  return LLDB_RECORD_RESULT(SBCommandInterpreterRunResult(result));
}

SBError SBDebugger::RunREPL(lldb::LanguageType language,
                            const char *repl_options) {
  LLDB_RECORD_METHOD(lldb::SBError, SBDebugger, RunREPL,
                     (lldb::LanguageType, const char *), language,
                     repl_options);

  SBError error;
  if (m_opaque_sp)
    error.ref() = m_opaque_sp->RunREPL(language, repl_options);
  else
    error.SetErrorString("invalid debugger");
  return LLDB_RECORD_RESULT(error);
}

void SBDebugger::reset(const DebuggerSP &debugger_sp) {
  m_opaque_sp = debugger_sp;
}

Debugger *SBDebugger::get() const { return m_opaque_sp.get(); }

Debugger &SBDebugger::ref() const {
  assert(m_opaque_sp.get());
  return *m_opaque_sp;
}

const lldb::DebuggerSP &SBDebugger::get_sp() const { return m_opaque_sp; }

SBDebugger SBDebugger::FindDebuggerWithID(int id) {
  LLDB_RECORD_STATIC_METHOD(lldb::SBDebugger, SBDebugger, FindDebuggerWithID,
                            (int), id);

  // No need to lock, the debugger list is thread safe
  SBDebugger sb_debugger;
  DebuggerSP debugger_sp = Debugger::FindDebuggerWithID(id);
  if (debugger_sp)
    sb_debugger.reset(debugger_sp);
  return LLDB_RECORD_RESULT(sb_debugger);
}

const char *SBDebugger::GetInstanceName() {
  LLDB_RECORD_METHOD_NO_ARGS(const char *, SBDebugger, GetInstanceName);

  return (m_opaque_sp ? m_opaque_sp->GetInstanceName().AsCString() : nullptr);
}

SBError SBDebugger::SetInternalVariable(const char *var_name, const char *value,
                                        const char *debugger_instance_name) {
  LLDB_RECORD_STATIC_METHOD(lldb::SBError, SBDebugger, SetInternalVariable,
                            (const char *, const char *, const char *),
                            var_name, value, debugger_instance_name);

  SBError sb_error;
  DebuggerSP debugger_sp(Debugger::FindDebuggerWithInstanceName(
      ConstString(debugger_instance_name)));
  Status error;
  if (debugger_sp) {
    ExecutionContext exe_ctx(
        debugger_sp->GetCommandInterpreter().GetExecutionContext());
    error = debugger_sp->SetPropertyValue(&exe_ctx, eVarSetOperationAssign,
                                          var_name, value);
  } else {
    error.SetErrorStringWithFormat("invalid debugger instance name '%s'",
                                   debugger_instance_name);
  }
  if (error.Fail())
    sb_error.SetError(error);
  return LLDB_RECORD_RESULT(sb_error);
}

SBStringList
SBDebugger::GetInternalVariableValue(const char *var_name,
                                     const char *debugger_instance_name) {
  LLDB_RECORD_STATIC_METHOD(
      lldb::SBStringList, SBDebugger, GetInternalVariableValue,
      (const char *, const char *), var_name, debugger_instance_name);

  DebuggerSP debugger_sp(Debugger::FindDebuggerWithInstanceName(
      ConstString(debugger_instance_name)));
  Status error;
  if (debugger_sp) {
    ExecutionContext exe_ctx(
        debugger_sp->GetCommandInterpreter().GetExecutionContext());
    lldb::OptionValueSP value_sp(
        debugger_sp->GetPropertyValue(&exe_ctx, var_name, false, error));
    if (value_sp) {
      StreamString value_strm;
      value_sp->DumpValue(&exe_ctx, value_strm, OptionValue::eDumpOptionValue);
      const std::string &value_str = std::string(value_strm.GetString());
      if (!value_str.empty()) {
        StringList string_list;
        string_list.SplitIntoLines(value_str);
        return LLDB_RECORD_RESULT(SBStringList(&string_list));
      }
    }
  }
  return LLDB_RECORD_RESULT(SBStringList());
}

uint32_t SBDebugger::GetTerminalWidth() const {
  LLDB_RECORD_METHOD_CONST_NO_ARGS(uint32_t, SBDebugger, GetTerminalWidth);

  return (m_opaque_sp ? m_opaque_sp->GetTerminalWidth() : 0);
}

void SBDebugger::SetTerminalWidth(uint32_t term_width) {
  LLDB_RECORD_DUMMY(void, SBDebugger, SetTerminalWidth, (uint32_t), term_width);

  if (m_opaque_sp)
    m_opaque_sp->SetTerminalWidth(term_width);
}

const char *SBDebugger::GetPrompt() const {
  LLDB_RECORD_METHOD_CONST_NO_ARGS(const char *, SBDebugger, GetPrompt);

  Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_API));

  LLDB_LOGF(log, "SBDebugger(%p)::GetPrompt () => \"%s\"",
            static_cast<void *>(m_opaque_sp.get()),
            (m_opaque_sp ? m_opaque_sp->GetPrompt().str().c_str() : ""));

  return (m_opaque_sp ? ConstString(m_opaque_sp->GetPrompt()).GetCString()
                      : nullptr);
}

void SBDebugger::SetPrompt(const char *prompt) {
  LLDB_RECORD_METHOD(void, SBDebugger, SetPrompt, (const char *), prompt);

  if (m_opaque_sp)
    m_opaque_sp->SetPrompt(llvm::StringRef(prompt));
}

const char *SBDebugger::GetReproducerPath() const {
  LLDB_RECORD_METHOD_CONST_NO_ARGS(const char *, SBDebugger, GetReproducerPath);

  return (m_opaque_sp
              ? ConstString(m_opaque_sp->GetReproducerPath()).GetCString()
              : nullptr);
}

ScriptLanguage SBDebugger::GetScriptLanguage() const {
  LLDB_RECORD_METHOD_CONST_NO_ARGS(lldb::ScriptLanguage, SBDebugger,
                                   GetScriptLanguage);

  return (m_opaque_sp ? m_opaque_sp->GetScriptLanguage() : eScriptLanguageNone);
}

void SBDebugger::SetScriptLanguage(ScriptLanguage script_lang) {
  LLDB_RECORD_METHOD(void, SBDebugger, SetScriptLanguage,
                     (lldb::ScriptLanguage), script_lang);

  if (m_opaque_sp) {
    m_opaque_sp->SetScriptLanguage(script_lang);
  }
}

bool SBDebugger::SetUseExternalEditor(bool value) {
  LLDB_RECORD_METHOD(bool, SBDebugger, SetUseExternalEditor, (bool), value);

  return (m_opaque_sp ? m_opaque_sp->SetUseExternalEditor(value) : false);
}

bool SBDebugger::GetUseExternalEditor() {
  LLDB_RECORD_METHOD_NO_ARGS(bool, SBDebugger, GetUseExternalEditor);

  return (m_opaque_sp ? m_opaque_sp->GetUseExternalEditor() : false);
}

bool SBDebugger::SetUseColor(bool value) {
  LLDB_RECORD_METHOD(bool, SBDebugger, SetUseColor, (bool), value);

  return (m_opaque_sp ? m_opaque_sp->SetUseColor(value) : false);
}

bool SBDebugger::GetUseColor() const {
  LLDB_RECORD_METHOD_CONST_NO_ARGS(bool, SBDebugger, GetUseColor);

  return (m_opaque_sp ? m_opaque_sp->GetUseColor() : false);
}

bool SBDebugger::SetUseSourceCache(bool value) {
  LLDB_RECORD_METHOD(bool, SBDebugger, SetUseSourceCache, (bool), value);

  return (m_opaque_sp ? m_opaque_sp->SetUseSourceCache(value) : false);
}

bool SBDebugger::GetUseSourceCache() const {
  LLDB_RECORD_METHOD_CONST_NO_ARGS(bool, SBDebugger, GetUseSourceCache);

  return (m_opaque_sp ? m_opaque_sp->GetUseSourceCache() : false);
}

bool SBDebugger::GetDescription(SBStream &description) {
  LLDB_RECORD_METHOD(bool, SBDebugger, GetDescription, (lldb::SBStream &),
                     description);

  Stream &strm = description.ref();

  if (m_opaque_sp) {
    const char *name = m_opaque_sp->GetInstanceName().AsCString();
    user_id_t id = m_opaque_sp->GetID();
    strm.Printf("Debugger (instance: \"%s\", id: %" PRIu64 ")", name, id);
  } else
    strm.PutCString("No value");

  return true;
}

user_id_t SBDebugger::GetID() {
  LLDB_RECORD_METHOD_NO_ARGS(lldb::user_id_t, SBDebugger, GetID);

  return (m_opaque_sp ? m_opaque_sp->GetID() : LLDB_INVALID_UID);
}

SBError SBDebugger::SetCurrentPlatform(const char *platform_name_cstr) {
  LLDB_RECORD_METHOD(lldb::SBError, SBDebugger, SetCurrentPlatform,
                     (const char *), platform_name_cstr);

  SBError sb_error;
  if (m_opaque_sp) {
    if (platform_name_cstr && platform_name_cstr[0]) {
      ConstString platform_name(platform_name_cstr);
      PlatformSP platform_sp(Platform::Find(platform_name));

      if (platform_sp) {
        // Already have a platform with this name, just select it
        m_opaque_sp->GetPlatformList().SetSelectedPlatform(platform_sp);
      } else {
        // We don't have a platform by this name yet, create one
        platform_sp = Platform::Create(platform_name, sb_error.ref());
        if (platform_sp) {
          // We created the platform, now append and select it
          bool make_selected = true;
          m_opaque_sp->GetPlatformList().Append(platform_sp, make_selected);
        }
      }
    } else {
      sb_error.ref().SetErrorString("invalid platform name");
    }
  } else {
    sb_error.ref().SetErrorString("invalid debugger");
  }
  return LLDB_RECORD_RESULT(sb_error);
}

bool SBDebugger::SetCurrentPlatformSDKRoot(const char *sysroot) {
  LLDB_RECORD_METHOD(bool, SBDebugger, SetCurrentPlatformSDKRoot,
                     (const char *), sysroot);

  Log *log(GetLogIfAllCategoriesSet(LIBLLDB_LOG_API));
  if (m_opaque_sp) {
    PlatformSP platform_sp(
        m_opaque_sp->GetPlatformList().GetSelectedPlatform());

    if (platform_sp) {
      if (log && sysroot)
        LLDB_LOGF(log, "SBDebugger::SetCurrentPlatformSDKRoot (\"%s\")",
                  sysroot);
      platform_sp->SetSDKRootDirectory(ConstString(sysroot));
      return true;
    }
  }
  return false;
}

bool SBDebugger::GetCloseInputOnEOF() const {
  LLDB_RECORD_METHOD_CONST_NO_ARGS(bool, SBDebugger, GetCloseInputOnEOF);

  return (m_opaque_sp ? m_opaque_sp->GetCloseInputOnEOF() : false);
}

void SBDebugger::SetCloseInputOnEOF(bool b) {
  LLDB_RECORD_METHOD(void, SBDebugger, SetCloseInputOnEOF, (bool), b);

  if (m_opaque_sp)
    m_opaque_sp->SetCloseInputOnEOF(b);
}

SBTypeCategory SBDebugger::GetCategory(const char *category_name) {
  LLDB_RECORD_METHOD(lldb::SBTypeCategory, SBDebugger, GetCategory,
                     (const char *), category_name);

  if (!category_name || *category_name == 0)
    return LLDB_RECORD_RESULT(SBTypeCategory());

  TypeCategoryImplSP category_sp;

  if (DataVisualization::Categories::GetCategory(ConstString(category_name),
                                                 category_sp, false)) {
    return LLDB_RECORD_RESULT(SBTypeCategory(category_sp));
  } else {
    return LLDB_RECORD_RESULT(SBTypeCategory());
  }
}

SBTypeCategory SBDebugger::GetCategory(lldb::LanguageType lang_type) {
  LLDB_RECORD_METHOD(lldb::SBTypeCategory, SBDebugger, GetCategory,
                     (lldb::LanguageType), lang_type);

  TypeCategoryImplSP category_sp;
  if (DataVisualization::Categories::GetCategory(lang_type, category_sp)) {
    return LLDB_RECORD_RESULT(SBTypeCategory(category_sp));
  } else {
    return LLDB_RECORD_RESULT(SBTypeCategory());
  }
}

SBTypeCategory SBDebugger::CreateCategory(const char *category_name) {
  LLDB_RECORD_METHOD(lldb::SBTypeCategory, SBDebugger, CreateCategory,
                     (const char *), category_name);

  if (!category_name || *category_name == 0)
    return LLDB_RECORD_RESULT(SBTypeCategory());

  TypeCategoryImplSP category_sp;

  if (DataVisualization::Categories::GetCategory(ConstString(category_name),
                                                 category_sp, true)) {
    return LLDB_RECORD_RESULT(SBTypeCategory(category_sp));
  } else {
    return LLDB_RECORD_RESULT(SBTypeCategory());
  }
}

bool SBDebugger::DeleteCategory(const char *category_name) {
  LLDB_RECORD_METHOD(bool, SBDebugger, DeleteCategory, (const char *),
                     category_name);

  if (!category_name || *category_name == 0)
    return false;

  return DataVisualization::Categories::Delete(ConstString(category_name));
}

uint32_t SBDebugger::GetNumCategories() {
  LLDB_RECORD_METHOD_NO_ARGS(uint32_t, SBDebugger, GetNumCategories);

  return DataVisualization::Categories::GetCount();
}

SBTypeCategory SBDebugger::GetCategoryAtIndex(uint32_t index) {
  LLDB_RECORD_METHOD(lldb::SBTypeCategory, SBDebugger, GetCategoryAtIndex,
                     (uint32_t), index);

  return LLDB_RECORD_RESULT(
      SBTypeCategory(DataVisualization::Categories::GetCategoryAtIndex(index)));
}

SBTypeCategory SBDebugger::GetDefaultCategory() {
  LLDB_RECORD_METHOD_NO_ARGS(lldb::SBTypeCategory, SBDebugger,
                             GetDefaultCategory);

  return LLDB_RECORD_RESULT(GetCategory("default"));
}

SBTypeFormat SBDebugger::GetFormatForType(SBTypeNameSpecifier type_name) {
  LLDB_RECORD_METHOD(lldb::SBTypeFormat, SBDebugger, GetFormatForType,
                     (lldb::SBTypeNameSpecifier), type_name);

  SBTypeCategory default_category_sb = GetDefaultCategory();
  if (default_category_sb.GetEnabled())
    return LLDB_RECORD_RESULT(default_category_sb.GetFormatForType(type_name));
  return LLDB_RECORD_RESULT(SBTypeFormat());
}

SBTypeSummary SBDebugger::GetSummaryForType(SBTypeNameSpecifier type_name) {
  LLDB_RECORD_METHOD(lldb::SBTypeSummary, SBDebugger, GetSummaryForType,
                     (lldb::SBTypeNameSpecifier), type_name);

  if (!type_name.IsValid())
    return LLDB_RECORD_RESULT(SBTypeSummary());
  return LLDB_RECORD_RESULT(
      SBTypeSummary(DataVisualization::GetSummaryForType(type_name.GetSP())));
}

SBTypeFilter SBDebugger::GetFilterForType(SBTypeNameSpecifier type_name) {
  LLDB_RECORD_METHOD(lldb::SBTypeFilter, SBDebugger, GetFilterForType,
                     (lldb::SBTypeNameSpecifier), type_name);

  if (!type_name.IsValid())
    return LLDB_RECORD_RESULT(SBTypeFilter());
  return LLDB_RECORD_RESULT(
      SBTypeFilter(DataVisualization::GetFilterForType(type_name.GetSP())));
}

SBTypeSynthetic SBDebugger::GetSyntheticForType(SBTypeNameSpecifier type_name) {
  LLDB_RECORD_METHOD(lldb::SBTypeSynthetic, SBDebugger, GetSyntheticForType,
                     (lldb::SBTypeNameSpecifier), type_name);

  if (!type_name.IsValid())
    return LLDB_RECORD_RESULT(SBTypeSynthetic());
  return LLDB_RECORD_RESULT(SBTypeSynthetic(
      DataVisualization::GetSyntheticForType(type_name.GetSP())));
}

static llvm::ArrayRef<const char *> GetCategoryArray(const char **categories) {
  if (categories == nullptr)
    return {};
  size_t len = 0;
  while (categories[len] != nullptr)
    ++len;
  return llvm::makeArrayRef(categories, len);
}

bool SBDebugger::EnableLog(const char *channel, const char **categories) {
  LLDB_RECORD_METHOD(bool, SBDebugger, EnableLog, (const char *, const char **),
                     channel, categories);

  if (m_opaque_sp) {
    uint32_t log_options =
        LLDB_LOG_OPTION_PREPEND_TIMESTAMP | LLDB_LOG_OPTION_PREPEND_THREAD_NAME;
    std::string error;
    llvm::raw_string_ostream error_stream(error);
    return m_opaque_sp->EnableLog(channel, GetCategoryArray(categories), "",
                                  log_options, error_stream);
  } else
    return false;
}

void SBDebugger::SetLoggingCallback(lldb::LogOutputCallback log_callback,
                                    void *baton) {
  LLDB_RECORD_DUMMY(void, SBDebugger, SetLoggingCallback,
                    (lldb::LogOutputCallback, void *), log_callback, baton);

  if (m_opaque_sp) {
    return m_opaque_sp->SetLoggingCallback(log_callback, baton);
  }
}

namespace lldb_private {
namespace repro {

template <> void RegisterMethods<SBInputReader>(Registry &R) {
  LLDB_REGISTER_METHOD(void, SBInputReader, SetIsDone, (bool));
  LLDB_REGISTER_METHOD_CONST(bool, SBInputReader, IsActive, ());
}

static void SetFileHandleRedirect(SBDebugger *, FILE *, bool) {
  // Do nothing.
}

static SBError SetFileRedirect(SBDebugger *, SBFile file) { return SBError(); }

static SBError SetFileRedirect(SBDebugger *, FileSP file) { return SBError(); }

template <> void RegisterMethods<SBDebugger>(Registry &R) {
  // Custom implementation.
  R.Register(&invoke<void (SBDebugger::*)(FILE *, bool)>::method<
                 &SBDebugger::SetErrorFileHandle>::record,
             &SetFileHandleRedirect);
  R.Register(&invoke<void (SBDebugger::*)(FILE *, bool)>::method<
                 &SBDebugger::SetOutputFileHandle>::record,
             &SetFileHandleRedirect);

  R.Register(&invoke<SBError (SBDebugger::*)(
                 SBFile)>::method<&SBDebugger::SetInputFile>::record,
             &SetFileRedirect);
  R.Register(&invoke<SBError (SBDebugger::*)(
                 SBFile)>::method<&SBDebugger::SetOutputFile>::record,
             &SetFileRedirect);
  R.Register(&invoke<SBError (SBDebugger::*)(
                 SBFile)>::method<&SBDebugger::SetErrorFile>::record,
             &SetFileRedirect);

  R.Register(&invoke<SBError (SBDebugger::*)(
                 FileSP)>::method<&SBDebugger::SetInputFile>::record,
             &SetFileRedirect);
  R.Register(&invoke<SBError (SBDebugger::*)(
                 FileSP)>::method<&SBDebugger::SetOutputFile>::record,
             &SetFileRedirect);
  R.Register(&invoke<SBError (SBDebugger::*)(
                 FileSP)>::method<&SBDebugger::SetErrorFile>::record,
             &SetFileRedirect);

  LLDB_REGISTER_CHAR_PTR_METHOD_STATIC(bool, SBDebugger,
                                       GetDefaultArchitecture);

  LLDB_REGISTER_CONSTRUCTOR(SBDebugger, ());
  LLDB_REGISTER_CONSTRUCTOR(SBDebugger, (const lldb::DebuggerSP &));
  LLDB_REGISTER_CONSTRUCTOR(SBDebugger, (const lldb::SBDebugger &));
  LLDB_REGISTER_METHOD(lldb::SBDebugger &,
                       SBDebugger, operator=,(const lldb::SBDebugger &));
  LLDB_REGISTER_STATIC_METHOD(void, SBDebugger, Initialize, ());
  LLDB_REGISTER_STATIC_METHOD(lldb::SBError, SBDebugger,
                              InitializeWithErrorHandling, ());
  LLDB_REGISTER_STATIC_METHOD(void, SBDebugger, Terminate, ());
  LLDB_REGISTER_METHOD(void, SBDebugger, Clear, ());
  LLDB_REGISTER_STATIC_METHOD(lldb::SBDebugger, SBDebugger, Create, ());
  LLDB_REGISTER_STATIC_METHOD(lldb::SBDebugger, SBDebugger, Create, (bool));
  LLDB_REGISTER_STATIC_METHOD(
      const char *, SBDebugger, GetProgressFromEvent,
      (const lldb::SBEvent &, uint64_t &, uint64_t &, uint64_t &, bool &));
  LLDB_REGISTER_STATIC_METHOD(const char *, SBDebugger, GetBroadcasterClass,
                              ());
  LLDB_REGISTER_METHOD(SBBroadcaster, SBDebugger, GetBroadcaster, ());
  LLDB_REGISTER_STATIC_METHOD(void, SBDebugger, Destroy, (lldb::SBDebugger &));
  LLDB_REGISTER_STATIC_METHOD(void, SBDebugger, MemoryPressureDetected, ());
  LLDB_REGISTER_METHOD_CONST(bool, SBDebugger, IsValid, ());
  LLDB_REGISTER_METHOD_CONST(bool, SBDebugger, operator bool,());
  LLDB_REGISTER_METHOD(void, SBDebugger, SetAsync, (bool));
  LLDB_REGISTER_METHOD(bool, SBDebugger, GetAsync, ());
  LLDB_REGISTER_METHOD(void, SBDebugger, SkipLLDBInitFiles, (bool));
  LLDB_REGISTER_METHOD(void, SBDebugger, SkipAppInitFiles, (bool));
  LLDB_REGISTER_METHOD(void, SBDebugger, SetInputFileHandle, (FILE *, bool));
  LLDB_REGISTER_METHOD(FILE *, SBDebugger, GetInputFileHandle, ());
  LLDB_REGISTER_METHOD(FILE *, SBDebugger, GetOutputFileHandle, ());
  LLDB_REGISTER_METHOD(FILE *, SBDebugger, GetErrorFileHandle, ());
  LLDB_REGISTER_METHOD(SBFile, SBDebugger, GetInputFile, ());
  LLDB_REGISTER_METHOD(SBFile, SBDebugger, GetOutputFile, ());
  LLDB_REGISTER_METHOD(SBFile, SBDebugger, GetErrorFile, ());
  LLDB_REGISTER_METHOD(void, SBDebugger, SaveInputTerminalState, ());
  LLDB_REGISTER_METHOD(void, SBDebugger, RestoreInputTerminalState, ());
  LLDB_REGISTER_METHOD(lldb::SBCommandInterpreter, SBDebugger,
                       GetCommandInterpreter, ());
  LLDB_REGISTER_METHOD(void, SBDebugger, HandleCommand, (const char *));
  LLDB_REGISTER_METHOD(lldb::SBListener, SBDebugger, GetListener, ());
  LLDB_REGISTER_METHOD(
      void, SBDebugger, HandleProcessEvent,
      (const lldb::SBProcess &, const lldb::SBEvent &, FILE *, FILE *));
  LLDB_REGISTER_METHOD(
      void, SBDebugger, HandleProcessEvent,
      (const lldb::SBProcess &, const lldb::SBEvent &, SBFile, SBFile));
  LLDB_REGISTER_METHOD(
      void, SBDebugger, HandleProcessEvent,
      (const lldb::SBProcess &, const lldb::SBEvent &, FileSP, FileSP));
  LLDB_REGISTER_METHOD(lldb::SBSourceManager, SBDebugger, GetSourceManager, ());
  LLDB_REGISTER_STATIC_METHOD(bool, SBDebugger, SetDefaultArchitecture,
                              (const char *));
  LLDB_REGISTER_METHOD(lldb::ScriptLanguage, SBDebugger, GetScriptingLanguage,
                       (const char *));
  LLDB_REGISTER_STATIC_METHOD(const char *, SBDebugger, GetVersionString, ());
  LLDB_REGISTER_STATIC_METHOD(const char *, SBDebugger, StateAsCString,
                              (lldb::StateType));
  LLDB_REGISTER_STATIC_METHOD(lldb::SBStructuredData, SBDebugger,
                              GetBuildConfiguration, ());
  LLDB_REGISTER_STATIC_METHOD(bool, SBDebugger, StateIsRunningState,
                              (lldb::StateType));
  LLDB_REGISTER_STATIC_METHOD(bool, SBDebugger, StateIsStoppedState,
                              (lldb::StateType));
  LLDB_REGISTER_METHOD(
      lldb::SBTarget, SBDebugger, CreateTarget,
      (const char *, const char *, const char *, bool, lldb::SBError &));
  LLDB_REGISTER_METHOD(lldb::SBTarget, SBDebugger,
                       CreateTargetWithFileAndTargetTriple,
                       (const char *, const char *));
  LLDB_REGISTER_METHOD(lldb::SBTarget, SBDebugger, CreateTargetWithFileAndArch,
                       (const char *, const char *));
  LLDB_REGISTER_METHOD(lldb::SBTarget, SBDebugger, CreateTarget,
                       (const char *));
  LLDB_REGISTER_METHOD(lldb::SBTarget, SBDebugger, GetDummyTarget, ());
  LLDB_REGISTER_METHOD(bool, SBDebugger, DeleteTarget, (lldb::SBTarget &));
  LLDB_REGISTER_METHOD(lldb::SBTarget, SBDebugger, GetTargetAtIndex,
                       (uint32_t));
  LLDB_REGISTER_METHOD(uint32_t, SBDebugger, GetIndexOfTarget,
                       (lldb::SBTarget));
  LLDB_REGISTER_METHOD(lldb::SBTarget, SBDebugger, FindTargetWithProcessID,
                       (lldb::pid_t));
  LLDB_REGISTER_METHOD(lldb::SBTarget, SBDebugger, FindTargetWithFileAndArch,
                       (const char *, const char *));
  LLDB_REGISTER_METHOD(uint32_t, SBDebugger, GetNumTargets, ());
  LLDB_REGISTER_METHOD(lldb::SBTarget, SBDebugger, GetSelectedTarget, ());
  LLDB_REGISTER_METHOD(void, SBDebugger, SetSelectedTarget, (lldb::SBTarget &));
  LLDB_REGISTER_METHOD(lldb::SBPlatform, SBDebugger, GetSelectedPlatform, ());
  LLDB_REGISTER_METHOD(void, SBDebugger, SetSelectedPlatform,
                       (lldb::SBPlatform &));
  LLDB_REGISTER_METHOD(uint32_t, SBDebugger, GetNumPlatforms, ());
  LLDB_REGISTER_METHOD(lldb::SBPlatform, SBDebugger, GetPlatformAtIndex,
                       (uint32_t));
  LLDB_REGISTER_METHOD(uint32_t, SBDebugger, GetNumAvailablePlatforms, ());
  LLDB_REGISTER_METHOD(lldb::SBStructuredData, SBDebugger,
                       GetAvailablePlatformInfoAtIndex, (uint32_t));
  LLDB_REGISTER_METHOD(void, SBDebugger, DispatchInputInterrupt, ());
  LLDB_REGISTER_METHOD(void, SBDebugger, DispatchInputEndOfFile, ());
  LLDB_REGISTER_METHOD(void, SBDebugger, PushInputReader,
                       (lldb::SBInputReader &));
  LLDB_REGISTER_METHOD(void, SBDebugger, RunCommandInterpreter, (bool, bool));
  LLDB_REGISTER_METHOD(void, SBDebugger, RunCommandInterpreter,
                       (bool, bool, lldb::SBCommandInterpreterRunOptions &,
                        int &, bool &, bool &));
  LLDB_REGISTER_METHOD(lldb::SBError, SBDebugger, RunREPL,
                       (lldb::LanguageType, const char *));
  LLDB_REGISTER_STATIC_METHOD(lldb::SBDebugger, SBDebugger, FindDebuggerWithID,
                              (int));
  LLDB_REGISTER_METHOD(const char *, SBDebugger, GetInstanceName, ());
  LLDB_REGISTER_STATIC_METHOD(lldb::SBError, SBDebugger, SetInternalVariable,
                              (const char *, const char *, const char *));
  LLDB_REGISTER_STATIC_METHOD(lldb::SBStringList, SBDebugger,
                              GetInternalVariableValue,
                              (const char *, const char *));
  LLDB_REGISTER_METHOD_CONST(uint32_t, SBDebugger, GetTerminalWidth, ());
  LLDB_REGISTER_METHOD(void, SBDebugger, SetTerminalWidth, (uint32_t));
  LLDB_REGISTER_METHOD_CONST(const char *, SBDebugger, GetPrompt, ());
  LLDB_REGISTER_METHOD(void, SBDebugger, SetPrompt, (const char *));
  LLDB_REGISTER_METHOD_CONST(const char *, SBDebugger, GetReproducerPath, ());
  LLDB_REGISTER_METHOD_CONST(lldb::ScriptLanguage, SBDebugger,
                             GetScriptLanguage, ());
  LLDB_REGISTER_METHOD(void, SBDebugger, SetScriptLanguage,
                       (lldb::ScriptLanguage));
  LLDB_REGISTER_METHOD(bool, SBDebugger, SetUseExternalEditor, (bool));
  LLDB_REGISTER_METHOD(bool, SBDebugger, GetUseExternalEditor, ());
  LLDB_REGISTER_METHOD(bool, SBDebugger, SetUseColor, (bool));
  LLDB_REGISTER_METHOD_CONST(bool, SBDebugger, GetUseColor, ());
  LLDB_REGISTER_METHOD(bool, SBDebugger, GetDescription, (lldb::SBStream &));
  LLDB_REGISTER_METHOD(lldb::user_id_t, SBDebugger, GetID, ());
  LLDB_REGISTER_METHOD(lldb::SBError, SBDebugger, SetCurrentPlatform,
                       (const char *));
  LLDB_REGISTER_METHOD(bool, SBDebugger, SetCurrentPlatformSDKRoot,
                       (const char *));
  LLDB_REGISTER_METHOD_CONST(bool, SBDebugger, GetCloseInputOnEOF, ());
  LLDB_REGISTER_METHOD(void, SBDebugger, SetCloseInputOnEOF, (bool));
  LLDB_REGISTER_METHOD(lldb::SBTypeCategory, SBDebugger, GetCategory,
                       (const char *));
  LLDB_REGISTER_METHOD(lldb::SBTypeCategory, SBDebugger, GetCategory,
                       (lldb::LanguageType));
  LLDB_REGISTER_METHOD(lldb::SBTypeCategory, SBDebugger, CreateCategory,
                       (const char *));
  LLDB_REGISTER_METHOD(bool, SBDebugger, DeleteCategory, (const char *));
  LLDB_REGISTER_METHOD(uint32_t, SBDebugger, GetNumCategories, ());
  LLDB_REGISTER_METHOD(lldb::SBTypeCategory, SBDebugger, GetCategoryAtIndex,
                       (uint32_t));
  LLDB_REGISTER_METHOD(lldb::SBTypeCategory, SBDebugger, GetDefaultCategory,
                       ());
  LLDB_REGISTER_METHOD(lldb::SBTypeFormat, SBDebugger, GetFormatForType,
                       (lldb::SBTypeNameSpecifier));
  LLDB_REGISTER_METHOD(lldb::SBTypeSummary, SBDebugger, GetSummaryForType,
                       (lldb::SBTypeNameSpecifier));
  LLDB_REGISTER_METHOD(lldb::SBTypeSynthetic, SBDebugger, GetSyntheticForType,
                       (lldb::SBTypeNameSpecifier));
  LLDB_REGISTER_METHOD(lldb::SBTypeFilter, SBDebugger, GetFilterForType,
                       (lldb::SBTypeNameSpecifier));
  LLDB_REGISTER_METHOD(bool, SBDebugger, EnableLog,
                       (const char *, const char **));
  LLDB_REGISTER_METHOD(lldb::SBCommandInterpreterRunResult, SBDebugger,
                       RunCommandInterpreter,
                       (const lldb::SBCommandInterpreterRunOptions &));
}

} // namespace repro
} // namespace lldb_private
