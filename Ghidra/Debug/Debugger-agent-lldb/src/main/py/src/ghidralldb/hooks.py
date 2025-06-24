## ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##
from dataclasses import dataclass, field
import threading
import time
from typing import Any, Optional, Union

import lldb

from . import commands, util


ALL_EVENTS = 0xFFFF


@dataclass(frozen=False)
class HookState(object):
    installed = False

    def __init__(self) -> None:
        self.installed = False


@dataclass(frozen=False)
class ProcessState(object):
    first = True
    # For things we can detect changes to between stops
    regions = False
    modules = False
    threads = False
    breaks = False
    watches = False
    # For frames and threads that have already been synced since last stop
    visited: set[Any] = field(default_factory=set)

    def __init__(self) -> None:
        self.first = True
        self.regions = False
        self.modules = False
        self.threads = False
        self.breaks = False
        self.watches = False
        self.visited = set()

    def record(self, description: Optional[str] = None) -> None:
        first = self.first
        self.first = False
        trace = commands.STATE.require_trace()
        if description is not None:
            trace.snapshot(description)
        if first:
            commands.put_processes()
            commands.put_environment()
        if self.threads:
            commands.put_threads()
            self.threads = False
        thread = util.selected_thread()
        if thread is not None:
            if first or thread.GetThreadID() not in self.visited:
                commands.put_frames()
                self.visited.add(thread.GetThreadID())
            frame = util.selected_frame()
            hashable_frame = (thread.GetThreadID(), frame.GetFrameID())
            if first or hashable_frame not in self.visited:
                banks = frame.GetRegisters()
                primary = banks.GetFirstValueByName(
                    commands.DEFAULT_REGISTER_BANK)
                if primary.value is None:
                    primary = banks[0]
                    if primary is not None:
                        commands.DEFAULT_REGISTER_BANK = primary.name
                if primary is not None:
                    commands.putreg(frame, primary)
                try:
                    commands.putmem("$pc", "1", result=None)
                except BaseException as e:
                    print(f"Couldn't record page with PC: {e}")
                try:
                    commands.putmem("$sp-1", "2", result=None)
                except BaseException as e:
                    print(f"Couldn't record page with SP: {e}")
                self.visited.add(hashable_frame)
        if first or self.regions or self.modules:
            # Sections, memory syscalls, or stack allocations
            commands.put_regions()
            self.regions = False
        if first or self.modules:
            commands.put_modules()
            self.modules = False
        if first or self.breaks:
            commands.put_breakpoints()
            self.breaks = False
        if first or self.watches:
            commands.put_watchpoints()
            self.watches = False

    def record_continued(self):
        commands.put_processes()
        commands.put_threads()

    def record_exited(self, exit_code):
        proc = util.get_process()
        ipath = commands.PROCESS_PATTERN.format(procnum=proc.GetProcessID())
        procobj = commands.STATE.trace.proxy_object_path(ipath)
        procobj.set_value('Exit Code', exit_code)
        procobj.set_value('State', 'TERMINATED')


HOOK_STATE = HookState()
PROC_STATE = {}


class QuitSentinel(object):
    pass


QUIT = QuitSentinel()


def process_event(self, listener: lldb.SBListener,
                  event: lldb.SBEvent) -> Union[QuitSentinel, bool]:
    try:
        desc = util.get_description(event)
        # print(f"Event: {desc}")
        target = util.get_target()
        if not target.IsValid():
            # LLDB may crash on event.GetBroadcasterClass, otherwise
            # All the checks below, e.g. SBTarget.EventIsTargetEvent, call this
            print(f"Ignoring {desc} because target is invalid")
            return False
        event_process = util.get_process()
        if event_process.IsValid() and event_process.GetProcessID() not in PROC_STATE:
            PROC_STATE[event_process.GetProcessID()] = ProcessState()
            rc = event_process.GetBroadcaster().AddListener(listener, ALL_EVENTS)
            if not rc:
                print("add listener for process failed")

        # NB: Calling put_state on running leaves an open transaction
        if not event_process.is_running:
            commands.put_state(event_process)
        type = event.GetType()
        if lldb.SBTarget.EventIsTargetEvent(event):
            if (type & lldb.SBTarget.eBroadcastBitBreakpointChanged) != 0:
                return on_breakpoint_modified(event)
            if (type & lldb.SBTarget.eBroadcastBitWatchpointChanged) != 0:
                return on_watchpoint_modified(event)
            if (type & lldb.SBTarget.eBroadcastBitModulesLoaded) != 0:
                return on_new_objfile(event)
            if (type & lldb.SBTarget.eBroadcastBitModulesUnloaded) != 0:
                return on_free_objfile(event)
            if (type & lldb.SBTarget.eBroadcastBitSymbolsLoaded) != 0:
                return True
        if lldb.SBProcess.EventIsProcessEvent(event):
            if (type & lldb.SBProcess.eBroadcastBitStateChanged) != 0:
                if not event_process.is_alive:
                    return on_exited(event)
                if event_process.is_stopped:
                    return on_stop(event)
                if event_process.is_running:
                    return on_cont(event)
                return True
            if (type & lldb.SBProcess.eBroadcastBitInterrupt) != 0:
                if event_process.is_stopped:
                    return on_stop(event)
            if (type & lldb.SBProcess.eBroadcastBitSTDOUT) != 0:
                return True
            if (type & lldb.SBProcess.eBroadcastBitSTDERR) != 0:
                return True
            if (type & lldb.SBProcess.eBroadcastBitProfileData) != 0:
                return True
            if (type & lldb.SBProcess.eBroadcastBitStructuredData) != 0:
                return True
        # NB: Thread events not currently processes
        if lldb.SBThread.EventIsThreadEvent(event):
            if (type & lldb.SBThread.eBroadcastBitStackChanged) != 0:
                return on_frame_selected()
            if (type & lldb.SBThread.eBroadcastBitThreadSuspended) != 0:
                if event_process.is_stopped:
                    return on_stop(event)
            if (type & lldb.SBThread.eBroadcastBitThreadResumed) != 0:
                return on_cont(event)
            if (type & lldb.SBThread.eBroadcastBitSelectedFrameChanged) != 0:
                return on_frame_selected()
            if (type & lldb.SBThread.eBroadcastBitThreadSelected) != 0:
                return on_thread_selected()
        if lldb.SBBreakpoint.EventIsBreakpointEvent(event):
            btype = lldb.SBBreakpoint.GetBreakpointEventTypeFromEvent(event)
            bpt = lldb.SBBreakpoint.GetBreakpointFromEvent(event)
            if btype is lldb.eBreakpointEventTypeAdded:
                return on_breakpoint_created(bpt)
            if btype is lldb.eBreakpointEventTypeAutoContinueChanged:
                return on_breakpoint_modified(bpt)
            if btype is lldb.eBreakpointEventTypeCommandChanged:
                return on_breakpoint_modified(bpt)
            if btype is lldb.eBreakpointEventTypeConditionChanged:
                return on_breakpoint_modified(bpt)
            if btype is lldb.eBreakpointEventTypeDisabled:
                return on_breakpoint_modified(bpt)
            if btype is lldb.eBreakpointEventTypeEnabled:
                return on_breakpoint_modified(bpt)
            if btype is lldb.eBreakpointEventTypeIgnoreChanged:
                return True
            if btype is lldb.eBreakpointEventTypeInvalidType:
                return True
            if btype is lldb.eBreakpointEventTypeLocationsAdded:
                return on_breakpoint_modified(bpt)
            if btype is lldb.eBreakpointEventTypeLocationsRemoved:
                return on_breakpoint_modified(bpt)
            if btype is lldb.eBreakpointEventTypeLocationsResolved:
                return on_breakpoint_modified(bpt)
            if btype is lldb.eBreakpointEventTypeRemoved:
                return on_breakpoint_deleted(bpt)
            if btype is lldb.eBreakpointEventTypeThreadChanged:
                return on_breakpoint_modified(bpt)
            print("UNKNOWN BREAKPOINT EVENT")
            return True
        if lldb.SBWatchpoint.EventIsWatchpointEvent(event):
            btype = lldb.SBWatchpoint.GetWatchpointEventTypeFromEvent(event)
            bpt = lldb.SBWatchpoint.GetWatchpointFromEvent(event)
            if btype is lldb.eWatchpointEventTypeAdded:
                return on_watchpoint_created(bpt)
            if btype is lldb.eWatchpointEventTypeCommandChanged:
                return on_watchpoint_modified(bpt)
            if btype is lldb.eWatchpointEventTypeConditionChanged:
                return on_watchpoint_modified(bpt)
            if btype is lldb.eWatchpointEventTypeDisabled:
                return on_watchpoint_modified(bpt)
            if btype is lldb.eWatchpointEventTypeEnabled:
                return on_watchpoint_modified(bpt)
            if btype is lldb.eWatchpointEventTypeIgnoreChanged:
                return True
            if btype is lldb.eWatchpointEventTypeInvalidType:
                return True
            if btype is lldb.eWatchpointEventTypeRemoved:
                return on_watchpoint_deleted(bpt)
            if btype is lldb.eWatchpointEventTypeThreadChanged:
                return on_watchpoint_modified(bpt)
            if btype is lldb.eWatchpointEventTypeTypeChanged:
                return on_watchpoint_modified(bpt)
            print("UNKNOWN WATCHPOINT EVENT")
            return True
        if lldb.SBCommandInterpreter.EventIsCommandInterpreterEvent(event):
            if (type & lldb.SBCommandInterpreter.eBroadcastBitAsynchronousErrorData) != 0:
                return True
            if (type & lldb.SBCommandInterpreter.eBroadcastBitAsynchronousOutputData) != 0:
                return True
            if (type & lldb.SBCommandInterpreter.eBroadcastBitQuitCommandReceived) != 0:
                # DO NOT return QUIT here.
                # For some reason, this event comes just after launch.
                # Maybe need to figure out *which* interpreter?
                return True
            if (type & lldb.SBCommandInterpreter.eBroadcastBitResetPrompt) != 0:
                return True
            if (type & lldb.SBCommandInterpreter.eBroadcastBitThreadShouldExit) != 0:
                return True
        print("UNKNOWN EVENT")
        return True
    except BaseException as e:
        print(e)
        return False


class EventThread(threading.Thread):
    func = process_event
    event = lldb.SBEvent()

    def run(self) -> None:
        # Let's only try at most 4 times to retrieve any kind of event.
        # After that, the thread exits.
        listener = lldb.SBListener('eventlistener')
        cli = util.get_debugger().GetCommandInterpreter()
        target = util.get_target()
        proc = util.get_process()
        rc = cli.GetBroadcaster().AddListener(listener, ALL_EVENTS)
        if not rc:
            print("add listener for cli failed")
            # return
        rc = target.GetBroadcaster().AddListener(listener, ALL_EVENTS)
        if not rc:
            print("add listener for target failed")
            # return
        rc = proc.GetBroadcaster().AddListener(listener, ALL_EVENTS)
        if not rc:
            print("add listener for process failed")
            # return

        # Not sure what effect this logic has
        rc = cli.GetBroadcaster().AddInitialEventsToListener(listener, ALL_EVENTS)
        if not rc:
            print("add initial events for cli failed")
            # return
        rc = target.GetBroadcaster().AddInitialEventsToListener(listener, ALL_EVENTS)
        if not rc:
            print("add initial events for target failed")
            # return
        rc = proc.GetBroadcaster().AddInitialEventsToListener(listener, ALL_EVENTS)
        if not rc:
            print("add initial events for process failed")
            # return

        rc = listener.StartListeningForEventClass(
            util.get_debugger(), lldb.SBThread.GetBroadcasterClassName(), ALL_EVENTS)
        if not rc:
            print("add listener for threads failed")
            # return
        # THIS WILL NOT WORK: listener = util.get_debugger().GetListener()

        while True:
            event_recvd = False
            while not event_recvd:
                if listener.WaitForEvent(lldb.UINT32_MAX, self.event):
                    try:
                        result = self.func(listener, self.event)
                        if result is QUIT:
                            return
                    except BaseException as e:
                        print(e)
                    while listener.GetNextEvent(self.event):
                        try:
                            result = self.func(listener, self.event)
                            if result is QUIT:
                                return
                        except BaseException as e:
                            print(e)
                    event_recvd = True
            proc = util.get_process()
            if proc is not None and not proc.is_alive:
                break
        return


"""   
    # Not sure if this is possible in LLDB...
    
    # Respond to user-driven state changes: (Not target-driven)
    lldb.events.memory_changed.connect(on_memory_changed)
    lldb.events.register_changed.connect(on_register_changed)
    # Respond to target-driven memory map changes:
    # group:memory is actually a bit broad, but will probably port better
    # One alternative is to name all syscalls that cause a change....
    # Ones we could probably omit:
    #     msync,
    #         (Deals in syncing file-backed pages to disk.)
    #     mlock, munlock, mlockall, munlockall, mincore, madvise,
    #         (Deal in paging. Doesn't affect valid addresses.)
    #     mbind, get_mempolicy, set_mempolicy, migrate_pages, move_pages
    #         (All NUMA stuff)
    #
    if HOOK_STATE.mem_catchpoint is not None:
        HOOK_STATE.mem_catchpoint.enabled = True
    else:
        breaks_before = set(lldb.breakpoints())
        lldb.execute(
            catch syscall group:memory
            commands
            silent
            ghidra-hook event-memory
            cont
            end
            )
        HOOK_STATE.mem_catchpoint = (
            set(lldb.breakpoints()) - breaks_before).pop()
"""


def on_new_process(event: lldb.SBEvent) -> None:
    trace = commands.STATE.trace
    if trace is None:
        return
    with trace.client.batch():
        with trace.open_tx(f"New Process {event.process.num}"):
            commands.put_processes()  # TODO: Could put just the one....


def on_process_selected() -> None:
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    with trace.client.batch():
        with trace.open_tx(f"Process {proc.GetProcessID()} selected"):
            PROC_STATE[proc.GetProcessID()].record()
            commands.activate()


def on_process_deleted(event: lldb.SBEvent) -> None:
    trace = commands.STATE.trace
    if trace is None:
        return
    if event.process.num in PROC_STATE:
        del PROC_STATE[event.process.num]
    with trace.client.batch():
        with trace.open_tx(f"Process {event.process.num} deleted"):
            commands.put_processes()  # TODO: Could just delete the one....


def on_new_thread(event: lldb.SBEvent) -> None:
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return
    PROC_STATE[proc.GetProcessID()].threads = True
    # TODO: Syscall clone/exit to detect thread destruction?


def on_thread_selected() -> bool:
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return False
    trace = commands.STATE.trace
    if trace is None:
        return False
    t = util.selected_thread()
    with trace.client.batch():
        with trace.open_tx(f"Thread {proc.GetProcessID()}.{t.GetThreadID()} selected"):
            PROC_STATE[proc.GetProcessID()].record()
            commands.put_threads()
            commands.activate()
    return True


def on_frame_selected() -> bool:
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return False
    trace = commands.STATE.trace
    if trace is None:
        return False
    f = util.selected_frame()
    t = f.GetThread()
    with trace.client.batch():
        with trace.open_tx(f"Frame {proc.GetProcessID()}.{t.GetThreadID()}.{f.GetFrameID()} selected"):
            PROC_STATE[proc.GetProcessID()].record()
            commands.put_threads()
            commands.put_frames()
            commands.activate()
    return True


def on_syscall_memory() -> bool:
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return False
    PROC_STATE[proc.GetProcessID()].regions = True
    return True


def on_memory_changed(event: lldb.SBEvent) -> bool:
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return False
    trace = commands.STATE.trace
    if trace is None:
        return False
    with trace.client.batch():
        with trace.open_tx(f"Memory *0x{event.address:08x} changed"):
            commands.put_bytes(event.address, event.address + event.length,
                               pages=False, result=None)
    return True


def on_register_changed(event: lldb.SBEvent) -> bool:
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return False
    trace = commands.STATE.trace
    if trace is None:
        return False
    with trace.client.batch():
        with trace.open_tx(f"Register {event.regnum} changed"):
            banks = event.frame.GetRegisters()
            commands.putreg(
                event.frame, banks.GetFirstValueByName(commands.DEFAULT_REGISTER_BANK))
    return True


def on_cont(event: lldb.SBEvent) -> bool:
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return False
    trace = commands.STATE.trace
    if trace is None:
        return False
    state = PROC_STATE[proc.GetProcessID()]
    with trace.client.batch():
        with trace.open_tx("Continued"):
            state.record_continued()
    return True


def on_stop(event: lldb.SBEvent) -> bool:
    proc = lldb.SBProcess.GetProcessFromEvent(
        event) if event is not None else util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        print("not in state")
        return False
    trace = commands.STATE.trace
    if trace is None:
        print("no trace")
        return False
    state = PROC_STATE[proc.GetProcessID()]
    state.visited.clear()
    with trace.client.batch():
        with trace.open_tx("Stopped"):
            state.record("Stopped")
            commands.put_event_thread()
            commands.put_threads()
            commands.put_frames()
            commands.activate()
    return True


def on_exited(event: lldb.SBEvent) -> bool:
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return False
    trace = commands.STATE.trace
    if trace is None:
        return False
    state = PROC_STATE[proc.GetProcessID()]
    state.visited.clear()
    exit_code = proc.GetExitStatus()
    description = "Exited with code {}".format(exit_code)
    with trace.client.batch():
        with trace.open_tx(description):
            state.record(description)
            state.record_exited(exit_code)
            commands.put_event_thread()
            commands.activate()
    return False


def modules_changed() -> bool:
    # Assumption: affects the current process
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return False
    PROC_STATE[proc.GetProcessID()].modules = True
    return True


def on_new_objfile(event: lldb.SBEvent) -> bool:
    modules_changed()
    return True


def on_free_objfile(event: lldb.SBEvent) -> bool:
    modules_changed()
    return True


def on_breakpoint_created(b: lldb.SBBreakpoint) -> bool:
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return False
    trace = commands.STATE.trace
    if trace is None:
        return False
    with trace.client.batch():
        with trace.open_tx("Breakpoint {} created".format(b.GetID())):
            commands.put_single_breakpoint(b, proc)
    return True


def on_breakpoint_modified(b: lldb.SBBreakpoint) -> bool:
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return False
    trace = commands.STATE.trace
    if trace is None:
        return False
    with trace.client.batch():
        with trace.open_tx("Breakpoint {} modified".format(b.GetID())):
            commands.put_single_breakpoint(b, proc)
    return True


def on_breakpoint_deleted(b: lldb.SBBreakpoint) -> bool:
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return False
    trace = commands.STATE.trace
    if trace is None:
        return False
    bpt_path = commands.PROC_BREAK_PATTERN.format(
        procnum=proc.GetProcessID(), breaknum=b.GetID())
    bpt_obj = trace.proxy_object_path(bpt_path)
    with trace.client.batch():
        with trace.open_tx("Breakpoint {} deleted".format(b.GetID())):
            bpt_obj.remove(tree=True)
    return True


def on_watchpoint_created(b: lldb.SBWatchpoint) -> bool:
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return False
    trace = commands.STATE.trace
    if trace is None:
        return False
    with trace.client.batch():
        with trace.open_tx("Breakpoint {} created".format(b.GetID())):
            commands.put_single_watchpoint(b, proc)
    return True


def on_watchpoint_modified(b: lldb.SBWatchpoint) -> bool:
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return False
    trace = commands.STATE.trace
    if trace is None:
        return False
    with trace.client.batch():
        with trace.open_tx("Watchpoint {} modified".format(b.GetID())):
            commands.put_single_watchpoint(b, proc)
    return True


def on_watchpoint_deleted(b: lldb.SBWatchpoint) -> bool:
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return False
    trace = commands.STATE.trace
    if trace is None:
        return False
    wpt_path = commands.PROC_WATCH_PATTERN.format(
        procnum=proc.GetProcessID(), watchnum=b.GetID())
    wpt_obj = trace.proxy_object_path(wpt_path)
    with trace.client.batch():
        with trace.open_tx("Watchpoint {} deleted".format(b.GetID())):
            wpt_obj.remove(tree=True)
    return True


def install_hooks() -> None:
    if HOOK_STATE.installed:
        return
    HOOK_STATE.installed = True

    event_thread = EventThread()
    event_thread.start()


def remove_hooks() -> None:
    if not HOOK_STATE.installed:
        return
    HOOK_STATE.installed = False


def enable_current_process() -> None:
    proc = util.get_process()
    PROC_STATE[proc.GetProcessID()] = ProcessState()


def disable_current_process() -> None:
    proc = util.get_process()
    if proc.GetProcessID() in PROC_STATE:
        # Silently ignore already disabled
        del PROC_STATE[proc.GetProcessID()]
