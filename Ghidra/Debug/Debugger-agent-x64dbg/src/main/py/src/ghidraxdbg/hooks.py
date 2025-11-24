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
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
import functools
import sys
import threading
import time
import traceback
from typing import Any, Callable, Collection, Dict, Optional, TypeVar, cast

from ghidratrace.client import Schedule
from x64dbg_automate.events import EventType
from x64dbg_automate.models import BreakpointType

from . import commands, util


ALL_EVENTS = 0xFFFF


@dataclass(frozen=False)
class HookState:
    installed = False
    mem_catchpoint = None


@dataclass(frozen=False)
class ProcessState:
    first = True
    # For things we can detect changes to between stops
    regions = False
    modules = False
    threads = False
    breaks = True
    watches = False
    # For frames and threads that have already been synced since last stop
    visited: set[Any] = field(default_factory=set)
    waiting = False

    def record(self, description: Optional[str] = None,
               time: Optional[Schedule] = None) -> None:
        first = self.first
        self.first = False
        trace = commands.STATE.require_trace()
        if description is not None:
            trace.snapshot(description, time=time)
        if first:
            commands.put_available()
            commands.put_processes()
            commands.put_environment()
            commands.put_threads()
        if self.threads:
            commands.put_threads()
            self.threads = False
        thread = util.selected_thread()
        if thread is not None:
            if first or thread not in self.visited:
                try:
                    commands.putreg()
                    commands.putmem('0x{:x}'.format(util.get_pc()),
                                    "1", display_result=False)
                    commands.putmem('0x{:x}'.format(util.get_sp()-1),
                                    "2", display_result=False)
                    commands.put_breakpoints(BreakpointType.BpNormal)
                    commands.put_breakpoints(BreakpointType.BpHardware)
                    commands.put_breakpoints(BreakpointType.BpMemory)
                except Exception:
                    pass
                #commands.put_frames()
                self.visited.add(thread)
        # TODO:  hoping to support this at some point once the relevant APIs are exposed
        #     frame = util.selected_frame()
        #     hashable_frame = (thread, frame)
        #     if first or hashable_frame not in self.visited:
        #         self.visited.add(hashable_frame)
        try:
            if first or self.regions or self.modules:
                commands.put_regions()
                self.regions = False
                self.modules = False
        except:
            pass

    def record_continued(self) -> None:
        try:
            proc = util.selected_process()
            commands.put_state(proc)
            commands.put_breakpoints(BreakpointType.BpNormal)
            commands.put_breakpoints(BreakpointType.BpHardware)
            commands.put_breakpoints(BreakpointType.BpMemory)
        except Exception:
            pass

    def record_exited(self, exit_code: Optional[str] = None,
                      time: Optional[Schedule] = None) -> None:
        trace = commands.STATE.require_trace()
        if exit_code is not None:
            trace.snapshot(f"Exited {exit_code}", time=time)
        ipath = commands.PROCESS_PATTERN.format(procnum=util.last_process)
        procobj = trace.proxy_object_path(ipath)
        procobj.set_value('Exit Code', exit_code)
        procobj.set_value('State', 'TERMINATED')


@dataclass(frozen=False)
class BrkState:
    break_loc_counts: Dict[int, int] = field(default_factory=dict)

    def update_brkloc_count(self, b, count: int) -> None:
        self.break_loc_counts[b.GetID()] = count

    def get_brkloc_count(self, b) -> int:
        return self.break_loc_counts.get(b.GetID(), 0)

    def del_brkloc_count(self, b) -> int:
        if b not in self.break_loc_counts:
            return 0  # TODO: Print a warning?
        count = self.break_loc_counts[b.GetID()]
        del self.break_loc_counts[b.GetID()]
        return count


HOOK_STATE = HookState()
BRK_STATE = BrkState()
PROC_STATE: Dict[int, ProcessState] = {}


C = TypeVar('C', bound=Callable)


def log_errors(func: C) -> C:
    """Wrap a function in a try-except that prints and reraises the exception.

    This is needed for exceptions that occur during event callbacks.
    """
    @functools.wraps(func)
    def _func(*args, **kwargs) -> Any:
        try:
            return func(*args, **kwargs)
        except:
            traceback.print_exc()
            raise
    return cast(C, _func)


@log_errors
def on_state_changed(*args) -> None:
    # print("ON_STATE_CHANGED")
    ev_type = args[0].event_type
    # print(ev_type)
    proc = util.selected_process()
    trace = commands.STATE.require_trace()
    with trace.client.batch():
        with trace.open_tx("State changed proc {}".format(proc)):
            commands.put_state(proc)
    if proc not in PROC_STATE:
        if ev_type == EventType.EVENT_EXIT_PROCESS:
            on_process_deleted(args)
        return
    PROC_STATE[proc].waiting = False
    try:
        if ev_type == EventType.EVENT_RESUME_DEBUG:
            on_cont()
        elif ev_type == EventType.EVENT_PAUSE_DEBUG:
            on_stop()
    except Exception:
        pass


@log_errors
def on_breakpoint_hit(*args) -> None:
    # print("ON_THREADS_CHANGED")
    proc = util.selected_process()
    if proc not in PROC_STATE:
        return
    data = args[0].event_data
    PROC_STATE[proc].breaks = True
    


@log_errors
def on_new_process(*args) -> None:
    # print("ON_NEW_PROCESS")
    trace = commands.STATE.trace
    if trace is None:
        return
    with trace.client.batch():
        with trace.open_tx("New Process {}".format(util.selected_process())):
            commands.put_processes()


def on_process_selected() -> None:
    # print("PROCESS_SELECTED")
    proc = util.selected_process()
    if proc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    with trace.client.batch():
        with trace.open_tx("Process {} selected".format(proc)):
            PROC_STATE[proc].record()
            commands.activate()


@log_errors
def on_process_deleted(*args) -> None:
    # print("PROCESS_DELETED: args={}".format(args))
    proc = util.selected_process()
    on_exited(args)
    if proc in PROC_STATE:
        del PROC_STATE[proc]
    trace = commands.STATE.trace
    if trace is None:
        return
    with trace.client.batch():
        with trace.open_tx("Process {} deleted".format(proc)):
            commands.put_processes()  # TODO: Could just delete the one....


@log_errors
def on_threads_changed(*args) -> None:
    # print("ON_THREADS_CHANGED")
    data = args[0].event_data
    proc = util.selected_process()
    if proc not in PROC_STATE:
        return
    util.threads[data.dwThreadId] = data
    state = PROC_STATE[proc]
    state.threads = True
    state.waiting = False
    trace = commands.STATE.require_trace()
    with trace.client.batch():
        with trace.open_tx("Threads changed proc {}".format(proc)):
            #commands.put_threads()
            commands.put_state(proc)
    


def on_thread_selected(*args) -> None:
    # print("THREAD_SELECTED: args={}".format(args))
    # sys.stdout.flush()
    nthrd = args[0][1]
    nproc = util.selected_process()
    if nproc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    with trace.client.batch():
        with trace.open_tx("Thread {}.{} selected".format(nproc, nthrd)):
            commands.put_state(nproc)
            state = PROC_STATE[nproc]
            if state.waiting:
                state.record_continued()
            else:
                state.record()
                commands.activate()


def on_register_changed(regnum) -> None:
    # print("REGISTER_CHANGED")
    proc = util.selected_process()
    if proc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    with trace.client.batch():
        with trace.open_tx("Register {} changed".format(regnum)):
            commands.putreg()
            commands.activate()


def on_memory_changed(space) -> None:
    proc = util.selected_process()
    if proc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    # Not great, but invalidate the whole space
    # UI will only re-fetch what it needs
    # But, some observations will not be recovered
    try:
        with trace.client.batch():
            with trace.open_tx("Memory changed"):
                commands.putmem_state(0, 2**64, 'unknown')
    except Exception:
        pass


def on_cont(*args) -> None:
    # print("ON CONT")
    proc = util.selected_process()
    if proc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    state = PROC_STATE[proc]
    with trace.client.batch():
        with trace.open_tx("Continued"):
            state.record_continued()
    return


def on_stop(*args) -> None:
    # print("ON STOP")
    proc = util.selected_process()
    if proc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    state = PROC_STATE[proc]
    state.visited.clear()
    time = None
    with trace.client.batch():
        with trace.open_tx("Stopped"):
            description = "Stopped"
            state.record(description, time)
            try:
                commands.put_event_thread()
            except:
                pass
            commands.activate()


def on_exited(*args) -> None:
    # print("ON EXITED")
    trace = commands.STATE.trace
    if trace is None:
        return
    state = PROC_STATE[util.last_process]
    state.visited.clear()
    with trace.client.batch():
        with trace.open_tx("Exited"):
            exit_code = args[0][0].event_data.dwExitCode
            state.record_exited(exit_code)
            commands.activate()


@log_errors
def on_modules_changed(*args) -> None:
    # print("ON_MODULES_CHANGED")
    #data = args[0].event_data
    proc = util.selected_process()
    if proc not in PROC_STATE:
        return
    state = PROC_STATE[proc]
    state.modules = True
    state.waiting = False
    trace = commands.STATE.require_trace()
    with trace.client.batch():
        with trace.open_tx("Modules changed proc {}".format(proc)):
            #commands.put_modules()
            commands.put_state(proc)


def install_hooks() -> None:
    # print("Installing hooks")
    if HOOK_STATE.installed:
        return
    HOOK_STATE.installed = True

    dbg = util.dbg.client
    dbg.watch_debug_event(EventType.EVENT_OUTPUT_DEBUG_STRING, lambda x: on_breakpoint_hit(x))
    dbg.watch_debug_event(EventType.EVENT_BREAKPOINT, lambda x: on_state_changed(x))
    dbg.watch_debug_event(EventType.EVENT_SYSTEMBREAKPOINT, lambda x: on_state_changed(x))
    dbg.watch_debug_event(EventType.EVENT_EXCEPTION, lambda x: on_state_changed(x))
    dbg.watch_debug_event(EventType.EVENT_CREATE_THREAD, lambda x: on_threads_changed(x))
    dbg.watch_debug_event(EventType.EVENT_EXIT_THREAD, lambda x: on_threads_changed(x))
    dbg.watch_debug_event(EventType.EVENT_LOAD_DLL, lambda x: on_modules_changed(x))
    dbg.watch_debug_event(EventType.EVENT_UNLOAD_DLL, lambda x: on_modules_changed(x))
    dbg.watch_debug_event(EventType.EVENT_STEPPED, lambda x: on_state_changed(x))
    dbg.watch_debug_event(EventType.EVENT_PAUSE_DEBUG, lambda x: on_state_changed(x))
    dbg.watch_debug_event(EventType.EVENT_RESUME_DEBUG, lambda x: on_state_changed(x))
    dbg.watch_debug_event(EventType.EVENT_ATTACH, lambda x: on_state_changed(x))
    dbg.watch_debug_event(EventType.EVENT_DETACH, lambda x: on_state_changed(x))
    dbg.watch_debug_event(EventType.EVENT_INIT_DEBUG, lambda x: on_state_changed(x))
    dbg.watch_debug_event(EventType.EVENT_STOP_DEBUG, lambda x: on_state_changed(x))
    dbg.watch_debug_event(EventType.EVENT_CREATE_PROCESS, lambda x: on_state_changed(x))
    dbg.watch_debug_event(EventType.EVENT_EXIT_PROCESS, lambda x: on_state_changed(x))


def remove_hooks() -> None:
    # print("Removing hooks")
    if HOOK_STATE.installed:
        HOOK_STATE.installed = False


def enable_current_process() -> None:
    # print("Enable current process")
    proc = util.selected_process()
    PROC_STATE[proc] = ProcessState()


def disable_current_process() -> None:
    # print("Disable current process")
    proc = util.selected_process()
    if proc in PROC_STATE:
        # Silently ignore already disabled
        del PROC_STATE[proc]

