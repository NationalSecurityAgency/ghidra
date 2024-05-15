## ###
#  IP: GHIDRA
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#       http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##
from _ctypes_test import func
import functools
import sys
import threading
import time
import traceback

from comtypes.hresult import S_OK
from pybag import pydbg
from pybag.dbgeng import core as DbgEng
from pybag.dbgeng import exception
from pybag.dbgeng.callbacks import EventHandler
from pybag.dbgeng.idebugbreakpoint import DebugBreakpoint

from . import commands, util


ALL_EVENTS = 0xFFFF


class HookState(object):
    __slots__ = ('installed', 'mem_catchpoint')

    def __init__(self):
        self.installed = False
        self.mem_catchpoint = None


class ProcessState(object):
    __slots__ = ('first', 'regions', 'modules', 'threads',
                 'breaks', 'watches', 'visited', 'waiting')

    def __init__(self):
        self.first = True
        # For things we can detect changes to between stops
        self.regions = False
        self.modules = False
        self.threads = False
        self.breaks = False
        self.watches = False
        # For frames and threads that have already been synced since last stop
        self.visited = set()
        self.waiting = False

    def record(self, description=None):
        # print("RECORDING")
        first = self.first
        self.first = False
        if description is not None:
            commands.STATE.trace.snapshot(description)
        if first:
            commands.put_processes()
            commands.put_environment()
        if self.threads:
            commands.put_threads()
            self.threads = False
        thread = util.selected_thread()
        if thread is not None:
            if first or thread not in self.visited:
                commands.putreg()
                commands.putmem('0x{:x}'.format(util.get_pc()),
                                "1", display_result=False)
                commands.putmem('0x{:x}'.format(util.get_sp()),
                                "1", display_result=False)
                commands.put_frames()
                self.visited.add(thread)
            frame = util.selected_frame()
            hashable_frame = (thread, frame)
            if first or hashable_frame not in self.visited:
                self.visited.add(hashable_frame)
        if first or self.regions:
            commands.put_regions()
            self.regions = False
        if first or self.modules:
            commands.put_modules()
            self.modules = False
        if first or self.breaks:
            commands.put_breakpoints()
            self.breaks = False

    def record_continued(self):
        commands.put_processes(running=True)
        commands.put_threads(running=True)

    def record_exited(self, exit_code, description=None):
        if description is not None:
            commands.STATE.trace.snapshot(description)
        proc = util.selected_process()
        ipath = commands.PROCESS_PATTERN.format(procnum=proc)
        procobj = commands.STATE.trace.proxy_object_path(ipath)
        procobj.set_value('Exit Code', exit_code)
        procobj.set_value('State', 'TERMINATED')


class BrkState(object):
    __slots__ = ('break_loc_counts',)

    def __init__(self):
        self.break_loc_counts = {}

    def update_brkloc_count(self, b, count):
        self.break_loc_counts[b.GetID()] = count

    def get_brkloc_count(self, b):
        return self.break_loc_counts.get(b.GetID(), 0)

    def del_brkloc_count(self, b):
        if b not in self.break_loc_counts:
            return 0  # TODO: Print a warning?
        count = self.break_loc_counts[b.GetID()]
        del self.break_loc_counts[b.GetID()]
        return count


HOOK_STATE = HookState()
BRK_STATE = BrkState()
PROC_STATE = {}


def log_errors(func):
    '''
    Wrap a function in a try-except that prints and reraises the
    exception.

    This is needed because pybag and/or the COM wrappers do not print
    exceptions that occur during event callbacks.
    '''
    @functools.wraps(func)
    def _func(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except:
            traceback.print_exc()
            raise
    return _func


@log_errors
def on_state_changed(*args):
    # print("ON_STATE_CHANGED")
    # print(args)
    if args[0] == DbgEng.DEBUG_CES_CURRENT_THREAD:
        return on_thread_selected(args)
    elif args[0] == DbgEng.DEBUG_CES_BREAKPOINTS:
        return on_breakpoint_modified(args)
    elif args[0] == DbgEng.DEBUG_CES_RADIX:
        util.set_convenience_variable('output-radix', args[1])
        return S_OK
    elif args[0] == DbgEng.DEBUG_CES_EXECUTION_STATUS:
        util.dbg._ces_exec_status(args[1])
        proc = util.selected_process()
        if args[1] & DbgEng.DEBUG_STATUS_INSIDE_WAIT:
            if proc in PROC_STATE:
                # Process may have exited (so deleted) first
                PROC_STATE[proc].waiting = True
            return S_OK
        if proc in PROC_STATE:
            # Process may have exited (so deleted) first.
            PROC_STATE[proc].waiting = False
        trace = commands.STATE.trace
        with commands.STATE.client.batch():
            with trace.open_tx("State changed proc {}".format(proc)):
                commands.put_state(proc)
        if args[1] == DbgEng.DEBUG_STATUS_BREAK:
            return on_stop(args)
        elif args[1] == DbgEng.DEBUG_STATUS_NO_DEBUGGEE:
            return on_exited(proc)
        else:
            return on_cont(args)
    return S_OK


@log_errors
def on_debuggee_changed(*args):
    # print("ON_DEBUGGEE_CHANGED: args={}".format(args))
    # sys.stdout.flush()
    trace = commands.STATE.trace
    if trace is None:
        return S_OK
    if args[0] == DbgEng.DEBUG_CDS_REGISTERS:
        on_register_changed(args[1])
    if args[0] == DbgEng.DEBUG_CDS_DATA:
        on_memory_changed(args[1])
    return S_OK


@log_errors
def on_session_status_changed(*args):
    print("ON_STATUS_CHANGED: args={}".format(args))
    trace = commands.STATE.trace
    if trace is None:
        return
    if args[0] == DbgEng.DEBUG_SESSION_ACTIVE or args[0] == DbgEng.DEBUG_SESSION_REBOOT:
        with commands.STATE.client.batch():
            with trace.open_tx("New Session {}".format(util.selected_process())):
                commands.put_processes()
                return DbgEng.DEBUG_STATUS_GO


@log_errors
def on_symbol_state_changed(*args):
    # print("ON_SYMBOL_STATE_CHANGED")
    proc = util.selected_process()
    if proc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    if args[0] == 1 or args[0] == 2:
        PROC_STATE[proc].modules = True
    return DbgEng.DEBUG_STATUS_GO


@log_errors
def on_system_error(*args):
    print("ON_SYSTEM_ERROR: args={}".format(args))
    # print(hex(args[0]))
    trace = commands.STATE.trace
    if trace is None:
        return
    with commands.STATE.client.batch():
        with trace.open_tx("System Error {}".format(util.selected_process())):
            commands.put_processes()
    return DbgEng.DEBUG_STATUS_BREAK


@log_errors
def on_new_process(*args):
    # print("ON_NEW_PROCESS")
    trace = commands.STATE.trace
    if trace is None:
        return
    with commands.STATE.client.batch():
        with trace.open_tx("New Process {}".format(util.selected_process())):
            commands.put_processes()
    return DbgEng.DEBUG_STATUS_BREAK


def on_process_selected():
    # print("PROCESS_SELECTED")
    proc = util.selected_process()
    if proc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    with commands.STATE.client.batch():
        with trace.open_tx("Process {} selected".format(proc)):
            PROC_STATE[proc].record()
            commands.activate()


@log_errors
def on_process_deleted(*args):
    # print("ON_PROCESS_DELETED")
    proc = args[0]
    on_exited(proc)
    if proc in PROC_STATE:
        del PROC_STATE[proc]
    trace = commands.STATE.trace
    if trace is None:
        return
    with commands.STATE.client.batch():
        with trace.open_tx("Process {} deleted".format(proc)):
            commands.put_processes()  # TODO: Could just delete the one....
    return DbgEng.DEBUG_STATUS_BREAK


@log_errors
def on_threads_changed(*args):
    # print("ON_THREADS_CHANGED")
    proc = util.selected_process()
    if proc not in PROC_STATE:
        return DbgEng.DEBUG_STATUS_GO
    PROC_STATE[proc].threads = True
    return DbgEng.DEBUG_STATUS_GO


def on_thread_selected(*args):
    # print("THREAD_SELECTED: args={}".format(args))
    # sys.stdout.flush()
    nthrd = args[0][1]
    nproc = util.selected_process()
    if nproc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    with commands.STATE.client.batch():
        with trace.open_tx("Thread {}.{} selected".format(nproc, nthrd)):
            commands.put_state(nproc)
            state = PROC_STATE[nproc]
            if state.waiting:
                state.record_continued()
            else:
                state.record()
                commands.activate()


def on_register_changed(regnum):
    # print("REGISTER_CHANGED")
    proc = util.selected_process()
    if proc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    with commands.STATE.client.batch():
        with trace.open_tx("Register {} changed".format(regnum)):
            commands.putreg()
            commands.activate()


def on_memory_changed(space):
    if space != DbgEng.DEBUG_DATA_SPACE_VIRTUAL:
        return
    proc = util.selected_process()
    if proc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    # Not great, but invalidate the whole space
    # UI will only re-fetch what it needs
    # But, some observations will not be recovered
    with commands.STATE.client.batch():
        with trace.open_tx("Memory changed"):
            commands.putmem_state(0, 2**64, 'unknown')


def on_cont(*args):
    # print("ON CONT")
    proc = util.selected_process()
    if proc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    state = PROC_STATE[proc]
    with commands.STATE.client.batch():
        with trace.open_tx("Continued"):
            state.record_continued()
    return DbgEng.DEBUG_STATUS_GO


def on_stop(*args):
    # print("ON STOP")
    proc = util.selected_process()
    if proc not in PROC_STATE:
        # print("not in state")
        return
    trace = commands.STATE.trace
    if trace is None:
        # print("no trace")
        return
    state = PROC_STATE[proc]
    state.visited.clear()
    with commands.STATE.client.batch():
        with trace.open_tx("Stopped"):
            state.record("Stopped")
            commands.put_event_thread()
            commands.activate()


def on_exited(proc):
    # print("ON EXITED")
    if proc not in PROC_STATE:
        # print("not in state")
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    state = PROC_STATE[proc]
    state.visited.clear()
    exit_code = util.GetExitCode()
    description = "Exited with code {}".format(exit_code)
    with commands.STATE.client.batch():
        with trace.open_tx(description):
            state.record_exited(exit_code, description)
            commands.activate()


@log_errors
def on_modules_changed(*args):
    # print("ON_MODULES_CHANGED")
    proc = util.selected_process()
    if proc not in PROC_STATE:
        return DbgEng.DEBUG_STATUS_GO
    PROC_STATE[proc].modules = True
    return DbgEng.DEBUG_STATUS_GO


def on_breakpoint_created(bp):
    # print("ON_BREAKPOINT_CREATED")
    proc = util.selected_process()
    if proc not in PROC_STATE:
        return
    PROC_STATE[proc].breaks = True
    trace = commands.STATE.trace
    if trace is None:
        return
    ibpath = commands.PROC_BREAKS_PATTERN.format(procnum=proc)
    with commands.STATE.client.batch():
        with trace.open_tx("Breakpoint {} created".format(bp.GetId())):
            ibobj = trace.create_object(ibpath)
            # Do not use retain_values or it'll remove other locs
            commands.put_single_breakpoint(bp, ibobj, proc, [])
            ibobj.insert()


def on_breakpoint_modified(*args):
    # print("BREAKPOINT_MODIFIED")
    proc = util.selected_process()
    if proc not in PROC_STATE:
        return
    PROC_STATE[proc].breaks = True
    trace = commands.STATE.trace
    if trace is None:
        return
    ibpath = commands.PROC_BREAKS_PATTERN.format(procnum=proc)
    ibobj = trace.create_object(ibpath)
    bpid = args[0][1]
    try:
        bp = util.dbg._base._control.GetBreakpointById(bpid)
    except exception.E_NOINTERFACE_Error:
        util.dbg._base.breakpoints._remove_stale(bpid)
        return on_breakpoint_deleted(bpid)
    return on_breakpoint_created(bp)


def on_breakpoint_deleted(bpid):
    proc = util.selected_process()
    if proc not in PROC_STATE:
        return
    PROC_STATE[proc].breaks = True
    trace = commands.STATE.trace
    if trace is None:
        return
    bpath = commands.PROC_BREAK_PATTERN.format(procnum=proc, breaknum=bpid)
    with commands.STATE.client.batch():
        with trace.open_tx("Breakpoint {} deleted".format(bpid)):
            trace.proxy_object_path(bpath).remove(tree=True)


@log_errors
def on_breakpoint_hit(*args):
    # print("ON_BREAKPOINT_HIT: args={}".format(args))
    return DbgEng.DEBUG_STATUS_BREAK


@log_errors
def on_exception(*args):
    # print("ON_EXCEPTION: args={}".format(args))
    return DbgEng.DEBUG_STATUS_BREAK


@util.dbg.eng_thread
def install_hooks():
    # print("Installing hooks")
    if HOOK_STATE.installed:
        return
    HOOK_STATE.installed = True

    events = util.dbg._base.events

    events.engine_state(handler=on_state_changed)
    events.debuggee_state(handler=on_debuggee_changed)
    events.session_status(handler=on_session_status_changed)
    events.symbol_state(handler=on_symbol_state_changed)
    events.system_error(handler=on_system_error)

    events.create_process(handler=on_new_process)
    events.exit_process(handler=on_process_deleted)
    events.create_thread(handler=on_threads_changed)
    events.exit_thread(handler=on_threads_changed)
    events.module_load(handler=on_modules_changed)
    events.unload_module(handler=on_modules_changed)

    events.breakpoint(handler=on_breakpoint_hit)
    events.exception(handler=on_exception)


@util.dbg.eng_thread
def remove_hooks():
    # print("Removing hooks")
    if not HOOK_STATE.installed:
        return
    HOOK_STATE.installed = False
    util.dbg._base._reset_callbacks()


def enable_current_process():
    # print("Enable current process")
    proc = util.selected_process()
    # print("proc: {}".format(proc))
    PROC_STATE[proc] = ProcessState()


def disable_current_process():
    proc = util.selected_process()
    if proc in PROC_STATE:
        # Silently ignore already disabled
        del PROC_STATE[proc]
