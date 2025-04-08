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
from concurrent.futures import Future, ThreadPoolExecutor
import re
import sys
from typing import Annotated, Any, Optional, Tuple

import lldb

from ghidratrace import sch
from ghidratrace.client import (
    MethodRegistry, ParamDesc, Address, AddressRange, TraceObject)

from . import commands, util


REGISTRY = MethodRegistry(ThreadPoolExecutor(max_workers=1))


def extre(base: re.Pattern, ext: str) -> re.Pattern:
    return re.compile(base.pattern + ext)


AVAILABLE_PATTERN = re.compile('Available\[(?P<pid>\\d*)\]')
PROCESS_PATTERN = re.compile('Processes\[(?P<procnum>\\d*)\]')
PROC_BREAKS_PATTERN = extre(PROCESS_PATTERN, '\.Breakpoints')
PROC_BREAK_PATTERN = extre(PROC_BREAKS_PATTERN, '\[(?P<breaknum>\\d*)\]')
PROC_BREAKLOC_PATTERN = extre(PROC_BREAK_PATTERN, '\[(?P<locnum>\\d*)\]')
PROC_WATCHES_PATTERN = extre(PROCESS_PATTERN, '\.Watchpoints')
PROC_WATCH_PATTERN = extre(PROC_WATCHES_PATTERN, '\[(?P<watchnum>\\d*)\]')
ENV_PATTERN = extre(PROCESS_PATTERN, '\.Environment')
THREADS_PATTERN = extre(PROCESS_PATTERN, '\.Threads')
THREAD_PATTERN = extre(THREADS_PATTERN, '\[(?P<tnum>\\d*)\]')
STACK_PATTERN = extre(THREAD_PATTERN, '\.Stack')
FRAME_PATTERN = extre(STACK_PATTERN, '\[(?P<level>\\d*)\]')
REGS_PATTERN = extre(FRAME_PATTERN, '.Registers')
MEMORY_PATTERN = extre(PROCESS_PATTERN, '\.Memory')
MODULES_PATTERN = extre(PROCESS_PATTERN, '\.Modules')


def find_availpid_by_pattern(pattern: re.Pattern, object: TraceObject, err_msg: str) -> int:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    pid = int(mat['pid'])
    return pid


def find_availpid_by_obj(object: TraceObject) -> int:
    return find_availpid_by_pattern(AVAILABLE_PATTERN, object, "an Available")


def find_proc_by_num(procnum: int) -> lldb.SBProcess:
    return util.get_process()


def find_proc_by_pattern(object: TraceObject, pattern: re.Pattern,
                         err_msg: str) -> lldb.SBProcess:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    procnum = int(mat['procnum'])
    return find_proc_by_num(procnum)


def find_proc_by_obj(object: TraceObject) -> lldb.SBProcess:
    return find_proc_by_pattern(object, PROCESS_PATTERN, "a Process")


def find_proc_by_procbreak_obj(object: TraceObject) -> lldb.SBProcess:
    return find_proc_by_pattern(object, PROC_BREAKS_PATTERN,
                                "a BreakpointLocationContainer")


def find_proc_by_procwatch_obj(object: TraceObject) -> lldb.SBProcess:
    return find_proc_by_pattern(object, PROC_WATCHES_PATTERN,
                                "a WatchpointContainer")


def find_proc_by_env_obj(object: TraceObject) -> lldb.SBProcess:
    return find_proc_by_pattern(object, ENV_PATTERN, "an Environment")


def find_proc_by_threads_obj(object: TraceObject) -> lldb.SBProcess:
    return find_proc_by_pattern(object, THREADS_PATTERN, "a ThreadContainer")


def find_proc_by_mem_obj(object: TraceObject) -> lldb.SBProcess:
    return find_proc_by_pattern(object, MEMORY_PATTERN, "a Memory")


def find_proc_by_modules_obj(object: TraceObject) -> lldb.SBProcess:
    return find_proc_by_pattern(object, MODULES_PATTERN, "a ModuleContainer")


def find_thread_by_num(proc: lldb.SBThread, tnum: int) -> lldb.SBThread:
    for t in proc.threads:
        if t.GetThreadID() == tnum:
            return t
    raise KeyError(
        f"Processes[{proc.GetProcessID()}].Threads[{tnum}] does not exist")


def find_thread_by_pattern(pattern: re.Pattern, object: TraceObject,
                           err_msg: str) -> lldb.SBThread:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    procnum = int(mat['procnum'])
    tnum = int(mat['tnum'])
    proc = find_proc_by_num(procnum)
    return find_thread_by_num(proc, tnum)


def find_thread_by_obj(object: TraceObject) -> lldb.SBThread:
    return find_thread_by_pattern(THREAD_PATTERN, object, "a Thread")


def find_thread_by_stack_obj(object: TraceObject) -> lldb.SBThread:
    return find_thread_by_pattern(STACK_PATTERN, object, "a Stack")


def find_frame_by_level(thread: lldb.SBThread, level: int) -> lldb.SBFrame:
    return thread.GetFrameAtIndex(level)


def find_frame_by_pattern(pattern: re.Pattern, object: TraceObject, err_msg: str) -> lldb.SBFrame:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    procnum = int(mat['procnum'])
    tnum = int(mat['tnum'])
    level = int(mat['level'])
    proc = find_proc_by_num(procnum)
    t = find_thread_by_num(proc, tnum)
    return find_frame_by_level(t, level)


def find_frame_by_obj(object: TraceObject) -> lldb.SBFrame:
    return find_frame_by_pattern(FRAME_PATTERN, object, "a StackFrame")


def find_frame_by_regs_obj(object: TraceObject) -> lldb.SBFrame:
    return find_frame_by_pattern(REGS_PATTERN, object,
                                 "a RegisterValueContainer")


# Oof. no lldb/Python method to get breakpoint by number
# I could keep my own cache in a dict, but why?
def find_bpt_by_number(breaknum: int) -> lldb.SBBreakpoint:
    # TODO: If len exceeds some threshold, use binary search?
    for i in range(0, util.get_target().GetNumBreakpoints()):
        b = util.get_target().GetBreakpointAtIndex(i)
        if b.GetID() == breaknum:
            return b
    raise KeyError(f"Breakpoints[{breaknum}] does not exist")


def find_bpt_by_pattern(pattern: re.Pattern, object: TraceObject,
                        err_msg: str) -> lldb.SBBreakpoint:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    breaknum = int(mat['breaknum'])
    return find_bpt_by_number(breaknum)


def find_bpt_by_obj(object: TraceObject) -> lldb.SBBreakpoint:
    return find_bpt_by_pattern(PROC_BREAK_PATTERN, object, "a BreakpointSpec")


# Oof. no lldb/Python method to get breakpoint by number
# I could keep my own cache in a dict, but why?
def find_wpt_by_number(watchnum: int) -> lldb.SBWatchpoint:
    # TODO: If len exceeds some threshold, use binary search?
    for i in range(0, util.get_target().GetNumWatchpoints()):
        w = util.get_target().GetWatchpointAtIndex(i)
        if w.GetID() == watchnum:
            return w
    raise KeyError(f"Watchpoints[{watchnum}] does not exist")


def find_wpt_by_pattern(pattern: re.Pattern, object: TraceObject,
                        err_msg: str) -> lldb.SBWatchpoint:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    watchnum = int(mat['watchnum'])
    return find_wpt_by_number(watchnum)


def find_wpt_by_obj(object: TraceObject) -> lldb.SBWatchpoint:
    return find_wpt_by_pattern(PROC_WATCH_PATTERN, object, "a WatchpointSpec")


def find_bptlocnum_by_pattern(pattern: re.Pattern, object: TraceObject,
                              err_msg: str) -> Tuple[int, int]:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    breaknum = int(mat['breaknum'])
    locnum = int(mat['locnum'])
    return breaknum, locnum


def find_bptlocnum_by_obj(object: TraceObject) -> Tuple[int, int]:
    return find_bptlocnum_by_pattern(PROC_BREAKLOC_PATTERN, object,
                                     "a BreakpointLocation")


def find_bpt_loc_by_obj(object: TraceObject) -> lldb.SBBreakpointLocation:
    breaknum, locnum = find_bptlocnum_by_obj(object)
    bpt = find_bpt_by_number(breaknum)
    # Requires lldb-13.1 or later
    return bpt.locations[locnum - 1]  # Display is 1-up


def exec_convert_errors(cmd: str, to_string: bool = False) -> Optional[str]:
    res = lldb.SBCommandReturnObject()
    util.get_debugger().GetCommandInterpreter().HandleCommand(cmd, res)
    if not res.Succeeded():
        if not to_string:
            print(res.GetError(), file=sys.stderr)
        raise RuntimeError(res.GetError())
    if to_string:
        return res.GetOutput()
    print(res.GetOutput(), end="")
    return None


class Attachable(TraceObject):
    pass


class AvailableContainer(TraceObject):
    pass


class BreakpointContainer(TraceObject):
    pass


class BreakpointLocation(TraceObject):
    pass


class BreakpointSpec(TraceObject):
    pass


class Environment(TraceObject):
    pass


class Memory(TraceObject):
    pass


class ModuleContainer(TraceObject):
    pass


class Process(TraceObject):
    pass


class ProcessContainer(TraceObject):
    pass


class RegisterValueContainer(TraceObject):
    pass


class Stack(TraceObject):
    pass


class StackFrame(TraceObject):
    pass


class Thread(TraceObject):
    pass


class ThreadContainer(TraceObject):
    pass


class WatchpointContainer(TraceObject):
    pass


class WatchpointSpec(TraceObject):
    pass


@REGISTRY.method()
def execute(cmd: str, to_string: bool = False) -> Optional[str]:
    """Execute a CLI command."""
    # TODO: Check for eCommandInterpreterResultQuitRequested?
    return exec_convert_errors(cmd, to_string)


@REGISTRY.method(display='Evaluate')
def evaluate(expr: str) -> Any:
    """Evaluate an expression."""
    value = util.get_target().EvaluateExpression(expr)
    if value.GetError().Fail():
        raise RuntimeError(value.GetError().GetCString())
    return commands.eval_value(value)


@REGISTRY.method(display="Python Evaluate")
def pyeval(expr: str) -> Any:
    return eval(expr)


@REGISTRY.method(action='refresh', display="Refresh Available")
def refresh_available(node: AvailableContainer) -> None:
    """List processes on lldb's host system."""
    with commands.open_tracked_tx('Refresh Available'):
        exec_convert_errors('ghidra trace put-available')


@REGISTRY.method(action='refresh', display="Refresh Processes")
def refresh_processes(node: ProcessContainer) -> None:
    """Refresh the list of processes."""
    with commands.open_tracked_tx('Refresh Processes'):
        exec_convert_errors('ghidra trace put-threads')


@REGISTRY.method(action='refresh', display="Refresh Breakpoints")
def refresh_proc_breakpoints(node: BreakpointContainer) -> None:
    """Refresh the breakpoints for the process."""
    with commands.open_tracked_tx('Refresh Breakpoint Locations'):
        exec_convert_errors('ghidra trace put-breakpoints')


@REGISTRY.method(action='refresh', display="Refresh Watchpoints")
def refresh_proc_watchpoints(node: WatchpointContainer) -> None:
    """Refresh the watchpoints for the process."""
    with commands.open_tracked_tx('Refresh Watchpoint Locations'):
        exec_convert_errors('ghidra trace put-watchpoints')


@REGISTRY.method(action='refresh', display="Refresh Environment")
def refresh_environment(node: Environment) -> None:
    """Refresh the environment descriptors (arch, os, endian)."""
    with commands.open_tracked_tx('Refresh Environment'):
        exec_convert_errors('ghidra trace put-environment')


@REGISTRY.method(action='refresh', display="Refresh Threads")
def refresh_threads(node: ThreadContainer) -> None:
    """Refresh the list of threads in the process."""
    with commands.open_tracked_tx('Refresh Threads'):
        exec_convert_errors('ghidra trace put-threads')


@REGISTRY.method(action='refresh', display="Refresh Stack")
def refresh_stack(node: Stack) -> None:
    """Refresh the backtrace for the thread."""
    t = find_thread_by_stack_obj(node)
    t.process.SetSelectedThread(t)
    with commands.open_tracked_tx('Refresh Stack'):
        exec_convert_errors('ghidra trace put-frames')


@REGISTRY.method(action='refresh', display="Refresh Registers")
def refresh_registers(node: RegisterValueContainer) -> None:
    """Refresh the register values for the frame."""
    f = find_frame_by_regs_obj(node)
    f.thread.SetSelectedFrame(f.GetFrameID())
    # TODO: Groups?
    with commands.open_tracked_tx('Refresh Registers'):
        exec_convert_errors('ghidra trace putreg')


@REGISTRY.method(action='refresh', display="Refresh Memory")
def refresh_mappings(node: Memory) -> None:
    """Refresh the list of memory regions for the process."""
    with commands.open_tracked_tx('Refresh Memory Regions'):
        exec_convert_errors('ghidra trace put-regions')


@REGISTRY.method(action='refresh', display="Refresh Modules")
def refresh_modules(node: ModuleContainer) -> None:
    """Refresh the modules and sections list for the process.

    This will refresh the sections for all modules, not just the
    selected one.
    """
    with commands.open_tracked_tx('Refresh Modules'):
        exec_convert_errors('ghidra trace put-modules')


@REGISTRY.method(action='activate', display='Activate Process')
def activate_process(process: Process) -> None:
    """Switch to the process."""
    # TODO
    return


@REGISTRY.method(action='activate', display='Activate Thread')
def activate_thread(thread: Thread) -> None:
    """Switch to the thread."""
    t = find_thread_by_obj(thread)
    t.process.SetSelectedThread(t)


@REGISTRY.method(action='activate', display='Activate Frame')
def activate_frame(frame: StackFrame) -> None:
    """Select the frame."""
    f = find_frame_by_obj(frame)
    f.thread.SetSelectedFrame(f.GetFrameID())


@REGISTRY.method(action='delete', display='Remove Process')
def remove_process(process: Process) -> None:
    """Remove the process."""
    proc = find_proc_by_obj(process)
    exec_convert_errors(f'target delete 0')


@REGISTRY.method(action='connect', display="Connect Target")
def target(process: Process, spec: str) -> None:
    """Connect to a target machine or process."""
    exec_convert_errors(f'target select {spec}')


@REGISTRY.method(action='attach', display="Attach by Attachable")
def attach_obj(process: Process, target: Attachable) -> None:
    """Attach the process to the given target."""
    pid = find_availpid_by_obj(target)
    exec_convert_errors(f'process attach -p {pid}')


@REGISTRY.method(action='attach', display="Attach by PID")
def attach_pid(process: Process, pid: int) -> None:
    """Attach the process to the given target."""
    exec_convert_errors(f'process attach -p {pid}')


@REGISTRY.method(action='attach', display="Attach by Name")
def attach_name(process: Process, name: str) -> None:
    """Attach the process to the given target."""
    exec_convert_errors(f'process attach -n {name}')


@REGISTRY.method(display="Detach")
def detach(process: Process) -> None:
    """Detach the process's target."""
    exec_convert_errors(f'process detach')


def do_launch(process: Process, file: str, args: str, cmd: str):
    exec_convert_errors(f'file {file}')
    if args != '':
        exec_convert_errors(f'settings set target.run-args {args}')
    exec_convert_errors(cmd)


@REGISTRY.method(action='launch', display="Launch at Entry")
def launch_loader(process: Process,
                  file: Annotated[str, ParamDesc(display='File')],
                  args: Annotated[str, ParamDesc(display='Arguments')] = '') -> None:
    """Start a native process with the given command line, stopping at 'main'.

    If 'main' is not defined in the file, this behaves like 'run'.
    """
    do_launch(process, file, args, 'process launch --stop-at-entry')


@REGISTRY.method(action='launch', display="Launch and Run")
def launch(process: Process,
           file: Annotated[str, ParamDesc(display='File')],
           args: Annotated[str, ParamDesc(display='Arguments')] = '') -> None:
    """Run a native process with the given command line.

    The process will not stop until it hits one of your breakpoints, or
    it is signaled.
    """
    do_launch(process, file, args, 'run')


@REGISTRY.method()
def kill(process: Process) -> None:
    """Kill execution of the process."""
    exec_convert_errors('process kill')


@REGISTRY.method(name='continue', action='resume', display="Continue")
def _continue(process: Process):
    """Continue execution of the process."""
    exec_convert_errors('process continue')


@REGISTRY.method()
def interrupt(process: Process):
    """Interrupt the execution of the debugged program."""
    exec_convert_errors('process interrupt')
    # util.get_process().SendAsyncInterrupt()
    # exec_convert_errors('^c')
    # util.get_process().Signal(2)


@REGISTRY.method(action='step_into')
def step_into(thread: Thread,
              n: Annotated[int, ParamDesc(display='N')] = 1) -> None:
    """Step one instruction exactly."""
    t = find_thread_by_obj(thread)
    t.process.SetSelectedThread(t)
    exec_convert_errors('thread step-inst')


@REGISTRY.method(action='step_over')
def step_over(thread: Thread,
              n: Annotated[int, ParamDesc(display='N')] = 1) -> None:
    """Step one instruction, but proceed through subroutine calls."""
    t = find_thread_by_obj(thread)
    t.process.SetSelectedThread(t)
    exec_convert_errors('thread step-inst-over')


@REGISTRY.method(action='step_out')
def step_out(thread: Thread) -> None:
    """Execute until the current stack frame returns."""
    if thread is not None:
        t = find_thread_by_obj(thread)
        t.process.SetSelectedThread(t)
    exec_convert_errors('thread step-out')


@REGISTRY.method(action='step_ext', display="Advance")
def step_advance(thread: Thread, address: Address) -> None:
    """Continue execution up to the given address."""
    t = find_thread_by_obj(thread)
    t.process.SetSelectedThread(t)
    offset = thread.trace.extra.require_mm().map_back(t.process, address)
    exec_convert_errors(f'thread until -a {offset}')


@REGISTRY.method(action='step_ext', display="Return")
def step_return(thread: Thread, value: Optional[int] = None) -> None:
    """Skip the remainder of the current function."""
    t = find_thread_by_obj(thread)
    t.process.SetSelectedThread(t)
    if value is None:
        exec_convert_errors('thread return')
    else:
        exec_convert_errors(f'thread return {value}')


@REGISTRY.method(action='break_sw_execute')
def break_address(process: Process, address: Address) -> None:
    """Set a breakpoint."""
    proc = find_proc_by_obj(process)
    offset = process.trace.extra.require_mm().map_back(proc, address)
    exec_convert_errors(f'breakpoint set -a 0x{offset:x}')


@REGISTRY.method(action='break_ext', display='Set Breakpoint')
def break_expression(expression: str):
    """Set a breakpoint."""
    # TODO: Escape?
    exec_convert_errors(f'breakpoint set -r {expression}')


@REGISTRY.method(action='break_hw_execute')
def break_hw_address(process: Process, address: Address) -> None:
    """Set a hardware-assisted breakpoint."""
    proc = find_proc_by_obj(process)
    offset = process.trace.extra.require_mm().map_back(proc, address)
    exec_convert_errors(f'breakpoint set -H -a 0x{offset:x}')


@REGISTRY.method(action='break_ext', display='Set Hardware Breakpoint')
def break_hw_expression(expression: str) -> None:
    """Set a hardware-assisted breakpoint."""
    # TODO: Escape?
    exec_convert_errors(f'breakpoint set -H -name {expression}')


@REGISTRY.method(action='break_read')
def break_read_range(process: Process, range: AddressRange) -> None:
    """Set a read watchpoint."""
    proc = find_proc_by_obj(process)
    offset_start = process.trace.extra.require_mm().map_back(
        proc, Address(range.space, range.min))
    sz = range.length()
    exec_convert_errors(
        f'watchpoint set expression -s {sz} -w read -- {offset_start}')


@REGISTRY.method(action='break_ext', display='Set Read Watchpoint')
def break_read_expression(expression: str, size: Optional[str] = None) -> None:
    """Set a read watchpoint."""
    size_part = '' if size is None else f'-s {size}'
    exec_convert_errors(
        f'watchpoint set expression {size_part} -w read -- {expression}')


@REGISTRY.method(action='break_write')
def break_write_range(process: Process, range: AddressRange) -> None:
    """Set a watchpoint."""
    proc = find_proc_by_obj(process)
    offset_start = process.trace.extra.require_mm().map_back(
        proc, Address(range.space, range.min))
    sz = range.length()
    exec_convert_errors(
        f'watchpoint set expression -s {sz} -- {offset_start}')


@REGISTRY.method(action='break_ext', display='Set Watchpoint')
def break_write_expression(expression: str, size: Optional[str] = None) -> None:
    """Set a watchpoint."""
    size_part = '' if size is None else f'-s {size}'
    exec_convert_errors(
        f'watchpoint set expression {size_part} -- {expression}')


@REGISTRY.method(action='break_access')
def break_access_range(process: Process, range: AddressRange) -> None:
    """Set a read/write watchpoint."""
    proc = find_proc_by_obj(process)
    offset_start = process.trace.extra.require_mm().map_back(
        proc, Address(range.space, range.min))
    sz = range.length()
    exec_convert_errors(
        f'watchpoint set expression -s {sz} -w read_write -- {offset_start}')


@REGISTRY.method(action='break_ext', display='Set Read/Write Watchpoint')
def break_access_expression(expression: str,
                            size: Optional[str] = None) -> None:
    """Set a read/write watchpoint."""
    size_part = '' if size is None else f'-s {size}'
    exec_convert_errors(
        f'watchpoint set expression {size_part} -w read_write -- {expression}')


@REGISTRY.method(action='break_ext', display="Break on Exception")
def break_exception(lang: str) -> None:
    """Set a catchpoint."""
    exec_convert_errors(f'breakpoint set -E {lang}')


@REGISTRY.method(action='toggle', display='Toggle Watchpoint')
def toggle_watchpoint(watchpoint: WatchpointSpec, enabled: bool) -> None:
    """Toggle a watchpoint."""
    wpt = find_wpt_by_obj(watchpoint)
    wpt.enabled = enabled
    cmd = 'enable' if enabled else 'disable'
    exec_convert_errors(f'watchpoint {cmd} {wpt.GetID()}')


@REGISTRY.method(action='toggle', display='Toggle Breakpoint')
def toggle_breakpoint(breakpoint: BreakpointSpec, enabled: bool) -> None:
    """Toggle a breakpoint."""
    bpt = find_bpt_by_obj(breakpoint)
    cmd = 'enable' if enabled else 'disable'
    exec_convert_errors(f'breakpoint {cmd} {bpt.GetID()}')


@REGISTRY.method(action='toggle', display='Toggle Breakpoint Location')
def toggle_breakpoint_location(location: BreakpointLocation,
                               enabled: bool) -> None:
    """Toggle a breakpoint location."""
    bptnum, locnum = find_bptlocnum_by_obj(location)
    cmd = 'enable' if enabled else 'disable'
    exec_convert_errors(f'breakpoint {cmd} {bptnum}.{locnum}')


@REGISTRY.method(action='delete', display='Delete Watchpoint')
def delete_watchpoint(watchpoint: WatchpointSpec) -> None:
    """Delete a watchpoint."""
    wpt = find_wpt_by_obj(watchpoint)
    wptnum = wpt.GetID()
    exec_convert_errors(f'watchpoint delete {wptnum}')


@REGISTRY.method(action='delete', display='Delete Breakpoint')
def delete_breakpoint(breakpoint: BreakpointSpec) -> None:
    """Delete a breakpoint."""
    bpt = find_bpt_by_obj(breakpoint)
    bptnum = bpt.GetID()
    exec_convert_errors(f'breakpoint delete {bptnum}')


@REGISTRY.method()
def read_mem(process: Process, range: AddressRange) -> None:
    """Read memory."""
    proc = find_proc_by_obj(process)
    offset_start = process.trace.extra.require_mm().map_back(
        proc, Address(range.space, range.min))
    ci = util.get_debugger().GetCommandInterpreter()
    with commands.open_tracked_tx('Read Memory'):
        result = lldb.SBCommandReturnObject()
        ci.HandleCommand(
            f'ghidra trace putmem 0x{offset_start:x} {range.length()}', result)
        if result.Succeeded():
            return
        # print(f"Could not read 0x{offset_start:x}: {result}")
        exec_convert_errors(
            f'ghidra trace putmem-state 0x{offset_start:x} {range.length()} error')


@REGISTRY.method()
def write_mem(process: Process, address: Address, data: bytes) -> None:
    """Write memory."""
    proc = find_proc_by_obj(process)
    offset = process.trace.extra.require_mm().map_back(proc, address)
    proc.write_memory(offset, data)


@REGISTRY.method()
def write_reg(frame: StackFrame, name: str, value: bytes) -> None:
    """Write a register."""
    f = find_frame_by_obj(frame)
    f.select()
    proc = lldb.selected_process()
    mname, mval = frame.trace.extra.require_rm().map_value_back(proc, name, value)
    size = int(lldb.parse_and_eval(f'sizeof(${mname})'))
    arr = '{' + ','.join(str(b) for b in mval) + '}'
    exec_convert_errors(
        f'expr ((unsigned char[{size}])${mname}) = {arr};')
