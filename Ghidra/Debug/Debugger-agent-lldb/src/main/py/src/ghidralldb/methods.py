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

from ghidratrace import sch
from ghidratrace.client import MethodRegistry, ParamDesc, Address, AddressRange

import lldb

from . import commands, util


REGISTRY = MethodRegistry(ThreadPoolExecutor(max_workers=1))


def extre(base, ext):
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


def find_availpid_by_pattern(pattern, object, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    pid = int(mat['pid'])
    return pid


def find_availpid_by_obj(object):
    return find_availpid_by_pattern(AVAILABLE_PATTERN, object, "an Available")


def find_proc_by_num(procnum):
    return util.get_process()


def find_proc_by_pattern(object, pattern, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    procnum = int(mat['procnum'])
    return find_proc_by_num(procnum)


def find_proc_by_obj(object):
    return find_proc_by_pattern(object, PROCESS_PATTERN, "a Process")


def find_proc_by_procbreak_obj(object):
    return find_proc_by_pattern(object, PROC_BREAKS_PATTERN,
                                "a BreakpointLocationContainer")


def find_proc_by_procwatch_obj(object):
    return find_proc_by_pattern(object, PROC_WATCHES_PATTERN,
                                "a WatchpointContainer")


def find_proc_by_env_obj(object):
    return find_proc_by_pattern(object, ENV_PATTERN, "an Environment")


def find_proc_by_threads_obj(object):
    return find_proc_by_pattern(object, THREADS_PATTERN, "a ThreadContainer")


def find_proc_by_mem_obj(object):
    return find_proc_by_pattern(object, MEMORY_PATTERN, "a Memory")


def find_proc_by_modules_obj(object):
    return find_proc_by_pattern(object, MODULES_PATTERN, "a ModuleContainer")


def find_thread_by_num(proc, tnum):
    for t in proc.threads:
        if t.GetThreadID() == tnum:
            return t
    raise KeyError(
        f"Processes[{proc.GetProcessID()}].Threads[{tnum}] does not exist")


def find_thread_by_pattern(pattern, object, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    procnum = int(mat['procnum'])
    tnum = int(mat['tnum'])
    proc = find_proc_by_num(procnum)
    return find_thread_by_num(proc, tnum)


def find_thread_by_obj(object):
    return find_thread_by_pattern(THREAD_PATTERN, object, "a Thread")


def find_thread_by_stack_obj(object):
    return find_thread_by_pattern(STACK_PATTERN, object, "a Stack")


def find_frame_by_level(thread, level):
    return thread.GetFrameAtIndex(level)


def find_frame_by_pattern(pattern, object, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    procnum = int(mat['procnum'])
    tnum = int(mat['tnum'])
    level = int(mat['level'])
    proc = find_proc_by_num(procnum)
    t = find_thread_by_num(proc, tnum)
    return find_frame_by_level(t, level)


def find_frame_by_obj(object):
    return find_frame_by_pattern(FRAME_PATTERN, object, "a StackFrame")


def find_frame_by_regs_obj(object):
    return find_frame_by_pattern(REGS_PATTERN, object,
                                 "a RegisterValueContainer")


# Because there's no method to get a register by name....
def find_reg_by_name(f, name):
    for reg in f.architecture().registers():
        if reg.name == name:
            return reg
    raise KeyError(f"No such register: {name}")


# Oof. no lldb/Python method to get breakpoint by number
# I could keep my own cache in a dict, but why?
def find_bpt_by_number(breaknum):
    # TODO: If len exceeds some threshold, use binary search?
    for i in range(0, util.get_target().GetNumBreakpoints()):
        b = util.get_target().GetBreakpointAtIndex(i)
        if b.GetID() == breaknum:
            return b
    raise KeyError(f"Breakpoints[{breaknum}] does not exist")


def find_bpt_by_pattern(pattern, object, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    breaknum = int(mat['breaknum'])
    return find_bpt_by_number(breaknum)


def find_bpt_by_obj(object):
    return find_bpt_by_pattern(PROC_BREAK_PATTERN, object, "a BreakpointSpec")


# Oof. no lldb/Python method to get breakpoint by number
# I could keep my own cache in a dict, but why?
def find_wpt_by_number(watchnum):
    # TODO: If len exceeds some threshold, use binary search?
    for i in range(0, util.get_target().GetNumWatchpoints()):
        w = util.get_target().GetWatchpointAtIndex(i)
        if w.GetID() == watchnum:
            return w
    raise KeyError(f"Watchpoints[{watchnum}] does not exist")


def find_wpt_by_pattern(pattern, object, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    watchnum = int(mat['watchnum'])
    return find_wpt_by_number(watchnum)


def find_wpt_by_obj(object):
    return find_wpt_by_pattern(PROC_WATCH_PATTERN, object, "a WatchpointSpec")


def find_bptlocnum_by_pattern(pattern, object, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypError(f"{object} is not {err_msg}")
    breaknum = int(mat['breaknum'])
    locnum = int(mat['locnum'])
    return breaknum, locnum


def find_bptlocnum_by_obj(object):
    return find_bptlocnum_by_pattern(PROC_BREAKLOC_PATTERN, object,
                                     "a BreakpointLocation")


def find_bpt_loc_by_obj(object):
    breaknum, locnum = find_bptlocnum_by_obj(object)
    bpt = find_bpt_by_number(breaknum)
    # Requires lldb-13.1 or later
    return bpt.locations[locnum - 1]  # Display is 1-up


def exec_convert_errors(cmd, to_string=False):
    res = lldb.SBCommandReturnObject()
    util.get_debugger().GetCommandInterpreter().HandleCommand(cmd, res)
    if not res.Succeeded():
        if not to_string:
            print(res.GetError(), file=sys.stderr)
        raise RuntimeError(res.GetError())
    if to_string:
        return res.GetOutput()
    print(res.GetOutput(), end="")


@REGISTRY.method
def execute(cmd: str, to_string: bool=False):
    """Execute a CLI command."""
    # TODO: Check for eCommandInterpreterResultQuitRequested?
    return exec_convert_errors(cmd, to_string)


@REGISTRY.method
def evaluate(expr: str):
    """Evaluate an expression."""
    value = util.get_target().EvaluateExpression(expr)
    if value.GetError().Fail():
        raise RuntimeError(value.GetError().GetCString())
    return commands.convert_value(value)


@REGISTRY.method
def pyeval(expr: str):
    return eval(expr)


@REGISTRY.method(action='refresh', display="Refresh Available")
def refresh_available(node: sch.Schema('AvailableContainer')):
    """List processes on lldb's host system."""
    with commands.open_tracked_tx('Refresh Available'):
        exec_convert_errors('ghidra trace put-available')


@REGISTRY.method(action='refresh', display="Refresh Processes")
def refresh_processes(node: sch.Schema('ProcessContainer')):
    """Refresh the list of processes."""
    with commands.open_tracked_tx('Refresh Processes'):
        exec_convert_errors('ghidra trace put-threads')


@REGISTRY.method(action='refresh', display="Refresh Breakpoints")
def refresh_proc_breakpoints(node: sch.Schema('BreakpointContainer')):
    """
    Refresh the breakpoints for the process.
    """
    with commands.open_tracked_tx('Refresh Breakpoint Locations'):
        exec_convert_errors('ghidra trace put-breakpoints')


@REGISTRY.method(action='refresh', display="Refresh Watchpoints")
def refresh_proc_watchpoints(node: sch.Schema('WatchpointContainer')):
    """
    Refresh the watchpoints for the process.
    """
    with commands.open_tracked_tx('Refresh Watchpoint Locations'):
        exec_convert_errors('ghidra trace put-watchpoints')


@REGISTRY.method(action='refresh', display="Refresh Environment")
def refresh_environment(node: sch.Schema('Environment')):
    """Refresh the environment descriptors (arch, os, endian)."""
    with commands.open_tracked_tx('Refresh Environment'):
        exec_convert_errors('ghidra trace put-environment')


@REGISTRY.method(action='refresh', display="Refresh Threads")
def refresh_threads(node: sch.Schema('ThreadContainer')):
    """Refresh the list of threads in the process."""
    with commands.open_tracked_tx('Refresh Threads'):
        exec_convert_errors('ghidra trace put-threads')


@REGISTRY.method(action='refresh', display="Refresh Stack")
def refresh_stack(node: sch.Schema('Stack')):
    """Refresh the backtrace for the thread."""
    t = find_thread_by_stack_obj(node)
    t.process.SetSelectedThread(t)
    with commands.open_tracked_tx('Refresh Stack'):
        exec_convert_errors('ghidra trace put-frames')


@REGISTRY.method(action='refresh', display="Refresh Registers")
def refresh_registers(node: sch.Schema('RegisterValueContainer')):
    """Refresh the register values for the frame."""
    f = find_frame_by_regs_obj(node)
    f.thread.SetSelectedFrame(f.GetFrameID())
    # TODO: Groups?
    with commands.open_tracked_tx('Refresh Registers'):
        exec_convert_errors('ghidra trace putreg')


@REGISTRY.method(action='refresh', display="Refresh Memory")
def refresh_mappings(node: sch.Schema('Memory')):
    """Refresh the list of memory regions for the process."""
    with commands.open_tracked_tx('Refresh Memory Regions'):
        exec_convert_errors('ghidra trace put-regions')


@REGISTRY.method(action='refresh', display="Refresh Modules")
def refresh_modules(node: sch.Schema('ModuleContainer')):
    """
    Refresh the modules and sections list for the process.

    This will refresh the sections for all modules, not just the selected one.
    """
    with commands.open_tracked_tx('Refresh Modules'):
        exec_convert_errors('ghidra trace put-modules')


@REGISTRY.method(action='activate')
def activate_process(process: sch.Schema('Process')):
    """Switch to the process."""
    # TODO
    return


@REGISTRY.method(action='activate')
def activate_thread(thread: sch.Schema('Thread')):
    """Switch to the thread."""
    t = find_thread_by_obj(thread)
    t.process.SetSelectedThread(t)


@REGISTRY.method(action='activate')
def activate_frame(frame: sch.Schema('StackFrame')):
    """Select the frame."""
    f = find_frame_by_obj(frame)
    f.thread.SetSelectedFrame(f.GetFrameID())


@REGISTRY.method(action='delete')
def remove_process(process: sch.Schema('Process')):
    """Remove the process."""
    proc = find_proc_by_obj(process)
    exec_convert_errors(f'target delete 0')


@REGISTRY.method(action='connect', display="Connect Target")
def target(process: sch.Schema('Process'), spec: str):
    """Connect to a target machine or process."""
    exec_convert_errors(f'target select {spec}')


@REGISTRY.method(action='attach', display="Attach by Attachable")
def attach_obj(process: sch.Schema('Process'), target: sch.Schema('Attachable')):
    """Attach the process to the given target."""
    pid = find_availpid_by_obj(target)
    exec_convert_errors(f'process attach -p {pid}')


@REGISTRY.method(action='attach', display="Attach by PID")
def attach_pid(process: sch.Schema('Process'), pid: int):
    """Attach the process to the given target."""
    exec_convert_errors(f'process attach -p {pid}')


@REGISTRY.method(action='attach', display="Attach by Name")
def attach_name(process: sch.Schema('Process'), name: str):
    """Attach the process to the given target."""
    exec_convert_errors(f'process attach -n {name}')


@REGISTRY.method(display="Detach")
def detach(process: sch.Schema('Process')):
    """Detach the process's target."""
    exec_convert_errors(f'process detach')


def do_launch(process, file, args, cmd):
    exec_convert_errors(f'file {file}')
    if args != '':
        exec_convert_errors(f'settings set target.run-args {args}')
    exec_convert_errors(cmd)


@REGISTRY.method(action='launch', display="Launch at Entry")
def launch_loader(process: sch.Schema('Process'),
                  file: ParamDesc(str, display='File'),
                  args: ParamDesc(str, display='Arguments')=''):
    """
    Start a native process with the given command line, stopping at 'main'.

    If 'main' is not defined in the file, this behaves like 'run'.
    """
    do_launch(process, file, args, 'process launch --stop-at-entry')


@REGISTRY.method(action='launch', display="Launch and Run")
def launch(process: sch.Schema('Process'),
           file: ParamDesc(str, display='File'),
           args: ParamDesc(str, display='Arguments')=''):
    """
    Run a native process with the given command line.

    The process will not stop until it hits one of your breakpoints, or it is
    signaled.
    """
    do_launch(process, file, args, 'run')


@REGISTRY.method
def kill(process: sch.Schema('Process')):
    """Kill execution of the process."""
    exec_convert_errors('process kill')


@REGISTRY.method(name='continue', action='resume')
def _continue(process: sch.Schema('Process')):
    """Continue execution of the process."""
    exec_convert_errors('process continue')


@REGISTRY.method
def interrupt(process: sch.Schema('Process')):
    """Interrupt the execution of the debugged program."""
    exec_convert_errors('process interrupt')
    # util.get_process().SendAsyncInterrupt()
    # exec_convert_errors('^c')
    # util.get_process().Signal(2)


@REGISTRY.method(action='step_into')
def step_into(thread: sch.Schema('Thread'), n: ParamDesc(int, display='N')=1):
    """Step on instruction exactly."""
    t = find_thread_by_obj(thread)
    t.process.SetSelectedThread(t)
    exec_convert_errors('thread step-inst')


@REGISTRY.method(action='step_over')
def step_over(thread: sch.Schema('Thread'), n: ParamDesc(int, display='N')=1):
    """Step one instruction, but proceed through subroutine calls."""
    t = find_thread_by_obj(thread)
    t.process.SetSelectedThread(t)
    exec_convert_errors('thread step-inst-over')


@REGISTRY.method(action='step_out')
def step_out(thread: sch.Schema('Thread')):
    """Execute until the current stack frame returns."""
    if thread is not None:
        t = find_thread_by_obj(thread)
        t.process.SetSelectedThread(t)
    exec_convert_errors('thread step-out')


@REGISTRY.method(action='step_ext', display="Advance")
def step_advance(thread: sch.Schema('Thread'), address: Address):
    """Continue execution up to the given address."""
    t = find_thread_by_obj(thread)
    t.process.SetSelectedThread(t)
    offset = thread.trace.memory_mapper.map_back(t.process, address)
    exec_convert_errors(f'thread until -a {offset}')


@REGISTRY.method(action='step_ext', display="Return")
def step_return(thread: sch.Schema('Thread'), value: int=None):
    """Skip the remainder of the current function."""
    t = find_thread_by_obj(thread)
    t.process.SetSelectedThread(t)
    if value is None:
        exec_convert_errors('thread return')
    else:
        exec_convert_errors(f'thread return {value}')


@REGISTRY.method(action='break_sw_execute')
def break_address(process: sch.Schema('Process'), address: Address):
    """Set a breakpoint."""
    proc = find_proc_by_obj(process)
    offset = process.trace.memory_mapper.map_back(proc, address)
    exec_convert_errors(f'breakpoint set -a 0x{offset:x}')


@REGISTRY.method(action='break_sw_execute')
def break_expression(expression: str):
    """Set a breakpoint."""
    # TODO: Escape?
    exec_convert_errors(f'breakpoint set -r {expression}')


@REGISTRY.method(action='break_hw_execute')
def break_hw_address(process: sch.Schema('Process'), address: Address):
    """Set a hardware-assisted breakpoint."""
    proc = find_proc_by_obj(process)
    offset = process.trace.memory_mapper.map_back(proc, address)
    exec_convert_errors(f'breakpoint set -H -a 0x{offset:x}')


@REGISTRY.method(action='break_hw_execute')
def break_hw_expression(expression: str):
    """Set a hardware-assisted breakpoint."""
    # TODO: Escape?
    exec_convert_errors(f'breakpoint set -H -name {expression}')


@REGISTRY.method(action='break_read')
def break_read_range(process: sch.Schema('Process'), range: AddressRange):
    """Set a read watchpoint."""
    proc = find_proc_by_obj(process)
    offset_start = process.trace.memory_mapper.map_back(
        proc, Address(range.space, range.min))
    sz = range.length()
    exec_convert_errors(
        f'watchpoint set expression -s {sz} -w read -- {offset_start}')


@REGISTRY.method(action='break_read')
def break_read_expression(expression: str, size=None):
    """Set a read watchpoint."""
    size_part = '' if size is None else f'-s {size}'
    exec_convert_errors(
        f'watchpoint set expression {size_part} -w read -- {expression}')


@REGISTRY.method(action='break_write')
def break_write_range(process: sch.Schema('Process'), range: AddressRange):
    """Set a watchpoint."""
    proc = find_proc_by_obj(process)
    offset_start = process.trace.memory_mapper.map_back(
        proc, Address(range.space, range.min))
    sz = range.length()
    exec_convert_errors(
        f'watchpoint set expression -s {sz} -- {offset_start}')


@REGISTRY.method(action='break_write')
def break_write_expression(expression: str, size=None):
    """Set a watchpoint."""
    size_part = '' if size is None else f'-s {size}'
    exec_convert_errors(
        f'watchpoint set expression {size_part} -- {expression}')


@REGISTRY.method(action='break_access')
def break_access_range(process: sch.Schema('Process'), range: AddressRange):
    """Set an access watchpoint."""
    proc = find_proc_by_obj(process)
    offset_start = process.trace.memory_mapper.map_back(
        proc, Address(range.space, range.min))
    sz = range.length()
    exec_convert_errors(
        f'watchpoint set expression -s {sz} -w read_write -- {offset_start}')


@REGISTRY.method(action='break_access')
def break_access_expression(expression: str, size=None):
    """Set an access watchpoint."""
    size_part = '' if size is None else f'-s {size}'
    exec_convert_errors(
        f'watchpoint set expression {size_part} -w read_write -- {expression}')


@REGISTRY.method(action='break_ext', display="Break on Exception")
def break_exception(lang: str):
    """Set a catchpoint."""
    exec_convert_errors(f'breakpoint set -E {lang}')


@REGISTRY.method(action='toggle')
def toggle_watchpoint(watchpoint: sch.Schema('WatchpointSpec'), enabled: bool):
    """Toggle a watchpoint."""
    wpt = find_wpt_by_obj(watchpoint)
    wpt.enabled = enabled
    cmd = 'enable' if enabled else 'disable'
    exec_convert_errors(f'watchpoint {cmd} {wpt.GetID()}')


@REGISTRY.method(action='toggle')
def toggle_breakpoint(breakpoint: sch.Schema('BreakpointSpec'), enabled: bool):
    """Toggle a breakpoint."""
    bpt = find_bpt_by_obj(breakpoint)
    cmd = 'enable' if enabled else 'disable'
    exec_convert_errors(f'breakpoint {cmd} {bpt.GetID()}')


@REGISTRY.method(action='toggle')
def toggle_breakpoint_location(location: sch.Schema('BreakpointLocation'), enabled: bool):
    """Toggle a breakpoint location."""
    bptnum, locnum = find_bptlocnum_by_obj(location)
    cmd = 'enable' if enabled else 'disable'
    exec_convert_errors(f'breakpoint {cmd} {bptnum}.{locnum}')


@REGISTRY.method(action='delete')
def delete_watchpoint(watchpoint: sch.Schema('WatchpointSpec')):
    """Delete a watchpoint."""
    wpt = find_wpt_by_obj(watchpoint)
    wptnum = wpt.GetID()
    exec_convert_errors(f'watchpoint delete {wptnum}')


@REGISTRY.method(action='delete')
def delete_breakpoint(breakpoint: sch.Schema('BreakpointSpec')):
    """Delete a breakpoint."""
    bpt = find_bpt_by_obj(breakpoint)
    bptnum = bpt.GetID()
    exec_convert_errors(f'breakpoint delete {bptnum}')


@REGISTRY.method
def read_mem(process: sch.Schema('Process'), range: AddressRange):
    """Read memory."""
    proc = find_proc_by_obj(process)
    offset_start = process.trace.memory_mapper.map_back(
        proc, Address(range.space, range.min))
    ci = util.get_debugger().GetCommandInterpreter()
    with commands.open_tracked_tx('Read Memory'):
        result = lldb.SBCommandReturnObject()
        ci.HandleCommand(
            f'ghidra trace putmem 0x{offset_start:x} {range.length()}', result)
        if result.Succeeded():
            return
        #print(f"Could not read 0x{offset_start:x}: {result}")
        exec_convert_errors(
            f'ghidra trace putmem-state 0x{offset_start:x} {range.length()} error')


@REGISTRY.method
def write_mem(process: sch.Schema('Process'), address: Address, data: bytes):
    """Write memory."""
    proc = find_proc_by_obj(process)
    offset = process.trace.memory_mapper.map_back(proc, address)
    proc.write_memory(offset, data)


@REGISTRY.method
def write_reg(frame: sch.Schema('StackFrame'), name: str, value: bytes):
    """Write a register."""
    f = find_frame_by_obj(frame)
    f.select()
    proc = lldb.selected_process()
    mname, mval = frame.trace.register_mapper.map_value_back(proc, name, value)
    reg = find_reg_by_name(f, mname)
    size = int(lldb.parse_and_eval(f'sizeof(${mname})'))
    arr = '{' + ','.join(str(b) for b in mval) + '}'
    exec_convert_errors(
        f'expr ((unsigned char[{size}])${mname}) = {arr};')
