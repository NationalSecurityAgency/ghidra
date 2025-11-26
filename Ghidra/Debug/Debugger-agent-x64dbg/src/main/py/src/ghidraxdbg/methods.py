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
from contextlib import redirect_stdout
from io import StringIO
import re
import sys
from typing import Annotated, Any, Dict, Optional

from ghidratrace import sch
from ghidratrace.client import (MethodRegistry, ParamDesc, Address,
                                AddressRange, Schedule, TraceObject)

from x64dbg_automate.events import *
from x64dbg_automate.models import BreakpointType, HardwareBreakpointType, MemoryBreakpointType
from . import util, commands

REGISTRY = MethodRegistry(ThreadPoolExecutor(
    max_workers=1, thread_name_prefix='MethodRegistry'))


def extre(base: re.Pattern, ext: str) -> re.Pattern:
    return re.compile(base.pattern + ext)


WATCHPOINT_PATTERN = re.compile('Watchpoints\\[(?P<watchnum>\\d*)\\]')
BREAKPOINT_PATTERN = re.compile('Breakpoints\\[(?P<breaknum>\\d*)\\]')
BREAK_LOC_PATTERN = extre(BREAKPOINT_PATTERN, '\\[(?P<locnum>\\d*)\\]')
SESSIONS_PATTERN = re.compile('Sessions')
SESSION_PATTERN = extre(SESSIONS_PATTERN, '\\[(?P<snum>\\d*)\\]')
AVAILABLE_PATTERN = extre(SESSION_PATTERN, '\\.Available\\[(?P<pid>\\d*)\\]')
PROCESSES_PATTERN = extre(SESSION_PATTERN, '\\.Processes')
PROCESS_PATTERN = extre(PROCESSES_PATTERN, '\\[(?P<procnum>\\d*)\\]')
PROC_DEBUG_PATTERN = extre(PROCESS_PATTERN, '.Debug')
PROC_SBREAKS_PATTERN = extre(PROC_DEBUG_PATTERN, '\\.Software Breakpoints')
PROC_HBREAKS_PATTERN = extre(PROC_DEBUG_PATTERN, '\\.Hardware Breakpoints')
PROC_MBREAKS_PATTERN = extre(PROC_DEBUG_PATTERN, '\\.Memory Breakpoints')
PROC_SBREAKBPT_PATTERN = extre(PROC_SBREAKS_PATTERN, '\\[(?P<breaknum>\\d*)\\]')
PROC_HBREAKBPT_PATTERN = extre(PROC_HBREAKS_PATTERN, '\\[(?P<breaknum>\\d*)\\]')
PROC_MBREAKBPT_PATTERN = extre(PROC_MBREAKS_PATTERN, '\\[(?P<breaknum>\\d*)\\]')
ENV_PATTERN = extre(PROCESS_PATTERN, '\\.Environment')
THREADS_PATTERN = extre(PROCESS_PATTERN, '\\.Threads')
THREAD_PATTERN = extre(THREADS_PATTERN, '\\[(?P<tnum>\\d*)\\]')
STACK_PATTERN = extre(THREAD_PATTERN, '\\.Stack.Frames')
#FRAME_PATTERN = extre(STACK_PATTERN, '\\[(?P<level>\\d*)\\]')
REGS_PATTERN0 = extre(THREAD_PATTERN, '\\.Registers')
#REGS_PATTERN = extre(FRAME_PATTERN, '\\.Registers')
MEMORY_PATTERN = extre(PROCESS_PATTERN, '\\.Memory')
MODULES_PATTERN = extre(PROCESS_PATTERN, '\\.Modules')


def find_availpid_by_pattern(pattern: re.Pattern, object: TraceObject,
                             err_msg: str) -> int:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    pid = int(mat['pid'])
    return pid


def find_availpid_by_obj(object: TraceObject) -> int:
    return find_availpid_by_pattern(AVAILABLE_PATTERN, object, "an Attachable")


def find_proc_by_num(id: int) -> int:
    return util.selected_process()


def find_proc_by_pattern(object: TraceObject, pattern: re.Pattern,
                         err_msg: str) -> int:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    procnum = int(mat['procnum'])
    return find_proc_by_num(procnum)


def find_proc_by_obj(object: TraceObject) -> int:
    return find_proc_by_pattern(object, PROCESS_PATTERN, "an Process")


def find_proc_by_env_obj(object: TraceObject) -> int:
    return find_proc_by_pattern(object, ENV_PATTERN, "an Environment")


def find_proc_by_threads_obj(object: TraceObject) -> int:
    return find_proc_by_pattern(object, THREADS_PATTERN, "a ThreadContainer")


def find_proc_by_mem_obj(object: TraceObject) -> int:
    return find_proc_by_pattern(object, MEMORY_PATTERN, "a Memory")


def find_proc_by_modules_obj(object: TraceObject) -> int:
    return find_proc_by_pattern(object, MODULES_PATTERN, "a ModuleContainer")


def find_thread_by_num(id: int) -> Optional[int]:
    if id != util.selected_thread():
        util.select_thread(id)
    return util.selected_thread()


def find_thread_by_pattern(pattern: re.Pattern, object: TraceObject,
                           err_msg: str) -> Optional[int]:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    pnum = int(mat['procnum'])
    tnum = int(mat['tnum'])
    find_proc_by_num(pnum)
    return find_thread_by_num(tnum)


def find_thread_by_obj(object: TraceObject) -> Optional[int]:
    return find_thread_by_pattern(THREAD_PATTERN, object, "a Thread")


def find_thread_by_stack_obj(object: TraceObject) -> Optional[int]:
    return find_thread_by_pattern(STACK_PATTERN, object, "a Stack")


def find_thread_by_regs_obj(object: TraceObject) -> Optional[int]:
    return find_thread_by_pattern(REGS_PATTERN0, object,
                                  "a RegisterValueContainer")


# TODO: if eventually exposed...
# def find_frame_by_level(level: int) -> DbgEng._DEBUG_STACK_FRAME:
#     for f in util.dbg.client.backtrace_list():
#         if f.FrameNumber == level:
#             return f
#     # return dbg().backtrace_list()[level]
#
#
# def find_frame_by_pattern(pattern: re.Pattern, object: TraceObject,
#                           err_msg: str) -> DbgEng._DEBUG_STACK_FRAME:
#     mat = pattern.fullmatch(object.path)
#     if mat is None:
#         raise TypeError(f"{object} is not {err_msg}")
#     pnum = int(mat['procnum'])
#     tnum = int(mat['tnum'])
#     level = int(mat['level'])
#     find_proc_by_num(pnum)
#     find_thread_by_num(tnum)
#     return find_frame_by_level(level)
#
#
# def find_frame_by_obj(object: TraceObject) -> DbgEng._DEBUG_STACK_FRAME:
#     return find_frame_by_pattern(FRAME_PATTERN, object, "a StackFrame")


def find_bpt_by_pattern(pattern: re.Pattern, object: TraceObject,
                        err_msg: str) -> int:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        return -1 #raise TypeError(f"{object} is not {err_msg}")
    breaknum = int(mat['breaknum'])
    return breaknum


def find_sbpt_by_obj(object: TraceObject) -> int:
    return find_bpt_by_pattern(PROC_SBREAKBPT_PATTERN, object, "a BreakpointSpec")


def find_hbpt_by_obj(object: TraceObject) -> int:
    return find_bpt_by_pattern(PROC_HBREAKBPT_PATTERN, object, "a BreakpointSpec")


def find_mbpt_by_obj(object: TraceObject) -> int:
    return find_bpt_by_pattern(PROC_MBREAKBPT_PATTERN, object, "a BreakpointSpec")


shared_globals: Dict[str, Any] = dict()


class Session(TraceObject):
    pass


class AvailableContainer(TraceObject):
    pass


class BreakpointContainer(TraceObject):
    pass


class ProcessContainer(TraceObject):
    pass


class Environment(TraceObject):
    pass


class ThreadContainer(TraceObject):
    pass


class Stack(TraceObject):
    pass


class RegisterValueContainer(TraceObject):
    pass


class Memory(TraceObject):
    pass


class ModuleContainer(TraceObject):
    pass


class State(TraceObject):
    pass


class Process(TraceObject):
    pass


class Thread(TraceObject):
    pass


class StackFrame(TraceObject):
    pass


class Attachable(TraceObject):
    pass


class BreakpointSpec(TraceObject):
    pass


class EventContainer(TraceObject):
    pass


class ExceptionContainer(TraceObject):
    pass


class ContinueOption(TraceObject):
    pass


class ExecutionOption(TraceObject):
    pass


@REGISTRY.method()
def execute(cmd: str, to_string: bool=False):
    """Execute a Python3 command or script."""
    # print("***{}***".format(cmd))
    # sys.stderr.flush()
    # sys.stdout.flush()
    if to_string:
        data = StringIO()
        with redirect_stdout(data):
            exec(cmd, shared_globals)
        return data.getvalue()
    else:
        exec(cmd, shared_globals)


@REGISTRY.method(action='evaluate', display='Evaluate')
def evaluate(
        session: Session,
        expr: Annotated[str, ParamDesc(display='Expr')]) -> str:
    """Evaluate a Python3 expression."""
    return str(eval(expr, shared_globals))


@REGISTRY.method(action='refresh', display='Refresh Available')
def refresh_available(node: AvailableContainer) -> None:
    """List processes on x64dbg's host system."""
    with commands.open_tracked_tx('Refresh Available'):
        commands.ghidra_trace_put_available()


@REGISTRY.method(action='refresh', display='Refresh Breakpoints')
def refresh_breakpoints(node: BreakpointContainer) -> None:
    """Refresh the list of breakpoints (including locations for the current
    process)."""
    with commands.open_tracked_tx('Refresh Breakpoints'):
        commands.ghidra_trace_put_breakpoints()


@REGISTRY.method(action='refresh', display='Refresh Processes')
def refresh_processes(node: ProcessContainer) -> None:
    """Refresh the list of processes."""
    with commands.open_tracked_tx('Refresh Processes'):
        commands.ghidra_trace_put_processes()


@REGISTRY.method(action='refresh', display='Refresh Environment')
def refresh_environment(node: Environment) -> None:
    """Refresh the environment descriptors (arch, os, endian)."""
    with commands.open_tracked_tx('Refresh Environment'):
        commands.ghidra_trace_put_environment()


@REGISTRY.method(action='refresh', display='Refresh Threads')
def refresh_threads(node: ThreadContainer) -> None:
    """Refresh the list of threads in the process."""
    with commands.open_tracked_tx('Refresh Threads'):
        commands.ghidra_trace_put_threads()


# TODO: if eventually exposed...
# @REGISTRY.method(action='refresh', display='Refresh Stack')
# def refresh_stack(node: Stack) -> None:
#     """Refresh the backtrace for the thread."""
#     tnum = find_thread_by_stack_obj(node)
#     util.reset_frames()
#     with commands.open_tracked_tx('Refresh Stack'):
#         commands.ghidra_trace_put_frames()
#     with commands.open_tracked_tx('Refresh Registers'):
#         commands.ghidra_trace_putreg()


@REGISTRY.method(action='refresh', display='Refresh Registers')
def refresh_registers(node: RegisterValueContainer) -> None:
    """Refresh the register values for the selected frame."""
    tnum = find_thread_by_regs_obj(node)
    with commands.open_tracked_tx('Refresh Registers'):
        commands.ghidra_trace_putreg()


@REGISTRY.method(action='refresh', display='Refresh Memory')
def refresh_mappings(node: Memory) -> None:
    """Refresh the list of memory regions for the process."""
    with commands.open_tracked_tx('Refresh Memory Regions'):
        commands.ghidra_trace_put_regions()


@REGISTRY.method(action='refresh', display='Refresh Modules')
def refresh_modules(node: ModuleContainer) -> None:
    """Refresh the modules and sections list for the process.

    This will refresh the sections for all modules, not just the
    selected one.
    """
    with commands.open_tracked_tx('Refresh Modules'):
        commands.ghidra_trace_put_modules()


@REGISTRY.method(action='activate')
def activate_process(process: Process,
                     time: Optional[str]=None) -> None:
    """Switch to the process."""
    find_proc_by_obj(process)


@REGISTRY.method(action='activate')
def activate_thread(thread: Thread,
                    time: Optional[str]=None) -> None:
    """Switch to the thread."""
    find_thread_by_obj(thread)


# TODO: if eventually exposed...
# @REGISTRY.method(action='activate')
# def activate_frame(frame: StackFrame,
#                    time: Optional[str]=None) -> None:
#     """Select the frame."""
#     do_maybe_activate_time(time)
#     f = find_frame_by_obj(frame)
#     util.select_frame(f.FrameNumber)
#     with commands.open_tracked_tx('Refresh Stack'):
#         commands.ghidra_trace_put_frames()
#     with commands.open_tracked_tx('Refresh Registers'):
#         commands.ghidra_trace_putreg()


@REGISTRY.method(action='delete')
def remove_process(process: Process) -> None:
    """Remove the process."""
    dbg().detach()


@REGISTRY.method(action='attach', display='Attach')
def attach_obj(target: Attachable) -> None:
    """Attach the process to the given target."""
    pid = find_availpid_by_obj(target)
    dbg().attach(pid)
    #dbg().wait_until_debugging()
    commands.ghidra_trace_stop()
    commands.ghidra_trace_start(str(pid))
    commands.ghidra_trace_sync_enable()
    with commands.open_tracked_tx('Put all'):
        commands.ghidra_trace_put_all()


@REGISTRY.method(action='attach', display='Attach by pid')
def attach_pid(session: Session,
        pid: Annotated[int, ParamDesc(display='PID')]) -> None:
    """Attach the process to the given target."""
    commands.ghidra_trace_stop()
    commands.ghidra_trace_start(str(pid))
    commands.ghidra_trace_sync_enable()
    with commands.open_tracked_tx('Put all'):
        commands.ghidra_trace_put_all()
    
    
@REGISTRY.method(action='detach', display='Detach')
def detach(process: Process) -> None:
    """Detach the process's target."""
    dbg().detach()


@REGISTRY.method(action='launch', display='Launch')
def launch(
        Session: Session,
        file: Annotated[str, ParamDesc(display='Image')],
        args: Annotated[str, ParamDesc(display='Arguments')]='',
        initial_dir: Annotated[str, ParamDesc(
            display='Initial Directory')]='',
        wait: Annotated[bool, ParamDesc(
            display='Wait',
            description='Perform the initial WaitForEvents')]=False) -> None:
    """Run a native process with the given command line."""
    commands.ghidra_trace_stop()
    commands.ghidra_trace_create(command=file, args=args, initdir=initial_dir, start_trace=True, wait=wait)
    commands.ghidra_trace_sync_enable()
    with commands.open_tracked_tx('Put all'):
        commands.ghidra_trace_put_all()


@REGISTRY.method()
def kill(process: Process) -> None:
    """Kill execution of the process."""
    commands.ghidra_trace_kill()


@REGISTRY.method(action='resume', display='Go')
def go(process: Process) -> None:
    """Continue execution of the process."""
    dbg().go()
    proc = util.selected_process()
    trace = commands.STATE.require_trace()
    with trace.client.batch():
        with trace.open_tx("Go proc {}".format(proc)):
            commands.put_state(proc)


@REGISTRY.method()
def interrupt(process: Process) -> None:
    """Interrupt the execution of the debugged program."""
    # SetInterrupt is reentrant, so bypass the thread checks
    dbg().pause()


@REGISTRY.method(action='Hide PEB')
def hide_peb(process: Process) -> None:
    """Interrupt the execution of the debugged program."""
    # SetInterrupt is reentrant, so bypass the thread checks
    dbg().hide_debugger_peb()


@REGISTRY.method(action='step_into')
def step_into(thread: Thread,
              n: Annotated[int, ParamDesc(display='N')]=1) -> None:
    """Step one instruction exactly."""
    # find_thread_by_obj(thread)
    find_thread_by_obj(thread)
    dbg().stepi(n)


@REGISTRY.method(action='step_over')
def step_over(thread: Thread,
              n: Annotated[int, ParamDesc(display='N')]=1) -> None:
    """Step one instruction, but proceed through subroutine calls."""
    # find_thread_by_obj(thread)
    find_thread_by_obj(thread)
    dbg().stepo(n)


@REGISTRY.method(action='skip', display='Skip')
def skip(thread: Thread,
              n: Annotated[int, ParamDesc(display='N')]=1) -> None:
    """Step one instruction, but proceed through subroutine calls."""
    # find_thread_by_obj(thread)
    find_thread_by_obj(thread)
    dbg().skip(n)


@REGISTRY.method(action='step_out')
def step_out(thread: Thread) -> None:
    """Execute until the current stack frame returns."""
    find_thread_by_obj(thread)
    dbg().ret()


@REGISTRY.method(action='pause_thread', display='Pause')
def pause_thread(thread: Thread) -> None:
    """Execute until the current stack frame returns."""
    tid = find_thread_by_obj(thread)
    if tid is not None:
        dbg().thread_pause(tid)


@REGISTRY.method(action='resume_thread', display='Resume')
def resume_thread(thread: Thread) -> None:
    """Execute until the current stack frame returns."""
    tid = find_thread_by_obj(thread)
    if tid is not None:
        dbg().thread_resume(tid)


@REGISTRY.method(action='kill_thread', display='Kill')
def kill_thread(thread: Thread) -> None:
    """Execute until the current stack frame returns."""
    tid = find_thread_by_obj(thread)
    if tid is not None:
        dbg().thread_terminate(tid)


@REGISTRY.method(action='break_sw_execute')
def break_address(process: Process, address: Address) -> None:
    """Set a breakpoint."""
    find_proc_by_obj(process)
    dbg().set_breakpoint(address_or_symbol=address.offset)


@REGISTRY.method(action='break_ext', display='Set Breakpoint')
def break_expression(expression: str) -> None:
    """Set a breakpoint."""
    # TODO: Escape?
    dbg().set_breakpoint(address_or_symbol=expression)


@REGISTRY.method(action='break_hw_execute')
def break_hw_address(process: Process, address: Address) -> None:
    """Set a hardware-assisted breakpoint."""
    find_proc_by_obj(process)
    dbg().set_hardware_breakpoint(address_or_symbol=address.offset)


@REGISTRY.method(action='break_ext', display='Set Hardware Breakpoint')
def break_hw_expression(expression: str) -> None:
    """Set a hardware-assisted breakpoint."""
    dbg().set_hardware_breakpoint(address_or_symbol=expression)


@REGISTRY.method(action='break_read')
def break_read_address(process: Process, address: Address, size: int) -> None:
    """Set a read breakpoint."""
    find_proc_by_obj(process)
    dbg().set_hardware_breakpoint(address_or_symbol=address.offset, bp_type=HardwareBreakpointType.r, size=size)


@REGISTRY.method(action='break_ext', display='Set Read Breakpoint')
def break_read_expression(expression: str) -> None:
    """Set a read breakpoint."""
    dbg().set_hardware_breakpoint(address_or_symbol=expression, bp_type=HardwareBreakpointType.r)


@REGISTRY.method(action='break_write')
def break_write_address(process: Process, address: Address, size: int) -> None:
    """Set a write breakpoint."""
    find_proc_by_obj(process)
    dbg().set_hardware_breakpoint(address_or_symbol=address.offset, bp_type=HardwareBreakpointType.w, size=size)


@REGISTRY.method(action='break_ext', display='Set Write Breakpoint')
def break_write_expression(expression: str) -> None:
    """Set a write breakpoint."""
    dbg().set_hardware_breakpoint(address_or_symbol=expression, bp_type=HardwareBreakpointType.w)


@REGISTRY.method(action='break_access')
def break_access_address(process: Process, address: Address) -> None:
    """Set an access breakpoint."""
    find_proc_by_obj(process)
    dbg().set_memory_breakpoint(address_or_symbol=address.offset, bp_type=MemoryBreakpointType.a)


@REGISTRY.method(action='break_ext', display='Set Access Breakpoint')
def break_access_expression(expression: str) -> None:
    """Set an access breakpoint."""
    dbg().set_memory_breakpoint(address_or_symbol=expression, bp_type=MemoryBreakpointType.a)


@REGISTRY.method(action='toggle', display='Toggle Breakpoint')
def toggle_breakpoint(breakpoint: BreakpointSpec, enabled: bool) -> None:
    """Toggle a breakpoint."""
    bpt = find_sbpt_by_obj(breakpoint)
    if bpt >= 0:
        dbg().toggle_breakpoint(address_name_symbol_or_none=bpt, on=enabled)
        with commands.open_tracked_tx('Toggle Breakpoints'):
            commands.put_breakpoints(BreakpointType.BpNormal)
        return
    bpt = find_hbpt_by_obj(breakpoint)
    if bpt >= 0:
        dbg().toggle_breakpoint(address_name_symbol_or_none=bpt, on=enabled)
        with commands.open_tracked_tx('Toggle Breakpoints'):
            commands.put_breakpoints(BreakpointType.BpHardware)
        return
    bpt = find_mbpt_by_obj(breakpoint)
    if bpt >= 0:
        dbg().toggle_breakpoint(address_name_symbol_or_none=bpt, on=enabled)
        with commands.open_tracked_tx('Toggle Breakpoints'):
            commands.put_breakpoints(BreakpointType.BpMemory)


@REGISTRY.method(action='delete', display='Delete Breakpoint')
def delete_breakpoint(breakpoint: BreakpointSpec) -> None:
    """Delete a breakpoint."""
    bpt = find_sbpt_by_obj(breakpoint)
    if bpt >= 0:
        dbg().clear_breakpoint(address_name_symbol_or_none=bpt)
        with commands.open_tracked_tx('Delete Breakpoints'):
            commands.put_breakpoints(BreakpointType.BpNormal)
        return
    bpt = find_hbpt_by_obj(breakpoint)
    if bpt >= 0:
        dbg().clear_hardware_breakpoint(address_symbol_or_none=bpt)
        with commands.open_tracked_tx('Delete Breakpoints'):
            commands.put_breakpoints(BreakpointType.BpHardware)
        return
    bpt = find_mbpt_by_obj(breakpoint)
    if bpt >= 0:
        dbg().clear_memory_breakpoint(address_symbol_or_none=bpt)
        with commands.open_tracked_tx('Delete Breakpoints'):
            commands.put_breakpoints(BreakpointType.BpMemory)
 

@REGISTRY.method()
def read_mem(process: Process, range: AddressRange) -> None:
    """Read memory."""
    # print("READ_MEM: process={}, range={}".format(process, range))
    nproc = find_proc_by_obj(process)
    offset_start = process.trace.extra.require_mm().map_back(
        nproc, Address(range.space, range.min))
    with commands.open_tracked_tx('Read Memory'):
        result = commands.put_bytes(
            offset_start, offset_start + range.length() - 1, pages=True,
            display_result=False)
        if result['count'] == 0:
            commands.putmem_state(
                offset_start, offset_start + range.length() - 1, 'error')


@REGISTRY.method()
def write_mem(process: Process, address: Address, data: bytes) -> None:
    """Write memory."""
    nproc = find_proc_by_obj(process)
    offset = process.trace.extra.required_mm().map_back(nproc, address)
    dbg().write_memory(offset, data)


@REGISTRY.method(action='set_reg', display='Set Register')
def write_reg(reg: RegisterValueContainer, name: str, value: int) -> None:
    """Write a register."""
    nproc = util.selected_process()
    dbg().set_reg(name, value)


def dbg():
    return util.dbg.client
