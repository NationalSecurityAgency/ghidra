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
import time
from typing import Annotated, Any, Dict, Optional, Tuple

import drgn
import drgn.cli
from drgn import StackFrame
try:
    from drgn import Module  # type: ignore
except Exception as e:
    class Module:
        pass  # not supported on older versions

from ghidratrace import sch
from ghidratrace.client import (
    MethodRegistry, ParamDesc, Address, AddressRange, TraceObject)

from . import util, commands, hooks


REGISTRY = MethodRegistry(ThreadPoolExecutor(
    max_workers=1, thread_name_prefix='MethodRegistry'))


def extre(base, ext) -> re.Pattern:
    return re.compile(base.pattern + ext)


PROCESSES_PATTERN = re.compile('Processes')
PROCESS_PATTERN = extre(PROCESSES_PATTERN, '\\[(?P<procnum>\\d*)\\]')
ENV_PATTERN = extre(PROCESS_PATTERN, '\\.Environment')
THREADS_PATTERN = extre(PROCESS_PATTERN, '\\.Threads')
THREAD_PATTERN = extre(THREADS_PATTERN, '\\[(?P<tnum>\\d*)\\]')
STACK_PATTERN = extre(THREAD_PATTERN, '\\.Stack')
FRAME_PATTERN = extre(STACK_PATTERN, '\\[(?P<level>\\d*)\\]')
REGS_PATTERN = extre(FRAME_PATTERN, '.Registers')
LOCALS_PATTERN = extre(FRAME_PATTERN, '.Locals')
MEMORY_PATTERN = extre(PROCESS_PATTERN, '\\.Memory')
MODULES_PATTERN = extre(PROCESS_PATTERN, '\\.Modules')
MODULE_PATTERN = extre(MODULES_PATTERN, '\\[(?P<modbase>.*)\\]')


class Environment(TraceObject):
    pass


class LocalsContainer(TraceObject):
    pass


class Memory(TraceObject):
    pass


class ModuleContainer(TraceObject):
    pass


class Process(TraceObject):
    pass


class ProcessContainer(TraceObject):
    pass


class Stack(TraceObject):
    pass


class RegisterValueContainer(TraceObject):
    pass


class SymbolContainer(TraceObject):
    pass


class Thread(TraceObject):
    pass


class ThreadContainer(TraceObject):
    pass


def find_proc_by_num(id: int) -> int:
    if id != util.selected_process():
        util.select_process(id)
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
    return find_thread_by_pattern(REGS_PATTERN, object, "a RegisterValueContainer")


def find_frame_by_level(level: int) -> Optional[Tuple[int, StackFrame]]:
    tnum = util.selected_thread()
    thread = commands.prog.thread(tnum)
    try:
        frames = thread.stack_trace()
    except Exception as e:
        print(e)
        return None

    for i, f in enumerate(frames):
        if i == level:
            if i != util.selected_frame():
                util.select_frame(i)
            return i, f
    return None


def find_frame_by_pattern(pattern: re.Pattern, object: TraceObject,
                          err_msg: str) -> Optional[Tuple[int, StackFrame]]:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    pnum = int(mat['procnum'])
    tnum = int(mat['tnum'])
    level = int(mat['level'])
    find_proc_by_num(pnum)
    find_thread_by_num(tnum)
    return find_frame_by_level(level)


def find_frame_by_obj(object: TraceObject) -> Optional[Tuple[int, StackFrame]]:
    return find_frame_by_pattern(FRAME_PATTERN, object, "a StackFrame")


def find_frame_by_regs_obj(object: TraceObject) -> Optional[Tuple[int, StackFrame]]:
    return find_frame_by_pattern(REGS_PATTERN, object, "a RegisterValueContainer")


def find_frame_by_locals_obj(object: TraceObject) -> Optional[Tuple[int, StackFrame]]:
    return find_frame_by_pattern(LOCALS_PATTERN, object, "a LocalsContainer")


def find_module_by_base(modbase: TraceObject) -> Module:
    for m in commands.prog.modules():  # type: ignore
        if modbase == str(hex(m.address_range[0])):
            return m


def find_module_by_pattern(pattern: re.Pattern, object: TraceObject,
                           err_msg: str) -> int:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    pnum = int(mat['procnum'])
    modbase = mat['modbase']
    find_proc_by_num(pnum)
    return find_module_by_base(modbase)


def find_module_by_obj(object: TraceObject) -> int:
    return find_module_by_pattern(MODULE_PATTERN, object, "a Module")


shared_globals: Dict[str, Any] = dict()


@REGISTRY.method()
def execute(cmd: str, to_string: bool = False) -> Optional[str]:
    """Execute a Python3 command or script."""
    if to_string:
        data = StringIO()
        with redirect_stdout(data):
            exec(cmd, shared_globals)
        return data.getvalue()
    else:
        exec(cmd, shared_globals)
        return None


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


# @REGISTRY.method(action='refresh', display='Refresh Symbols')
# def refresh_symbols(node: SymbolContainer) -> None:
#    """Refresh the list of symbols in the process."""
#    with commands.open_tracked_tx('Refresh Symbols'):
#        commands.ghidra_trace_put_symbols()


@REGISTRY.method(action='show_symbol', display='Retrieve Symbols')
def retrieve_symbols(
        conainer: SymbolContainer,
        pattern: Annotated[str, ParamDesc(display='Pattern')]) -> None:
    """Load the symbol set matching the pattern."""
    with commands.open_tracked_tx('Retrieve Symbols'):
        commands.put_symbols(pattern)


@REGISTRY.method(action='refresh', display='Refresh Stack')
def refresh_stack(node: Stack) -> None:
    """Refresh the backtrace for the thread."""
    tnum = find_thread_by_stack_obj(node)
    with commands.open_tracked_tx('Refresh Stack'):
        commands.ghidra_trace_put_frames()


@REGISTRY.method(action='refresh', display='Refresh Registers')
def refresh_registers(node: RegisterValueContainer) -> None:
    """Refresh the register values for the selected frame."""
    level = find_frame_by_regs_obj(node)
    with commands.open_tracked_tx('Refresh Registers'):
        commands.ghidra_trace_putreg()


@REGISTRY.method(action='refresh', display='Refresh Locals')
def refresh_locals(node: LocalsContainer) -> None:
    """Refresh the local values for the selected frame."""
    level = find_frame_by_locals_obj(node)
    with commands.open_tracked_tx('Refresh Registers'):
        commands.ghidra_trace_put_locals()


@REGISTRY.method(action='refresh', display='Refresh Memory',
                 condition=hasattr(drgn, 'RelocatableModule'))
def refresh_mappings(node: Memory) -> None:
    """Refresh the list of memory regions for the process."""
    with commands.open_tracked_tx('Refresh Memory Regions'):
        commands.ghidra_trace_put_regions()


@REGISTRY.method(action='refresh', display='Refresh Modules',
                 condition=hasattr(drgn, 'RelocatableModule'))
def refresh_modules(node: ModuleContainer) -> None:
    """Refresh the modules list for the process."""
    with commands.open_tracked_tx('Refresh Modules'):
        commands.ghidra_trace_put_modules()


@REGISTRY.method(action='activate')
def activate_process(process: Process) -> None:
    """Switch to the process."""
    find_proc_by_obj(process)


@REGISTRY.method(action='activate')
def activate_thread(thread: Thread) -> None:
    """Switch to the thread."""
    find_thread_by_obj(thread)


@REGISTRY.method(action='activate')
def activate_frame(frame: TraceObject) -> None:
    """Select the frame."""
    res = find_frame_by_obj(frame)
    if res is None:
        return
    i, f = res
    util.select_frame(i)
    with commands.open_tracked_tx('Refresh Stack'):
        commands.ghidra_trace_put_frames()
    with commands.open_tracked_tx('Refresh Registers'):
        commands.ghidra_trace_putreg()


@REGISTRY.method()
def read_mem(process: Process, range: AddressRange) -> None:
    """Read memory."""
    # print("READ_MEM: process={}, range={}".format(process, range))
    nproc = find_proc_by_obj(process)
    offset_start = process.trace.extra.require_mm().map_back(
        nproc, Address(range.space, range.min))
    with commands.open_tracked_tx('Read Memory'):
        result = commands.put_bytes(
            offset_start, offset_start + range.length() - 1, pages=True, display_result=False)
        if result['count'] == 0:
            commands.putmem_state(
                offset_start, offset_start+range.length() - 1, 'error')


@REGISTRY.method(action='attach', display='Attach by pid')
def attach_pid(processes: ProcessContainer,
               pid: Annotated[str, ParamDesc(display='PID')]) -> None:
    """Attach the process to the given target."""
    prog = drgn.Program()
    prog.set_pid(int(pid))
    util.selected_pid = int(pid)
    util.selected_tid = prog.main_thread().tid
    default_symbols = {"default": True, "main": True}
    try:
        prog.load_debug_info(None, **default_symbols)
    except drgn.MissingDebugInfoError as e:
        print(e)
    # commands.ghidra_trace_start(pid)
    commands.PROGRAMS[pid] = prog
    commands.prog = prog
    with commands.open_tracked_tx('Refresh Processes'):
        commands.ghidra_trace_put_processes()


@REGISTRY.method(action='attach', display='Attach core dump')
def attach_core(processes: ProcessContainer,
                core: Annotated[str, ParamDesc(display='Core dump')]) -> None:
    """Attach the process to the given target."""
    prog = drgn.Program()
    prog.set_core_dump(core)
    default_symbols = {"default": True, "main": True}
    try:
        prog.load_debug_info(None, **default_symbols)
    except drgn.MissingDebugInfoError as e:
        print(e)

    util.selected_pid += 1
    commands.PROGRAMS[util.selected_pid] = prog
    commands.prog = prog
    with commands.open_tracked_tx('Refresh Processes'):
        commands.ghidra_trace_put_processes()


@REGISTRY.method(action='step_into')
def step_into(thread: Thread,
              n: Annotated[int, ParamDesc(display='N')] = 1) -> None:
    """Step one instruction exactly."""
    find_thread_by_obj(thread)
    time.sleep(1)
    hooks.on_stop()


# @REGISTRY.method
# def kill(process: Process) -> None:
#     """Kill execution of the process."""
#     commands.ghidra_trace_kill()


# @REGISTRY.method(action='resume')
# def go(process: Process) -> None:
#     """Continue execution of the process."""
#     util.dbg.run_async(lambda: dbg().go())


# @REGISTRY.method
# def interrupt(process: Process) -> None:
#     """Interrupt the execution of the debugged program."""
#     # SetInterrupt is reentrant, so bypass the thread checks
#     util.dbg._protected_base._control.SetInterrupt(
#         DbgEng.DEBUG_INTERRUPT_ACTIVE)
