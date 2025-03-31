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
from pybag import pydbg  # type: ignore
from pybag.dbgeng import core as DbgEng, exception  # type: ignore

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
PROC_BREAKS_PATTERN = extre(PROC_DEBUG_PATTERN, '\\.Breakpoints')
PROC_BREAKBPT_PATTERN = extre(PROC_BREAKS_PATTERN, '\\[(?P<breaknum>\\d*)\\]')
ENV_PATTERN = extre(PROCESS_PATTERN, '\\.Environment')
THREADS_PATTERN = extre(PROCESS_PATTERN, '\\.Threads')
THREAD_PATTERN = extre(THREADS_PATTERN, '\\[(?P<tnum>\\d*)\\]')
STACK_PATTERN = extre(THREAD_PATTERN, '\\.Stack.Frames')
FRAME_PATTERN = extre(STACK_PATTERN, '\\[(?P<level>\\d*)\\]')
REGS_PATTERN0 = extre(THREAD_PATTERN, '\\.Registers')
REGS_PATTERN = extre(FRAME_PATTERN, '\\.Registers')
MEMORY_PATTERN = extre(PROCESS_PATTERN, '\\.Memory')
MODULES_PATTERN = extre(PROCESS_PATTERN, '\\.Modules')
PROC_EVENTS_PATTERN = extre(PROC_DEBUG_PATTERN, '\\.Events')
PROC_EVENT_PATTERN = extre(PROC_EVENTS_PATTERN, '\\[(?P<eventnum>\\d*)\\]')
PROC_EVENT_CONT_PATTERN = extre(PROC_EVENT_PATTERN, '.Cont')
PROC_EVENT_EXEC_PATTERN = extre(PROC_EVENT_PATTERN, '.Exec')
PROC_EXCEPTIONS_PATTERN = extre(PROC_DEBUG_PATTERN, '\\.Exceptions')
PROC_EXCEPTION_PATTERN = extre(
    PROC_EXCEPTIONS_PATTERN, '\\[(?P<excnum>\\d*)\\]')
PROC_EXCEPTION_CONT_PATTERN = extre(PROC_EXCEPTION_PATTERN, '.Cont')
PROC_EXCEPTION_EXEC_PATTERN = extre(PROC_EXCEPTION_PATTERN, '.Exec')


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


def find_proc_by_procbreak_obj(object: TraceObject) -> int:
    return find_proc_by_pattern(object, PROC_BREAKS_PATTERN,
                                "a BreakpointLocationContainer")


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


@util.dbg.eng_thread
def find_frame_by_level(level: int) -> DbgEng._DEBUG_STACK_FRAME:
    for f in util.dbg._base.backtrace_list():
        if f.FrameNumber == level:
            return f
    # return dbg().backtrace_list()[level]


def find_frame_by_pattern(pattern: re.Pattern, object: TraceObject,
                          err_msg: str) -> DbgEng._DEBUG_STACK_FRAME:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    pnum = int(mat['procnum'])
    tnum = int(mat['tnum'])
    level = int(mat['level'])
    find_proc_by_num(pnum)
    find_thread_by_num(tnum)
    return find_frame_by_level(level)


def find_frame_by_obj(object: TraceObject) -> DbgEng._DEBUG_STACK_FRAME:
    return find_frame_by_pattern(FRAME_PATTERN, object, "a StackFrame")


def find_bpt_by_number(breaknum: int) -> DbgEng.IDebugBreakpoint:
    try:
        bp = dbg()._control.GetBreakpointById(breaknum)
        return bp
    except exception.E_NOINTERFACE_Error:
        raise KeyError(f"Breakpoints[{breaknum}] does not exist")


def find_bpt_by_pattern(pattern: re.Pattern, object: TraceObject,
                        err_msg: str) -> DbgEng.IDebugBreakpoint:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    breaknum = int(mat['breaknum'])
    return find_bpt_by_number(breaknum)


def find_bpt_by_obj(object: TraceObject) -> DbgEng.IDebugBreakpoint:
    return find_bpt_by_pattern(PROC_BREAKBPT_PATTERN, object, "a BreakpointSpec")


def find_evt_by_number(eventnum: int) -> DbgEng._DEBUG_SPECIFIC_FILTER_PARAMETERS:
    try:
        return util.GetSpecificFilterParameters(eventnum, 1)
    except exception.E_NOINTERFACE_Error:
        raise KeyError(f"Events[{eventnum}] does not exist")


def find_evt_by_pattern(pattern: re.Pattern, object: TraceObject,
                        err_msg: str) -> DbgEng._DEBUG_SPECIFIC_FILTER_PARAMETERS:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    eventnum = int(mat['eventnum'])
    return (eventnum, find_evt_by_number(eventnum))


def find_evt_cont_by_obj(object: TraceObject) -> DbgEng._DEBUG_SPECIFIC_FILTER_PARAMETERS:
    return find_evt_by_pattern(PROC_EVENT_CONT_PATTERN, object, "as Event")


def find_evt_exec_by_obj(object: TraceObject) -> DbgEng._DEBUG_SPECIFIC_FILTER_PARAMETERS:
    return find_evt_by_pattern(PROC_EVENT_EXEC_PATTERN, object, "as Event")


def find_exc_by_number(excnum: int) -> DbgEng._DEBUG_EXCEPTION_FILTER_PARAMETERS:
    try:
        (n_events, n_spec_exc, n_arb_exc) = util.GetNumberEventFilters()
        return util.GetExceptionFilterParameters(n_events + excnum, None, 1)
    except exception.E_NOINTERFACE_Error:
        raise KeyError(f"Events[{excnum}] does not exist")


def find_exc_by_pattern(pattern: re.Pattern, object: TraceObject,
                        err_msg: str) -> DbgEng._DEBUG_EXCEPTION_FILTER_PARAMETERS:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    excnum = int(mat['excnum'])
    return (excnum, find_exc_by_number(excnum))


def find_exc_cont_by_obj(object: TraceObject) -> DbgEng._DEBUG_SPECIFIC_FILTER_PARAMETERS:
    return find_exc_by_pattern(PROC_EXCEPTION_CONT_PATTERN, object, "as Exception")


def find_exc_exec_by_obj(object: TraceObject) -> DbgEng._DEBUG_SPECIFIC_FILTER_PARAMETERS:
    return find_exc_by_pattern(PROC_EXCEPTION_EXEC_PATTERN, object, "as Exception")


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
# @util.dbg.eng_thread
def execute(cmd: str, to_string: bool = False):
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
# @util.dbg.eng_thread
def evaluate(
        session: Session,
        expr: Annotated[str, ParamDesc(display='Expr')]) -> str:
    """Evaluate a Python3 expression."""
    return str(eval(expr, shared_globals))


@REGISTRY.method(action='refresh', display="Refresh",
                 condition=util.dbg.use_generics)
def refresh_generic(node: TraceObject) -> None:
    """List the children for a generic node."""
    with commands.open_tracked_tx('Refresh Generic'):
        commands.ghidra_trace_put_generic(node)


@REGISTRY.method(action='refresh', display='Refresh Available')
def refresh_available(node: AvailableContainer) -> None:
    """List processes on pydbg's host system."""
    with commands.open_tracked_tx('Refresh Available'):
        commands.ghidra_trace_put_available()


@REGISTRY.method(action='refresh', display='Refresh Breakpoints')
def refresh_breakpoints(node: BreakpointContainer) -> None:
    """Refresh the list of breakpoints (including locations for the current
    process)."""
    with commands.open_tracked_tx('Refresh Breakpoints'):
        commands.ghidra_trace_put_breakpoints()


@REGISTRY.method(action='refresh', display='Refresh Events')
def refresh_events(node: EventContainer) -> None:
    """
    Refresh the list of control events.
    """
    with commands.open_tracked_tx('Refresh Events'):
        commands.ghidra_trace_put_events()


@REGISTRY.method(action='refresh', display='Refresh Exceptions')
def refresh_exceptions(node: ExceptionContainer) -> None:
    """
    Refresh the list of exceptions.
    """
    with commands.open_tracked_tx('Refresh Exceptions'):
        commands.ghidra_trace_put_exceptions()


@REGISTRY.method(action='toggle', display='Toggle Execution Option')
def toggle_exec(node: ExecutionOption, enabled: bool) -> None:
    """
    Toggle the execution option
    """
    if "Events" in str(node):
        (n, events) = find_evt_exec_by_obj(node)
        with commands.open_tracked_tx('Toggle Execution Option'):
            commands.toggle_evt_exec_option(n, events)
            commands.ghidra_trace_put_events()
    elif "Exceptions" in str(node):
        (n, events) = find_exc_exec_by_obj(node)
        with commands.open_tracked_tx('Toggle Execution Option'):
            commands.toggle_exc_exec_option(n, events)
            commands.ghidra_trace_put_exceptions()


@REGISTRY.method(action='toggle', display='Toggle Continue Option')
def toggle_cont(node: ContinueOption, enabled: bool) -> None:
    """
    Toggle the execution option
    """
    if "Events" in str(node):
        (n, events) = find_evt_cont_by_obj(node)
        with commands.open_tracked_tx('Toggle Execution Option'):
            commands.toggle_evt_cont_option(n, events)
            commands.ghidra_trace_put_events()
    elif "Exceptions" in str(node):
        (n, events) = find_exc_cont_by_obj(node)
        with commands.open_tracked_tx('Toggle Execution Option'):
            commands.toggle_exc_cont_option(n, events)
            commands.ghidra_trace_put_exceptions()


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


@REGISTRY.method(action='refresh', display='Refresh Stack')
def refresh_stack(node: Stack) -> None:
    """Refresh the backtrace for the thread."""
    tnum = find_thread_by_stack_obj(node)
    util.reset_frames()
    with commands.open_tracked_tx('Refresh Stack'):
        commands.ghidra_trace_put_frames()
    with commands.open_tracked_tx('Refresh Registers'):
        commands.ghidra_trace_putreg()


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


@REGISTRY.method(action='refresh', display='Refresh Events')
def refresh_trace_events(node: State) -> None:
    """
    Refresh the events list for a trace.
    """
    with commands.open_tracked_tx('Refresh Events'):
        commands.ghidra_trace_put_trace_events()


@util.dbg.eng_thread
def do_maybe_activate_time(time: Optional[str]) -> None:
    if time is not None:
        sch: Schedule = Schedule.parse(time)
        dbg().cmd(f"!tt " + util.schedule2ss(sch), quiet=False)
        dbg().wait()


@REGISTRY.method(action='activate')
def activate_process(process: Process,
                     time: Optional[str] = None) -> None:
    """Switch to the process."""
    do_maybe_activate_time(time)
    find_proc_by_obj(process)


@REGISTRY.method(action='activate')
def activate_thread(thread: Thread,
                    time: Optional[str] = None) -> None:
    """Switch to the thread."""
    do_maybe_activate_time(time)
    find_thread_by_obj(thread)


@REGISTRY.method(action='activate')
def activate_frame(frame: StackFrame,
                   time: Optional[str] = None) -> None:
    """Select the frame."""
    do_maybe_activate_time(time)
    f = find_frame_by_obj(frame)
    util.select_frame(f.FrameNumber)
    with commands.open_tracked_tx('Refresh Stack'):
        commands.ghidra_trace_put_frames()
    with commands.open_tracked_tx('Refresh Registers'):
        commands.ghidra_trace_putreg()


@REGISTRY.method(action='delete')
@util.dbg.eng_thread
def remove_process(process: Process) -> None:
    """Remove the process."""
    find_proc_by_obj(process)
    dbg().detach_proc()


@REGISTRY.method(action='connect', display='Connect')
@util.dbg.eng_thread
def target(
        session: Session,
        cmd: Annotated[str, ParamDesc(display='Command')]) -> None:
    """Connect to a target machine or process."""
    dbg().attach_kernel(cmd)


@REGISTRY.method(action='attach', display='Attach')
@util.dbg.eng_thread
def attach_obj(target: Attachable) -> None:
    """Attach the process to the given target."""
    pid = find_availpid_by_obj(target)
    dbg().attach_proc(pid)


@REGISTRY.method(action='attach', display='Attach by pid')
@util.dbg.eng_thread
def attach_pid(
        session: Session,
        pid: Annotated[int, ParamDesc(display='PID')]) -> None:
    """Attach the process to the given target."""
    dbg().attach_proc(pid)


@REGISTRY.method(action='attach', display='Attach by name')
@util.dbg.eng_thread
def attach_name(
        session: Session,
        name: Annotated[str, ParamDesc(display='Name')]) -> None:
    """Attach the process to the given target."""
    dbg().attach_proc(name)


@REGISTRY.method(action='detach', display='Detach')
@util.dbg.eng_thread
def detach(process: Process) -> None:
    """Detach the process's target."""
    dbg().detach_proc()


@REGISTRY.method(action='launch', display='Launch')
def launch_loader(
        session: Session,
        file: Annotated[str, ParamDesc(display='File')],
        args: Annotated[str, ParamDesc(display='Arguments')] = '',
        timeout: Annotated[int, ParamDesc(display='Timeout')] = -1,
        wait: Annotated[bool, ParamDesc(
            display='Wait',
            description='Perform the initial WaitForEvents')] = False) -> None:
    """Start a native process with the given command line, stopping at the
    ntdll initial breakpoint."""
    command = file
    if args != None:
        command += " " + args
    commands.ghidra_trace_create(command=command, start_trace=False,
                                 timeout=timeout, wait=wait)


@REGISTRY.method(action='launch', display='LaunchEx')
def launch(
        session: Session,
        file: Annotated[str, ParamDesc(display='File')],
        args: Annotated[str, ParamDesc(display='Arguments')] = '',
        initial_break: Annotated[bool, ParamDesc(
            display='Initial Break')] = True,
        timeout: Annotated[int, ParamDesc(display='Timeout')] = -1,
        wait: Annotated[bool, ParamDesc(
            display='Wait',
            description='Perform the initial WaitForEvents')] = False) -> None:
    """Run a native process with the given command line."""
    command = file
    if args != None:
        command += " " + args
    commands.ghidra_trace_create(command=command, start_trace=False,
                                 initial_break=initial_break,
                                 timeout=timeout, wait=wait)


@REGISTRY.method()
@util.dbg.eng_thread
def kill(process: Process) -> None:
    """Kill execution of the process."""
    commands.ghidra_trace_kill()


@REGISTRY.method(action='resume', display="Go")
def go(process: Process) -> None:
    """Continue execution of the process."""
    util.dbg.run_async(lambda: dbg().go())


@REGISTRY.method(action='step_ext', display='Go (backwards)',
                 icon='icon.debugger.resume.back', condition=util.dbg.IS_TRACE)
@util.dbg.eng_thread
def go_back(process: Process) -> None:
    """Continue execution of the process backwards."""
    dbg().cmd("g-")
    dbg().wait()


@REGISTRY.method()
def interrupt(process: Process) -> None:
    """Interrupt the execution of the debugged program."""
    # SetInterrupt is reentrant, so bypass the thread checks
    util.dbg._protected_base._control.SetInterrupt(
        DbgEng.DEBUG_INTERRUPT_ACTIVE)


@REGISTRY.method(action='step_into')
def step_into(thread: Thread,
              n: Annotated[int, ParamDesc(display='N')] = 1) -> None:
    """Step one instruction exactly."""
    find_thread_by_obj(thread)
    util.dbg.run_async(lambda: dbg().stepi(n))


@REGISTRY.method(action='step_over')
def step_over(thread: Thread,
              n: Annotated[int, ParamDesc(display='N')] = 1) -> None:
    """Step one instruction, but proceed through subroutine calls."""
    find_thread_by_obj(thread)
    util.dbg.run_async(lambda: dbg().stepo(n))


@REGISTRY.method(action='step_ext', display='Step Into (backwards)',
                 icon='icon.debugger.step.back.into',
                 condition=util.dbg.IS_TRACE)
@util.dbg.eng_thread
def step_back_into(thread: Thread,
                   n: Annotated[int, ParamDesc(display='N')] = 1) -> None:
    """Step one instruction backward exactly."""
    dbg().cmd("t- " + str(n))
    dbg().wait()


@REGISTRY.method(action='step_ext', display='Step Over (backwards)',
                 icon='icon.debugger.step.back.over',
                 condition=util.dbg.IS_TRACE)
@util.dbg.eng_thread
def step_back_over(thread: Thread,
                   n: Annotated[int, ParamDesc(display='N')] = 1) -> None:
    """Step one instruction backward, but proceed through subroutine calls."""
    dbg().cmd("p- " + str(n))
    dbg().wait()


@REGISTRY.method(action='step_out')
def step_out(thread: Thread) -> None:
    """Execute until the current stack frame returns."""
    find_thread_by_obj(thread)
    util.dbg.run_async(lambda: dbg().stepout())


@REGISTRY.method(action='step_to', display='Step To')
def step_to(thread: Thread, address: Address,
            max: Optional[int] = None) -> None:
    """Continue execution up to the given address."""
    find_thread_by_obj(thread)
    # TODO: The address may need mapping.
    util.dbg.run_async(lambda: dbg().stepto(address.offset, max))


@REGISTRY.method(action='go_to_time', display='Go To (event)',
                 condition=util.dbg.IS_TRACE)
@util.dbg.eng_thread
def go_to_time(node: State,
               evt: Annotated[str, ParamDesc(display='Event')]) -> None:
    """Reset the trace to a specific time."""
    dbg().cmd("!tt " + evt)
    dbg().wait()


@REGISTRY.method(action='break_sw_execute')
@util.dbg.eng_thread
def break_address(process: Process, address: Address) -> None:
    """Set a breakpoint."""
    find_proc_by_obj(process)
    dbg().bp(expr=address.offset)


@REGISTRY.method(action='break_ext', display='Set Breakpoint')
@util.dbg.eng_thread
def break_expression(expression: str) -> None:
    """Set a breakpoint."""
    # TODO: Escape?
    dbg().bp(expr=expression)


@REGISTRY.method(action='break_hw_execute')
@util.dbg.eng_thread
def break_hw_address(process: Process, address: Address) -> None:
    """Set a hardware-assisted breakpoint."""
    find_proc_by_obj(process)
    dbg().ba(expr=address.offset)


@REGISTRY.method(action='break_ext', display='Set Hardware Breakpoint')
@util.dbg.eng_thread
def break_hw_expression(expression: str) -> None:
    """Set a hardware-assisted breakpoint."""
    dbg().ba(expr=expression)


@REGISTRY.method(action='break_read')
@util.dbg.eng_thread
def break_read_range(process: Process, range: AddressRange) -> None:
    """Set a read breakpoint."""
    find_proc_by_obj(process)
    dbg().ba(expr=range.min, size=range.length(),
             access=DbgEng.DEBUG_BREAK_READ)


@REGISTRY.method(action='break_ext', display='Set Read Breakpoint')
@util.dbg.eng_thread
def break_read_expression(expression: str) -> None:
    """Set a read breakpoint."""
    dbg().ba(expr=expression, access=DbgEng.DEBUG_BREAK_READ)


@REGISTRY.method(action='break_write')
@util.dbg.eng_thread
def break_write_range(process: Process, range: AddressRange) -> None:
    """Set a write breakpoint."""
    find_proc_by_obj(process)
    dbg().ba(expr=range.min, size=range.length(),
             access=DbgEng.DEBUG_BREAK_WRITE)


@REGISTRY.method(action='break_ext', display='Set Write Breakpoint')
@util.dbg.eng_thread
def break_write_expression(expression: str) -> None:
    """Set a write breakpoint."""
    dbg().ba(expr=expression, access=DbgEng.DEBUG_BREAK_WRITE)


@REGISTRY.method(action='break_access')
@util.dbg.eng_thread
def break_access_range(process: Process, range: AddressRange) -> None:
    """Set an access breakpoint."""
    find_proc_by_obj(process)
    dbg().ba(expr=range.min, size=range.length(),
             access=DbgEng.DEBUG_BREAK_READ | DbgEng.DEBUG_BREAK_WRITE)


@REGISTRY.method(action='break_ext', display='Set Access Breakpoint')
@util.dbg.eng_thread
def break_access_expression(expression: str) -> None:
    """Set an access breakpoint."""
    dbg().ba(expr=expression,
             access=DbgEng.DEBUG_BREAK_READ | DbgEng.DEBUG_BREAK_WRITE)


@REGISTRY.method(action='toggle', display='Toggle Breakpoint')
@util.dbg.eng_thread
def toggle_breakpoint(breakpoint: BreakpointSpec, enabled: bool) -> None:
    """Toggle a breakpoint."""
    bpt = find_bpt_by_obj(breakpoint)
    if enabled:
        dbg().be(bpt.GetId())
    else:
        dbg().bd(bpt.GetId())


@REGISTRY.method(action='delete', display='Delete Breakpoint')
@util.dbg.eng_thread
def delete_breakpoint(breakpoint: BreakpointSpec) -> None:
    """Delete a breakpoint."""
    bpt = find_bpt_by_obj(breakpoint)
    dbg().cmd("bc {}".format(bpt.GetId()))


@REGISTRY.method()
@util.dbg.eng_thread
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
@util.dbg.eng_thread
def write_mem(process: Process, address: Address, data: bytes) -> None:
    """Write memory."""
    nproc = find_proc_by_obj(process)
    offset = process.trace.extra.required_mm().map_back(nproc, address)
    dbg().write(offset, data)


@REGISTRY.method()
@util.dbg.eng_thread
def write_reg(frame: StackFrame, name: str, value: bytes) -> None:
    """Write a register."""
    f = find_frame_by_obj(frame)
    util.select_frame(f.FrameNumber)
    nproc = pydbg.selected_process()
    dbg().reg._set_register(name, value)


@REGISTRY.method(display='Refresh Events (custom)', condition=util.dbg.IS_TRACE)
@util.dbg.eng_thread
def refresh_trace_events_custom(node: State,
                                cmd: Annotated[str, ParamDesc(display='Cmd')],
                                prefix: Annotated[str, ParamDesc(display='Prefix')] = "dx -r2 @$cursession.TTD") -> None:
    """Parse TTD objects generated from a LINQ command."""
    with commands.open_tracked_tx('Put Events (custom)'):
        commands.ghidra_trace_put_trace_events_custom(prefix, cmd)


def dbg():
    return util.dbg._base
