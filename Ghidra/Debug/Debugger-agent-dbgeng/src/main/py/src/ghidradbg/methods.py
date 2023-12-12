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
from concurrent.futures import Future, ThreadPoolExecutor
import re
import sys

from ghidratrace import sch
from ghidratrace.client import MethodRegistry, ParamDesc, Address, AddressRange

from pybag import pydbg
from pybag.dbgeng import core as DbgEng

from . import util, commands
from contextlib import redirect_stdout
from io import StringIO


REGISTRY = MethodRegistry(ThreadPoolExecutor(max_workers=1))


def extre(base, ext):
    return re.compile(base.pattern + ext)


AVAILABLE_PATTERN = re.compile('Available\[(?P<pid>\\d*)\]')
WATCHPOINT_PATTERN = re.compile('Watchpoints\[(?P<watchnum>\\d*)\]')
BREAKPOINT_PATTERN = re.compile('Breakpoints\[(?P<breaknum>\\d*)\]')
BREAK_LOC_PATTERN = extre(BREAKPOINT_PATTERN, '\[(?P<locnum>\\d*)\]')
PROCESS_PATTERN = re.compile('Processes\[(?P<procnum>\\d*)\]')
PROC_BREAKS_PATTERN = extre(PROCESS_PATTERN, '\.Breakpoints')
PROC_BREAKBPT_PATTERN = extre(PROC_BREAKS_PATTERN, '\[(?P<breaknum>\\d*)\]')
ENV_PATTERN = extre(PROCESS_PATTERN, '\.Environment')
THREADS_PATTERN = extre(PROCESS_PATTERN, '\.Threads')
THREAD_PATTERN = extre(THREADS_PATTERN, '\[(?P<tnum>\\d*)\]')
STACK_PATTERN = extre(THREAD_PATTERN, '\.Stack')
FRAME_PATTERN = extre(STACK_PATTERN, '\[(?P<level>\\d*)\]')
REGS_PATTERN0 = extre(THREAD_PATTERN, '.Registers')
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


def find_proc_by_num(id):
    if id != util.selected_process():
        util.select_process(id)
    return util.selected_process()


def find_proc_by_pattern(object, pattern, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    procnum = int(mat['procnum'])
    return find_proc_by_num(procnum)


def find_proc_by_obj(object):
    return find_proc_by_pattern(object, PROCESS_PATTERN, "an Process")


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


def find_thread_by_num(id):
    if id != util.selected_thread():
        util.select_thread(id)
    return util.selected_thread()


def find_thread_by_pattern(pattern, object, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    pnum = int(mat['procnum'])
    tnum = int(mat['tnum'])
    find_proc_by_num(pnum)
    return find_thread_by_num(tnum)


def find_thread_by_obj(object):
    return find_thread_by_pattern(THREAD_PATTERN, object, "a Thread")


def find_thread_by_stack_obj(object):
    return find_thread_by_pattern(STACK_PATTERN, object, "a Stack")


def find_thread_by_regs_obj(object):
    return find_thread_by_pattern(REGS_PATTERN0, object, "a RegisterValueContainer")


def find_frame_by_level(level):
    return dbg().backtrace_list()[level]


def find_frame_by_pattern(pattern, object, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    pnum = int(mat['procnum'])
    tnum = int(mat['tnum'])
    level = int(mat['level'])
    find_proc_by_num(pnum)
    find_thread_by_num(tnum)
    return find_frame_by_level(level)


def find_frame_by_obj(object):
    return find_frame_by_pattern(FRAME_PATTERN, object, "a StackFrame")


def find_bpt_by_number(breaknum):
    try:
        bp = dbg()._control.GetBreakpointById(breaknum)
        return bp
    except exception.E_NOINTERFACE_Error:
        raise KeyError(f"Breakpoints[{breaknum}] does not exist")


def find_bpt_by_pattern(pattern, object, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    breaknum = int(mat['breaknum'])
    return find_bpt_by_number(breaknum)


def find_bpt_by_obj(object):
    return find_bpt_by_pattern(PROC_BREAKBPT_PATTERN, object, "a BreakpointSpec")


shared_globals = dict()

@REGISTRY.method
def execute(cmd: str, to_string: bool=False):
    """Execute a CLI command."""
    #print("***{}***".format(cmd))
    #sys.stderr.flush()
    #sys.stdout.flush()
    if to_string:
        data = StringIO()
        with redirect_stdout(data):
            exec("{}".format(cmd), shared_globals)
        return data.getvalue()
    else:
        exec("{}".format(cmd), shared_globals)


@REGISTRY.method
def evaluate(expr: str):
    """Execute a CLI command."""
    return str(eval("{}".format(expr), shared_globals))


@REGISTRY.method(action='refresh')
def refresh_available(node: sch.Schema('AvailableContainer')):
    """List processes on pydbg's host system."""
    with commands.open_tracked_tx('Refresh Available'):
        commands.ghidra_trace_put_available()


@REGISTRY.method(action='refresh')
def refresh_breakpoints(node: sch.Schema('BreakpointContainer')):
    """
    Refresh the list of breakpoints (including locations for the current
    process).
    """
    with commands.open_tracked_tx('Refresh Breakpoints'):
        commands.ghidra_trace_put_breakpoints()


@REGISTRY.method(action='refresh')
def refresh_processes(node: sch.Schema('ProcessContainer')):
    """Refresh the list of processes."""
    with commands.open_tracked_tx('Refresh Processes'):
        commands.ghidra_trace_put_threads()


@REGISTRY.method(action='refresh')
def refresh_proc_breakpoints(node: sch.Schema('BreakpointLocationContainer')):
    """
    Refresh the breakpoint locations for the process.

    In the course of refreshing the locations, the breakpoint list will also be
    refreshed.
    """
    with commands.open_tracked_tx('Refresh Breakpoint Locations'):
        commands.ghidra_trace_put_breakpoints()


@REGISTRY.method(action='refresh')
def refresh_environment(node: sch.Schema('Environment')):
    """Refresh the environment descriptors (arch, os, endian)."""
    with commands.open_tracked_tx('Refresh Environment'):
        commands.ghidra_trace_put_environment()

@REGISTRY.method(action='refresh')
def refresh_threads(node: sch.Schema('ThreadContainer')):
    """Refresh the list of threads in the process."""
    with commands.open_tracked_tx('Refresh Threads'):
        commands.ghidra_trace_put_threads()


@REGISTRY.method(action='refresh')
def refresh_stack(node: sch.Schema('Stack')):
    """Refresh the backtrace for the thread."""
    tnum = find_thread_by_stack_obj(node)
    with commands.open_tracked_tx('Refresh Stack'):
        commands.ghidra_trace_put_frames()


@REGISTRY.method(action='refresh')
def refresh_registers(node: sch.Schema('RegisterValueContainer')):
    """Refresh the register values for the frame."""
    tnum = find_thread_by_regs_obj(node)
    with commands.open_tracked_tx('Refresh Registers'):
        commands.ghidra_trace_putreg()


@REGISTRY.method(action='refresh')
def refresh_mappings(node: sch.Schema('Memory')):
    """Refresh the list of memory regions for the process."""
    with commands.open_tracked_tx('Refresh Memory Regions'):
        commands.ghidra_trace_put_regions()


@REGISTRY.method(action='refresh')
def refresh_modules(node: sch.Schema('ModuleContainer')):
    """
    Refresh the modules and sections list for the process.

    This will refresh the sections for all modules, not just the selected one.
    """
    with commands.open_tracked_tx('Refresh Modules'):
        commands.ghidra_trace_put_modules()


@REGISTRY.method(action='activate')
def activate_process(process: sch.Schema('Process')):
    """Switch to the process."""
    find_proc_by_obj(process)

@REGISTRY.method(action='activate')
def activate_thread(thread: sch.Schema('Thread')):
    """Switch to the thread."""
    find_thread_by_obj(thread)


@REGISTRY.method(action='activate')
def activate_frame(frame: sch.Schema('StackFrame')):
    """Select the frame."""
    find_frame_by_obj(frame)


@REGISTRY.method(action='delete')
def remove_process(process: sch.Schema('Process')):
    """Remove the process."""
    find_proc_by_obj(process)
    dbg().detach()


@REGISTRY.method(action='connect')
def target(process: sch.Schema('Process'), spec: str):
    """Connect to a target machine or process."""
    find_proc_by_obj(process)
    dbg().attach(spec)


@REGISTRY.method(action='attach')
def attach_obj(target: sch.Schema('Attachable')):
    """Attach the process to the given target."""
    pid = find_availpid_by_obj(target)
    dbg().attach(pid)

@REGISTRY.method(action='attach')
def attach_pid(pid: int):
    """Attach the process to the given target."""
    dbg().attach(pid)

@REGISTRY.method(action='attach')
def attach_name(process: sch.Schema('Process'), name: str):
    """Attach the process to the given target."""
    dbg().atach(name)


@REGISTRY.method
def detach(process: sch.Schema('Process')):
    """Detach the process's target."""
    dbg().detach()


@REGISTRY.method(action='launch')
def launch_loader(
          file: ParamDesc(str, display='File'),
          args: ParamDesc(str, display='Arguments')=''):
    """
    Start a native process with the given command line, stopping at the ntdll initial breakpoint.
    """
    command = file
    if args != None:
        command += " "+args
    commands.ghidra_trace_create(command=file, start_trace=False)


@REGISTRY.method(action='launch')
def launch(
        timeout: ParamDesc(int, display='Timeout'),
        file: ParamDesc(str, display='File'),
        args: ParamDesc(str, display='Arguments')=''):
    """
    Run a native process with the given command line.
    """
    command = file
    if args != None:
        command += " "+args
    commands.ghidra_trace_create(command, initial_break=False, timeout=timeout, start_trace=False)


@REGISTRY.method
def kill(process: sch.Schema('Process')):
    """Kill execution of the process."""
    dbg().terminate()


@REGISTRY.method(name='continue', action='resume')
def _continue(process: sch.Schema('Process')):
    """Continue execution of the process."""
    dbg().go()


@REGISTRY.method
def interrupt(process: sch.Schema('Process')):
    """Interrupt the execution of the debugged program."""
    dbg()._control.SetInterrupt(DbgEng.DEBUG_INTERRUPT_ACTIVE)


@REGISTRY.method(action='step_into')
def step_into(thread: sch.Schema('Thread'), n: ParamDesc(int, display='N')=1):
    """Step one instruction exactly."""
    find_thread_by_obj(thread)
    dbg().stepi(n)


@REGISTRY.method(action='step_over')
def step_over(thread: sch.Schema('Thread'), n: ParamDesc(int, display='N')=1):
    """Step one instruction, but proceed through subroutine calls."""
    find_thread_by_obj(thread)
    dbg().stepo(n)


@REGISTRY.method(action='step_out')
def step_out(thread: sch.Schema('Thread')):
    """Execute until the current stack frame returns."""
    find_thread_by_obj(thread)
    dbg().stepout()


@REGISTRY.method(action='step_to')
def step_to(thread: sch.Schema('Thread'), address: Address, max=None):
    """Continue execution up to the given address."""
    find_thread_by_obj(thread)
    return dbg().stepto(address.offset, max)


@REGISTRY.method(action='break_sw_execute')
def break_address(process: sch.Schema('Process'), address: Address):
    """Set a breakpoint."""
    find_proc_by_obj(process)
    dbg().bp(expr=address.offset)


@REGISTRY.method(action='break_sw_execute')
def break_expression(expression: str):
    """Set a breakpoint."""
    # TODO: Escape?
    dbg().bp(expr=expression)


@REGISTRY.method(action='break_hw_execute')
def break_hw_address(process: sch.Schema('Process'), address: Address):
    """Set a hardware-assisted breakpoint."""
    find_proc_by_obj(process)
    dbg().ba(expr=address.offset)


@REGISTRY.method(action='break_hw_execute')
def break_hw_expression(expression: str):
    """Set a hardware-assisted breakpoint."""
    dbg().ba(expr=expression)


@REGISTRY.method(action='break_read')
def break_read_range(process: sch.Schema('Process'), range: AddressRange):
    """Set a read watchpoint."""
    find_proc_by_obj(process)
    dbg().ba(expr=range.min, size=range.length(), access=DbgEng.DEBUG_BREAK_READ)


@REGISTRY.method(action='break_read')
def break_read_expression(expression: str):
    """Set a read watchpoint."""
    dbg().ba(expr=expression, access=DbgEng.DEBUG_BREAK_READ)


@REGISTRY.method(action='break_write')
def break_write_range(process: sch.Schema('Process'), range: AddressRange):
    """Set a watchpoint."""
    find_proc_by_obj(process)
    dbg().ba(expr=range.min, size=range.length(), access=DbgEng.DEBUG_BREAK_WRITE)


@REGISTRY.method(action='break_write')
def break_write_expression(expression: str):
    """Set a watchpoint."""
    dbg().ba(expr=expression, access=DbgEng.DEBUG_BREAK_WRITE)


@REGISTRY.method(action='break_access')
def break_access_range(process: sch.Schema('Process'), range: AddressRange):
    """Set an access watchpoint."""
    find_proc_by_obj(process)
    dbg().ba(expr=range.min, size=range.length(), access=DbgEng.DEBUG_BREAK_READ|DbgEng.DEBUG_BREAK_WRITE)


@REGISTRY.method(action='break_access')
def break_access_expression(expression: str):
    """Set an access watchpoint."""
    dbg().ba(expr=expression, access=DbgEng.DEBUG_BREAK_READ|DbgEng.DEBUG_BREAK_WRITE)


@REGISTRY.method(action='toggle')
def toggle_breakpoint(breakpoint: sch.Schema('BreakpointSpec'), enabled: bool):
    """Toggle a breakpoint."""
    bpt = find_bpt_by_obj(breakpoint)
    if enabled:
        dbg().be(bpt.GetId())
    else:
        dbg().bd(bpt.GetId())


@REGISTRY.method(action='delete')
def delete_breakpoint(breakpoint: sch.Schema('BreakpointSpec')):
    """Delete a breakpoint."""
    bpt = find_bpt_by_obj(breakpoint)
    dbg().cmd("bc {}".format(bpt.GetId()))


@REGISTRY.method
def read_mem(process: sch.Schema('Process'), range: AddressRange):
    """Read memory."""
    nproc = find_proc_by_obj(process)
    offset_start = process.trace.memory_mapper.map_back(
        nproc, Address(range.space, range.min))
    with commands.open_tracked_tx('Read Memory'):
        dbg().read(range.min, range.length())


@REGISTRY.method
def write_mem(process: sch.Schema('Process'), address: Address, data: bytes):
    """Write memory."""
    nproc = find_proc_by_obj(process)
    offset = process.trace.memory_mapper.map_back(nproc, address)
    dbg().write(offset, data)


@REGISTRY.method
def write_reg(frame: sch.Schema('StackFrame'), name: str, value: bytes):
    """Write a register."""
    util.select_frame()
    nproc = pydbg.selected_process()
    dbg().reg._set_register(name, value)
    
    
def dbg():
    return util.get_debugger()
