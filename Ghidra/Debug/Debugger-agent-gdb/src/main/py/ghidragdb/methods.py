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
from concurrent.futures import Future, Executor
import re

from ghidratrace import sch
from ghidratrace.client import MethodRegistry, ParamDesc, Address, AddressRange

import gdb

from . import commands, hooks, util


class GdbExecutor(Executor):
    def submit(self, fn, *args, **kwargs):
        fut = Future()

        def _exec():
            try:
                result = fn(*args, **kwargs)
                hooks.HOOK_STATE.end_batch()
                fut.set_result(result)
            except Exception as e:
                fut.set_exception(e)

        gdb.post_event(_exec)
        return fut


REGISTRY = MethodRegistry(GdbExecutor())


def extre(base, ext):
    return re.compile(base.pattern + ext)


AVAILABLE_PATTERN = re.compile('Available\[(?P<pid>\\d*)\]')
BREAKPOINT_PATTERN = re.compile('Breakpoints\[(?P<breaknum>\\d*)\]')
BREAK_LOC_PATTERN = extre(BREAKPOINT_PATTERN, '\[(?P<locnum>\\d*)\]')
INFERIOR_PATTERN = re.compile('Inferiors\[(?P<infnum>\\d*)\]')
INF_BREAKS_PATTERN = extre(INFERIOR_PATTERN, '\.Breakpoints')
ENV_PATTERN = extre(INFERIOR_PATTERN, '\.Environment')
THREADS_PATTERN = extre(INFERIOR_PATTERN, '\.Threads')
THREAD_PATTERN = extre(THREADS_PATTERN, '\[(?P<tnum>\\d*)\]')
STACK_PATTERN = extre(THREAD_PATTERN, '\.Stack')
FRAME_PATTERN = extre(STACK_PATTERN, '\[(?P<level>\\d*)\]')
REGS_PATTERN = extre(FRAME_PATTERN, '.Registers')
MEMORY_PATTERN = extre(INFERIOR_PATTERN, '\.Memory')
MODULES_PATTERN = extre(INFERIOR_PATTERN, '\.Modules')


def find_availpid_by_pattern(pattern, object, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    pid = int(mat['pid'])
    return pid


def find_availpid_by_obj(object):
    return find_availpid_by_pattern(AVAILABLE_PATTERN, object, "an Available")


def find_inf_by_num(infnum):
    for inf in gdb.inferiors():
        if inf.num == infnum:
            return inf
    raise KeyError(f"Inferiors[{infnum}] does not exist")


def find_inf_by_pattern(object, pattern, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    infnum = int(mat['infnum'])
    return find_inf_by_num(infnum)


def find_inf_by_obj(object):
    return find_inf_by_pattern(object, INFERIOR_PATTERN, "an Inferior")


def find_inf_by_infbreak_obj(object):
    return find_inf_by_pattern(object, INF_BREAKS_PATTERN,
                               "a BreakpointLocationContainer")


def find_inf_by_env_obj(object):
    return find_inf_by_pattern(object, ENV_PATTERN, "an Environment")


def find_inf_by_threads_obj(object):
    return find_inf_by_pattern(object, THREADS_PATTERN, "a ThreadContainer")


def find_inf_by_mem_obj(object):
    return find_inf_by_pattern(object, MEMORY_PATTERN, "a Memory")


def find_inf_by_modules_obj(object):
    return find_inf_by_pattern(object, MODULES_PATTERN, "a ModuleContainer")


def find_thread_by_num(inf, tnum):
    for t in inf.threads():
        if t.num == tnum:
            return t
    raise KeyError(f"Inferiors[{inf.num}].Threads[{tnum}] does not exist")


def find_thread_by_pattern(pattern, object, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    infnum = int(mat['infnum'])
    tnum = int(mat['tnum'])
    inf = find_inf_by_num(infnum)
    return find_thread_by_num(inf, tnum)


def find_thread_by_obj(object):
    return find_thread_by_pattern(THREAD_PATTERN, object, "a Thread")


def find_thread_by_stack_obj(object):
    return find_thread_by_pattern(STACK_PATTERN, object, "a Stack")


def find_frame_by_level(thread, level):
    # Because threads don't have any attribute to get at frames
    thread.switch()
    f = gdb.selected_frame()

    # Navigate up or down, because I can't just get by level
    down = level - f.level()
    while down > 0:
        f = f.older()
        if f is None:
            raise KeyError(
                f"Inferiors[{thread.inferior.num}].Threads[{thread.num}].Stack[{level}] does not exist")
        down -= 1
    while down < 0:
        f = f.newer()
        if f is None:
            raise KeyError(
                f"Inferiors[{thread.inferior.num}].Threads[{thread.num}].Stack[{level}] does not exist")
        down += 1
    assert f.level() == level
    return f


def find_frame_by_pattern(pattern, object, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    infnum = int(mat['infnum'])
    tnum = int(mat['tnum'])
    level = int(mat['level'])
    inf = find_inf_by_num(infnum)
    t = find_thread_by_num(inf, tnum)
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


# Oof. no gdb/Python method to get breakpoint by number
# I could keep my own cache in a dict, but why?
def find_bpt_by_number(breaknum):
    # TODO: If len exceeds some threshold, use binary search?
    for b in gdb.breakpoints():
        if b.number == breaknum:
            return b
    raise KeyError(f"Breakpoints[{breaknum}] does not exist")


def find_bpt_by_pattern(pattern, object, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    breaknum = int(mat['breaknum'])
    return find_bpt_by_number(breaknum)


def find_bpt_by_obj(object):
    return find_bpt_by_pattern(BREAKPOINT_PATTERN, object, "a BreakpointSpec")


def find_bptlocnum_by_pattern(pattern, object, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypError(f"{object} is not {err_msg}")
    breaknum = int(mat['breaknum'])
    locnum = int(mat['locnum'])
    return breaknum, locnum


def find_bptlocnum_by_obj(object):
    return find_bptlocnum_by_pattern(BREAK_LOC_PATTERN, object,
                                     "a BreakpointLocation")


def find_bpt_loc_by_obj(object):
    breaknum, locnum = find_bptlocnum_by_obj(object)
    bpt = find_bpt_by_number(breaknum)
    # Requires gdb-13.1 or later
    return bpt.locations[locnum - 1]  # Display is 1-up


def switch_inferior(inferior):
    if gdb.selected_inferior().num == inferior.num:
        return
    gdb.execute("inferior {}".format(inferior.num))


@REGISTRY.method
def execute(cmd: str, to_string: bool=False):
    """Execute a CLI command."""
    return gdb.execute(cmd, to_string=to_string)


@REGISTRY.method(action='refresh')
def refresh_available(node: sch.Schema('AvailableContainer')):
    """List processes on gdb's host system."""
    with commands.open_tracked_tx('Refresh Available'):
        gdb.execute('ghidra trace put-available')


@REGISTRY.method(action='refresh')
def refresh_breakpoints(node: sch.Schema('BreakpointContainer')):
    """
    Refresh the list of breakpoints (including locations for the current
    inferior).
    """
    with commands.open_tracked_tx('Refresh Breakpoints'):
        gdb.execute('ghidra trace put-breakpoints')


@REGISTRY.method(action='refresh')
def refresh_inferiors(node: sch.Schema('InferiorContainer')):
    """Refresh the list of inferiors."""
    with commands.open_tracked_tx('Refresh Inferiors'):
        gdb.execute('ghidra trace put-inferiors')


@REGISTRY.method(action='refresh')
def refresh_inf_breakpoints(node: sch.Schema('BreakpointLocationContainer')):
    """
    Refresh the breakpoint locations for the inferior.

    In the course of refreshing the locations, the breakpoint list will also be
    refreshed.
    """
    switch_inferior(find_inf_by_infbreak_obj(node))
    with commands.open_tracked_tx('Refresh Breakpoint Locations'):
        gdb.execute('ghidra trace put-breakpoints')


@REGISTRY.method(action='refresh')
def refresh_environment(node: sch.Schema('Environment')):
    """Refresh the environment descriptors (arch, os, endian)."""
    switch_inferior(find_inf_by_env_obj(node))
    with commands.open_tracked_tx('Refresh Environment'):
        gdb.execute('ghidra trace put-environment')


@REGISTRY.method(action='refresh')
def refresh_threads(node: sch.Schema('ThreadContainer')):
    """Refresh the list of threads in the inferior."""
    switch_inferior(find_inf_by_threads_obj(node))
    with commands.open_tracked_tx('Refresh Threads'):
        gdb.execute('ghidra trace put-threads')


@REGISTRY.method(action='refresh')
def refresh_stack(node: sch.Schema('Stack')):
    """Refresh the backtrace for the thread."""
    find_thread_by_stack_obj(node).switch()
    with commands.open_tracked_tx('Refresh Stack'):
        gdb.execute('ghidra trace put-frames')


@REGISTRY.method(action='refresh')
def refresh_registers(node: sch.Schema('RegisterValueContainer')):
    """Refresh the register values for the frame."""
    find_frame_by_regs_obj(node).select()
    # TODO: Groups?
    with commands.open_tracked_tx('Refresh Registers'):
        gdb.execute('ghidra trace putreg')


@REGISTRY.method(action='refresh')
def refresh_mappings(node: sch.Schema('Memory')):
    """Refresh the list of memory regions for the inferior."""
    switch_inferior(find_inf_by_mem_obj(node))
    with commands.open_tracked_tx('Refresh Memory Regions'):
        gdb.execute('ghidra trace put-regions')


@REGISTRY.method(action='refresh')
def refresh_modules(node: sch.Schema('ModuleContainer')):
    """
    Refresh the modules and sections list for the inferior.

    This will refresh the sections for all modules, not just the selected one.
    """
    switch_inferior(find_inf_by_modules_obj(node))
    with commands.open_tracked_tx('Refresh Modules'):
        gdb.execute('ghidra trace put-modules')


@REGISTRY.method(action='activate')
def activate_inferior(inferior: sch.Schema('Inferior')):
    """Switch to the inferior."""
    switch_inferior(find_inf_by_obj(inferior))


@REGISTRY.method(action='activate')
def activate_thread(thread: sch.Schema('Thread')):
    """Switch to the thread."""
    find_thread_by_obj(thread).switch()


@REGISTRY.method(action='activate')
def activate_frame(frame: sch.Schema('StackFrame')):
    """Select the frame."""
    find_frame_by_obj(frame).select()


@REGISTRY.method
def add_inferior(container: sch.Schema('InferiorContainer')):
    """Add a new inferior."""
    gdb.execute('add-inferior')


@REGISTRY.method(action='delete')
def delete_inferior(inferior: sch.Schema('Inferior')):
    """Remove the inferior."""
    inf = find_inf_by_obj(inferior)
    gdb.execute(f'remove-inferior {inf.num}')


# TODO: Separate method for each of core, exec, remote, etc...?
@REGISTRY.method
def connect(inferior: sch.Schema('Inferior'), spec: str):
    """Connect to a target machine or process."""
    switch_inferior(find_inf_by_obj(inferior))
    gdb.execute(f'target {spec}')


@REGISTRY.method(action='attach')
def attach_obj(inferior: sch.Schema('Inferior'), target: sch.Schema('Attachable')):
    """Attach the inferior to the given target."""
    switch_inferior(find_inf_by_obj(inferior))
    pid = find_availpid_by_obj(target)
    gdb.execute(f'attach {pid}')


@REGISTRY.method(action='attach')
def attach_pid(inferior: sch.Schema('Inferior'), pid: int):
    """Attach the inferior to the given target."""
    switch_inferior(find_inf_by_obj(inferior))
    gdb.execute(f'attach {pid}')


@REGISTRY.method
def detach(inferior: sch.Schema('Inferior')):
    """Detach the inferior's target."""
    switch_inferior(find_inf_by_obj(inferior))
    gdb.execute('detach')


@REGISTRY.method(action='launch')
def launch_main(inferior: sch.Schema('Inferior'),
                file: ParamDesc(str, display='File'),
                args: ParamDesc(str, display='Arguments')=''):
    """
    Start a native process with the given command line, stopping at 'main'
    (start).

    If 'main' is not defined in the file, this behaves like 'run'.
    """
    switch_inferior(find_inf_by_obj(inferior))
    gdb.execute(f'''
    file {file}
    set args {args}
    start
    ''')


@REGISTRY.method(action='launch', condition=util.GDB_VERSION.major >= 9)
def launch_loader(inferior: sch.Schema('Inferior'),
                  file: ParamDesc(str, display='File'),
                  args: ParamDesc(str, display='Arguments')=''):
    """
    Start a native process with the given command line, stopping at first
    instruction (starti).
    """
    switch_inferior(find_inf_by_obj(inferior))
    gdb.execute(f'''
    file {file}
    set args {args}
    starti
    ''')


@REGISTRY.method(action='launch')
def launch_run(inferior: sch.Schema('Inferior'),
               file: ParamDesc(str, display='File'),
               args: ParamDesc(str, display='Arguments')=''):
    """
    Run a native process with the given command line (run).

    The process will not stop until it hits one of your breakpoints, or it is
    signaled.
    """
    switch_inferior(find_inf_by_obj(inferior))
    gdb.execute(f'''
    file {file}
    set args {args}
    run
    ''')


@REGISTRY.method
def kill(inferior: sch.Schema('Inferior')):
    """Kill execution of the inferior."""
    switch_inferior(find_inf_by_obj(inferior))
    gdb.execute('kill')


@REGISTRY.method
def resume(inferior: sch.Schema('Inferior')):
    """Continue execution of the inferior."""
    switch_inferior(find_inf_by_obj(inferior))
    gdb.execute('continue')


@REGISTRY.method
def interrupt():
    """Interrupt the execution of the debugged program."""
    gdb.execute('interrupt')


@REGISTRY.method
def step_into(thread: sch.Schema('Thread'), n: ParamDesc(int, display='N')=1):
    """Step one instruction exactly (stepi)."""
    find_thread_by_obj(thread).switch()
    gdb.execute('stepi')


@REGISTRY.method
def step_over(thread: sch.Schema('Thread'), n: ParamDesc(int, display='N')=1):
    """Step one instruction, but proceed through subroutine calls (nexti)."""
    find_thread_by_obj(thread).switch()
    gdb.execute('nexti')


@REGISTRY.method
def step_out(thread: sch.Schema('Thread')):
    """Execute until the current stack frame returns (finish)."""
    find_thread_by_obj(thread).switch()
    gdb.execute('finish')


@REGISTRY.method(action='step_ext')
def step_advance(thread: sch.Schema('Thread'), address: Address):
    """Continue execution up to the given address (advance)."""
    t = find_thread_by_obj(thread)
    t.switch()
    offset = thread.trace.memory_mapper.map_back(t.inferior, address)
    gdb.execute(f'advance *0x{offset:x}')


@REGISTRY.method(action='step_ext')
def step_return(thread: sch.Schema('Thread'), value: int=None):
    """Skip the remainder of the current function (return)."""
    find_thread_by_obj(thread).switch()
    if value is None:
        gdb.execute('return')
    else:
        gdb.execute(f'return {value}')


@REGISTRY.method(action='break_sw_execute')
def break_sw_execute_address(inferior: sch.Schema('Inferior'), address: Address):
    """Set a breakpoint (break)."""
    inf = find_inf_by_obj(inferior)
    offset = inferior.trace.memory_mapper.map_back(inf, address)
    gdb.execute(f'break *0x{offset:x}')


@REGISTRY.method(action='break_sw_execute')
def break_sw_execute_expression(expression: str):
    """Set a breakpoint (break)."""
    # TODO: Escape?
    gdb.execute(f'break {expression}')


@REGISTRY.method(action='break_hw_execute')
def break_hw_execute_address(inferior: sch.Schema('Inferior'), address: Address):
    """Set a hardware-assisted breakpoint (hbreak)."""
    inf = find_inf_by_obj(inferior)
    offset = inferior.trace.memory_mapper.map_back(inf, address)
    gdb.execute(f'hbreak *0x{offset:x}')


@REGISTRY.method(action='break_hw_execute')
def break_hw_execute_expression(expression: str):
    """Set a hardware-assisted breakpoint (hbreak)."""
    # TODO: Escape?
    gdb.execute(f'hbreak {expression}')


@REGISTRY.method(action='break_read')
def break_read_range(inferior: sch.Schema('Inferior'), range: AddressRange):
    """Set a read watchpoint (rwatch)."""
    inf = find_inf_by_obj(inferior)
    offset_start = inferior.trace.memory_mapper.map_back(
        inf, Address(range.space, range.min))
    gdb.execute(
        f'rwatch -location *((char(*)[{range.length()}]) 0x{offset_start:x})')


@REGISTRY.method(action='break_read')
def break_read_expression(expression: str):
    """Set a read watchpoint (rwatch)."""
    gdb.execute(f'rwatch {expression}')


@REGISTRY.method(action='break_write')
def break_write_range(inferior: sch.Schema('Inferior'), range: AddressRange):
    """Set a watchpoint (watch)."""
    inf = find_inf_by_obj(inferior)
    offset_start = inferior.trace.memory_mapper.map_back(
        inf, Address(range.space, range.min))
    gdb.execute(
        f'watch -location *((char(*)[{range.length()}]) 0x{offset_start:x})')


@REGISTRY.method(action='break_write')
def break_write_expression(expression: str):
    """Set a watchpoint (watch)."""
    gdb.execute(f'watch {expression}')


@REGISTRY.method(action='break_access')
def break_access_range(inferior: sch.Schema('Inferior'), range: AddressRange):
    """Set an access watchpoint (awatch)."""
    inf = find_inf_by_obj(inferior)
    offset_start = inferior.trace.memory_mapper.map_back(
        inf, Address(range.space, range.min))
    gdb.execute(
        f'awatch -location *((char(*)[{range.length()}]) 0x{offset_start:x})')


@REGISTRY.method(action='break_access')
def break_access_expression(expression: str):
    """Set an access watchpoint (awatch)."""
    gdb.execute(f'awatch {expression}')


@REGISTRY.method(action='break_ext')
def break_event(spec: str):
    """Set a catchpoint (catch)."""
    gdb.execute(f'catch {spec}')


@REGISTRY.method(action='toggle')
def toggle_breakpoint(breakpoint: sch.Schema('BreakpointSpec'), enabled: bool):
    """Toggle a breakpoint."""
    bpt = find_bpt_by_obj(breakpoint)
    bpt.enabled = enabled


@REGISTRY.method(action='toggle', condition=util.GDB_VERSION.major >= 13)
def toggle_breakpoint_location(location: sch.Schema('BreakpointLocation'), enabled: bool):
    """Toggle a breakpoint location."""
    loc = find_bpt_loc_by_obj(location)
    loc.enabled = enabled


@REGISTRY.method(action='toggle', condition=util.GDB_VERSION.major < 13)
def toggle_breakpoint_location(location: sch.Schema('BreakpointLocation'), enabled: bool):
    """Toggle a breakpoint location."""
    bptnum, locnum = find_bptlocnum_by_obj(location)
    cmd = 'enable' if enabled else 'disable'
    gdb.execute(f'{cmd} {bptnum}.{locnum}')


@REGISTRY.method(action='delete')
def delete_breakpoint(breakpoint: sch.Schema('BreakpointSpec')):
    """Delete a breakpoint."""
    bpt = find_bpt_by_obj(breakpoint)
    bpt.delete()


@REGISTRY.method
def read_mem(inferior: sch.Schema('Inferior'), range: AddressRange):
    """Read memory."""
    inf = find_inf_by_obj(inferior)
    offset_start = inferior.trace.memory_mapper.map_back(
        inf, Address(range.space, range.min))
    with commands.open_tracked_tx('Read Memory'):
        gdb.execute(f'ghidra trace putmem 0x{offset_start:x} {range.length()}')


@REGISTRY.method
def write_mem(inferior: sch.Schema('Inferior'), address: Address, data: bytes):
    """Write memory."""
    inf = find_inf_by_obj(inferior)
    offset = inferior.trace.memory_mapper.map_back(inf, address)
    inf.write_memory(offset, data)


@REGISTRY.method
def write_reg(frame: sch.Schema('Frame'), name: str, value: bytes):
    """Write a register."""
    f = find_frame_by_obj(frame)
    f.select()
    inf = gdb.selected_inferior()
    mname, mval = frame.trace.register_mapper.map_value_back(inf, name, value)
    reg = find_reg_by_name(f, mname)
    size = int(gdb.parse_and_eval(f'sizeof(${mname})'))
    arr = '{' + ','.join(str(b) for b in mval) + '}'
    gdb.execute(f'set ((unsigned char[{size}])${mname}) = {arr}')
