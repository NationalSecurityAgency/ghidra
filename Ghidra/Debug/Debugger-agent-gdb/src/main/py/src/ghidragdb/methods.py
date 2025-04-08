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
from concurrent.futures import Future, Executor
from contextlib import contextmanager
import re
from typing import Annotated, Generator, Optional, Tuple, Union

import gdb
from ghidratrace import sch
from ghidratrace.client import (MethodRegistry, ParamDesc, Address,
                                AddressRange, Trace, TraceObject)

from . import commands, hooks, util


@contextmanager
def no_pagination() -> Generator[None, None, None]:
    before = gdb.parameter('pagination')
    util.set_bool_param('pagination', False)
    yield
    util.set_bool_param('pagination', bool(before))


@contextmanager
def no_confirm() -> Generator[None, None, None]:
    before = gdb.parameter('confirm')
    util.set_bool_param('confirm', False)
    yield
    util.set_bool_param('confirm', bool(before))


class GdbExecutor(Executor):
    def submit(self, fn, *args, **kwargs):
        fut = Future()

        def _exec():
            try:
                with no_pagination():
                    result = fn(*args, **kwargs)
                hooks.HOOK_STATE.end_batch()
                fut.set_result(result)
            except Exception as e:
                fut.set_exception(e)

        gdb.post_event(_exec)
        return fut


REGISTRY = MethodRegistry(GdbExecutor())


def extre(base: re.Pattern, ext: str) -> re.Pattern:
    return re.compile(base.pattern + ext)


AVAILABLE_PATTERN = re.compile('Available\\[(?P<pid>\\d*)\\]')
BREAKPOINT_PATTERN = re.compile('Breakpoints\\[(?P<breaknum>\\d*)\\]')
BREAK_LOC_PATTERN = extre(BREAKPOINT_PATTERN, '\\[(?P<locnum>\\d*)\\]')
INFERIOR_PATTERN = re.compile('Inferiors\\[(?P<infnum>\\d*)\\]')
INF_BREAKS_PATTERN = extre(INFERIOR_PATTERN, '\\.Breakpoints')
ENV_PATTERN = extre(INFERIOR_PATTERN, '\\.Environment')
THREADS_PATTERN = extre(INFERIOR_PATTERN, '\\.Threads')
THREAD_PATTERN = extre(THREADS_PATTERN, '\\[(?P<tnum>\\d*)\\]')
STACK_PATTERN = extre(THREAD_PATTERN, '\\.Stack')
FRAME_PATTERN = extre(STACK_PATTERN, '\\[(?P<level>\\d*)\\]')
REGS_PATTERN = extre(FRAME_PATTERN, '\\.Registers')
MEMORY_PATTERN = extre(INFERIOR_PATTERN, '\\.Memory')
MODULES_PATTERN = extre(INFERIOR_PATTERN, '\\.Modules')
MODULE_PATTERN = extre(MODULES_PATTERN, '\\[(?P<modname>.*)\\]')


def find_availpid_by_pattern(pattern: re.Pattern, object: TraceObject,
                             err_msg: str) -> int:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    pid = int(mat['pid'])
    return pid


def find_availpid_by_obj(object: TraceObject) -> int:
    return find_availpid_by_pattern(AVAILABLE_PATTERN, object, "an Available")


def find_inf_by_num(infnum: int) -> gdb.Inferior:
    for inf in gdb.inferiors():
        if inf.num == infnum:
            return inf
    raise KeyError(f"Inferiors[{infnum}] does not exist")


def find_inf_by_pattern(object: TraceObject, pattern: re.Pattern,
                        err_msg: str) -> gdb.Inferior:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    infnum = int(mat['infnum'])
    return find_inf_by_num(infnum)


def find_inf_by_obj(object: TraceObject) -> gdb.Inferior:
    return find_inf_by_pattern(object, INFERIOR_PATTERN, "an Inferior")


def find_inf_by_infbreak_obj(object: TraceObject) -> gdb.Inferior:
    return find_inf_by_pattern(object, INF_BREAKS_PATTERN,
                               "a BreakpointLocationContainer")


def find_inf_by_env_obj(object: TraceObject) -> gdb.Inferior:
    return find_inf_by_pattern(object, ENV_PATTERN, "an Environment")


def find_inf_by_threads_obj(object: TraceObject) -> gdb.Inferior:
    return find_inf_by_pattern(object, THREADS_PATTERN, "a ThreadContainer")


def find_inf_by_mem_obj(object: TraceObject) -> gdb.Inferior:
    return find_inf_by_pattern(object, MEMORY_PATTERN, "a Memory")


def find_inf_by_modules_obj(object: TraceObject) -> gdb.Inferior:
    return find_inf_by_pattern(object, MODULES_PATTERN, "a ModuleContainer")


def find_inf_by_mod_obj(object: TraceObject) -> gdb.Inferior:
    return find_inf_by_pattern(object, MODULE_PATTERN, "a Module")


def find_module_name_by_mod_obj(object: TraceObject) -> str:
    mat = MODULE_PATTERN.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not a Module")
    return mat['modname']


def find_thread_by_num(inf: gdb.Inferior, tnum: int) -> gdb.InferiorThread:
    for t in inf.threads():
        if t.num == tnum:
            return t
    raise KeyError(f"Inferiors[{inf.num}].Threads[{tnum}] does not exist")


def find_thread_by_pattern(pattern: re.Pattern, object: TraceObject,
                           err_msg: str) -> gdb.InferiorThread:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    infnum = int(mat['infnum'])
    tnum = int(mat['tnum'])
    inf = find_inf_by_num(infnum)
    return find_thread_by_num(inf, tnum)


def find_thread_by_obj(object: TraceObject) -> gdb.InferiorThread:
    return find_thread_by_pattern(THREAD_PATTERN, object, "a Thread")


def find_thread_by_stack_obj(object: TraceObject) -> gdb.InferiorThread:
    return find_thread_by_pattern(STACK_PATTERN, object, "a Stack")


def find_frame_by_level(thread: gdb.InferiorThread,
                        level: int) -> Optional[gdb.Frame]:
    # Because threads don't have any attribute to get at frames
    thread.switch()
    f = util.selected_frame()
    if f is None:
        return None

    # Navigate up or down, because I can't just get by level
    down = level - util.get_level(f)
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
    return f


def find_frame_by_pattern(pattern: re.Pattern, object: TraceObject,
                          err_msg: str) -> Optional[gdb.Frame]:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    infnum = int(mat['infnum'])
    tnum = int(mat['tnum'])
    level = int(mat['level'])
    inf = find_inf_by_num(infnum)
    t = find_thread_by_num(inf, tnum)
    return find_frame_by_level(t, level)


def find_frame_by_obj(object: TraceObject) -> Optional[gdb.Frame]:
    return find_frame_by_pattern(FRAME_PATTERN, object, "a StackFrame")


def find_frame_by_regs_obj(object: TraceObject) -> Optional[gdb.Frame]:
    return find_frame_by_pattern(REGS_PATTERN, object,
                                 "a RegisterValueContainer")


# Because there's no method to get a register by name....
def find_reg_by_name(f: gdb.Frame, name: str) -> Union[gdb.RegisterDescriptor,
                                                       util.RegisterDesc]:
    for reg in util.get_register_descs(f.architecture()):
        # TODO: gdb appears to be case sensitive, but until we encounter a
        # situation where case matters, we'll be insensitive
        if reg.name.lower() == name.lower():
            return reg
    raise KeyError(f"No such register: {name}")


# Oof. no gdb/Python method to get breakpoint by number
# I could keep my own cache in a dict, but why?
def find_bpt_by_number(breaknum: int) -> gdb.Breakpoint:
    # TODO: If len exceeds some threshold, use binary search?
    for b in gdb.breakpoints():
        if b.number == breaknum:
            return b
    raise KeyError(f"Breakpoints[{breaknum}] does not exist")


def find_bpt_by_pattern(pattern: re.Pattern, object: TraceObject,
                        err_msg: str) -> gdb.Breakpoint:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    breaknum = int(mat['breaknum'])
    return find_bpt_by_number(breaknum)


def find_bpt_by_obj(object: TraceObject) -> gdb.Breakpoint:
    return find_bpt_by_pattern(BREAKPOINT_PATTERN, object, "a BreakpointSpec")


def find_bptlocnum_by_pattern(pattern: re.Pattern, object: TraceObject,
                              err_msg: str) -> Tuple[int, int]:
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    breaknum = int(mat['breaknum'])
    locnum = int(mat['locnum'])
    return breaknum, locnum


def find_bptlocnum_by_obj(object: TraceObject) -> Tuple[int, int]:
    return find_bptlocnum_by_pattern(BREAK_LOC_PATTERN, object,
                                     "a BreakpointLocation")


def find_bpt_loc_by_obj(object: TraceObject) -> gdb.BreakpointLocation:
    breaknum, locnum = find_bptlocnum_by_obj(object)
    bpt = find_bpt_by_number(breaknum)
    # Requires gdb-13.1 or later
    return bpt.locations[locnum - 1]  # Display is 1-up


def switch_inferior(inferior: gdb.Inferior) -> None:
    if gdb.selected_inferior().num == inferior.num:
        return
    gdb.execute(f'inferior {inferior.num}')


class Attachable(TraceObject):
    pass


class AvailableContainer(TraceObject):
    pass


class BreakpointContainer(TraceObject):
    pass


class BreakpointLocation(TraceObject):
    pass


class BreakpointLocationContainer(TraceObject):
    pass


class BreakpointSpec(TraceObject):
    pass


class Environment(TraceObject):
    pass


class Inferior(TraceObject):
    pass


class InferiorContainer(TraceObject):
    pass


class Memory(TraceObject):
    pass


class Module(TraceObject):
    pass


class ModuleContainer(TraceObject):
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


@REGISTRY.method()
def execute(cmd: str, to_string: bool = False) -> Optional[str]:
    """Execute a CLI command."""
    return gdb.execute(cmd, to_string=to_string)


@REGISTRY.method(action='refresh', display='Refresh Available')
def refresh_available(node: AvailableContainer) -> None:
    """List processes on gdb's host system."""
    with commands.open_tracked_tx('Refresh Available'):
        gdb.execute('ghidra trace put-available')


@REGISTRY.method(action='refresh', display='Refresh Breakpoints')
def refresh_breakpoints(node: BreakpointContainer) -> None:
    """Refresh the list of breakpoints (including locations for the current
    inferior)."""
    with commands.open_tracked_tx('Refresh Breakpoints'):
        gdb.execute('ghidra trace put-breakpoints')


@REGISTRY.method(action='refresh', display='Refresh Inferiors')
def refresh_inferiors(node: InferiorContainer) -> None:
    """Refresh the list of inferiors."""
    with commands.open_tracked_tx('Refresh Inferiors'):
        gdb.execute('ghidra trace put-inferiors')


@REGISTRY.method(action='refresh', display='Refresh Breakpoint Locations')
def refresh_inf_breakpoints(node: BreakpointLocationContainer) -> None:
    """Refresh the breakpoint locations for the inferior.

    In the course of refreshing the locations, the breakpoint list will
    also be refreshed.
    """
    switch_inferior(find_inf_by_infbreak_obj(node))
    with commands.open_tracked_tx('Refresh Breakpoint Locations'):
        gdb.execute('ghidra trace put-breakpoints')


@REGISTRY.method(action='refresh', display='Refresh Environment')
def refresh_environment(node: Environment) -> None:
    """Refresh the environment descriptors (arch, os, endian)."""
    switch_inferior(find_inf_by_env_obj(node))
    with commands.open_tracked_tx('Refresh Environment'):
        gdb.execute('ghidra trace put-environment')


@REGISTRY.method(action='refresh', display='Refresh Threads')
def refresh_threads(node: ThreadContainer) -> None:
    """Refresh the list of threads in the inferior."""
    switch_inferior(find_inf_by_threads_obj(node))
    with commands.open_tracked_tx('Refresh Threads'):
        gdb.execute('ghidra trace put-threads')


@REGISTRY.method(action='refresh', display='Refresh Stack')
def refresh_stack(node: Stack) -> None:
    """Refresh the backtrace for the thread."""
    find_thread_by_stack_obj(node).switch()
    with commands.open_tracked_tx('Refresh Stack'):
        gdb.execute('ghidra trace put-frames')


@REGISTRY.method(action='refresh', display='Refresh Registers')
def refresh_registers(node: RegisterValueContainer) -> None:
    """Refresh the register values for the frame."""
    f = find_frame_by_regs_obj(node)
    if f is None:
        return
    f.select()
    # TODO: Groups?
    with commands.open_tracked_tx('Refresh Registers'):
        gdb.execute('ghidra trace putreg')


@REGISTRY.method(action='refresh', display='Refresh Memory')
def refresh_mappings(node: Memory) -> None:
    """Refresh the list of memory regions for the inferior."""
    switch_inferior(find_inf_by_mem_obj(node))
    with commands.open_tracked_tx('Refresh Memory Regions'):
        gdb.execute('ghidra trace put-regions')


@REGISTRY.method(action='refresh', display="Refresh Modules")
def refresh_modules(node: ModuleContainer) -> None:
    """Refresh the modules list for the inferior."""
    switch_inferior(find_inf_by_modules_obj(node))
    with commands.open_tracked_tx('Refresh Modules'):
        gdb.execute('ghidra trace put-modules')


# node is Module so this appears in Modules panel
@REGISTRY.method(display='Refresh all Modules and all Sections')
def load_all_sections(node: Module) -> None:
    """Load/refresh all modules and all sections."""
    switch_inferior(find_inf_by_mod_obj(node))
    with commands.open_tracked_tx('Refresh all Modules and all Sections'):
        gdb.execute('ghidra trace put-sections -all-objects')


@REGISTRY.method(action='refresh', display="Refresh Module and Sections")
def refresh_sections(node: Module) -> None:
    """Load/refresh the module and its sections."""
    switch_inferior(find_inf_by_mod_obj(node))
    with commands.open_tracked_tx('Refresh Module and Sections'):
        modname = find_module_name_by_mod_obj(node)
        gdb.execute(f'ghidra trace put-sections "{modname}"')


@REGISTRY.method(action='activate', display="Activate Inferior")
def activate_inferior(inferior: Inferior) -> None:
    """Switch to the inferior."""
    switch_inferior(find_inf_by_obj(inferior))


@REGISTRY.method(action='activate', display="Activate Thread")
def activate_thread(thread: Thread) -> None:
    """Switch to the thread."""
    find_thread_by_obj(thread).switch()


@REGISTRY.method(action='activate', display="Activate Frame")
def activate_frame(frame: StackFrame) -> None:
    """Select the frame."""
    f = find_frame_by_obj(frame)
    if not f is None:
        f.select()


@REGISTRY.method(display='Add Inferior')
def add_inferior(container: InferiorContainer) -> None:
    """Add a new inferior."""
    gdb.execute('add-inferior')


@REGISTRY.method(action='delete', display="Delete Inferior")
def delete_inferior(inferior: Inferior) -> None:
    """Remove the inferior."""
    inf = find_inf_by_obj(inferior)
    gdb.execute(f'remove-inferior {inf.num}')


# TODO: Separate method for each of core, exec, remote, etc...?
@REGISTRY.method(display='Connect Target')
def connect(inferior: Inferior, spec: str) -> None:
    """Connect to a target machine or process."""
    switch_inferior(find_inf_by_obj(inferior))
    gdb.execute(f'target {spec}')


@REGISTRY.method(action='attach', display='Attach')
def attach_obj(target: Attachable) -> None:
    """Attach the inferior to the given target."""
    # switch_inferior(find_inf_by_obj(inferior))
    pid = find_availpid_by_obj(target)
    gdb.execute(f'attach {pid}')


@REGISTRY.method(action='attach', display='Attach by PID')
def attach_pid(inferior: Inferior, pid: int) -> None:
    """Attach the inferior to the given target."""
    switch_inferior(find_inf_by_obj(inferior))
    gdb.execute(f'attach {pid}')


@REGISTRY.method(display='Detach')
def detach(inferior: Inferior) -> None:
    """Detach the inferior's target."""
    switch_inferior(find_inf_by_obj(inferior))
    gdb.execute('detach')


@REGISTRY.method(action='launch', display='Launch at main')
def launch_main(inferior: Inferior,
                file: Annotated[str, ParamDesc(display='File')],
                args: Annotated[str, ParamDesc(display='Arguments')] = '') -> None:
    """Start a native process with the given command line, stopping at 'main'
    (start).

    If 'main' is not defined in the file, this behaves like 'run'.
    """
    switch_inferior(find_inf_by_obj(inferior))
    gdb.execute(f'''
    file {file}
    set args {args}
    start
    ''')


@REGISTRY.method(action='launch', display='Launch at Loader',
                 condition=util.GDB_VERSION.major >= 9)
def launch_loader(inferior: Inferior,
                  file: Annotated[str, ParamDesc(display='File')],
                  args: Annotated[str, ParamDesc(display='Arguments')] = '') -> None:
    """Start a native process with the given command line, stopping at first
    instruction (starti)."""
    switch_inferior(find_inf_by_obj(inferior))
    gdb.execute(f'''
    file {file}
    set args {args}
    starti
    ''')


@REGISTRY.method(action='launch', display='Launch and Run')
def launch_run(inferior: Inferior,
               file: Annotated[str, ParamDesc(display='File')],
               args: Annotated[str, ParamDesc(display='Arguments')] = '') -> None:
    """Run a native process with the given command line (run).

    The process will not stop until it hits one of your breakpoints, or
    it is signaled.
    """
    switch_inferior(find_inf_by_obj(inferior))
    gdb.execute(f'''
    file {file}
    set args {args}
    run
    ''')


@REGISTRY.method()
def kill(inferior: Inferior) -> None:
    """Kill execution of the inferior."""
    switch_inferior(find_inf_by_obj(inferior))
    with no_confirm():
        gdb.execute('kill')


@REGISTRY.method()
def resume(inferior: Inferior) -> None:
    """Continue execution of the inferior."""
    switch_inferior(find_inf_by_obj(inferior))
    gdb.execute('continue')


@REGISTRY.method(action='step_ext', icon='icon.debugger.resume.back',
                 condition=util.IS_TRACE)
def resume_back(inferior: Inferior) -> None:
    """Continue execution of the inferior backwards."""
    gdb.execute('reverse-continue')


# Technically, inferior is not required, but it hints that the affected object
# is the current inferior. This in turn queues the UI to enable or disable the
# button appropriately
@REGISTRY.method()
def interrupt(inferior: Inferior) -> None:
    """Interrupt the execution of the debugged program."""
    gdb.execute('interrupt')


@REGISTRY.method()
def step_into(thread: Thread,
              n: Annotated[int, ParamDesc(display='N')] = 1) -> None:
    """Step one instruction exactly (stepi)."""
    find_thread_by_obj(thread).switch()
    gdb.execute('stepi')


@REGISTRY.method()
def step_over(thread: Thread,
              n: Annotated[int, ParamDesc(display='N')] = 1) -> None:
    """Step one instruction, but proceed through subroutine calls (nexti)."""
    find_thread_by_obj(thread).switch()
    gdb.execute('nexti')


@REGISTRY.method()
def step_out(thread: Thread) -> None:
    """Execute until the current stack frame returns (finish)."""
    find_thread_by_obj(thread).switch()
    gdb.execute('finish')


@REGISTRY.method(action='step_ext', display='Advance')
def step_advance(thread: Thread, address: Address) -> None:
    """Continue execution up to the given address (advance)."""
    t = find_thread_by_obj(thread)
    t.switch()
    offset = thread.trace.extra.require_mm().map_back(t.inferior, address)
    gdb.execute(f'advance *0x{offset:x}')


@REGISTRY.method(action='step_ext', display='Return')
def step_return(thread: Thread, value: Optional[int] = None) -> None:
    """Skip the remainder of the current function (return)."""
    find_thread_by_obj(thread).switch()
    if value is None:
        gdb.execute('return')
    else:
        gdb.execute(f'return {value}')


@REGISTRY.method(action='step_ext', icon='icon.debugger.step.back.into',
                 condition=util.IS_TRACE)
def step_back_into(thread: Thread,
                   n: Annotated[int, ParamDesc(display='N')] = 1) -> None:
    """Step backwards one instruction exactly (reverse-stepi)."""
    gdb.execute('reverse-stepi')


@REGISTRY.method(action='step_ext', icon='icon.debugger.step.back.over',
                 condition=util.IS_TRACE)
def step_back_over(thread: Thread,
                   n: Annotated[int, ParamDesc(display='N')] = 1) -> None:
    """Step one instruction backwards, but proceed through subroutine calls
    (reverse-nexti)."""
    gdb.execute('reverse-nexti')


@REGISTRY.method(action='break_sw_execute')
def break_sw_execute_address(inferior: Inferior, address: Address) -> None:
    """Set a breakpoint (break)."""
    inf = find_inf_by_obj(inferior)
    offset = inferior.trace.extra.require_mm().map_back(inf, address)
    gdb.execute(f'break *0x{offset:x}')


@REGISTRY.method(action='break_ext', display="Set Breakpoint")
def break_sw_execute_expression(expression: str) -> None:
    """Set a breakpoint (break)."""
    # TODO: Escape?
    gdb.execute(f'break {expression}')


@REGISTRY.method(action='break_hw_execute')
def break_hw_execute_address(inferior: Inferior, address: Address) -> None:
    """Set a hardware-assisted breakpoint (hbreak)."""
    inf = find_inf_by_obj(inferior)
    offset = inferior.trace.extra.require_mm().map_back(inf, address)
    gdb.execute(f'hbreak *0x{offset:x}')


@REGISTRY.method(action='break_ext', display="Set Hardware Breakpoint")
def break_hw_execute_expression(expression: str) -> None:
    """Set a hardware-assisted breakpoint (hbreak)."""
    # TODO: Escape?
    gdb.execute(f'hbreak {expression}')


@REGISTRY.method(action='break_read')
def break_read_range(inferior: Inferior, range: AddressRange) -> None:
    """Set a read watchpoint (rwatch)."""
    inf = find_inf_by_obj(inferior)
    offset_start = inferior.trace.extra.require_mm().map_back(
        inf, Address(range.space, range.min))
    gdb.execute(
        f'rwatch -location *((char(*)[{range.length()}]) 0x{offset_start:x})')


@REGISTRY.method(action='break_ext', display="Set Read Watchpoint")
def break_read_expression(expression: str) -> None:
    """Set a read watchpoint (rwatch)."""
    gdb.execute(f'rwatch {expression}')


@REGISTRY.method(action='break_write')
def break_write_range(inferior: Inferior, range: AddressRange) -> None:
    """Set a watchpoint (watch)."""
    inf = find_inf_by_obj(inferior)
    offset_start = inferior.trace.extra.require_mm().map_back(
        inf, Address(range.space, range.min))
    gdb.execute(
        f'watch -location *((char(*)[{range.length()}]) 0x{offset_start:x})')


@REGISTRY.method(action='break_ext', display="Set Watchpoint")
def break_write_expression(expression: str) -> None:
    """Set a watchpoint (watch)."""
    gdb.execute(f'watch {expression}')


@REGISTRY.method(action='break_access')
def break_access_range(inferior: Inferior, range: AddressRange) -> None:
    """Set an access watchpoint (awatch)."""
    inf = find_inf_by_obj(inferior)
    offset_start = inferior.trace.extra.require_mm().map_back(
        inf, Address(range.space, range.min))
    gdb.execute(
        f'awatch -location *((char(*)[{range.length()}]) 0x{offset_start:x})')


@REGISTRY.method(action='break_ext', display="Set Access Watchpoint")
def break_access_expression(expression: str) -> None:
    """Set an access watchpoint (awatch)."""
    gdb.execute(f'awatch {expression}')


@REGISTRY.method(action='break_ext', display='Catch Event')
def break_ext_event(inferior: Inferior,
                    spec: Annotated[str, ParamDesc(display='Type')]) -> None:
    """Set a generic catchpoint (catch)."""
    gdb.execute(f'catch {spec}')


@REGISTRY.method(display='Catch Event')
def break_event(container: BreakpointContainer,
                spec: Annotated[str, ParamDesc(display='Type')],
                desc: Annotated[str, ParamDesc(display='Desc')]) -> None:
    """Set a generic catchpoint (catch)."""
    gdb.execute(f'catch {spec} {desc}')


@REGISTRY.method(action='break_ext', display='Catch Signal')
def break_ext_signal(inferior: Inferior, signal: Annotated[
        str, ParamDesc(display='Signal (opt)')]) -> None:
    """Set a signal catchpoint (catch signal)."""
    gdb.execute(f'catch signal {signal}')


@REGISTRY.method(display='Catch Signal')
def break_signal(container: BreakpointContainer, signal: Annotated[
        str, ParamDesc(display='Signal (opt)')]) -> None:
    """Set a signal catchpoint (catch signal))."""
    gdb.execute(f'catch signal {signal}')


@REGISTRY.method(action='break_ext', display='Catch Syscall')
def break_ext_syscall(inferior: Inferior, syscall: Annotated[
        str, ParamDesc(display='Syscall (opt)')]) -> None:
    """Set a syscall catchpoint (catch syscall))."""
    gdb.execute(f'catch syscall {syscall}')


@REGISTRY.method(display='Catch Syscall')
def break_syscall(container: BreakpointContainer, syscall: Annotated[
        str, ParamDesc(display='Syscall (opt)')]) -> None:
    """Set a syscall catchpoint (catch syscall)."""
    gdb.execute(f'catch syscall {syscall}')


@REGISTRY.method(action='break_ext', display='Catch Load')
def break_ext_load(inferior: Inferior, library: Annotated[
        str, ParamDesc(display='Library (opt)')]) -> None:
    """Set a load catchpoint (catch load))."""
    gdb.execute(f'catch load {library}')


@REGISTRY.method(display='Catch Load')
def break_load(container: BreakpointContainer, library: Annotated[
        str, ParamDesc(display='Library (opt)')]) -> None:
    """Set a load catchpoint (catch load)."""
    gdb.execute(f'catch load {library}')


@REGISTRY.method(action='break_ext', display='Catch Unload')
def break_ext_unload(inferior: Inferior,
                     library: Annotated[
                         str, ParamDesc(display='Library (opt)')]) -> None:
    """Set a unload catchpoint (catch unload))."""
    gdb.execute(f'catch unload {library}')


@REGISTRY.method(display='Catch Unload')
def break_unload(container: BreakpointContainer, library: Annotated[
        str, ParamDesc(display='Library (opt)')]) -> None:
    """Set a unload catchpoint (catch unload)."""
    gdb.execute(f'catch unload {library}')


@REGISTRY.method(action='break_ext', display='Catch Catch')
def break_ext_catch(inferior: Inferior, exception: Annotated[
        str, ParamDesc(display='Exception (opt)')]) -> None:
    """Set a catch catchpoint (catch catch))."""
    gdb.execute(f'catch catch {exception}')


@REGISTRY.method(display='Catch Catch')
def break_catch(container: BreakpointContainer, exception: Annotated[
        str, ParamDesc(display='Exception (opt)')]) -> None:
    """Set a catch catchpoint (catch catch)."""
    gdb.execute(f'catch catch {exception}')


@REGISTRY.method(action='break_ext', display='Catch Throw')
def break_ext_throw(inferior: Inferior, exception: Annotated[
        str, ParamDesc(display='Exception (opt)')]) -> None:
    """Set a throw catchpoint (catch throw))."""
    gdb.execute(f'catch throw {exception}')


@REGISTRY.method(display='Catch Throw')
def break_throw(container: BreakpointContainer, exception: Annotated[
        str, ParamDesc(display='Exception (opt)')]) -> None:
    """Set a throw catchpoint (catch throw)."""
    gdb.execute(f'catch throw {exception}')


@REGISTRY.method(action='break_ext', display='Catch Rethrow')
def break_ext_rethrow(inferior: Inferior, exception: Annotated[
        str, ParamDesc(display='Exception (opt)')]) -> None:
    """Set a rethrow catchpoint (catch rethrow))."""
    gdb.execute(f'catch rethrow {exception}')


@REGISTRY.method(display='Catch Rethrow')
def break_rethrow(container: BreakpointContainer, exception: Annotated[
        str, ParamDesc(display='Exception (opt)')]) -> None:
    """Set a rethrow catchpoint (catch rethrow)."""
    gdb.execute(f'catch rethrow {exception}')


@REGISTRY.method(display='Describe')
def break_describe(breakpoint: BreakpointSpec):
    """Add a description"""
    bpt = find_bpt_by_obj(breakpoint)
    desc = gdb.execute(f'info break {bpt.number}', to_string=True)
    lines = desc.split('\n')
    index = lines[0].index('What')
    if index is not None:
        breakpoint.set_value('_display', "[{key}] {desc}".format(
            key=bpt.number, desc=lines[1][index:]))
    with commands.open_tracked_tx('Refresh Breakpoints'):
        gdb.execute('ghidra trace put-breakpoints')


@REGISTRY.method(action='toggle', display="Toggle Breakpoint")
def toggle_breakpoint(breakpoint: BreakpointSpec, enabled: bool) -> None:
    """Toggle a breakpoint."""
    bpt = find_bpt_by_obj(breakpoint)
    bpt.enabled = enabled


@REGISTRY.method(action='toggle', display="Toggle Breakpoint Location",
                 condition=util.GDB_VERSION.major >= 13)
def toggle_breakpoint_location(location: BreakpointLocation,
                               enabled: bool) -> None:
    """Toggle a breakpoint location."""
    loc = find_bpt_loc_by_obj(location)
    loc.enabled = enabled


@REGISTRY.method(action='toggle', display="Toggle Breakpoint Location",
                 condition=util.GDB_VERSION.major < 13)
def toggle_breakpoint_location_pre13(location: BreakpointLocation,
                                     enabled: bool) -> None:
    """Toggle a breakpoint location."""
    bptnum, locnum = find_bptlocnum_by_obj(location)
    cmd = 'enable' if enabled else 'disable'
    gdb.execute(f'{cmd} {bptnum}.{locnum}')


@REGISTRY.method(action='delete', display="Delete Breakpoint")
def delete_breakpoint(breakpoint: BreakpointSpec) -> None:
    """Delete a breakpoint."""
    bpt = find_bpt_by_obj(breakpoint)
    bpt.delete()


@REGISTRY.method()
def read_mem(inferior: Inferior, range: AddressRange) -> None:
    """Read memory."""
    inf = find_inf_by_obj(inferior)
    offset_start = inferior.trace.extra.require_mm().map_back(
        inf, Address(range.space, range.min))
    with commands.open_tracked_tx('Read Memory'):
        try:
            gdb.execute(
                f'ghidra trace putmem 0x{offset_start:x} {range.length()}')
        except:
            gdb.execute(
                f'ghidra trace putmem-state 0x{offset_start:x} {range.length()} error')


@REGISTRY.method()
def write_mem(inferior: Inferior, address: Address, data: bytes) -> None:
    """Write memory."""
    inf = find_inf_by_obj(inferior)
    offset = inferior.trace.extra.require_mm().map_back(inf, address)
    inf.write_memory(offset, data)


@REGISTRY.method()
def write_reg(frame: StackFrame, name: str, value: bytes) -> None:
    """Write a register."""
    f = find_frame_by_obj(frame)
    if f is None:
        raise gdb.GdbError(f"Frame {frame.path} no longer exists")
    f.select()
    inf = gdb.selected_inferior()
    trace: Trace[commands.Extra] = frame.trace
    rv = trace.extra.require_rm().map_value_back(inf, name, value)
    reg = find_reg_by_name(f, rv.name)
    size = int(gdb.parse_and_eval(f'sizeof(${reg.name})'))
    arr = '{' + ','.join(str(b) for b in rv.value) + '}'
    gdb.execute(f'set ((unsigned char[{size}])${reg.name}) = {arr}')
