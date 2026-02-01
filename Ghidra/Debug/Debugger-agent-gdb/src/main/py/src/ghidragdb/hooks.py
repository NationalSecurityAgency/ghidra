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
from dataclasses import dataclass, field
import functools
import time
import traceback
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar, cast

import gdb

from ghidratrace.client import Batch

from . import commands, util


class GhidraHookPrefix(gdb.Command):
    """Commands for exporting data to a Ghidra trace."""

    def __init__(self) -> None:
        super().__init__('hooks-ghidra', gdb.COMMAND_NONE, prefix=True)


GhidraHookPrefix()


@dataclass(frozen=False)
class HookState(object):
    installed = False
    batch: Optional[Batch] = None
    skip_continue = False
    in_break_w_cont = False

    def ensure_batch(self) -> None:
        if self.batch is None:
            self.batch = commands.STATE.require_client().start_batch()

    def end_batch(self) -> None:
        if self.batch is None:
            return
        self.batch = None
        commands.STATE.require_client().end_batch()

    def check_skip_continue(self) -> bool:
        skip = self.skip_continue
        self.skip_continue = False
        return skip


@dataclass(frozen=False)
class InferiorState(object):
    first = True
    # For things we can detect changes to between stops
    regions: List[util.Region] = field(default_factory=list)
    modules = False
    threads = False
    breaks = False
    # For frames and threads that have already been synced since last stop
    visited: set[Any] = field(default_factory=set)

    def record(self, description: Optional[str] = None) -> None:
        first = self.first
        self.first = False
        trace = commands.STATE.require_trace()
        if description is not None:
            trace.snapshot(description)
        if first:
            commands.put_inferiors()
            commands.put_environment()
        else:
            commands.put_inferior_state(gdb.selected_inferior())
        if self.threads:
            commands.put_threads()
            self.threads = False
        thread = gdb.selected_thread()
        if thread is not None:
            if first or thread not in self.visited:
                # NB: This command will fail if the process is running
                commands.put_frames()
                self.visited.add(thread)
            frame = util.selected_frame()
            if frame is None:
                return
            hashable_frame = (thread, util.get_level(frame))
            if first or hashable_frame not in self.visited:
                commands.putreg(
                    frame, util.get_register_descs(frame.architecture(), 'general'))
                try:
                    commands.putmem("$pc", "1", from_tty=False)
                except gdb.MemoryError as e:
                    print(f"Couldn't record page with PC: {e}")
                try:
                    commands.putmem("$sp-1", "2", from_tty=False)
                except gdb.MemoryError as e:
                    print(f"Couldn't record page with SP: {e}")
                self.visited.add(hashable_frame)
        # NB: These commands (put_modules/put_regions) will fail if the process is running
        regions_changed, regions = util.REGION_INFO_READER.have_changed(
            self.regions)
        if regions_changed:
            self.regions = commands.put_regions(regions)
        if first or self.modules:
            commands.put_modules()
            self.modules = False
        if first or self.breaks:
            commands.put_breakpoints()
            self.breaks = False

    def record_continued(self) -> None:
        commands.put_inferiors()
        commands.put_threads()

    def record_exited(self, exit_code: int) -> None:
        inf = gdb.selected_inferior()
        ipath = commands.INFERIOR_PATTERN.format(infnum=inf.num)
        infobj = commands.STATE.require_trace().proxy_object_path(ipath)
        infobj.set_value('Exit Code', exit_code)
        infobj.set_value('State', 'TERMINATED')


@dataclass(frozen=False)
class BrkState(object):
    break_loc_counts: Dict[gdb.Breakpoint, int] = field(default_factory=dict)

    def update_brkloc_count(self, b: gdb.Breakpoint, count: int) -> None:
        self.break_loc_counts[b] = count

    def get_brkloc_count(self, b: gdb.Breakpoint) -> int:
        return self.break_loc_counts.get(b, 0)

    def del_brkloc_count(self, b: gdb.Breakpoint) -> int:
        if b not in self.break_loc_counts:
            return 0  # TODO: Print a warning?
        count = self.break_loc_counts[b]
        del self.break_loc_counts[b]
        return count


HOOK_STATE = HookState()
BRK_STATE = BrkState()
INF_STATES: Dict[int, InferiorState] = {}


C = TypeVar('C', bound=Callable)


def log_errors(func: C) -> C:
    """Wrap a function in a try-except that prints and reraises the exception.

    This is needed because pybag and/or the COM wrappers do not print
    exceptions that occur during event callbacks.
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
def on_new_inferior(event: gdb.NewInferiorEvent) -> None:
    trace = commands.STATE.trace
    if trace is None:
        return
    HOOK_STATE.ensure_batch()
    with trace.open_tx(f"New Inferior {event.inferior.num}"):
        commands.put_inferiors()  # TODO: Could put just the one....


def on_inferior_selected() -> None:
    inf = gdb.selected_inferior()
    if inf.num not in INF_STATES:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    HOOK_STATE.ensure_batch()
    with trace.open_tx(f"Inferior {inf.num} selected"):
        INF_STATES[inf.num].record()
        commands.activate()


@log_errors
def on_inferior_deleted(event: gdb.InferiorDeletedEvent) -> None:
    trace = commands.STATE.trace
    if trace is None:
        return
    if event.inferior.num in INF_STATES:
        del INF_STATES[event.inferior.num]
    HOOK_STATE.ensure_batch()
    with trace.open_tx(f"Inferior {event.inferior.num} deleted"):
        commands.put_inferiors()  # TODO: Could just delete the one....


@log_errors
def on_new_thread(event: gdb.ThreadEvent) -> None:
    inf = gdb.selected_inferior()
    if inf.num not in INF_STATES:
        return
    INF_STATES[inf.num].threads = True
    # TODO: Syscall clone/exit to detect thread destruction?


def on_thread_selected(event: Optional[gdb.ThreadEvent]) -> None:
    inf = gdb.selected_inferior()
    if inf.num not in INF_STATES:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    t = gdb.selected_thread()
    HOOK_STATE.ensure_batch()
    with trace.open_tx(f"Thread {inf.num}.{t.num} selected"):
        INF_STATES[inf.num].record()
        commands.activate()


def on_frame_selected() -> None:
    inf = gdb.selected_inferior()
    if inf.num not in INF_STATES:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    t = gdb.selected_thread()
    f = util.selected_frame()
    if f is None:
        return
    HOOK_STATE.ensure_batch()
    with trace.open_tx(f"Frame {inf.num}.{t.num}.{util.get_level(f)} selected"):
        INF_STATES[inf.num].record()
        commands.activate()


@log_errors
def on_memory_changed(event: gdb.MemoryChangedEvent) -> None:
    inf = gdb.selected_inferior()
    if inf.num not in INF_STATES:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    HOOK_STATE.ensure_batch()
    address = int(event.address)
    length = int(event.length)
    with trace.open_tx(f"Memory *0x{address:08x} changed"):
        commands.put_bytes(address, address + length,
                           pages=False, is_mi=False, from_tty=False)


@log_errors
def on_register_changed(event: gdb.RegisterChangedEvent) -> None:
    inf = gdb.selected_inferior()
    if inf.num not in INF_STATES:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    # I'd rather have a descriptor!
    # TODO: How do I get the descriptor from the number?
    # For now, just record the lot
    HOOK_STATE.ensure_batch()
    with trace.open_tx(f"Register {event.regnum} changed"):
        commands.putreg(event.frame, util.get_register_descs(
            event.frame.architecture()))


@log_errors
def on_cont(event):
    if gdb.selected_thread() is None:
        # thread-based state computed in record_continued will
        # fail in some versions of gdb because the current_thread is None
        # and gdb fails to test for None before switching
        return
    if (HOOK_STATE.check_skip_continue()):
        return
    inf = gdb.selected_inferior()
    if inf.num not in INF_STATES:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    state = INF_STATES[inf.num]
    HOOK_STATE.ensure_batch()
    with trace.open_tx("Continued"):
        state.record_continued()


def check_for_continue(event: Optional[gdb.StopEvent]) -> bool:
    # Attribute check because of version differences
    if isinstance(event, gdb.StopEvent) and hasattr(event, 'breakpoints'):
        if HOOK_STATE.in_break_w_cont:
            return True
        for brk in event.breakpoints:
            if hasattr(brk, 'commands') and brk.commands is not None:
                for cmd in brk.commands:
                    if cmd == 'c' or cmd.startswith('cont'):
                        HOOK_STATE.in_break_w_cont = True
                        return True
    HOOK_STATE.in_break_w_cont = False
    return False


@log_errors
def on_stop(event: Optional[gdb.StopEvent]) -> None:
    if check_for_continue(event):
        HOOK_STATE.skip_continue = True
        return
    inf = gdb.selected_inferior()
    if inf.num not in INF_STATES:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    state = INF_STATES[inf.num]
    state.visited.clear()
    HOOK_STATE.ensure_batch()
    with trace.open_tx("Stopped"):
        state.record("Stopped")
        commands.put_event_thread()
        commands.activate()
    HOOK_STATE.end_batch()


@log_errors
def on_exited(event: gdb.ExitedEvent) -> None:
    inf = gdb.selected_inferior()
    if inf.num not in INF_STATES:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    state = INF_STATES[inf.num]
    state.visited.clear()
    description = "Exited"
    if hasattr(event, 'exit_code'):
        description += " with code {}".format(event.exit_code)
    HOOK_STATE.ensure_batch()
    with trace.open_tx(description):
        state.record(description)
        if hasattr(event, 'exit_code'):
            state.record_exited(event.exit_code)
        commands.put_event_thread()
        commands.activate()
    HOOK_STATE.end_batch()


def notify_others_breaks(inf: gdb.Inferior) -> None:
    for num, state in INF_STATES.items():
        if num != inf.num:
            state.breaks = True


def modules_changed() -> None:
    # Assumption: affects the current inferior
    inf = gdb.selected_inferior()
    if inf.num not in INF_STATES:
        return
    INF_STATES[inf.num].modules = True


@log_errors
def on_clear_objfiles(event: gdb.ClearObjFilesEvent) -> None:
    modules_changed()


@log_errors
def on_new_objfile(event: gdb.NewObjFileEvent) -> None:
    modules_changed()


if hasattr(gdb, 'FreeObjFileEvent'):
    @log_errors
    def on_free_objfile(event: gdb.FreeObjFileEvent) -> None:
        modules_changed()


@log_errors
def on_breakpoint_created(b: gdb.Breakpoint) -> None:
    inf = gdb.selected_inferior()
    notify_others_breaks(inf)
    if inf.num not in INF_STATES:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    ibpath = commands.INF_BREAKS_PATTERN.format(infnum=inf.num)
    HOOK_STATE.ensure_batch()
    with trace.open_tx(f"Breakpoint {b.number} created"):
        ibobj = trace.create_object(ibpath)
        # Do not use retain_values or it'll remove other locs
        commands.put_single_breakpoint(b, ibobj, inf, [])
        ibobj.insert()


@log_errors
def on_breakpoint_modified(b: gdb.Breakpoint) -> None:
    inf = gdb.selected_inferior()
    notify_others_breaks(inf)
    if inf.num not in INF_STATES:
        return
    old_count = BRK_STATE.get_brkloc_count(b)
    trace = commands.STATE.trace
    if trace is None:
        return
    ibpath = commands.INF_BREAKS_PATTERN.format(infnum=inf.num)
    HOOK_STATE.ensure_batch()
    with trace.open_tx("Breakpoint {} modified".format(b.number)):
        ibobj = trace.create_object(ibpath)
        commands.put_single_breakpoint(b, ibobj, inf, [])
        new_count = BRK_STATE.get_brkloc_count(b)
        # NOTE: Location may not apply to inferior, but whatever.
        for i in range(new_count, old_count):
            ikey = commands.INF_BREAK_KEY_PATTERN.format(
                breaknum=b.number, locnum=i + 1)
            ibobj.set_value(ikey, None)


@log_errors
def on_breakpoint_deleted(b: gdb.Breakpoint) -> None:
    inf = gdb.selected_inferior()
    notify_others_breaks(inf)
    if inf.num not in INF_STATES:
        return
    old_count = BRK_STATE.del_brkloc_count(b)
    trace = commands.STATE.trace
    if trace is None:
        return
    bpath = commands.BREAKPOINT_PATTERN.format(breaknum=b.number)
    ibobj = trace.proxy_object_path(
        commands.INF_BREAKS_PATTERN.format(infnum=inf.num))
    HOOK_STATE.ensure_batch()
    with trace.open_tx("Breakpoint {} modified".format(b.number)):
        trace.proxy_object_path(bpath).remove(tree=True)
        for i in range(old_count):
            ikey = commands.INF_BREAK_KEY_PATTERN.format(
                breaknum=b.number, locnum=i + 1)
            ibobj.set_value(ikey, None)


@log_errors
def on_before_prompt() -> object:
    HOOK_STATE.end_batch()
    return None


@dataclass(frozen=True)
class HookFunc(object):
    wrapped: Callable[[], None]
    hook: Type[gdb.Command]
    unhook: Callable[[], None]

    def __call__(self) -> None:
        self.wrapped()


def cmd_hook(name: str):

    def _cmd_hook(func: Callable[[], None]) -> HookFunc:

        class _ActiveCommand(gdb.Command):

            def __init__(self) -> None:
                # It seems we can't hook commands using the Python API....
                super().__init__(f"hooks-ghidra def-{name}", gdb.COMMAND_USER)
                gdb.execute(f"""
                define {name}
                  hooks-ghidra def-{name}
                end
                """)

            def invoke(self, argument: str, from_tty: bool) -> None:
                self.dont_repeat()
                func()

        def _unhook_command() -> None:
            gdb.execute(f"""
            define {name}
            end
            """)

        return HookFunc(func, _ActiveCommand, _unhook_command)

    return _cmd_hook


@cmd_hook('hookpost-inferior')
def hook_inferior() -> None:
    on_inferior_selected()


@cmd_hook('hookpost-thread')
def hook_thread() -> None:
    on_thread_selected(None)


@cmd_hook('hookpost-frame')
def hook_frame() -> None:
    on_frame_selected()


@cmd_hook('hookpost-up')
def hook_frame_up() -> None:
    on_frame_selected()


@cmd_hook('hookpost-down')
def hook_frame_down() -> None:
    on_frame_selected()


# TODO: Checks and workarounds for events missing in gdb 9
def install_hooks() -> None:
    if HOOK_STATE.installed:
        return
    HOOK_STATE.installed = True

    gdb.events.new_inferior.connect(on_new_inferior)
    hook_inferior.hook()
    gdb.events.inferior_deleted.connect(on_inferior_deleted)

    gdb.events.new_thread.connect(on_new_thread)
    hook_thread.hook()
    hook_frame.hook()
    hook_frame_up.hook()
    hook_frame_down.hook()

    # Respond to user-driven state changes: (Not target-driven)
    gdb.events.memory_changed.connect(on_memory_changed)
    gdb.events.register_changed.connect(on_register_changed)

    gdb.events.cont.connect(on_cont)
    gdb.events.stop.connect(on_stop)
    gdb.events.exited.connect(on_exited)  # Inferior exited

    gdb.events.clear_objfiles.connect(on_clear_objfiles)
    if hasattr(gdb.events, 'free_objfile'):
        gdb.events.free_objfile.connect(on_free_objfile)
    gdb.events.new_objfile.connect(on_new_objfile)

    gdb.events.breakpoint_created.connect(on_breakpoint_created)
    gdb.events.breakpoint_deleted.connect(on_breakpoint_deleted)
    gdb.events.breakpoint_modified.connect(on_breakpoint_modified)

    gdb.events.before_prompt.connect(on_before_prompt)


def remove_hooks() -> None:
    if not HOOK_STATE.installed:
        return
    HOOK_STATE.installed = False

    gdb.events.new_inferior.disconnect(on_new_inferior)
    hook_inferior.unhook()
    gdb.events.inferior_deleted.disconnect(on_inferior_deleted)

    gdb.events.new_thread.disconnect(on_new_thread)
    hook_thread.unhook()
    hook_frame.unhook()
    hook_frame_up.unhook()
    hook_frame_down.unhook()

    gdb.events.memory_changed.disconnect(on_memory_changed)
    gdb.events.register_changed.disconnect(on_register_changed)

    gdb.events.cont.disconnect(on_cont)
    gdb.events.stop.disconnect(on_stop)
    gdb.events.exited.disconnect(on_exited)  # Inferior exited

    gdb.events.clear_objfiles.disconnect(on_clear_objfiles)
    if hasattr(gdb.events, 'free_objfile'):
        gdb.events.free_objfile.disconnect(on_free_objfile)
    gdb.events.new_objfile.disconnect(on_new_objfile)

    gdb.events.breakpoint_created.disconnect(on_breakpoint_created)
    gdb.events.breakpoint_deleted.disconnect(on_breakpoint_deleted)
    gdb.events.breakpoint_modified.disconnect(on_breakpoint_modified)

    gdb.events.before_prompt.disconnect(on_before_prompt)


def enable_current_inferior() -> None:
    inf = gdb.selected_inferior()
    INF_STATES[inf.num] = InferiorState()


def disable_current_inferior() -> None:
    inf = gdb.selected_inferior()
    if inf.num in INF_STATES:
        # Silently ignore already disabled
        del INF_STATES[inf.num]
