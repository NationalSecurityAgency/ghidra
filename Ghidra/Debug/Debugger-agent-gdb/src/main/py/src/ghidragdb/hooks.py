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
import functools
import time
import traceback

import gdb

from . import commands, util


class GhidraHookPrefix(gdb.Command):
    """Commands for exporting data to a Ghidra trace"""

    def __init__(self):
        super().__init__('hooks-ghidra', gdb.COMMAND_NONE, prefix=True)


GhidraHookPrefix()


class HookState(object):
    __slots__ = ('installed', 'batch', 'skip_continue', 'in_break_w_cont')

    def __init__(self):
        self.installed = False
        self.batch = None
        self.skip_continue = False
        self.in_break_w_cont = False

    def ensure_batch(self):
        if self.batch is None:
            self.batch = commands.STATE.client.start_batch()

    def end_batch(self):
        if self.batch is None:
            return
        self.batch = None
        commands.STATE.client.end_batch()

    def check_skip_continue(self):
        skip = self.skip_continue
        self.skip_continue = False
        return skip


class InferiorState(object):
    __slots__ = ('first', 'regions', 'modules', 'threads', 'breaks', 'visited')

    def __init__(self):
        self.first = True
        # For things we can detect changes to between stops
        self.regions = []
        self.modules = False
        self.threads = False
        self.breaks = False
        # For frames and threads that have already been synced since last stop
        self.visited = set()

    def record(self, description=None):
        first = self.first
        self.first = False
        if description is not None:
            commands.STATE.trace.snapshot(description)
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
                    commands.putmem("$sp", "1", from_tty=False)
                except gdb.MemoryError as e:
                    print(f"Couldn't record page with SP: {e}")
                self.visited.add(hashable_frame)
        # NB: These commands (put_modules/put_regions) will fail if the process is running
        regions_changed, regions = util.REGION_INFO_READER.have_changed(self.regions)
        if regions_changed:
            self.regions = commands.put_regions(regions)
        if first or self.modules:
            commands.put_modules()
            self.modules = False
        if first or self.breaks:
            commands.put_breakpoints()
            self.breaks = False

    def record_continued(self):
        commands.put_inferiors()
        commands.put_threads()

    def record_exited(self, exit_code):
        inf = gdb.selected_inferior()
        ipath = commands.INFERIOR_PATTERN.format(infnum=inf.num)
        infobj = commands.STATE.trace.proxy_object_path(ipath)
        infobj.set_value('Exit Code', exit_code)
        infobj.set_value('State', 'TERMINATED')


class BrkState(object):
    __slots__ = ('break_loc_counts',)

    def __init__(self):
        self.break_loc_counts = {}

    def update_brkloc_count(self, b, count):
        self.break_loc_counts[b] = count

    def get_brkloc_count(self, b):
        return self.break_loc_counts.get(b, 0)

    def del_brkloc_count(self, b):
        if b not in self.break_loc_counts:
            return 0  # TODO: Print a warning?
        count = self.break_loc_counts[b]
        del self.break_loc_counts[b]
        return count


HOOK_STATE = HookState()
BRK_STATE = BrkState()
INF_STATES = {}


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
def on_new_inferior(event):
    trace = commands.STATE.trace
    if trace is None:
        return
    HOOK_STATE.ensure_batch()
    with trace.open_tx("New Inferior {}".format(event.inferior.num)):
        commands.put_inferiors()  # TODO: Could put just the one....


def on_inferior_selected():
    inf = gdb.selected_inferior()
    if inf.num not in INF_STATES:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    HOOK_STATE.ensure_batch()
    with trace.open_tx("Inferior {} selected".format(inf.num)):
        INF_STATES[inf.num].record()
        commands.activate()


@log_errors
def on_inferior_deleted(event):
    trace = commands.STATE.trace
    if trace is None:
        return
    if event.inferior.num in INF_STATES:
        del INF_STATES[event.inferior.num]
    HOOK_STATE.ensure_batch()
    with trace.open_tx("Inferior {} deleted".format(event.inferior.num)):
        commands.put_inferiors()  # TODO: Could just delete the one....


@log_errors
def on_new_thread(event):
    inf = gdb.selected_inferior()
    if inf.num not in INF_STATES:
        return
    INF_STATES[inf.num].threads = True
    # TODO: Syscall clone/exit to detect thread destruction?


def on_thread_selected():
    inf = gdb.selected_inferior()
    if inf.num not in INF_STATES:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    t = gdb.selected_thread()
    HOOK_STATE.ensure_batch()
    with trace.open_tx("Thread {}.{} selected".format(inf.num, t.num)):
        INF_STATES[inf.num].record()
        commands.activate()


def on_frame_selected():
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
    with trace.open_tx("Frame {}.{}.{} selected".format(inf.num, t.num, util.get_level(f))):
        INF_STATES[inf.num].record()
        commands.activate()


@log_errors
def on_memory_changed(event):
    inf = gdb.selected_inferior()
    if inf.num not in INF_STATES:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    HOOK_STATE.ensure_batch()
    with trace.open_tx("Memory *0x{:08x} changed".format(event.address)):
        commands.put_bytes(event.address, event.address + event.length,
                           pages=False, is_mi=False, from_tty=False)


@log_errors
def on_register_changed(event):
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
    with trace.open_tx("Register {} changed".format(event.regnum)):
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


def check_for_continue(event):
    if hasattr(event, 'breakpoints'):
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
def on_stop(event):
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
def on_exited(event):
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


def notify_others_breaks(inf):
    for num, state in INF_STATES.items():
        if num != inf.num:
            state.breaks = True


def modules_changed():
    # Assumption: affects the current inferior
    inf = gdb.selected_inferior()
    if inf.num not in INF_STATES:
        return
    INF_STATES[inf.num].modules = True


@log_errors
def on_clear_objfiles(event):
    modules_changed()


@log_errors
def on_new_objfile(event):
    modules_changed()


@log_errors
def on_free_objfile(event):
    modules_changed()


@log_errors
def on_breakpoint_created(b):
    inf = gdb.selected_inferior()
    notify_others_breaks(inf)
    if inf.num not in INF_STATES:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    ibpath = commands.INF_BREAKS_PATTERN.format(infnum=inf.num)
    HOOK_STATE.ensure_batch()
    with trace.open_tx("Breakpoint {} created".format(b.number)):
        ibobj = trace.create_object(ibpath)
        # Do not use retain_values or it'll remove other locs
        commands.put_single_breakpoint(b, ibobj, inf, [])
        ibobj.insert()


@log_errors
def on_breakpoint_modified(b):
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
def on_breakpoint_deleted(b):
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
def on_before_prompt():
    HOOK_STATE.end_batch()


def cmd_hook(name):

    def _cmd_hook(func):

        class _ActiveCommand(gdb.Command):

            def __init__(self):
                # It seems we can't hook commands using the Python API....
                super().__init__(f"hooks-ghidra def-{name}", gdb.COMMAND_USER)
                gdb.execute(f"""
                define {name}
                  hooks-ghidra def-{name}
                end
                """)

            def invoke(self, argument, from_tty):
                self.dont_repeat()
                func()

        def _unhook_command():
            gdb.execute(f"""
            define {name}
            end
            """)

        func.hook = _ActiveCommand
        func.unhook = _unhook_command
        return func

    return _cmd_hook


@cmd_hook('hookpost-inferior')
def hook_inferior():
    on_inferior_selected()


@cmd_hook('hookpost-thread')
def hook_thread():
    on_thread_selected()


@cmd_hook('hookpost-frame')
def hook_frame():
    on_frame_selected()


@cmd_hook('hookpost-up')
def hook_frame_up():
    on_frame_selected()


@cmd_hook('hookpost-down')
def hook_frame_down():
    on_frame_selected()


# TODO: Checks and workarounds for events missing in gdb 9
def install_hooks():
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


def remove_hooks():
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


def enable_current_inferior():
    inf = gdb.selected_inferior()
    INF_STATES[inf.num] = InferiorState()


def disable_current_inferior():
    inf = gdb.selected_inferior()
    if inf.num in INF_STATES:
        # Silently ignore already disabled
        del INF_STATES[inf.num]
