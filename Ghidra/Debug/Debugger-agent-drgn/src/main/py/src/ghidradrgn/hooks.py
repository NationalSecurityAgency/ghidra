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
import threading
import time

import drgn

from . import commands, util


ALL_EVENTS = 0xFFFF


class HookState(object):
    __slots__ = ('installed', 'mem_catchpoint')

    def __init__(self):
        self.installed = False
        self.mem_catchpoint = None


class ProcessState(object):
    __slots__ = ('first', 'regions', 'modules', 'threads',
                 'breaks', 'watches', 'visited')

    def __init__(self):
        self.first = True
        # For things we can detect changes to between stops
        self.regions = False
        self.modules = False
        self.threads = False
        self.breaks = False
        self.watches = False
        # For frames and threads that have already been synced since last stop
        self.visited = set()

    def record(self, description=None):
        first = self.first
        self.first = False
        if description is not None:
            commands.STATE.trace.snapshot(description)
        if first:
            commands.put_processes()
            commands.put_environment()
        if self.threads:
            commands.put_threads()
            self.threads = False
        nthrd = util.selected_thread()
        if nthrd is not None:
            if first or nthrd not in self.visited:
                commands.put_frames()
                self.visited.add(nthrd)
            level = util.selected_frame()
            hashable_frame = (nthrd, level)
            if first or hashable_frame not in self.visited:
                commands.putreg()
                try:
                    commands.putmem(commands.get_pc(), 1, True, True)
                except BaseException as e:
                    print(f"Couldn't record page with PC: {e}")
                try:
                    commands.putmem(commands.get_sp(), 1, True, True)
                except BaseException as e:
                    print(f"Couldn't record page with SP: {e}")
                self.visited.add(hashable_frame)
        if first or self.regions or self.modules:
            # Sections, memory syscalls, or stack allocations
            commands.put_regions()
            self.regions = False
        if first or self.modules:
            commands.put_modules()
            self.modules = False

    def record_continued(self):
        commands.put_processes()
        commands.put_threads()

    def record_exited(self, exit_code):
        nproc = util.selected_process()
        ipath = commands.PROCESS_PATTERN.format(procnum=nproc)
        procobj = commands.STATE.trace.proxy_object_path(ipath)
        procobj.set_value('Exit Code', exit_code)
        procobj.set_value('State', 'TERMINATED')


HOOK_STATE = HookState()
PROC_STATE = {}

def on_new_process(event):
    trace = commands.STATE.trace
    if trace is None:
        return
    with commands.STATE.client.batch():
        with trace.open_tx("New Process {}".format(event.process.num)):
            commands.put_processes()  # TODO: Could put just the one....


def on_process_selected():
    nproc = util.selected_process()
    if nproc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    with commands.STATE.client.batch():
        with trace.open_tx("Process {} selected".format(nproc)):
            PROC_STATE[nproc].record()
            commands.activate()


def on_new_thread(event):
    nproc = util.selected_process()
    if nproc not in PROC_STATE:
        return
    PROC_STATE[nproc].threads = True


def on_thread_selected():
    nproc = util.selected_process()
    if nproc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    nthrd = util.selected_thread()
    with commands.STATE.client.batch():
        with trace.open_tx("Thread {}.{} selected".format(nproc, nthrd)):
            PROC_STATE[nproc].record()
            commands.put_threads()
            commands.activate()


def on_frame_selected():
    nproc = util.selected_process()
    if nproc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    nthrd = util.selected_thread()
    level = util.selected_frame()
    with commands.STATE.client.batch():
        with trace.open_tx("Frame {}.{}.{} selected".format(nproc, nthrd, level)):
            PROC_STATE[nproc].record()
            commands.put_threads()
            commands.put_frames()
            commands.activate()


def on_memory_changed(event):
    nproc = util.get_process()
    if nproc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    with commands.STATE.client.batch():
        with trace.open_tx("Memory *0x{:08x} changed".format(event.address)):
            commands.put_bytes(event.address, event.address + event.length,
                               pages=False, is_mi=False, result=None)


def on_register_changed(event):
    nproc = util.get_process()
    if nproc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    with commands.STATE.client.batch():
        with trace.open_tx("Register {} changed".format(event.regnum)):
            commands.putreg()


def on_cont(event):
    nproc = util.selected_process()
    if nproc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    state = PROC_STATE[nproc]
    with commands.STATE.client.batch():
        with trace.open_tx("Continued"):
            state.record_continued()


def on_stop(event):
    nproc = util.selected_process()
    if nproc not in PROC_STATE:
        PROC_STATE[nproc] = ProcessState()
    trace = commands.STATE.trace
    if trace is None:
        print("no trace")
        return
    state = PROC_STATE[nproc]
    state.visited.clear()
    with commands.STATE.client.batch():
        with trace.open_tx("Stopped"):
            state.record("Stopped")
            commands.put_threads()
            commands.put_frames()
            commands.activate()


def modules_changed():
    nproc = util.selected_process()
    if nproc not in PROC_STATE:
        return
    PROC_STATE[nproc].modules = True


def install_hooks():
    if HOOK_STATE.installed:
        return
    HOOK_STATE.installed = True

    event_thread = EventThread()
    event_thread.start()


def remove_hooks():
    if not HOOK_STATE.installed:
        return
    HOOK_STATE.installed = False


def enable_current_process():
    nproc = util.selected_process()
    PROC_STATE[nproc] = ProcessState()


def disable_current_process():
    nproc = util.selected_process()
    if nproc in PROC_STATE:
        del PROC_STATE[nproc]
