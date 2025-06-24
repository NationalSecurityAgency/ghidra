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
import threading
import time

import drgn

from typing import Any, Callable, Collection, Dict, Optional, TypeVar, cast

from . import commands, util


ALL_EVENTS = 0xFFFF


@dataclass(frozen=False)
class HookState(object):
    installed = False


@dataclass(frozen=False)
class ProcessState(object):
    first = True
    # For things we can detect changes to between stops
    regions = False
    modules = False
    threads = False
    breaks = False
    watches = False
    # For frames and threads that have already been synced since last stop
    visited: set[Any] = field(default_factory=set)

    def record(self, description: Optional[str] = None) -> None:
        first = self.first
        self.first = False
        trace = commands.STATE.require_trace()
        if description is not None:
            trace.snapshot(description)
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

    def record_continued(self) -> None:
        commands.put_processes()
        commands.put_threads()

    def record_exited(self, exit_code: int) -> None:
        trace = commands.STATE.require_trace()
        nproc = util.selected_process()
        ipath = commands.PROCESS_PATTERN.format(procnum=nproc)
        procobj = trace.proxy_object_path(ipath)
        procobj.set_value('Exit Code', exit_code)
        procobj.set_value('State', 'TERMINATED')


HOOK_STATE = HookState()
PROC_STATE: Dict[int, ProcessState] = {}


def on_new_process(id: int) -> None:
    trace = commands.STATE.trace
    if trace is None:
        return
    with trace.client.batch():
        with trace.open_tx("New Process {}".format(id)):
            commands.put_processes()  # TODO: Could put just the one....


def on_process_selected() -> None:
    nproc = util.selected_process()
    if nproc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    with trace.client.batch():
        with trace.open_tx("Process {} selected".format(nproc)):
            PROC_STATE[nproc].record()
            commands.activate()


def on_new_thread() -> None:
    nproc = util.selected_process()
    if nproc not in PROC_STATE:
        return
    PROC_STATE[nproc].threads = True


def on_thread_selected() -> None:
    nproc = util.selected_process()
    if nproc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    nthrd = util.selected_thread()
    with trace.client.batch():
        with trace.open_tx("Thread {}.{} selected".format(nproc, nthrd)):
            PROC_STATE[nproc].record()
            commands.put_threads()
            commands.activate()


def on_frame_selected() -> None:
    nproc = util.selected_process()
    if nproc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    nthrd = util.selected_thread()
    level = util.selected_frame()
    with trace.client.batch():
        with trace.open_tx("Frame {}.{}.{} selected".format(nproc, nthrd, level)):
            PROC_STATE[nproc].record()
            commands.put_threads()
            commands.put_frames()
            commands.activate()


def on_cont() -> None:
    nproc = util.selected_process()
    if nproc not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    state = PROC_STATE[nproc]
    with trace.client.batch():
        with trace.open_tx("Continued"):
            state.record_continued()


def on_stop() -> None:
    nproc = util.selected_process()
    if nproc not in PROC_STATE:
        PROC_STATE[nproc] = ProcessState()
    trace = commands.STATE.trace
    if trace is None:
        print("no trace")
        return
    state = PROC_STATE[nproc]
    state.visited.clear()
    with trace.client.batch():
        with trace.open_tx("Stopped"):
            state.record("Stopped")
            commands.put_threads()
            commands.put_frames()
            commands.activate()


def modules_changed() -> None:
    nproc = util.selected_process()
    if nproc not in PROC_STATE:
        return
    PROC_STATE[nproc].modules = True


def install_hooks() -> None:
    if HOOK_STATE.installed:
        return
    HOOK_STATE.installed = True


def remove_hooks() -> None:
    if not HOOK_STATE.installed:
        return
    HOOK_STATE.installed = False


def enable_current_process() -> None:
    nproc = util.selected_process()
    PROC_STATE[nproc] = ProcessState()


def disable_current_process() -> None:
    nproc = util.selected_process()
    if nproc in PROC_STATE:
        del PROC_STATE[nproc]
