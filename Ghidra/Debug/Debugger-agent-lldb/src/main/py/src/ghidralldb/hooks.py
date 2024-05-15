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
import threading
import time

import lldb

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
        thread = util.selected_thread()
        if thread is not None:
            if first or thread.GetThreadID() not in self.visited:
                commands.put_frames()
                self.visited.add(thread.GetThreadID())
            frame = util.selected_frame()
            hashable_frame = (thread.GetThreadID(), frame.GetFrameID())
            if first or hashable_frame not in self.visited:
                banks = frame.GetRegisters()
                primary = banks.GetFirstValueByName(
                    commands.DEFAULT_REGISTER_BANK)
                if primary.value is None:
                    primary = banks[0]
                    if primary is not None:
                        commands.DEFAULT_REGISTER_BANK = primary.name
                if primary is not None:
                    commands.putreg(frame, primary)
                try:
                    commands.putmem("$pc", "1", result=None)
                except BaseException as e:
                    print(f"Couldn't record page with PC: {e}")
                try:
                    commands.putmem("$sp", "1", result=None)
                except BaseException as e:
                    print(f"Couldn't record page with SP: {e}")
                self.visited.add(hashable_frame)
        if first or self.regions or self.threads or self.modules:
            # Sections, memory syscalls, or stack allocations
            commands.put_regions()
            self.regions = False
        if first or self.modules:
            commands.put_modules()
            self.modules = False
        if first or self.breaks:
            commands.put_breakpoints()
            self.breaks = False
        if first or self.watches:
            commands.put_watchpoints()
            self.watches = False

    def record_continued(self):
        commands.put_processes()
        commands.put_threads()

    def record_exited(self, exit_code):
        proc = util.get_process()
        ipath = commands.PROCESS_PATTERN.format(procnum=proc.GetProcessID())
        procobj = commands.STATE.trace.proxy_object_path(ipath)
        procobj.set_value('Exit Code', exit_code)
        procobj.set_value('State', 'TERMINATED')


class BrkState(object):
    __slots__ = ('break_loc_counts',)

    def __init__(self):
        self.break_loc_counts = {}

    def update_brkloc_count(self, b, count):
        self.break_loc_counts[b.GetID()] = count

    def get_brkloc_count(self, b):
        return self.break_loc_counts.get(b.GetID(), 0)

    def del_brkloc_count(self, b):
        if b.GetID() not in self.break_loc_counts:
            return 0  # TODO: Print a warning?
        count = self.break_loc_counts[b.GetID()]
        del self.break_loc_counts[b.GetID()]
        return count


HOOK_STATE = HookState()
BRK_STATE = BrkState()
PROC_STATE = {}


class QuitSentinel(object):
    pass


QUIT = QuitSentinel()


def process_event(self, listener, event):
    try:
        desc = util.get_description(event)
        # print(f"Event: {desc}")
        target = util.get_target()
        if not target.IsValid():
            # LLDB may crash on event.GetBroadcasterClass, otherwise
            # All the checks below, e.g. SBTarget.EventIsTargetEvent, call this
            print(f"Ignoring {desc} because target is invalid")
            return
        event_process = util.get_process()
        if event_process.IsValid() and event_process not in PROC_STATE:
            PROC_STATE[event_process.GetProcessID()] = ProcessState()
            rc = event_process.GetBroadcaster().AddListener(listener, ALL_EVENTS)
            if not rc:
                print("add listener for process failed")

        # NB: Calling put_state on running leaves an open transaction
        if not event_process.is_running:
            commands.put_state(event_process)
        type = event.GetType()
        if lldb.SBTarget.EventIsTargetEvent(event):
            if (type & lldb.SBTarget.eBroadcastBitBreakpointChanged) != 0:
                return on_breakpoint_modified(event)
            if (type & lldb.SBTarget.eBroadcastBitWatchpointChanged) != 0:
                return on_watchpoint_modified(event)
            if (type & lldb.SBTarget.eBroadcastBitModulesLoaded) != 0:
                return on_new_objfile(event)
            if (type & lldb.SBTarget.eBroadcastBitModulesUnloaded) != 0:
                return on_free_objfile(event)
            if (type & lldb.SBTarget.eBroadcastBitSymbolsLoaded) != 0:
                return True
        if lldb.SBProcess.EventIsProcessEvent(event):
            if (type & lldb.SBProcess.eBroadcastBitStateChanged) != 0:
                if not event_process.is_alive:
                    return on_exited(event)
                if event_process.is_stopped:
                    return on_stop(event)
                if event_process.is_running:
                    return on_cont(event)
                return True
            if (type & lldb.SBProcess.eBroadcastBitInterrupt) != 0:
                if event_process.is_stopped:
                    return on_stop(event)
            if (type & lldb.SBProcess.eBroadcastBitSTDOUT) != 0:
                return True
            if (type & lldb.SBProcess.eBroadcastBitSTDERR) != 0:
                return True
            if (type & lldb.SBProcess.eBroadcastBitProfileData) != 0:
                return True
            if (type & lldb.SBProcess.eBroadcastBitStructuredData) != 0:
                return True
        # NB: Thread events not currently processes
        if lldb.SBThread.EventIsThreadEvent(event):
            if (type & lldb.SBThread.eBroadcastBitStackChanged) != 0:
                return on_frame_selected()
            if (type & lldb.SBThread.eBroadcastBitThreadSuspended) != 0:
                if event_process.is_stopped:
                    return on_stop(event)
            if (type & lldb.SBThread.eBroadcastBitThreadResumed) != 0:
                return on_cont(event)
            if (type & lldb.SBThread.eBroadcastBitSelectedFrameChanged) != 0:
                return on_frame_selected()
            if (type & lldb.SBThread.eBroadcastBitThreadSelected) != 0:
                return on_thread_selected()
        if lldb.SBBreakpoint.EventIsBreakpointEvent(event):
            btype = lldb.SBBreakpoint.GetBreakpointEventTypeFromEvent(event)
            bpt = lldb.SBBreakpoint.GetBreakpointFromEvent(event)
            if btype is lldb.eBreakpointEventTypeAdded:
                return on_breakpoint_created(bpt)
            if btype is lldb.eBreakpointEventTypeAutoContinueChanged:
                return on_breakpoint_modified(bpt)
            if btype is lldb.eBreakpointEventTypeCommandChanged:
                return on_breakpoint_modified(bpt)
            if btype is lldb.eBreakpointEventTypeConditionChanged:
                return on_breakpoint_modified(bpt)
            if btype is lldb.eBreakpointEventTypeDisabled:
                return on_breakpoint_modified(bpt)
            if btype is lldb.eBreakpointEventTypeEnabled:
                return on_breakpoint_modified(bpt)
            if btype is lldb.eBreakpointEventTypeIgnoreChanged:
                return True
            if btype is lldb.eBreakpointEventTypeInvalidType:
                return True
            if btype is lldb.eBreakpointEventTypeLocationsAdded:
                return on_breakpoint_modified(bpt)
            if btype is lldb.eBreakpointEventTypeLocationsRemoved:
                return on_breakpoint_modified(bpt)
            if btype is lldb.eBreakpointEventTypeLocationsResolved:
                return on_breakpoint_modified(bpt)
            if btype is lldb.eBreakpointEventTypeRemoved:
                return on_breakpoint_deleted(bpt)
            if btype is lldb.eBreakpointEventTypeThreadChanged:
                return on_breakpoint_modified(bpt)
            print("UNKNOWN BREAKPOINT EVENT")
            return True
        if lldb.SBWatchpoint.EventIsWatchpointEvent(event):
            btype = lldb.SBWatchpoint.GetWatchpointEventTypeFromEvent(event)
            bpt = lldb.SBWatchpoint.GetWatchpointFromEvent(eventt)
            if btype is lldb.eWatchpointEventTypeAdded:
                return on_watchpoint_added(bpt)
            if btype is lldb.eWatchpointEventTypeCommandChanged:
                return on_watchpoint_modified(bpt)
            if btype is lldb.eWatchpointEventTypeConditionChanged:
                return on_watchpoint_modified(bpt)
            if btype is lldb.eWatchpointEventTypeDisabled:
                return on_watchpoint_modified(bpt)
            if btype is lldb.eWatchpointEventTypeEnabled:
                return on_watchpoint_modified(bpt)
            if btype is lldb.eWatchpointEventTypeIgnoreChanged:
                return True
            if btype is lldb.eWatchpointEventTypeInvalidType:
                return True
            if btype is lldb.eWatchpointEventTypeRemoved:
                return on_watchpoint_deleted(bpt)
            if btype is lldb.eWatchpointEventTypeThreadChanged:
                return on_watchpoint_modified(bpt)
            if btype is lldb.eWatchpointEventTypeTypeChanged:
                return on_watchpoint_modified(bpt)
            print("UNKNOWN WATCHPOINT EVENT")
            return True
        if lldb.SBCommandInterpreter.EventIsCommandInterpreterEvent(event):
            if (type & lldb.SBCommandInterpreter.eBroadcastBitAsynchronousErrorData) != 0:
                return True
            if (type & lldb.SBCommandInterpreter.eBroadcastBitAsynchronousOutputData) != 0:
                return True
            if (type & lldb.SBCommandInterpreter.eBroadcastBitQuitCommandReceived) != 0:
                # DO NOT return QUIT here.
                # For some reason, this event comes just after launch.
                # Maybe need to figure out *which* interpreter?
                return True
            if (type & lldb.SBCommandInterpreter.eBroadcastBitResetPrompt) != 0:
                return True
            if (type & lldb.SBCommandInterpreter.eBroadcastBitThreadShouldExit) != 0:
                return True
        print("UNKNOWN EVENT")
        return True
    except BaseException as e:
        print(e)


class EventThread(threading.Thread):
    func = process_event
    event = lldb.SBEvent()

    def run(self):
        # Let's only try at most 4 times to retrieve any kind of event.
        # After that, the thread exits.
        listener = lldb.SBListener('eventlistener')
        cli = util.get_debugger().GetCommandInterpreter()
        target = util.get_target()
        proc = util.get_process()
        rc = cli.GetBroadcaster().AddListener(listener, ALL_EVENTS)
        if not rc:
            print("add listener for cli failed")
            # return
        rc = target.GetBroadcaster().AddListener(listener, ALL_EVENTS)
        if not rc:
            print("add listener for target failed")
            # return
        rc = proc.GetBroadcaster().AddListener(listener, ALL_EVENTS)
        if not rc:
            print("add listener for process failed")
            # return

        # Not sure what effect this logic has
        rc = cli.GetBroadcaster().AddInitialEventsToListener(listener, ALL_EVENTS)
        if not rc:
            print("add initial events for cli failed")
            # return
        rc = target.GetBroadcaster().AddInitialEventsToListener(listener, ALL_EVENTS)
        if not rc:
            print("add initial events for target failed")
            # return
        rc = proc.GetBroadcaster().AddInitialEventsToListener(listener, ALL_EVENTS)
        if not rc:
            print("add initial events for process failed")
            # return

        rc = listener.StartListeningForEventClass(
            util.get_debugger(), lldb.SBThread.GetBroadcasterClassName(), ALL_EVENTS)
        if not rc:
            print("add listener for threads failed")
            # return
        # THIS WILL NOT WORK: listener = util.get_debugger().GetListener()

        while True:
            event_recvd = False
            while not event_recvd:
                if listener.WaitForEvent(lldb.UINT32_MAX, self.event):
                    try:
                        result = self.func(listener, self.event)
                        if result is QUIT:
                            return
                    except BaseException as e:
                        print(e)
                    while listener.GetNextEvent(self.event):
                        try:
                            result = self.func(listener, self.event)
                            if result is QUIT:
                                return
                        except BaseException as e:
                            print(e)
                    event_recvd = True
            proc = util.get_process()
            if proc is not None and not proc.is_alive:
                break
        return


"""   
    # Not sure if this is possible in LLDB...
    
    # Respond to user-driven state changes: (Not target-driven)
    lldb.events.memory_changed.connect(on_memory_changed)
    lldb.events.register_changed.connect(on_register_changed)
    # Respond to target-driven memory map changes:
    # group:memory is actually a bit broad, but will probably port better
    # One alternative is to name all syscalls that cause a change....
    # Ones we could probably omit:
    #     msync,
    #         (Deals in syncing file-backed pages to disk.)
    #     mlock, munlock, mlockall, munlockall, mincore, madvise,
    #         (Deal in paging. Doesn't affect valid addresses.)
    #     mbind, get_mempolicy, set_mempolicy, migrate_pages, move_pages
    #         (All NUMA stuff)
    #
    if HOOK_STATE.mem_catchpoint is not None:
        HOOK_STATE.mem_catchpoint.enabled = True
    else:
        breaks_before = set(lldb.breakpoints())
        lldb.execute(
            catch syscall group:memory
            commands
            silent
            ghidra-hook event-memory
            cont
            end
            )
        HOOK_STATE.mem_catchpoint = (
            set(lldb.breakpoints()) - breaks_before).pop()
"""


def on_new_process(event):
    trace = commands.STATE.trace
    if trace is None:
        return
    with commands.STATE.client.batch():
        with trace.open_tx("New Process {}".format(event.process.num)):
            commands.put_processes()  # TODO: Could put just the one....


def on_process_selected():
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    with commands.STATE.client.batch():
        with trace.open_tx("Process {} selected".format(proc.GetProcessID())):
            PROC_STATE[proc.GetProcessID()].record()
            commands.activate()


def on_process_deleted(event):
    trace = commands.STATE.trace
    if trace is None:
        return
    if event.process.num in PROC_STATE:
        del PROC_STATE[event.process.num]
    with commands.STATE.client.batch():
        with trace.open_tx("Process {} deleted".format(event.process.num)):
            commands.put_processes()  # TODO: Could just delete the one....


def on_new_thread(event):
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return
    PROC_STATE[proc.GetProcessID()].threads = True
    # TODO: Syscall clone/exit to detect thread destruction?


def on_thread_selected():
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    t = util.selected_thread()
    with commands.STATE.client.batch():
        with trace.open_tx("Thread {}.{} selected".format(proc.GetProcessID(), t.GetThreadID())):
            PROC_STATE[proc.GetProcessID()].record()
            commands.put_threads()
            commands.activate()


def on_frame_selected():
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    f = util.selected_frame()
    t = f.GetThread()
    with commands.STATE.client.batch():
        with trace.open_tx("Frame {}.{}.{} selected".format(proc.GetProcessID(), t.GetThreadID(), f.GetFrameID())):
            PROC_STATE[proc.GetProcessID()].record()
            commands.put_threads()
            commands.put_frames()
            commands.activate()


def on_syscall_memory():
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return
    PROC_STATE[proc.GetProcessID()].regions = True


def on_memory_changed(event):
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    with commands.STATE.client.batch():
        with trace.open_tx("Memory *0x{:08x} changed".format(event.address)):
            commands.put_bytes(event.address, event.address + event.length,
                               pages=False, is_mi=False, result=None)


def on_register_changed(event):
    # print("Register changed: {}".format(dir(event)))
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    # I'd rather have a descriptor!
    # TODO: How do I get the descriptor from the number?
    # For now, just record the lot
    with commands.STATE.client.batch():
        with trace.open_tx("Register {} changed".format(event.regnum)):
            banks = event.frame.GetRegisters()
            commands.putreg(
                event.frame, banks.GetFirstValueByName(commands.DEFAULT_REGISTER_BANK))


def on_cont(event):
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    state = PROC_STATE[proc.GetProcessID()]
    with commands.STATE.client.batch():
        with trace.open_tx("Continued"):
            state.record_continued()


def on_stop(event):
    proc = lldb.SBProcess.GetProcessFromEvent(
        event) if event is not None else util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        print("not in state")
        return
    trace = commands.STATE.trace
    if trace is None:
        print("no trace")
        return
    state = PROC_STATE[proc.GetProcessID()]
    state.visited.clear()
    with commands.STATE.client.batch():
        with trace.open_tx("Stopped"):
            state.record("Stopped")
            commands.put_event_thread()
            commands.put_threads()
            commands.put_frames()
            commands.activate()


def on_exited(event):
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    state = PROC_STATE[proc.GetProcessID()]
    state.visited.clear()
    exit_code = proc.GetExitStatus()
    description = "Exited with code {}".format(exit_code)
    with commands.STATE.client.batch():
        with trace.open_tx(description):
            state.record(description)
            state.record_exited(exit_code)
            commands.put_event_thread()
            commands.activate()


def notify_others_breaks(proc):
    for num, state in PROC_STATE.items():
        if num != proc.GetProcessID():
            state.breaks = True


def notify_others_watches(proc):
    for num, state in PROC_STATE.items():
        if num != proc.GetProcessID():
            state.watches = True


def modules_changed():
    # Assumption: affects the current process
    proc = util.get_process()
    if proc.GetProcessID() not in PROC_STATE:
        return
    PROC_STATE[proc.GetProcessID()].modules = True


def on_new_objfile(event):
    modules_changed()


def on_free_objfile(event):
    modules_changed()


def on_breakpoint_created(b):
    proc = util.get_process()
    notify_others_breaks(proc)
    if proc.GetProcessID() not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    ibpath = commands.PROC_BREAKS_PATTERN.format(procnum=proc.GetProcessID())
    with commands.STATE.client.batch():
        with trace.open_tx("Breakpoint {} created".format(b.GetID())):
            ibobj = trace.create_object(ibpath)
            # Do not use retain_values or it'll remove other locs
            commands.put_single_breakpoint(b, ibobj, proc, [])
            ibobj.insert()


def on_breakpoint_modified(b):
    proc = util.get_process()
    notify_others_breaks(proc)
    if proc.GetProcessID() not in PROC_STATE:
        return
    old_count = BRK_STATE.get_brkloc_count(b)
    trace = commands.STATE.trace
    if trace is None:
        return
    ibpath = commands.PROC_BREAKS_PATTERN.format(procnum=proc.GetProcessID())
    with commands.STATE.client.batch():
        with trace.open_tx("Breakpoint {} modified".format(b.GetID())):
            ibobj = trace.create_object(ibpath)
            commands.put_single_breakpoint(b, ibobj, proc, [])
            new_count = BRK_STATE.get_brkloc_count(b)
            # NOTE: Location may not apply to process, but whatever.
            for i in range(new_count, old_count):
                ikey = commands.PROC_BREAK_KEY_PATTERN.format(
                    breaknum=b.GetID(), locnum=i+1)
                ibobj.set_value(ikey, None)


def on_breakpoint_deleted(b):
    proc = util.get_process()
    notify_others_breaks(proc)
    if proc.GetProcessID() not in PROC_STATE:
        return
    old_count = BRK_STATE.del_brkloc_count(b)
    trace = commands.STATE.trace
    if trace is None:
        return
    bpath = commands.BREAKPOINT_PATTERN.format(breaknum=b.GetID())
    ibobj = trace.proxy_object_path(
        commands.PROC_BREAKS_PATTERN.format(procnum=proc.GetProcessID()))
    with commands.STATE.client.batch():
        with trace.open_tx("Breakpoint {} deleted".format(b.GetID())):
            trace.proxy_object_path(bpath).remove(tree=True)
            for i in range(old_count):
                ikey = commands.PROC_BREAK_KEY_PATTERN.format(
                    breaknum=b.GetID(), locnum=i+1)
                ibobj.set_value(ikey, None)


def on_watchpoint_created(b):
    proc = util.get_process()
    notify_others_watches(proc)
    if proc.GetProcessID() not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    ibpath = commands.PROC_WATCHES_PATTERN.format(procnum=proc.GetProcessID())
    with commands.STATE.client.batch():
        with trace.open_tx("Breakpoint {} created".format(b.GetID())):
            ibobj = trace.create_object(ibpath)
            # Do not use retain_values or it'll remove other locs
            commands.put_single_watchpoint(b, ibobj, proc, [])
            ibobj.insert()


def on_watchpoint_modified(b):
    proc = util.get_process()
    notify_others_watches(proc)
    if proc.GetProcessID() not in PROC_STATE:
        return
    old_count = BRK_STATE.get_brkloc_count(b)
    trace = commands.STATE.trace
    if trace is None:
        return
    ibpath = commands.PROC_WATCHES_PATTERN.format(procnum=proc.GetProcessID())
    with commands.STATE.client.batch():
        with trace.open_tx("Watchpoint {} modified".format(b.GetID())):
            ibobj = trace.create_object(ibpath)
            commands.put_single_watchpoint(b, ibobj, proc, [])


def on_watchpoint_deleted(b):
    proc = util.get_process()
    notify_others_watches(proc)
    if proc.GetProcessID() not in PROC_STATE:
        return
    trace = commands.STATE.trace
    if trace is None:
        return
    bpath = commands.WATCHPOINT_PATTERN.format(watchnum=b.GetID())
    ibobj = trace.proxy_object_path(
        commands.PROC_WATCHES_PATTERN.format(procnum=proc.GetProcessID()))
    with commands.STATE.client.batch():
        with trace.open_tx("Watchpoint {} deleted".format(b.GetID())):
            trace.proxy_object_path(bpath).remove(tree=True)


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
    proc = util.get_process()
    PROC_STATE[proc.GetProcessID()] = ProcessState()


def disable_current_process():
    proc = util.get_process()
    if proc.GetProcessID() in PROC_STATE:
        # Silently ignore already disabled
        del PROC_STATE[proc.GetProcessID()]
