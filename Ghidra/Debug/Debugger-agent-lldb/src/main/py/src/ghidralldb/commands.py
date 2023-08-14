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
from contextlib import contextmanager
import inspect
import os.path
import socket
import time
import sys

from ghidratrace import sch
from ghidratrace.client import Client, Address, AddressRange, TraceObject
import psutil

import lldb

from . import arch, hooks, methods, util

PAGE_SIZE = 4096

DEFAULT_REGISTER_BANK = "General Purpose Registers"

AVAILABLES_PATH = 'Available'
AVAILABLE_KEY_PATTERN = '[{pid}]'
AVAILABLE_PATTERN = AVAILABLES_PATH + AVAILABLE_KEY_PATTERN
BREAKPOINTS_PATH = 'Breakpoints'
BREAKPOINT_KEY_PATTERN = '[{breaknum}]'
BREAKPOINT_PATTERN = BREAKPOINTS_PATH + BREAKPOINT_KEY_PATTERN
WATCHPOINTS_PATH = 'Watchpoints'
WATCHPOINT_KEY_PATTERN = '[{watchnum}]'
WATCHPOINT_PATTERN = WATCHPOINTS_PATH + WATCHPOINT_KEY_PATTERN
BREAK_LOC_KEY_PATTERN = '[{locnum}]'
PROCESSES_PATH = 'Processes'
PROCESS_KEY_PATTERN = '[{procnum}]'
PROCESS_PATTERN = PROCESSES_PATH + PROCESS_KEY_PATTERN
PROC_WATCHES_PATTERN = PROCESS_PATTERN + '.Watchpoints'
PROC_WATCH_KEY_PATTERN = PROC_WATCHES_PATTERN + '[{watchnum}]'
PROC_BREAKS_PATTERN = PROCESS_PATTERN + '.Breakpoints'
PROC_BREAK_KEY_PATTERN = '[{breaknum}.{locnum}]'
ENV_PATTERN = PROCESS_PATTERN + '.Environment'
THREADS_PATTERN = PROCESS_PATTERN + '.Threads'
THREAD_KEY_PATTERN = '[{tnum}]'
THREAD_PATTERN = THREADS_PATTERN + THREAD_KEY_PATTERN
STACK_PATTERN = THREAD_PATTERN + '.Stack'
FRAME_KEY_PATTERN = '[{level}]'
FRAME_PATTERN = STACK_PATTERN + FRAME_KEY_PATTERN
REGS_PATTERN = FRAME_PATTERN + '.Registers'
BANK_PATTERN = REGS_PATTERN + '.{bank}'
MEMORY_PATTERN = PROCESS_PATTERN + '.Memory'
REGION_KEY_PATTERN = '[{start:08x}]'
REGION_PATTERN = MEMORY_PATTERN + REGION_KEY_PATTERN
MODULES_PATTERN = PROCESS_PATTERN + '.Modules'
MODULE_KEY_PATTERN = '[{modpath}]'
MODULE_PATTERN = MODULES_PATTERN + MODULE_KEY_PATTERN
SECTIONS_ADD_PATTERN = '.Sections'
SECTION_KEY_PATTERN = '[{secname}]'
SECTION_ADD_PATTERN = SECTIONS_ADD_PATTERN + SECTION_KEY_PATTERN

# TODO: Symbols


class State(object):

    def __init__(self):
        self.reset_client()

    def require_client(self):
        if self.client is None:
            raise RuntimeError("Not connected")
        return self.client

    def require_no_client(self):
        if self.client is not None:
            raise RuntimeError("Already connected")

    def reset_client(self):
        self.client = None
        self.reset_trace()

    def require_trace(self):
        if self.trace is None:
            raise RuntimeError("No trace active")
        return self.trace

    def require_no_trace(self):
        if self.trace is not None:
            raise RuntimeError("Trace already started")

    def reset_trace(self):
        self.trace = None
        util.set_convenience_variable('_ghidra_tracing', "false")
        self.reset_tx()

    def require_tx(self):
        if self.tx is None:
            raise RuntimeError("No transaction")
        return self.tx

    def require_no_tx(self):
        if self.tx is not None:
            raise RuntimeError("Transaction already started")

    def reset_tx(self):
        self.tx = None


STATE = State()

if __name__ == '__main__':
    lldb.SBDebugger.InitializeWithErrorHandling();
    lldb.debugger = lldb.SBDebugger.Create()
elif lldb.debugger:
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_connect         "ghidra_trace_connect"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_listen          "ghidra_trace_listen"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_disconnect      "ghidra_trace_disconnect"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_start           "ghidra_trace_start"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_stop            "ghidra_trace_stop"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_restart         "ghidra_trace_restart"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_info            "ghidra_trace_info"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_info_lcsp       "ghidra_trace_info_lcsp"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_txstart         "ghidra_trace_txstart"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_txcommit        "ghidra_trace_txcommit"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_txabort         "ghidra_trace_txabort"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_txopen          "ghidra_trace_txopen"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_save            "ghidra_trace_save"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_new_snap        "ghidra_trace_new_snap"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_set_snap        "ghidra_trace_set_snap"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_putmem          "ghidra_trace_putmem"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_putval          "ghidra_trace_putval"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_putmem_state    "ghidra_trace_putmem_state"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_delmem          "ghidra_trace_delmem"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_putreg          "ghidra_trace_putreg"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_delreg          "ghidra_trace_delreg"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_create_obj      "ghidra_trace_create_obj"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_insert_obj      "ghidra_trace_insert_obj"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_remove_obj      "ghidra_trace_remove_obj"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_set_value       "ghidra_trace_set_value"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_retain_values   "ghidra_trace_retain_values"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_get_obj         "ghidra_trace_get_obj"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_get_values      "ghidra_trace_get_values"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_get_values_rng  "ghidra_trace_get_values_rng"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_activate        "ghidra_trace_activate"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_disassemble     "ghidra_trace_disassemble"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_put_processes   "ghidra_trace_put_processes"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_put_available   "ghidra_trace_put_available"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_put_breakpoints "ghidra_trace_put_breakpoints"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_put_watchpoints "ghidra_trace_put_watchpoints"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_put_environment "ghidra_trace_put_environment"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_put_regions     "ghidra_trace_put_regions"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_put_modules     "ghidra_trace_put_modules"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_put_threads     "ghidra_trace_put_threads"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_put_frames      "ghidra_trace_put_frames"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_put_all         "ghidra_trace_put_all"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_install_hooks   "ghidra_trace_install_hooks"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_remove_hooks    "ghidra_trace_remove_hooks"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_sync_enable     "ghidra_trace_sync_enable"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_trace_sync_disable    "ghidra_trace_sync_disable"')
    lldb.debugger.HandleCommand('command script add -f ghidralldb.commands.ghidra_util_mark             "_mark_"')
    #lldb.debugger.HandleCommand('target stop-hook add -P ghidralldb.hooks.StopHook')
    lldb.debugger.SetAsync(True)
    print("Commands loaded.")
    
def ghidra_trace_connect(debugger, command, result, internal_dict):
    """
    Connect LLDB to Ghidra for tracing

    Address must be of the form 'host:port'
    """

    STATE.require_no_client()
    address = command if len(command) > 0 else None
    if address is None:
        raise RuntimeError("'ghidra_trace_connect': missing required argument 'address'")
        
    parts = address.split(':')
    if len(parts) != 2:
        raise RuntimeError("address must be in the form 'host:port'")
    host, port = parts
    try:
        c = socket.socket()
        c.connect((host, int(port)))
        STATE.client = Client(c, methods.REGISTRY)
    except ValueError:
        raise RuntimeError("port must be numeric")

    
def ghidra_trace_listen(debugger, command, result, internal_dict):
    """
    Listen for Ghidra to connect for tracing

    Takes an optional address for the host and port on which to listen. Either
    the form 'host:port' or just 'port'. If omitted, it will bind to an
    ephemeral port on all interfaces. If only the port is given, it will bind to
    that port on all interfaces. This command will block until the connection is
    established.
    """

    STATE.require_no_client()
    address = command if len(command) > 0 else None
    if address is not None:
        parts = address.split(':')
        if len(parts) == 1:
            host, port = '0.0.0.0', parts[0]
        elif len(parts) == 2:
            host, port = parts
        else:
            raise RuntimeError("address must be 'port' or 'host:port'")
    else:
        host, port = '0.0.0.0', 0
    try:
        s = socket.socket()
        s.bind((host, int(port)))
        host, port = s.getsockname()
        s.listen(1)
        print("Listening at {}:{}...\n".format(host, port))
        c, (chost, cport) = s.accept()
        s.close()
        print("Connection from {}:{}\n".format(chost, cport))
        STATE.client = Client(c, methods.REGISTRY)
    except ValueError:
        raise RuntimeError("port must be numeric")


def ghidra_trace_disconnect(debugger, command, result, internal_dict):
    """Disconnect LLDB from Ghidra for tracing"""

    STATE.require_client().close()
    STATE.reset_client()


def compute_name():
    target = lldb.debugger.GetTargetAtIndex(0)
    progname = target.executable.basename
    if progname is None:
        return 'lldb/noname'
    else:
        return 'lldb/' + progname.split('/')[-1]


def start_trace(name):
    language, compiler = arch.compute_ghidra_lcsp()
    STATE.trace = STATE.client.create_trace(name, language, compiler)
    # TODO: Is adding an attribute like this recommended in Python?
    STATE.trace.memory_mapper = arch.compute_memory_mapper(language)
    STATE.trace.register_mapper = arch.compute_register_mapper(language)

    parent = os.path.dirname(inspect.getfile(inspect.currentframe()))
    schema_fn = os.path.join(parent, 'schema.xml')
    with open(schema_fn, 'r') as schema_file:
        schema_xml = schema_file.read()
    with STATE.trace.open_tx("Create Root Object"):
        root = STATE.trace.create_root_object(schema_xml, 'Session')
        root.set_value('_display', 'GNU lldb ' + util.LLDB_VERSION.full)
    util.set_convenience_variable('_ghidra_tracing', "true")


def ghidra_trace_start(debugger, command, result, internal_dict):
    """Start a Trace in Ghidra"""

    STATE.require_client()
    name = command if len(command) > 0 else compute_name()
    #if name is None:
    #    name = compute_name()
    STATE.require_no_trace()
    start_trace(name)


def ghidra_trace_stop(debugger, command, result, internal_dict):
    """Stop the Trace in Ghidra"""

    STATE.require_trace().close()
    STATE.reset_trace()


def ghidra_trace_restart(debugger, command, result, internal_dict):
    """Restart or start the Trace in Ghidra"""

    STATE.require_client()
    if STATE.trace is not None:
        STATE.trace.close()
        STATE.reset_trace()
    name = command if len(command) > 0 else compute_name()
    #if name is None:
    #    name = compute_name()
    start_trace(name)


def ghidra_trace_info(debugger, command, result, internal_dict):
    """Get info about the Ghidra connection"""

    result = {}
    if STATE.client is None:
        print("Not connected to Ghidra\n")
        return
    host, port = STATE.client.s.getpeername()
    print("Connected to Ghidra at {}:{}\n".format(host, port))
    if STATE.trace is None:
        print("No trace\n")
        return
    print("Trace active\n")
    return result


def ghidra_trace_info_lcsp(debugger, command, result, internal_dict):
    """
    Get the selected Ghidra language-compiler-spec pair. Even when
    'show ghidra language' is 'auto' and/or 'show ghidra compiler' is 'auto',
    this command provides the current actual language and compiler spec.
    """

    language, compiler = arch.compute_ghidra_lcsp()
    print("Selected Ghidra language: {}\n".format(language))
    print("Selected Ghidra compiler: {}\n".format(compiler))


def ghidra_trace_txstart(debugger, command, result, internal_dict):
    """
    Start a transaction on the trace
    """

    description = command
    STATE.require_no_tx()
    STATE.tx = STATE.require_trace().start_tx(description, undoable=False)


def ghidra_trace_txcommit(debugger, command, result, internal_dict):
    """
    Commit the current transaction
    """

    STATE.require_tx().commit()
    STATE.reset_tx()


def ghidra_trace_txabort(debugger, command, result, internal_dict):
    """
    Abort the current transaction

    Use only in emergencies.
    """

    tx = STATE.require_tx()
    print("Aborting trace transaction!\n")
    tx.abort()
    STATE.reset_tx()


@contextmanager
def open_tracked_tx(description):
    with STATE.require_trace().open_tx(description) as tx:
        STATE.tx = tx
        yield tx
    STATE.reset_tx()


def ghidra_trace_txopen(debugger, command, result, internal_dict):
    """
    Run a command with an open transaction

    If possible, use this in the following idiom to ensure your transactions
    are closed:

       define my-cmd
         ghidra_trace_put...
         ghidra_trace_put...
       end
       ghidra_trace_tx-open "My tx" "my-cmd"

    If you instead do:

       ghidra_trace_tx-start "My tx"
       ghidra_trace_put...
       ghidra_trace_put...
       ghidra_trace_tx-commit

    and something goes wrong with one of the puts, the transaction may never be
    closed, leading to further crashes when trying to start a new transaction.
    """

    items = command.split(" ");
    description = items[0]
    command = items[1]
    with open_tracked_tx(description):
        lldb.debugger.HandleCommand(command);


def ghidra_trace_save(debugger, command, result, internal_dict):
    """
    Save the current trace
    """

    STATE.require_trace().save()


def ghidra_trace_new_snap(debugger, command, result, internal_dict):
    """
    Create a new snapshot

    Subsequent modifications to machine state will affect the new snapshot.
    """

    description = str(command)
    STATE.require_tx()
    return {'snap': STATE.require_trace().snapshot(description)}

# TODO: A convenience var for the current snapshot
# Will need to update it on:
#     ghidra_trace_snapshot/set-snap
#     process ? (only if per-process tracing.... I don't think I'm doing that.)
#     ghidra_trace_trace start/stop/restart


def ghidra_trace_set_snap(debugger, command, result, internal_dict):
    """
    Go to a snapshot

    Subsequent modifications to machine state will affect the given snapshot.
    """

    snap = command
    eval = util.get_eval(snap)
    if eval.IsValid():
        snap = eval.GetValueAsUnsigned()
        
    STATE.require_trace().set_snap(int(snap))


def put_bytes(start, end, pages, from_tty):
    trace = STATE.require_trace()
    if pages:
        start = start // PAGE_SIZE * PAGE_SIZE
        end = (end + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE
    proc = util.get_process()
    error = lldb.SBError()
    if end - start <= 0:
        return {'count': 0}
    buf = proc.ReadMemory(start, end - start, error)
    
    count = 0
    if error.Success() and buf is not None:
        base, addr = trace.memory_mapper.map(proc, start)
        if base != addr.space:
            trace.create_overlay_space(base, addr.space)
        count = trace.put_bytes(addr, buf)
        if from_tty:
            print("Wrote {} bytes\n".format(count))
    return {'count': count}


def eval_address(address):
    try:
        return util.parse_and_eval(address)
    except e:
        raise RuntimeError("Cannot convert '{}' to address".format(address))


def eval_range(address, length):
    start = eval_address(address)
    try:
        end = start + util.parse_and_eval(length)
    except e:
        raise RuntimeError("Cannot convert '{}' to length".format(length))
    return start, end


def putmem(address, length, pages=True, from_tty=True):
    start, end = eval_range(address, length)
    return put_bytes(start, end, pages, from_tty)


def ghidra_trace_putmem(debugger, command, result, internal_dict):
    """
    Record the given block of memory into the Ghidra trace.
    """

    items = command.split(" ")
    address = items[0]
    length = items[1]
    pages = items[2] if len(items) > 2 else True
    
    STATE.require_tx()
    return putmem(address, length, pages, True)


def ghidra_trace_putval(debugger, command, result, internal_dict):
    """
    Record the given value into the Ghidra trace, if it's in memory.
    """

    items = command.split(" ")
    value = items[0]
    pages = items[1] if len(items) > 1 else True
    
    STATE.require_tx()
    try:
        start = util.parse_and_eval(value)
    except e:
        raise RuntimeError("Value '{}' has no address".format(value))
    end = start + int(start.GetType().GetByteSize())
    return put_bytes(start, end, pages, True)


def ghidra_trace_putmem_state(debugger, command, result, internal_dict):
    """
    Set the state of the given range of memory in the Ghidra trace.
    """

    items = command.split(" ")
    address = items[0]
    length = items[1]
    state = items[2]

    STATE.require_tx()
    STATE.trace.validate_state(state)
    start, end = eval_range(address, length)
    proc = util.get_process()
    base, addr = STATE.trace.memory_mapper.map(proc, start)
    if base != addr.space:
        trace.create_overlay_space(base, addr.space)
    STATE.trace.set_memory_state(addr.extend(end - start), state)


def ghidra_trace_delmem(debugger, command, result, internal_dict):
    """
    Delete the given range of memory from the Ghidra trace.

    Why would you do this? Keep in mind putmem quantizes to full pages by
    default, usually to take advantage of spatial locality. This command does
    not quantize. You must do that yourself, if necessary.
    """

    items = command.split(" ")
    address = items[0]
    length = items[1]

    STATE.require_tx()
    start, end = eval_range(address, length)
    proc = util.get_process()
    base, addr = STATE.trace.memory_mapper.map(proc, start)
    # Do not create the space. We're deleting stuff.
    STATE.trace.delete_bytes(addr.extend(end - start))


def putreg(frame, bank):
    proc = util.get_process()
    space = REGS_PATTERN.format(procnum=proc.GetProcessID(), tnum=util.selected_thread().GetThreadID(),
                                level=frame.GetFrameID())
    subspace = BANK_PATTERN.format(procnum=proc.GetProcessID(), tnum=util.selected_thread().GetThreadID(),
                                level=frame.GetFrameID(), bank=bank.name)
    STATE.trace.create_overlay_space('register', space)
    robj = STATE.trace.create_object(space)
    robj.insert()
    bobj = STATE.trace.create_object(subspace)
    bobj.insert()
    mapper = STATE.trace.register_mapper
    values = []
    for i in range(0, bank.GetNumChildren()):
        item = bank.GetChildAtIndex(i, lldb.eDynamicCanRunTarget, True)
        values.append(mapper.map_value(proc, item.GetName(), item.GetValueAsUnsigned()))
        bobj.set_value(item.GetName(), hex(item.GetValueAsUnsigned()))
    # TODO: Memorize registers that failed for this arch, and omit later.
    return {'missing': STATE.trace.put_registers(space, values)}


def ghidra_trace_putreg(debugger, command, result, internal_dict):
    """
    Record the given register group for the current frame into the Ghidra trace.

    If no group is specified, 'all' is assumed.
    """

    group = command if len(command) > 0 else 'all'

    STATE.require_tx()
    frame = util.selected_frame()
    regs = frame.GetRegisters()
    if group is not 'all':
        bank = regs.GetFirstValueByName(group)
        return putreg(frame, bank)
    
    for i in range(0, regs.GetSize()):
        bank = regs.GetValueAtIndex(i)
        putreg(frame, bank)


def ghidra_trace_delreg(debugger, command, result, internal_dict):
    """
    Delete the given register group for the curent frame from the Ghidra trace.

    Why would you do this? If no group is specified, 'all' is assumed.
    """

    group = command if len(command) > 0 else 'all'

    STATE.require_tx()
    proc = util.get_process()
    frame = util.selected_frame()
    space = 'Processes[{}].Threads[{}].Stack[{}].Registers'.format(
        proc.GetProcessID(), util.selected_thread().GetThreadID(), frame.GetFrameID()
    )
    mapper = STATE.trace.register_mapper
    names = []
    for desc in frame.registers:
        names.append(mapper.map_name(proc, desc.name))
    return STATE.trace.delete_registers(space, names)


def ghidra_trace_create_obj(debugger, command, result, internal_dict):
    """
    Create an object in the Ghidra trace.

    The new object is in a detached state, so it may not be immediately
    recognized by the Debugger GUI. Use 'ghidra_trace_insert-obj' to finish the
    object, after all its required attributes are set.
    """

    path = command
    
    STATE.require_tx()
    obj = STATE.trace.create_object(path)
    obj.insert()
    print("Created object: id={}, path='{}'\n".format(obj.id, obj.path))
    return {'id': obj.id, 'path': obj.path}


def ghidra_trace_insert_obj(debugger, command, result, internal_dict):
    """
    Insert an object into the Ghidra trace.
    """

    path = command
    
    # NOTE: id parameter is probably not necessary, since this command is for
    # humans.
    STATE.require_tx()
    span = STATE.trace.proxy_object_path(path).insert()
    print("Inserted object: lifespan={}\n".format(span))
    return {'lifespan': span}


def ghidra_trace_remove_obj(debugger, command, result, internal_dict):
    """
    Remove an object from the Ghidra trace.

    This does not delete the object. It just removes it from the tree for the
    current snap and onwards.
    """

    path = command

    # NOTE: id parameter is probably not necessary, since this command is for
    # humans.
    STATE.require_tx()
    STATE.trace.proxy_object_path(path).remove()


def to_bytes(value, type):
    n = value.GetNumChildren()
    return bytes(int(value.GetChildAtIndex(i).GetValueAsUnsigned()) for i in range(0,n))


def to_string(value, type, encoding, full):
    n = value.GetNumChildren()
    b = bytes(int(value.GetChildAtIndex(i).GetValueAsUnsigned()) for i in range(0,n))
    return str(b, encoding)


def to_bool_list(value, type):
    n = value.GetNumChildren()
    return [bool(int(value.GetChildAtIndex(i).GetValueAsUnsigned())) for i in range(0,n)]


def to_int_list(value, type):
    n = value.GetNumChildren()
    return [int(value.GetChildAtIndex(i).GetValueAsUnsigned()) for i in range(0,n)]


def to_short_list(value, type):
    n = value.GetNumChildren()
    return [int(value.GetChildAtIndex(i).GetValueAsUnsigned()) for i in range(0,n)]


def eval_value(value, schema=None):
    val = util.get_eval(value)
    type = val.GetType()
    while type.IsTypedefType():
        type = type.GetTypedefedType()
        
    code = type.GetBasicType()
    if code == lldb.eBasicTypeVoid:
        return None, sch.VOID
    if code == lldb.eBasicTypeChar or code == lldb.eBasicTypeSignedChar or code == lldb.eBasicTypeUnsignedChar:
        if not "\\x" in val.GetValue():
            return int(val.GetValueAsUnsigned()), sch.CHAR
        return int(val.GetValueAsUnsigned()), sch.BYTE
    if code == lldb.eBasicTypeShort or code == lldb.eBasicTypeUnsignedShort:
        return int(val.GetValue()), sch.SHORT
    if code == lldb.eBasicTypeInt or code == lldb.eBasicTypeUnsignedInt:
        return int(val.GetValue()), sch.INT
    if code == lldb.eBasicTypeLong or code == lldb.eBasicTypeUnsignedLong:
        return int(val.GetValue()), sch.LONG
    if code == lldb.eBasicTypeLongLong or code == lldb.eBasicTypeUnsignedLongLong:
        return int(val.GetValue()), sch.LONG
    if code == lldb.eBasicTypeBool:
        return bool(val.GetValue()), sch.BOOL
    
    # TODO: This seems like a bit of a hack
    type_name = type.GetName()
    if type_name.startswith("const char["):
        return val.GetSummary(), sch.STRING
    if type_name.startswith("const wchar_t["):
        return val.GetSummary(), sch.STRING
    
    if type.IsArrayType():
        etype = type.GetArrayElementType()
        while etype.IsTypedefType():
            etype = etype.GetTypedefedType()
        ecode = etype.GetBasicType()
        if ecode == lldb.eBasicTypeBool:
            return to_bool_list(val, type), sch.BOOL_ARR
        elif ecode == lldb.eBasicTypeChar or ecode == lldb.eBasicTypeSignedChar or ecode == lldb.eBasicTypeUnsignedChar:
            if schema == sch.BYTE_ARR:
                return to_bytes(val, type), schema
            elif schema == sch.CHAR_ARR:
                return to_string(val, type, 'utf-8', full=True), schema
            return to_string(val, type, 'utf-8', full=False), sch.STRING
        elif ecode == lldb.eBasicTypeShort or ecode == lldb.eBasicTypeUnsignedShort:
            if schema is None:
                if etype.name == 'wchar_t':
                    return to_string(val, type, 'utf-16', full=False), sch.STRING
                schema = sch.SHORT_ARR
            elif schema == sch.CHAR_ARR:
                return to_string(val, type, 'utf-16', full=True), schema
            return to_int_list(val, type), schema
        elif ecode == lldb.eBasicTypeSignedWChar or ecode == lldb.eBasicTypeUnsignedWChar:
            if schema is not None and schema != sch.CHAR_ARR:
                return to_short_list(val, type), schema
            else:
                return to_string(val, type, 'utf-16', full=False), sch.STRING
        elif ecode == lldb.eBasicTypeInt or ecode == lldb.eBasicTypeUnsignedInt:
            if schema is None:
                if etype.name == 'wchar_t':
                    return to_string(val, type, 'utf-32', full=False), sch.STRING
                schema = sch.INT_ARR
            elif schema == sch.CHAR_ARR:
                return to_string(val, type, 'utf-32', full=True), schema
            return to_int_list(val, type), schema
        elif ecode == lldb.eBasicTypeLong or ecode == lldb.eBasicTypeUnsignedLong or ecode == lldb.eBasicTypeLongLong or ecode == lldb.eBasicTypeUnsignedLongLong:
            if schema is not None:
                return to_int_list(val, type), schema
            else:
                return to_int_list(val, type), sch.LONG_ARR
    elif type.IsPointerType():
        offset = int(val.GetValue(),16)
        proc = util.get_process()
        base, addr = STATE.trace.memory_mapper.map(proc, offset)
        return (base, addr), sch.ADDRESS
    raise ValueError(
        "Cannot convert ({}): '{}', value='{}'".format(schema, value, val))


def ghidra_trace_set_value(debugger, command, result, internal_dict):
    """
    Set a value (attribute or element) in the Ghidra trace's object tree.

    A void value implies removal. NOTE: The type of an expression may be
    subject to LLDB's current language. e.g., there is no 'bool' in C. You may
    have to change to C++ if you need this type. Alternatively, you can use the
    Python API.
    """

    # NOTE: id parameter is probably not necessary, since this command is for
    # humans.
    # TODO: path and key are two separate parameters.... This is mostly to
    # spare me from porting path parsing to Python, but it may also be useful
    # if we ever allow ids here, since the id would be for the object, not the
    # complete value path.
    
    items = command.split(" ")
    path = items[0]
    key = items[1]
    value = items[2]
    if len(items) > 3 and items[3] is not "":
        schema = items[3]
        # This is a horrible hack
        if (value.startswith("\"") or value.startswith("L\"")) and schema.endswith("\""):
            value = value+" "+schema
            schema = None
    else:
        schema = None
        
    schema = None if schema is None else sch.Schema(schema)
    STATE.require_tx()
    if schema == sch.OBJECT:
        val = STATE.trace.proxy_object_path(value)
    else:
        val, schema = eval_value(value, schema)
        if schema == sch.ADDRESS:
            base, addr = val
            val = addr
            if base != addr.space:
                trace.create_overlay_space(base, addr.space)
    STATE.trace.proxy_object_path(path).set_value(key, val, schema)


def ghidra_trace_retain_values(debugger, command, result, internal_dict):
    """
    Retain only those keys listed, settings all others to null.

    Takes a list of keys to retain. The first argument may optionally be one of
    the following:

        --elements To set all other elements to null (default)
        --attributes To set all other attributes to null
        --both To set all other values (elements and attributes) to null

    If, for some reason, one of the keys to retain would be mistaken for this
    switch, then the switch is required. Only the first argument is taken as the
    switch. All others are taken as keys.
    """

    items = command.split(" ")
    path = items[0]
    keys = items[1:]

    STATE.require_tx()
    kinds = 'elements'
    if keys[0] == '--elements':
        kinds = 'elements'
        keys = keys[1:]
    elif keys[0] == '--attributes':
        kinds = 'attributes'
        keys = keys[1:]
    elif keys[0] == '--both':
        kinds = 'both'
        keys = keys[1:]
    elif keys[0].startswith('--'):
        raise RuntimeError("Invalid argument: " + keys[0])
    STATE.trace.proxy_object_path(path).retain_values(keys, kinds=kinds)


def ghidra_trace_get_obj(debugger, command, result, internal_dict):
    """
    Get an object descriptor by its canonical path.

    This isn't the most informative, but it will at least confirm whether an
    object exists and provide its id.
    """

    path = command
	
    trace = STATE.require_trace()
    object = trace.get_object(path)
    print("{}\t{}\n".format(object.id, object.path))
    return object


class TableColumn(object):
    def __init__(self, head):
        self.head = head
        self.contents = [head]
        self.is_last = False

    def add_data(self, data):
        self.contents.append(str(data))

    def finish(self):
        self.width = max(len(d) for d in self.contents) + 1

    def print_cell(self, i):
        print(
            self.contents[i] if self.is_last else self.contents[i].ljust(self.width))


class Tabular(object):
    def __init__(self, heads):
        self.columns = [TableColumn(h) for h in heads]
        self.columns[-1].is_last = True
        self.num_rows = 1

    def add_row(self, datas):
        for c, d in zip(self.columns, datas):
            c.add_data(d)
        self.num_rows += 1

    def print_table(self):
        for c in self.columns:
            c.finish()
        for rn in range(self.num_rows):
            for c in self.columns:
                c.print_cell(rn)
            print('\n')


def val_repr(value):
    if isinstance(value, TraceObject):
        return value.path
    elif isinstance(value, Address):
        return '{}:{:08x}'.format(value.space, value.offset)
    return repr(value)


def print_values(values):
    table = Tabular(['Parent', 'Key', 'Span', 'Value', 'Type'])
    for v in values:
        table.add_row(
            [v.parent.path, v.key, v.span, val_repr(v.value), v.schema])
    table.print_table()


def ghidra_trace_get_values(debugger, command, result, internal_dict):
    """
    List all values matching a given path pattern.
    """

    pattern = command
    
    trace = STATE.require_trace()
    values = trace.get_values(pattern)
    print_values(values)
    return values


def ghidra_trace_get_values_rng(debugger, command, result, internal_dict):
    """
    List all values intersecting a given address range.
    """

    items = command.split(" ")
    address = items[0]
    length = items[1]

    trace = STATE.require_trace()
    start, end = eval_range(address, length)
    proc = util.get_process()
    base, addr = trace.memory_mapper.map(proc, start)
    # Do not create the space. We're querying. No tx.
    values = trace.get_values_intersecting(addr.extend(end - start))
    print_values(values)
    return values


def activate(path=None):
    trace = STATE.require_trace()
    if path is None:
        proc = util.get_process()
        t = util.selected_thread()
        if t is None:
            path = PROCESS_PATTERN.format(procnum=proc.GetProcessID())
        else:
            frame = util.selected_frame()
            if frame is None:
                path = THREAD_PATTERN.format(procnum=proc.GetProcessID(), tnum=t.GetThreadID())
            else:
                path = FRAME_PATTERN.format(
                    procnum=proc.GetProcessID(), tnum=t.GetThreadID(), level=frame.GetFrameID())
        trace.proxy_object_path(path).activate()


def ghidra_trace_activate(debugger, command, result, internal_dict):
    """
    Activate an object in Ghidra's GUI.

    This has no effect if the current trace is not current in Ghidra. If path is
    omitted, this will activate the current frame.
    """
    
    path = command if len(command) > 0 else None

    activate(path)


def ghidra_trace_disassemble(debugger, command, result, internal_dict):
    """
    Disassemble starting at the given seed.

    Disassembly proceeds linearly and terminates at the first branch or unknown
    memory encountered.
    """

    address = command

    STATE.require_tx()
    start = eval_address(address)
    proc = util.get_process()
    base, addr = STATE.trace.memory_mapper.map(proc, start)
    if base != addr.space:
        trace.create_overlay_space(base, addr.space)

    length = STATE.trace.disassemble(addr)
    print("Disassembled {} bytes\n".format(length))
    return {'length': length}


def compute_proc_state(proc = None):
    if proc.is_running:  
        return 'RUNNING'
    return 'STOPPED'


def put_processes():
    keys = []
    proc = util.get_process()
    ipath = PROCESS_PATTERN.format(procnum=proc.GetProcessID())
    keys.append(PROCESS_KEY_PATTERN.format(procnum=proc.GetProcessID()))
    procobj = STATE.trace.create_object(ipath)
    istate = compute_proc_state(proc)
    procobj.set_value('_state', istate)
    procobj.insert()
    STATE.trace.proxy_object_path(PROCESSES_PATH).retain_values(keys)

def put_state(event_process):
    STATE.require_no_tx()
    STATE.tx = STATE.require_trace().start_tx("state", undoable=False)
    ipath = PROCESS_PATTERN.format(procnum=event_process.GetProcessID())
    procobj = STATE.trace.create_object(ipath)
    state = "STOPPED" if event_process.is_stopped else "RUNNING"
    procobj.set_value('_state', state)
    procobj.insert()
    STATE.require_tx().commit()
    STATE.reset_tx()


def ghidra_trace_put_processes(debugger, command, result, internal_dict):
    """
    Put the list of processes into the trace's Processes list.
    """

    STATE.require_tx()
    with STATE.client.batch() as b:
        put_processes()


def put_available():
    keys = []
    for proc in psutil.process_iter():
        ppath = AVAILABLE_PATTERN.format(pid=proc.pid)
        procobj = STATE.trace.create_object(ppath)
        keys.append(AVAILABLE_KEY_PATTERN.format(pid=proc.pid))
        procobj.set_value('_pid', proc.pid)
        procobj.set_value('_display', '{} {}'.format(proc.pid, proc.name))
        procobj.insert()
    STATE.trace.proxy_object_path(AVAILABLES_PATH).retain_values(keys)


def ghidra_trace_put_available(debugger, command, result, internal_dict):
    """
    Put the list of available processes into the trace's Available list.
    """

    STATE.require_tx()
    with STATE.client.batch() as b:
        put_available()


def put_single_breakpoint(b, ibobj, proc, ikeys):
    mapper = STATE.trace.memory_mapper
    bpath = BREAKPOINT_PATTERN.format(breaknum=b.GetID())
    brkobj = STATE.trace.create_object(bpath)
    if b.IsHardware():
        brkobj.set_value('_expression', util.get_description(b))
        brkobj.set_value('_kinds', 'HW_EXECUTE')
    else:
        brkobj.set_value('_expression', util.get_description(b))
        brkobj.set_value('_kinds', 'SW_EXECUTE')
    cmdList = lldb.SBStringList()
    if b.GetCommandLineCommands(cmdList):
        list = []
        for i in range(0,cmdList.GetSize()):
            list.append(cmdList.GetStringAtIndex(i))
        brkobj.set_value('Commands', list)
    if b.GetCondition():
        brkobj.set_value('Condition', b.GetCondition())
    brkobj.set_value('Hit Count', b.GetHitCount())
    brkobj.set_value('Ignore Count', b.GetIgnoreCount())
    brkobj.set_value('Temporary', b.IsOneShot())
    keys = []
    locs = util.BREAKPOINT_LOCATION_INFO_READER.get_locations(b)
    hooks.BRK_STATE.update_brkloc_count(b, len(locs))
    for i, l in enumerate(locs):
        # Retain the key, even if not for this process
        k = BREAK_LOC_KEY_PATTERN.format(locnum=i+1)
        keys.append(k)
        locobj = STATE.trace.create_object(bpath + k)
        ik = PROC_BREAK_KEY_PATTERN.format(breaknum=b.GetID(), locnum=i+1)
        ikeys.append(ik)
        if b.location is not None:  # Implies execution break
            base, addr = mapper.map(proc, l.GetLoadAddress())
            if base != addr.space:
                STATE.trace.create_overlay_space(base, addr.space)
            locobj.set_value('_range', addr.extend(1))
        else:  # I guess it's a catchpoint
            pass
        locobj.insert()
        ibobj.set_value(ik, locobj)
    brkobj.retain_values(keys)
    brkobj.insert()

def put_single_watchpoint(b, ibobj, proc, ikeys):
    mapper = STATE.trace.memory_mapper
    bpath = PROC_WATCH_KEY_PATTERN.format(procnum=proc.GetProcessID(), watchnum=b.GetID())
    brkobj = STATE.trace.create_object(bpath)
    desc = util.get_description(b, level=0)
    brkobj.set_value('_expression', desc)
    brkobj.set_value('_kinds', 'WRITE')
    if "type = r" in desc:
       brkobj.set_value('_kinds', 'READ')
    if "type = rw" in desc:
       brkobj.set_value('_kinds', 'READ,WRITE')
    base, addr = mapper.map(proc, b.GetWatchAddress())
    if base != addr.space:
        STATE.trace.create_overlay_space(base, addr.space)
    brkobj.set_value('_range', addr.extend(b.GetWatchSize()))
    if b.GetCondition():
        brkobj.set_value('Condition', b.GetCondition())
    brkobj.set_value('Hit Count', b.GetHitCount())
    brkobj.set_value('Ignore Count', b.GetIgnoreCount())
    brkobj.set_value('Hardware Index', b.GetHardwareIndex())
    brkobj.set_value('Watch Address', hex(b.GetWatchAddress()))
    brkobj.set_value('Watch Size', b.GetWatchSize())
    brkobj.insert()


def put_breakpoints():
    target = util.get_target()
    proc = util.get_process()
    ibpath = PROC_BREAKS_PATTERN.format(procnum=proc.GetProcessID())
    ibobj = STATE.trace.create_object(ibpath)
    keys = []
    ikeys = []
    for i in range(0, target.GetNumBreakpoints()):
        b = target.GetBreakpointAtIndex(i)
        keys.append(BREAKPOINT_KEY_PATTERN.format(breaknum=b.GetID()))
        put_single_breakpoint(b, ibobj, proc, ikeys)
    ibobj.insert()
    STATE.trace.proxy_object_path(BREAKPOINTS_PATH).retain_values(keys)
    ibobj.retain_values(ikeys)

def put_watchpoints():
    target = util.get_target()
    proc = util.get_process()
    ibpath = PROC_WATCHES_PATTERN.format(procnum=proc.GetProcessID())
    ibobj = STATE.trace.create_object(ibpath)
    keys = []
    ikeys = []
    for i in range(0, target.GetNumWatchpoints()):
        b = target.GetWatchpointAtIndex(i)
        keys.append(WATCHPOINT_KEY_PATTERN.format(watchnum=b.GetID()))
        put_single_watchpoint(b, ibobj, proc, ikeys)
    ibobj.insert()
    STATE.trace.proxy_object_path(WATCHPOINTS_PATH).retain_values(keys)


def ghidra_trace_put_breakpoints(debugger, command, result, internal_dict):
    """
    Put the current process's breakpoints into the trace.
    """

    STATE.require_tx()
    with STATE.client.batch() as b:
        put_breakpoints()
 
def ghidra_trace_put_watchpoints(debugger, command, result, internal_dict):
    """
    Put the current process's watchpoints into the trace.
    """

    STATE.require_tx()
    with STATE.client.batch() as b:
        put_watchpoints()
 

def put_environment():
    proc = util.get_process()
    epath = ENV_PATTERN.format(procnum=proc.GetProcessID())
    envobj = STATE.trace.create_object(epath)
    envobj.set_value('_debugger', 'lldb')
    envobj.set_value('_arch', arch.get_arch())
    envobj.set_value('_os', arch.get_osabi())
    envobj.set_value('_endian', arch.get_endian())
    envobj.insert()


def ghidra_trace_put_environment(debugger, command, result, internal_dict):
    """
    Put some environment indicators into the Ghidra trace
    """

    STATE.require_tx()
    with STATE.client.batch() as b:
        put_environment()


def put_regions():
    proc = util.get_process()
    try:
        regions = util.REGION_INFO_READER.get_regions()
    except Exception:
        regions = []
    if len(regions) == 0 and util.selected_thread() is not None:
        regions = [util.REGION_INFO_READER.full_mem()]
    mapper = STATE.trace.memory_mapper
    keys = []
    for r in regions:
        rpath = REGION_PATTERN.format(procnum=proc.GetProcessID(), start=r.start)
        keys.append(REGION_KEY_PATTERN.format(start=r.start))
        regobj = STATE.trace.create_object(rpath)
        start_base, start_addr = mapper.map(proc, r.start)
        if start_base != start_addr.space:
            STATE.trace.create_overlay_space(start_base, start_addr.space)
        regobj.set_value('_range', start_addr.extend(r.end - r.start))
        regobj.set_value('_readable', r.perms == None or 'r' in r.perms)
        regobj.set_value('_writable', r.perms == None or 'w' in r.perms)
        regobj.set_value('_executable', r.perms == None or 'x' in r.perms)
        regobj.set_value('_offset', r.offset)
        regobj.set_value('_objfile', r.objfile)
        regobj.insert()
    STATE.trace.proxy_object_path(
        MEMORY_PATTERN.format(procnum=proc.GetProcessID())).retain_values(keys)


def ghidra_trace_put_regions(debugger, command, result, internal_dict):
    """
    Read the memory map, if applicable, and write to the trace's Regions
    """

    STATE.require_tx()
    with STATE.client.batch() as b:
        put_regions()


def put_modules():
    target = util.get_target()
    proc = util.get_process()
    modules = util.MODULE_INFO_READER.get_modules()
    mapper = STATE.trace.memory_mapper
    mod_keys = []
    for mk, m in modules.items():
        mpath = MODULE_PATTERN.format(procnum=proc.GetProcessID(), modpath=mk)
        modobj = STATE.trace.create_object(mpath)
        mod_keys.append(MODULE_KEY_PATTERN.format(modpath=mk))
        modobj.set_value('_module_name', m.name)
        base_base, base_addr = mapper.map(proc, m.base)
        if base_base != base_addr.space:
            STATE.trace.create_overlay_space(base_base, base_addr.space)
        if m.max > m.base:
            modobj.set_value('_range', base_addr.extend(m.max - m.base + 1))
        sec_keys = []
        for sk, s in m.sections.items():
            spath = mpath + SECTION_ADD_PATTERN.format(secname=sk)
            secobj = STATE.trace.create_object(spath)
            sec_keys.append(SECTION_KEY_PATTERN.format(secname=sk))
            start_base, start_addr = mapper.map(proc, s.start)
            if start_base != start_addr.space:
                STATE.trace.create_overlay_space(
                    start_base, start_addr.space)
            secobj.set_value('_range', start_addr.extend(s.end - s.start + 1))
            secobj.set_value('_offset', s.offset)
            secobj.set_value('_attrs', s.attrs)
            secobj.insert()
        # In case there are no sections, we must still insert the module
        modobj.insert()
        STATE.trace.proxy_object_path(
            mpath + SECTIONS_ADD_PATTERN).retain_values(sec_keys)
    STATE.trace.proxy_object_path(MODULES_PATTERN.format(
        procnum=proc.GetProcessID())).retain_values(mod_keys)


def ghidra_trace_put_modules(debugger, command, result, internal_dict):
    """
    Gather object files, if applicable, and write to the trace's Modules
    """

    STATE.require_tx()
    with STATE.client.batch() as b:
        put_modules()


def convert_state(t):
    if t.IsSuspended():
        return 'SUSPENDED'
    if t.IsStopped():
        return 'STOPPED'
    return 'RUNNING'


def convert_tid(t):
    if t[1] == 0:
        return t[2]
    return t[1]


@contextmanager
def restore_frame():
    f = util.selected_frame()
    yield
    f.select()


def compute_thread_display(t):
    return util.get_description(t)


def put_threads():
    radix = util.get_convenience_variable('output-radix')
    if radix == 'auto':
        radix = 16
    proc = util.get_process()
    keys = []
    for t in proc.threads:
        tpath = THREAD_PATTERN.format(procnum=proc.GetProcessID(), tnum=t.GetThreadID())
        tobj = STATE.trace.create_object(tpath)
        keys.append(THREAD_KEY_PATTERN.format(tnum=t.GetThreadID()))
        tobj.set_value('_state', convert_state(t))
        tobj.set_value('_name', t.GetName())
        tid = t.GetThreadID()
        tobj.set_value('_tid', tid)
        tidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(tid)
        tobj.set_value('_short_display', '[{}.{}:{}]'.format(
            proc.GetProcessID(), t.GetThreadID(), tidstr))
        tobj.set_value('_display', compute_thread_display(t))
        tobj.insert()
    STATE.trace.proxy_object_path(
        THREADS_PATTERN.format(procnum=proc.GetProcessID())).retain_values(keys)


def put_event_thread():
    proc = util.get_process()
    # Assumption: Event thread is selected by lldb upon stopping
    t = util.selected_thread()
    if t is not None:
        tpath = THREAD_PATTERN.format(procnum=proc.GetProcessID(), tnum=t.GetThreadID())
        tobj = STATE.trace.proxy_object_path(tpath)
    else:
        tobj = None
    STATE.trace.proxy_object_path('').set_value('_event_thread', tobj)


def ghidra_trace_put_threads(debugger, command, result, internal_dict):
    """
    Put the current process's threads into the Ghidra trace
    """

    STATE.require_tx()
    with STATE.client.batch() as b:
        put_threads()


def put_frames():
    proc = util.get_process()
    mapper = STATE.trace.memory_mapper
    t = util.selected_thread()
    if t is None:
        return
    keys = []
    for i in range(0,t.GetNumFrames()):
        f = t.GetFrameAtIndex(i)
        fpath = FRAME_PATTERN.format(
            procnum=proc.GetProcessID(), tnum=t.GetThreadID(), level=f.GetFrameID())
        fobj = STATE.trace.create_object(fpath)
        keys.append(FRAME_KEY_PATTERN.format(level=f.GetFrameID()))
        base, pc = mapper.map(proc, f.GetPC())
        if base != pc.space:
            STATE.trace.create_overlay_space(base, pc.space)
        fobj.set_value('_pc', pc)
        fobj.set_value('_func', str(f.GetFunctionName()))
        fobj.set_value('_display', util.get_description(f))
        fobj.insert()
    STATE.trace.proxy_object_path(STACK_PATTERN.format(
        procnum=proc.GetProcessID(), tnum=t.GetThreadID())).retain_values(keys)


def ghidra_trace_put_frames(debugger, command, result, internal_dict):
    """
    Put the current thread's frames into the Ghidra trace
    """

    STATE.require_tx()
    with STATE.client.batch() as b:
        put_frames()


def ghidra_trace_put_all(debugger, command, result, internal_dict):
    """
    Put everything currently selected into the Ghidra trace
    """

    STATE.require_tx()
    with STATE.client.batch() as b:
        ghidra_trace_putreg(debugger, DEFAULT_REGISTER_BANK, result, internal_dict)
        ghidra_trace_putmem(debugger, "$pc 1", result, internal_dict)
        ghidra_trace_putmem(debugger, "$sp 1", result, internal_dict)
        put_processes()
        put_environment()
        put_regions()
        put_modules()
        put_threads()
        put_frames()
        put_breakpoints()
        put_watchpoints()
        put_available()
 

def ghidra_trace_install_hooks(debugger, command, result, internal_dict):
    """
    Install hooks to trace in Ghidra
    """

    hooks.install_hooks()


def ghidra_trace_remove_hooks(debugger, command, result, internal_dict):
    """
    Remove hooks to trace in Ghidra

    Using this directly is not recommended, unless it seems the hooks are
    preventing lldb or other extensions from operating. Removing hooks will break
    trace synchronization until they are replaced.
    """

    hooks.remove_hooks()


def ghidra_trace_sync_enable(debugger, command, result, internal_dict):
    """
    Synchronize the current process with the Ghidra trace

    This will automatically install hooks if necessary. The goal is to record
    the current frame, thread, and process into the trace immediately, and then
    to append the trace upon stopping and/or selecting new frames. This action
    is effective only for the current process. This command must be executed
    for each individual process you'd like to synchronize. In older versions of
    lldb, certain events cannot be hooked. In that case, you may need to execute
    certain "trace put" commands manually, or go without.

    This will have no effect unless or until you start a trace.
    """

    hooks.install_hooks()
    hooks.enable_current_process()


def ghidra_trace_sync_disable(debugger, command, result, internal_dict):
    """
    Cease synchronizing the current process with the Ghidra trace

    This is the opposite of 'ghidra_trace_sync-disable', except it will not
    automatically remove hooks.
    """

    hooks.disable_current_process()


def ghidra_util_wait_stopped(debugger, command, result, internal_dict):
    """
    Spin wait until the selected thread is stopped.
    """

    timeout = commmand if len(command) > 0 else '1'
    
    timeout = int(timeout)
    start = time.time()
    t = util.selected_thread()
    if t is None:
        return
    while not t.IsStopped() and not t.IsSuspended():
        t = util.selected_thread()  # I suppose it could change
        time.sleep(0.1)
        if time.time() - start > timeout:
            raise RuntimeError('Timed out waiting for thread to stop')
           
            
def ghidra_util_mark(debugger, command, result, internal_dict):
    print(command)
