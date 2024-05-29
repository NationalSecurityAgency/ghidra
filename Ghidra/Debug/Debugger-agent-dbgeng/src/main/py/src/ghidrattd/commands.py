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
import re

from ghidratrace import sch
from ghidratrace.client import Client, Address, AddressRange, Lifespan, TraceObject

#from pybag import pydbg, userdbg, kerneldbg
#from pybag.dbgeng import core as DbgEng
#from pybag.dbgeng import exception
from pyttd import pyTTD

from . import util, arch, methods, hooks
import code

PAGE_SIZE = 4096

AVAILABLES_PATH = 'Available'
AVAILABLE_KEY_PATTERN = '[{pid}]'
AVAILABLE_PATTERN = AVAILABLES_PATH + AVAILABLE_KEY_PATTERN
PROCESSES_PATH = 'Processes'
PROCESS_KEY_PATTERN = '[{procnum}]'
PROCESS_PATTERN = PROCESSES_PATH + PROCESS_KEY_PATTERN
PROC_BREAKS_PATTERN = PROCESS_PATTERN + '.Breakpoints'
PROC_BREAK_KEY_PATTERN = '[{breaknum}]'
PROC_BREAK_PATTERN = PROC_BREAKS_PATTERN + PROC_BREAK_KEY_PATTERN
ENV_PATTERN = PROCESS_PATTERN + '.Environment'
THREADS_PATTERN = PROCESS_PATTERN + '.Threads'
THREAD_KEY_PATTERN = '[{tnum}]'
THREAD_PATTERN = THREADS_PATTERN + THREAD_KEY_PATTERN
STACK_PATTERN = THREAD_PATTERN + '.Stack'
FRAME_KEY_PATTERN = '[{level}]'
FRAME_PATTERN = STACK_PATTERN + FRAME_KEY_PATTERN
REGS_PATTERN = THREAD_PATTERN + '.Registers'
MEMORY_PATTERN = PROCESS_PATTERN + '.Memory'
REGION_KEY_PATTERN = '[{start:08x}]'
REGION_PATTERN = MEMORY_PATTERN + REGION_KEY_PATTERN
MODULES_PATTERN = PROCESS_PATTERN + '.Modules'
MODULE_KEY_PATTERN = '[{modpath}]'
MODULE_PATTERN = MODULES_PATTERN + MODULE_KEY_PATTERN
SECTIONS_ADD_PATTERN = '.Sections'
SECTION_KEY_PATTERN = '[{secname}]'
SECTION_ADD_PATTERN = SECTIONS_ADD_PATTERN + SECTION_KEY_PATTERN
DESCRIPTION_PATTERN = '{major}:{minor} {type}'

# TODO: Symbols


class ErrorWithCode(Exception):
    def __init__(self, code):
        self.code = code

    def __str__(self)->str:
        return repr(self.code)


class State(object):

    def __init__(self):
        self.reset_client()

    def require_client(self):
        if self.client is None:
            raise RuntimeError("Not connected")
        return self.client

    def require_no_client(self):
        if self.client != None:
            raise RuntimeError("Already connected")

    def reset_client(self):
        self.client = None
        self.reset_trace()

    def require_trace(self):
        if self.trace is None:
            raise RuntimeError("No trace active")
        return self.trace

    def require_no_trace(self):
        if self.trace != None:
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
        if self.tx != None:
            raise RuntimeError("Transaction already started")

    def reset_tx(self):
        self.tx = None


STATE = State()


def ghidra_trace_connect(address=None):
    """
    Connect Python to Ghidra for tracing

    Address must be of the form 'host:port'
    """

    STATE.require_no_client()
    if address is None:
        raise RuntimeError(
            "'ghidra_trace_connect': missing required argument 'address'")

    parts = address.split(':')
    if len(parts) != 2:
        raise RuntimeError("address must be in the form 'host:port'")
    host, port = parts
    try:
        c = socket.socket()
        c.connect((host, int(port)))
        # TODO: Can we get version info from the DLL?
        STATE.client = Client(c, "dbgeng.dll", methods.REGISTRY)
        print(f"Connected to {STATE.client.description} at {address}")
    except ValueError:
        raise RuntimeError("port must be numeric")


def ghidra_trace_listen(address='0.0.0.0:0'):
    """
    Listen for Ghidra to connect for tracing

    Takes an optional address for the host and port on which to listen. Either
    the form 'host:port' or just 'port'. If omitted, it will bind to an
    ephemeral port on all interfaces. If only the port is given, it will bind to
    that port on all interfaces. This command will block until the connection is
    established.
    """

    STATE.require_no_client()
    parts = address.split(':')
    if len(parts) == 1:
        host, port = '0.0.0.0', parts[0]
    elif len(parts) == 2:
        host, port = parts
    else:
        raise RuntimeError("address must be 'port' or 'host:port'")

    try:
        s = socket.socket()
        s.bind((host, int(port)))
        host, port = s.getsockname()
        s.listen(1)
        print("Listening at {}:{}...\n".format(host, port))
        c, (chost, cport) = s.accept()
        s.close()
        print("Connection from {}:{}\n".format(chost, cport))
        STATE.client = Client(c, "dbgeng.dll", methods.REGISTRY)
    except ValueError:
        raise RuntimeError("port must be numeric")


def ghidra_trace_disconnect():
    """Disconnect Python from Ghidra for tracing"""

    STATE.require_client().close()
    STATE.reset_client()


def compute_name(progname=None):
    if progname is None:
        try:
            buffer = util.GetCurrentProcessExecutableName()
            progname = buffer.decode('utf-8')
        except Exception:
            return 'pydbg/noname'
    return 'pydbg/' + re.split(r'/|\\', progname)[-1]


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
        root = STATE.trace.create_root_object(schema_xml, 'TTDSession')
        root.set_value('_display', 'pyTTD ' + util.DBG_VERSION.full)
    util.set_convenience_variable('_ghidra_tracing', "true")


def ghidra_trace_start(name=None):
    """Start a Trace in Ghidra"""

    STATE.require_client()
    name = compute_name(name)
    STATE.require_no_trace()
    start_trace(name)


def ghidra_trace_stop():
    """Stop the Trace in Ghidra"""

    STATE.require_trace().close()
    STATE.reset_trace()


def ghidra_trace_restart(name=None):
    """Restart or start the Trace in Ghidra"""

    STATE.require_client()
    if STATE.trace != None:
        STATE.trace.close()
        STATE.reset_trace()
    name = compute_name(name)
    start_trace(name)


def ghidra_trace_create(command=None, initial_break=True, timeout=None, start_trace=True):
    """
    Create a session.
    """

    eng = pyTTD.ReplayEngine()
    util.eng = eng
    if command != None:
        eng.initialize(command)
        util.first = eng.get_first_position()
        util.last = eng.get_last_position()
        print(f"Trace from {util.first} to {util.last}")
        cursor = eng.new_cursor()
        cursor.set_position(util.first)
        util.lastpos = util.first
        util.base = cursor
    if start_trace:
        print(f"calling start with {command}")
        ghidra_trace_start(command)
        print(f"started")
    events = sorted(
        list((x, "modload") for x in eng.get_module_loaded_event_list())
        + list((x, "modunload") for x in eng.get_module_unloaded_event_list())
        + list((x, "threadcreated")
               for x in eng.get_thread_created_event_list())
        + list((x, "threadterm")
               for x in eng.get_thread_terminated_event_list()),
        key=lambda event: event[0].position
    )

    keys = []
    radix = util.get_convenience_variable('output-radix')
    if radix == 'auto':
        radix = 16
    nproc = 0

    for event, evtype in events:
        pos = event.position
        util.events[pos.major] = event
        util.evttypes[pos.major] = evtype
        with open_tracked_tx('Populate events'):
            index = util.pos2snap(pos)
            STATE.trace.snapshot(DESCRIPTION_PATTERN.format(
                major=pos.major, minor=pos.minor, type=evtype), snap=index)
        if evtype == "modload":
            with open_tracked_tx(evtype):
                id = event.info.base_addr
                path = event.info.path
                size = event.info.image_size
                mobj = get_module(keys, nproc, path, id, size)
                util.starts[id] = index
                mobj.insert(span=Lifespan(index))
            print(f"[{event.position.major:x}:{event.position.minor:x}]", end=" ")
            print(f"Module {event.info.path} loaded")
        elif evtype == "modunload":
            with open_tracked_tx(evtype):
                id = event.info.base_addr
                path = event.info.path
                size = event.info.image_size
                mobj = get_module(keys, nproc, path, id, size)
                util.stops[id] = index
                mobj.remove(span=Lifespan(index))
            #print(f"[{event.position.major:x}:{event.position.minor:x}]", end=" ")
            #print(f"Module {event.info.path} unloaded")
        elif evtype == "threadcreated":
            with open_tracked_tx(evtype):
                id = event.info.threadid
                tobj = get_thread(keys, radix, nproc, id)
                util.starts[id] = index
                tobj.insert(span=Lifespan(index))
            print(f"[{event.position.major:x}:{event.position.minor:x}]", end=" ")
            print(f"Thread {event.info.threadid:x} created")
        elif evtype == "threadterm":
            with open_tracked_tx(evtype):
                id = event.info.threadid
                tobj = get_thread(keys, radix, 0, id)
                util.stops[id] = index
                tobj.remove(span=Lifespan(index))
            #print(f"[{event.position.major:x}:{event.position.minor:x}]", end=" ")
            #print(f"Thread {event.info.threadid:x} terminated")
    ghidra_trace_set_snap(util.first.major)


def ghidra_trace_kill():
    """
    Kill a session.
    """

    print("ghidra_trace_kill")


def ghidra_trace_info():
    """Get info about the Ghidra connection"""

    result = {}
    if STATE.client is None:
        print("Not connected to Ghidra\n")
        return
    host, port = STATE.client.s.getpeername()
    print(f"Connected to {STATE.client.description} at {host}:{port}\n")
    if STATE.trace is None:
        print("No trace\n")
        return
    print("Trace active\n")
    return result


def ghidra_trace_info_lcsp():
    """
    Get the selected Ghidra language-compiler-spec pair. 
    """

    language, compiler = arch.compute_ghidra_lcsp()
    print("Selected Ghidra language: {}\n".format(language))
    print("Selected Ghidra compiler: {}\n".format(compiler))


def ghidra_trace_txstart(description="tx"):
    """
    Start a transaction on the trace
    """

    STATE.require_no_tx()
    STATE.tx = STATE.require_trace().start_tx(description, undoable=False)


def ghidra_trace_txcommit():
    """
    Commit the current transaction
    """

    STATE.require_tx().commit()
    STATE.reset_tx()


def ghidra_trace_txabort():
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


def ghidra_trace_save():
    """
    Save the current trace
    """

    STATE.require_trace().save()


def ghidra_trace_new_snap(description=None, snap=None):
    """
    Create a new snapshot

    Subsequent modifications to machine state will affect the new snapshot.
    """

    description = str(description)
    STATE.require_tx()
    return {'snap': STATE.require_trace().snapshot(description, snap=snap)}


def ghidra_trace_set_snap(snap=None):
    """
    Go to a snapshot

    Subsequent modifications to machine state will affect the given snapshot.
    """

    STATE.require_trace().set_snap(int(snap))


def put_bytes(start, end, pages, display_result):
    trace = STATE.require_trace()
    if pages:
        start = start // PAGE_SIZE * PAGE_SIZE
        end = (end + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE
    nproc = util.selected_process()
    if end - start <= 0:
        return {'count': 0}
    buf = dbg().read_mem(start, end - start)

    count = 0
    if buf != None:
        base, addr = trace.memory_mapper.map(nproc, start)
        if base != addr.space:
            trace.create_overlay_space(base, addr.space)
        count = trace.put_bytes(addr, buf)
        if display_result:
            print("Wrote {} bytes\n".format(count))
    return {'count': count}


def eval_address(address):
    try:
        return util.parse_and_eval(address)
    except Exception:
        raise RuntimeError("Cannot convert '{}' to address".format(address))


def eval_range(address, length):
    start = eval_address(address)
    try:
        end = start + util.parse_and_eval(length)
    except Exception as e:
        raise RuntimeError("Cannot convert '{}' to length".format(length))
    return start, end


def putmem(address, length, pages=True, display_result=True):
    start, end = eval_range(address, length)
    return put_bytes(start, end, pages, display_result)


def ghidra_trace_putmem(items):
    """
    Record the given block of memory into the Ghidra trace.
    """

    items = items.split(" ")
    address = items[0]
    length = items[1]
    pages = items[2] if len(items) > 2 else True

    STATE.require_tx()
    return putmem(address, length, pages, True)


def ghidra_trace_putval(items):
    """
    Record the given value into the Ghidra trace, if it's in memory.
    """

    items = items.split(" ")
    value = items[0]
    pages = items[1] if len(items) > 1 else True

    STATE.require_tx()
    try:
        start = util.parse_and_eval(value)
    except e:
        raise RuntimeError("Value '{}' has no address".format(value))
    end = start + int(start.GetType().GetByteSize())
    return put_bytes(start, end, pages, True)


def ghidra_trace_putmem_state(items):
    """
    Set the state of the given range of memory in the Ghidra trace.
    """

    items = items.split(" ")
    address = items[0]
    length = items[1]
    state = items[2]

    STATE.require_tx()
    STATE.trace.validate_state(state)
    start, end = eval_range(address, length)
    nproc = util.selected_process()
    base, addr = STATE.trace.memory_mapper.map(nproc, start)
    if base != addr.space:
        trace.create_overlay_space(base, addr.space)
    STATE.trace.set_memory_state(addr.extend(end - start), state)


def ghidra_trace_delmem(items):
    """
    Delete the given range of memory from the Ghidra trace.

    Why would you do this? Keep in mind putmem quantizes to full pages by
    default, usually to take advantage of spatial locality. This command does
    not quantize. You must do that yourself, if necessary.
    """

    items = items.split(" ")
    address = items[0]
    length = items[1]

    STATE.require_tx()
    start, end = eval_range(address, length)
    nproc = util.selected_process()
    base, addr = STATE.trace.memory_mapper.map(nproc, start)
    # Do not create the space. We're deleting stuff.
    STATE.trace.delete_bytes(addr.extend(end - start))


def putreg():
    nproc = util.selected_process()
    if nproc < 0:
        return
    nthrd = util.selected_thread()
    space = REGS_PATTERN.format(procnum=nproc, tnum=nthrd)
    STATE.trace.create_overlay_space('register', space)
    robj = STATE.trace.create_object(space)
    robj.insert()
    mapper = STATE.trace.register_mapper
    values = []
    regs = dbg().get_context_x86_64()
    keys = ["seg_cs", "seg_ds", "seg_es", "seg_fs", "seg_gs", "seg_ss", "rflags",
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "rip",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    vals = [regs.seg_cs, regs.seg_ds, regs.seg_es, regs.seg_fs, regs.seg_gs,
            regs.seg_ss, regs.eflags, regs.rax, regs.rbx, regs.rcx, regs.rdx,
            regs.rsi, regs.rdi, regs.rsp, regs.rbp, regs.rip,
            regs.r8, regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14,
            regs.r15]
    for i in range(0, len(keys)):
        name = keys[i]
        value = vals[i]
        try:
            values.append(mapper.map_value(nproc, name, value))
            robj.set_value(name, hex(value))
        except Exception:
            pass
    return {'missing': STATE.trace.put_registers(space, values)}


def ghidra_trace_putreg():
    """
    Record the given register group for the current frame into the Ghidra trace.

    If no group is specified, 'all' is assumed.
    """

    STATE.require_tx()
    putreg()


def ghidra_trace_delreg(group='all'):
    """
    Delete the given register group for the curent frame from the Ghidra trace.

    Why would you do this? If no group is specified, 'all' is assumed.
    """

    STATE.require_tx()
    nproc = util.selected_process()
    nthrd = util.selected_thread()
    space = REGS_PATTERN.format(procnum=nproc, tnum=nthrd)
    mapper = STATE.trace.register_mapper
    names = []
    names.append(mapper.map_name(nproc, group))
    return STATE.trace.delete_registers(space, names)


def ghidra_trace_create_obj(path=None):
    """
    Create an object in the Ghidra trace.

    The new object is in a detached state, so it may not be immediately
    recognized by the Debugger GUI. Use 'ghidra_trace_insert-obj' to finish the
    object, after all its required attributes are set.
    """

    STATE.require_tx()
    obj = STATE.trace.create_object(path)
    obj.insert()
    print("Created object: id={}, path='{}'\n".format(obj.id, obj.path))
    return {'id': obj.id, 'path': obj.path}


def ghidra_trace_insert_obj(path):
    """
    Insert an object into the Ghidra trace.
    """

    # NOTE: id parameter is probably not necessary, since this command is for
    # humans.
    STATE.require_tx()
    span = STATE.trace.proxy_object_path(path).insert()
    print("Inserted object: lifespan={}\n".format(span))
    return {'lifespan': span}


def ghidra_trace_remove_obj(path):
    """
    Remove an object from the Ghidra trace.

    This does not delete the object. It just removes it from the tree for the
    current snap and onwards.
    """

    STATE.require_tx()
    STATE.trace.proxy_object_path(path).remove()


def to_bytes(value):
    return bytes(ord(value[i]) if type(value[i]) == str else int(value[i]) for i in range(0, len(value)))


def to_string(value, encoding):
    b = bytes(ord(value[i]) if type(value[i]) == str else int(
        value[i]) for i in range(0, len(value)))
    return str(b, encoding)


def to_bool_list(value):
    return [bool(value[i]) for i in range(0, len(value))]


def to_int_list(value):
    return [ord(value[i]) if type(value[i]) == str else int(value[i]) for i in range(0, len(value))]


def to_short_list(value):
    return [ord(value[i]) if type(value[i]) == str else int(value[i]) for i in range(0, len(value))]


def to_string_list(value, encoding):
    return [to_string(value[i], encoding) for i in range(0, len(value))]


def eval_value(value, schema=None):
    if schema == sch.CHAR or schema == sch.BYTE or schema == sch.SHORT or schema == sch.INT or schema == sch.LONG or schema == None:
        value = util.get_eval(value)
        return value, schema
    if schema == sch.ADDRESS:
        value = util.get_eval(value)
        nproc = util.selected_process()
        base, addr = STATE.trace.memory_mapper.map(nproc, value)
        return (base, addr), sch.ADDRESS
    if type(value) != str:
        value = eval("{}".format(value))
    if schema == sch.BOOL_ARR:
        return to_bool_list(value), schema
    if schema == sch.BYTE_ARR:
        return to_bytes(value), schema
    if schema == sch.SHORT_ARR:
        return to_short_list(value), schema
    if schema == sch.INT_ARR:
        return to_int_list(value), schema
    if schema == sch.LONG_ARR:
        return to_int_list(value), schema
    if schema == sch.STRING_ARR:
        return to_string_list(value, 'utf-8'), schema
    if schema == sch.CHAR_ARR:
        return to_string(value, 'utf-8'), sch.CHAR_ARR
    if schema == sch.STRING:
        return to_string(value, 'utf-8'), sch.STRING

    return value, schema


def ghidra_trace_set_value(path: str, key: str, value, schema=None):
    """
    Set a value (attribute or element) in the Ghidra trace's object tree.

    A void value implies removal. 
    NOTE: The type of an expression may be subject to the dbgeng's current 
    language. which current defaults to DEBUG_EXPR_CPLUSPLUS (vs DEBUG_EXPR_MASM). 
    For most non-primitive cases, we are punting to the Python API.
    """
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


def ghidra_trace_retain_values(path: str, keys: str):
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

    keys = keys.split(" ")

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


def ghidra_trace_get_obj(path):
    """
    Get an object descriptor by its canonical path.

    This isn't the most informative, but it will at least confirm whether an
    object exists and provide its id.
    """

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
            self.contents[i] if self.is_last else self.contents[i].ljust(self.width), end='')


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


def ghidra_trace_get_values(pattern):
    """
    List all values matching a given path pattern.
    """

    trace = STATE.require_trace()
    values = trace.get_values(pattern)
    print_values(values)
    return values


def ghidra_trace_get_values_rng(items):
    """
    List all values intersecting a given address range.
    """

    items = items.split(" ")
    address = items[0]
    length = items[1]

    trace = STATE.require_trace()
    start, end = eval_range(address, length)
    nproc = util.selected_process()
    base, addr = trace.memory_mapper.map(nproc, start)
    # Do not create the space. We're querying. No tx.
    values = trace.get_values_intersecting(addr.extend(end - start))
    print_values(values)
    return values


def activate(path=None):
    trace = STATE.require_trace()
    if path is None:
        nproc = util.selected_process()
        if nproc is None:
            path = PROCESSES_PATH
        else:
            nthrd = util.selected_thread()
            if nthrd is None:
                path = PROCESS_PATTERN.format(procnum=nproc)
            else:
                path = THREAD_PATTERN.format(procnum=nproc, tnum=nthrd)
    trace.proxy_object_path(path).activate()


def ghidra_trace_activate(path=None):
    """
    Activate an object in Ghidra's GUI.

    This has no effect if the current trace is not current in Ghidra. If path is
    omitted, this will activate the current frame.
    """

    activate(path)


def ghidra_trace_disassemble(address):
    """
    Disassemble starting at the given seed.

    Disassembly proceeds linearly and terminates at the first branch or unknown
    memory encountered.
    """

    STATE.require_tx()
    start = eval_address(address)
    nproc = util.selected_process()
    base, addr = STATE.trace.memory_mapper.map(nproc, start)
    if base != addr.space:
        trace.create_overlay_space(base, addr.space)

    length = STATE.trace.disassemble(addr)
    print("Disassembled {} bytes\n".format(length))
    return {'length': length}


def compute_proc_state(nproc=None):
    return 'STOPPED'


def put_processes(running=False):
    radix = util.get_convenience_variable('output-radix')
    if radix == 'auto':
        radix = 16
    keys = []
    for i, p in enumerate(util.process_list(running)):
        ipath = PROCESS_PATTERN.format(procnum=i)
        keys.append(PROCESS_KEY_PATTERN.format(procnum=i))
        procobj = STATE.trace.create_object(ipath)

        istate = compute_proc_state(p)
        procobj.set_value('State', istate)
        if running == False:
            procobj.set_value('PID', p)
            pidstr = ('0x{:x}' if radix ==
                      16 else '0{:o}' if radix == 8 else '{}').format(p)
            procobj.set_value('_display', pidstr)
            #procobj.set_value('Name', str(p[1]))
            procobj.set_value('PEB', hex(util.eng.get_peb_address()))
        procobj.insert()
    STATE.trace.proxy_object_path(PROCESSES_PATH).retain_values(keys)


def put_state(event_process):
    STATE.require_no_tx()
    STATE.tx = STATE.require_trace().start_tx("state", undoable=False)
    ipath = PROCESS_PATTERN.format(procnum=event_process)
    procobj = STATE.trace.create_object(ipath)
    state = compute_proc_state(event_process)
    procobj.set_value('State', state)
    procobj.insert()
    tnum = util.selected_thread()
    if tnum is not None:
        ipath = THREAD_PATTERN.format(procnum=event_process, tnum=tnum)
        threadobj = STATE.trace.create_object(ipath)
        threadobj.set_value('State', state)
        threadobj.insert()
    STATE.require_tx().commit()
    STATE.reset_tx()


def ghidra_trace_put_processes():
    """
    Put the list of processes into the trace's Processes list.
    """

    STATE.require_tx()
    with STATE.client.batch() as b:
        put_processes()


def put_available():
    radix = util.get_convenience_variable('output-radix')
    keys = []
    result = dbg().cmd(".tlist")
    lines = result.split("\n")
    for i in lines:
        i = i.strip()
        if i == "":
            continue
        if i.startswith("0n") is False:
            continue
        items = i.strip().split(" ")
        id = items[0][2:]
        name = items[1]
        ppath = AVAILABLE_PATTERN.format(pid=id)
        procobj = STATE.trace.create_object(ppath)
        keys.append(AVAILABLE_KEY_PATTERN.format(pid=id))
        pidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(id)
        procobj.set_value('PID', id)
        procobj.set_value('Name', name)
        procobj.set_value('_display', '{} {}'.format(pidstr, name))
        procobj.insert()
    STATE.trace.proxy_object_path(AVAILABLES_PATH).retain_values(keys)


def ghidra_trace_put_available():
    """
    Put the list of available processes into the trace's Available list.
    """

    STATE.require_tx()
    with STATE.client.batch() as b:
        put_available()


def put_single_breakpoint(bp, ibobj, nproc, ikeys):
    mapper = STATE.trace.memory_mapper
    bpath = PROC_BREAK_PATTERN.format(procnum=nproc, breaknum=bp.id)
    brkobj = STATE.trace.create_object(bpath)
    status = True
    address = bp.addr
    expr = bp.expr
    offset = "%016x" % address

    prot = bp.flags
    width = bp.size
    prot = {4: 'HW_EXECUTE', 3: 'READ', 2: 'WRITE'}[prot]

    if address is not None:  # Implies execution break
        base, addr = mapper.map(nproc, address)
        if base != addr.space:
            STATE.trace.create_overlay_space(base, addr.space)
        brkobj.set_value('Range', addr.extend(1))
    elif expr is not None:  # Implies watchpoint
        try:
            address = int(util.parse_and_eval('&({})'.format(expr)))
            base, addr = mapper.map(inf, address)
            if base != addr.space:
                STATE.trace.create_overlay_space(base, addr.space)
            brkobj.set_value('Range', addr.extend(width))
        except Exception as e:
            print("Error: Could not get range for breakpoint: {}\n".format(e))
        else:  # I guess it's a catchpoint
            pass

    brkobj.set_value('Expression', expr)
    brkobj.set_value('Range', addr.extend(1))
    brkobj.set_value('Kinds', prot)
    brkobj.set_value('Enabled', status)
    brkobj.set_value('Flags', prot)
    brkobj.insert()

    k = PROC_BREAK_KEY_PATTERN.format(breaknum=bp.id)
    ikeys.append(k)


def put_breakpoints():
    target = util.get_target()
    nproc = util.selected_process()
    ibpath = PROC_BREAKS_PATTERN.format(procnum=nproc)
    ibobj = STATE.trace.create_object(ibpath)
    keys = []
    ikeys = []
    #ids = [bpid for bpid in util.breakpoints]
    for bp in util.breakpoints:
        keys.append(PROC_BREAK_KEY_PATTERN.format(breaknum=bp.id))
        put_single_breakpoint(bp, ibobj, nproc, ikeys)
    ibobj.insert()
    STATE.trace.proxy_object_path(PROC_BREAKS_PATTERN).retain_values(keys)
    ibobj.retain_values(ikeys)


def ghidra_trace_put_breakpoints():
    """
    Put the current process's breakpoints into the trace.
    """

    STATE.require_tx()
    with STATE.client.batch() as b:
        put_breakpoints()


def put_environment():
    epath = ENV_PATTERN.format(procnum=util.selected_process())
    envobj = STATE.trace.create_object(epath)
    envobj.set_value('Debugger', 'pyttd')
    envobj.set_value('Arch', arch.get_arch())
    envobj.set_value('OS', arch.get_osabi())
    envobj.set_value('Endian', arch.get_endian())
    envobj.insert()


def ghidra_trace_put_environment():
    """
    Put some environment indicators into the Ghidra trace
    """

    STATE.require_tx()
    with STATE.client.batch() as b:
        put_environment()


def put_regions():
    nproc = util.selected_process()
    try:
        modules = util.module_list()
    except Exception:
        modules = []
    if len(modules) == 0 and util.selected_thread() != None:
        modules = [util.REGION_INFO_READER.full_mem()]
    mapper = STATE.trace.memory_mapper
    keys = []
    for m in modules:
        rpath = REGION_PATTERN.format(procnum=nproc, start=m.base_addr)
        keys.append(REGION_KEY_PATTERN.format(start=m.base_addr))
        regobj = STATE.trace.create_object(rpath)
        start_base, start_addr = mapper.map(nproc, m.base_addr)
        if start_base != start_addr.space:
            STATE.trace.create_overlay_space(start_base, start_addr.space)
        regobj.set_value('Range', start_addr.extend(m.image_size))
        regobj.set_value('_readable', True)
        regobj.set_value('_writable', False)
        regobj.set_value('_executable', False)
        regobj.insert()
    STATE.trace.proxy_object_path(
        MEMORY_PATTERN.format(procnum=nproc)).retain_values(keys)


def ghidra_trace_put_regions():
    """
    Read the memory map, if applicable, and write to the trace's Regions
    """

    STATE.require_tx()
    with STATE.client.batch() as b:
        put_regions()


def put_modules():
    target = util.get_target()
    nproc = util.selected_process()
    modules = util.module_list()
    keys = []
    for m in modules:
        mobj = get_module(keys, nproc, m.path, m.base_addr, m.image_size)
        lspan = Lifespan(util.starts[m.base_addr], util.stops[m.base_addr])
        mobj.insert(span=lspan)
    # STATE.trace.proxy_object_path(MODULES_PATTERN.format(
    #    procnum=nproc)).retain_values(keys)


def get_module(keys, nproc: int, path, base, size):
    split = path.split("\\")
    name = split[len(split)-1]
    hbase = hex(base)
    #flags = m[1].Flags
    mpath = MODULE_PATTERN.format(procnum=nproc, modpath=hbase)
    modobj = STATE.trace.create_object(mpath)
    keys.append(MODULE_KEY_PATTERN.format(modpath=hbase))
    mapper = STATE.trace.memory_mapper
    base_base, base_addr = mapper.map(nproc, base)
    if base_base != base_addr.space:
        STATE.trace.create_overlay_space(base_base, base_addr.space)
    modobj.set_value('Range', base_addr.extend(size))
    modobj.set_value('Name', name)
    modobj.set_value('Path', path)
    return modobj


def ghidra_trace_put_modules():
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


def compute_thread_display(tidstr):
    return '[{}]'.format(tidstr)


def put_threads(running=False):
    radix = util.get_convenience_variable('output-radix')
    if radix == 'auto':
        radix = 16
    nproc = util.selected_process()
    if nproc == None:
        return
    keys = []
    for t in util.thread_list():
        tobj = get_thread(keys, radix, nproc, t.threadid)
        lspan = Lifespan(util.starts[t.threadid], util.stops[t.threadid])
        tobj.insert(span=lspan)
    # STATE.trace.proxy_object_path(
    #    THREADS_PATTERN.format(procnum=nproc)).retain_values(keys)


def get_thread(keys, radix, pid: int, tid: int):
    tpath = THREAD_PATTERN.format(procnum=pid, tnum=tid)
    tobj = STATE.trace.create_object(tpath)
    keys.append(THREAD_KEY_PATTERN.format(tnum=tid))
    tobj.set_value('TID', tid, span=Lifespan(0))
    tidstr = ('0x{:x}' if radix == 16 else '0{:o}' if radix ==
              8 else '{}').format(tid)
    tobj.set_value('_short_display', '[{}:{}]'.format(
        pid, tidstr), span=Lifespan(0))
    tobj.set_value('_display', compute_thread_display(
        tidstr), span=Lifespan(0))
    return tobj


def put_event_thread(nthrd=None):
    nproc = util.selected_process()
    # Assumption: Event thread is selected by pydbg upon stopping
    if nthrd is None:
        nthrd = util.selected_thread()
    if nthrd != None:
        tpath = THREAD_PATTERN.format(procnum=nproc, tnum=nthrd)
        tobj = STATE.trace.proxy_object_path(tpath)
    else:
        tobj = None
    STATE.trace.proxy_object_path('').set_value('_event_thread', tobj)


def ghidra_trace_put_threads():
    """
    Put the current process's threads into the Ghidra trace
    """

    STATE.require_tx()
    with STATE.client.batch() as b:
        put_threads()


def put_frames():
    nproc = util.selected_process()
    mapper = STATE.trace.memory_mapper
    nthrd = util.selected_thread()
    if nthrd is None:
        return
    keys = []
    # f : _DEBUG_STACK_FRAME
    for f in dbg().backtrace_list():
        fpath = FRAME_PATTERN.format(
            procnum=nproc, tnum=nthrd, level=f.FrameNumber)
        fobj = STATE.trace.create_object(fpath)
        keys.append(FRAME_KEY_PATTERN.format(level=f.FrameNumber))
        base, offset_inst = mapper.map(nproc, f.InstructionOffset)
        if base != offset_inst.space:
            STATE.trace.create_overlay_space(base, offset_inst.space)
        base, offset_stack = mapper.map(nproc, f.StackOffset)
        if base != offset_stack.space:
            STATE.trace.create_overlay_space(base, offset_stack.space)
        base, offset_ret = mapper.map(nproc, f.ReturnOffset)
        if base != offset_ret.space:
            STATE.trace.create_overlay_space(base, offset_ret.space)
        base, offset_frame = mapper.map(nproc, f.FrameOffset)
        if base != offset_frame.space:
            STATE.trace.create_overlay_space(base, offset_frame.space)
        fobj.set_value('Instruction Offset', offset_inst)
        fobj.set_value('Stack Offset', offset_stack)
        fobj.set_value('Return Offset', offset_ret)
        fobj.set_value('Frame Offset', offset_frame)
        fobj.set_value('_display', "#{} {}".format(
            f.FrameNumber, offset_inst.offset))
        fobj.insert()
    STATE.trace.proxy_object_path(STACK_PATTERN.format(
        procnum=nproc, tnum=nthrd)).retain_values(keys)


def ghidra_trace_put_frames():
    """
    Put the current thread's frames into the Ghidra trace
    """

    STATE.require_tx()
    with STATE.client.batch() as b:
        put_frames()


def ghidra_trace_put_all():
    """
    Put everything currently selected into the Ghidra trace
    """

    STATE.require_tx()
    with STATE.client.batch() as b:
        # put_available()
        put_processes()
        put_environment()
        put_regions()
        put_modules()
        put_threads()
        # put_frames()
        put_breakpoints()
        # put_available()
        ghidra_trace_putreg()
        ghidra_trace_putmem("$pc 1")
        ghidra_trace_putmem("$sp 1")


def ghidra_trace_install_hooks():
    """
    Install hooks to trace in Ghidra
    """

    hooks.install_hooks()


def ghidra_trace_remove_hooks():
    """
    Remove hooks to trace in Ghidra

    Using this directly is not recommended, unless it seems the hooks are
    preventing pydbg or other extensions from operating. Removing hooks will break
    trace synchronization until they are replaced.
    """

    hooks.remove_hooks()


def ghidra_trace_sync_enable():
    """
    Synchronize the current process with the Ghidra trace

    This will automatically install hooks if necessary. The goal is to record
    the current frame, thread, and process into the trace immediately, and then
    to append the trace upon stopping and/or selecting new frames. This action
    is effective only for the current process. This command must be executed
    for each individual process you'd like to synchronize. In older versions of
    pydbg, certain events cannot be hooked. In that case, you may need to execute
    certain "trace put" commands manually, or go without.

    This will have no effect unless or until you start a trace.
    """

    hooks.install_hooks()
    hooks.enable_current_process()
    put_state(0)


def ghidra_trace_sync_disable():
    """
    Cease synchronizing the current process with the Ghidra trace

    This is the opposite of 'ghidra_trace_sync-disable', except it will not
    automatically remove hooks.
    """

    hooks.disable_current_process()


def ghidra_util_wait_stopped(timeout=1):
    """
    Spin wait until the selected thread is stopped.
    """

    start = time.time()
    t = util.selected_thread()
    if t is None:
        return
    while not t.IsStopped() and not t.IsSuspended():
        t = util.selected_thread()  # I suppose it could change
        time.sleep(0.1)
        if time.time() - start > timeout:
            raise RuntimeError('Timed out waiting for thread to stop')


def dbg():
    return util.get_debugger()


SHOULD_WAIT = ['GO', 'STEP_BRANCH', 'STEP_INTO', 'STEP_OVER']


def repl():
    print("This is the dbgeng.dll (WinDbg) REPL. To drop to Python3, press Ctrl-C.")
    while True:
        # TODO: Implement prompt retrieval in PR to pybag?
        print('dbg> ', end='')
        try:
            cmd = input().strip()
            if not cmd:
                continue
            dbg().cmd(cmd, quiet=True)
            stat = dbg().exec_status()
            if stat != 'BREAK':
                dbg().wait()
            else:
                pass
                # dbg().dispatch_events()
        except KeyboardInterrupt as e:
            print("")
            print("You have left the dbgeng REPL and are now at the Python3 interpreter.")
            print("use repl() to re-enter.")
            return
        except:
            # Assume cmd() has already output the error
            pass
