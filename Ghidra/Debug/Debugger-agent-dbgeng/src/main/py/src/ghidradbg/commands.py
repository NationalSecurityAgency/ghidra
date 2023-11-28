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
from ghidratrace.client import Client, Address, AddressRange, TraceObject

from pybag import pydbg, userdbg, kerneldbg
from pybag.dbgeng import core as DbgEng
from pybag.dbgeng import exception

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

# TODO: Symbols

class ErrorWithCode(Exception):
    def __init__(self,code):
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
        STATE.client = Client(c, methods.REGISTRY)
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
        root = STATE.trace.create_root_object(schema_xml, 'Session')
        root.set_value('_display', 'pydbg(dbgeng) ' + util.DBG_VERSION.full)
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

    util.base = userdbg.UserDbg()
    if command != None:
        if timeout != None:
            util.base._client.CreateProcess(command, DbgEng.DEBUG_PROCESS)
            if initial_break:
                util.base._control.AddEngineOptions(DbgEng.DEBUG_ENGINITIAL_BREAK)
            util.base.wait(timeout)
        else:
            util.base.create(command, initial_break)
    if start_trace:
        ghidra_trace_start(command)


def ghidra_trace_kill():
    """
    Kill a session.
    """

    dbg()._client.TerminateCurrentProcess()


def ghidra_trace_info():
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


def ghidra_trace_new_snap(description=None):
    """
    Create a new snapshot

    Subsequent modifications to machine state will affect the new snapshot.
    """

    description = str(description)
    STATE.require_tx()
    return {'snap': STATE.require_trace().snapshot(description)}


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
    buf = dbg().read(start, end - start)
    
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
    regs = dbg().reg
    for i in range(0, len(regs)):
        name = regs._reg.GetDescription(i)[0]
        value = regs._get_register_by_index(i)
        try:
            values.append(mapper.map_value(nproc, name, value))
            robj.set_value(name, value)
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
    regs = dbg().reg
    for i in range(0, len(regs)):
        name = regs._reg.GetDescription(i)[0]
        names.append(mapper.map_name(nproc, name))
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
    return bytes(ord(value[i]) if type(value[i]) == str else int(value[i]) for i in range(0,len(value)))


def to_string(value, encoding):
    b = bytes(ord(value[i]) if type(value[i]) == str else int(value[i]) for i in range(0,len(value)))
    return str(b, encoding)


def to_bool_list(value):
    return [bool(value[i]) for i in range(0,len(value))]


def to_int_list(value):
    return [ord(value[i]) if type(value[i]) == str else int(value[i]) for i in range(0,len(value))]


def to_short_list(value):
    return [ord(value[i]) if type(value[i]) == str else int(value[i]) for i in range(0,len(value))]


def to_string_list(value, encoding):
    return [to_string(value[i], encoding) for i in range(0,len(value))]


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
    status = dbg()._control.GetExecutionStatus()
    if status == DbgEng.DEBUG_STATUS_BREAK:  
        return 'STOPPED'
    return 'RUNNING'


def put_processes(running=False):
    radix = util.get_convenience_variable('output-radix')
    if radix == 'auto':
        radix = 16
    keys = []
    for i, p in enumerate(util.process_list(running)):
        ipath = PROCESS_PATTERN.format(procnum=i)
        keys.append(PROCESS_KEY_PATTERN.format(procnum=i))
        procobj = STATE.trace.create_object(ipath)

        istate = compute_proc_state(i)
        procobj.set_value('_state', istate)
        if running == False:
            procobj.set_value('_pid', p[0])
            pidstr = ('0x{:x}' if radix == 16 else '0{:o}' if radix == 8 else '{}').format(p[0])
            procobj.set_value('_display', pidstr)
            procobj.set_value('Name', str(p[1]))
            procobj.set_value('PEB', hex(p[2]))
        procobj.insert()
    STATE.trace.proxy_object_path(PROCESSES_PATH).retain_values(keys)

def put_state(event_process):
    STATE.require_no_tx()
    STATE.tx = STATE.require_trace().start_tx("state", undoable=False)
    ipath = PROCESS_PATTERN.format(procnum=event_process)
    procobj = STATE.trace.create_object(ipath)
    state = compute_proc_state(event_process)
    procobj.set_value('_state', state)
    procobj.insert()
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
    result =  dbg().cmd(".tlist")
    lines = result.split("\n")
    for i in lines:
        i = i.strip();
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
        procobj.set_value('_pid', id)
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
    bpath = PROC_BREAK_PATTERN.format(procnum=nproc, breaknum=bp.GetId())
    brkobj = STATE.trace.create_object(bpath)
    if bp.GetFlags() & DbgEng.DEBUG_BREAKPOINT_ENABLED:
        status = True
    else:
        status = False
    if bp.GetFlags() & DbgEng.DEBUG_BREAKPOINT_DEFERRED:
        offset = "[Deferred]"
        expr = bp.GetOffsetExpression()
    else:
        address = bp.GetOffset()
        offset = "%016x" % address
        expr = dbg().get_name_by_offset(address)
    try:
        tid = bp.GetMatchThreadId()
        tid = "%04x" % tid
    except exception.E_NOINTERFACE_Error:
        tid = "****"

    if bp.GetType()[0] == DbgEng.DEBUG_BREAKPOINT_DATA:
        width, prot = bp.GetDataParameters()
        width = str(width)
        prot = {4: 'HW_EXECUTE', 2: 'READ', 1: 'WRITE'}[prot] 
    else:
        width = ' '
        prot  = 'SW_EXECUTE'

    if address is not None:  # Implies execution break
        base, addr = mapper.map(nproc, address)
        if base != addr.space:
            STATE.trace.create_overlay_space(base, addr.space)
        brkobj.set_value('_range', addr.extend(1))
    elif expr is not None:  # Implies watchpoint
        try:
            address = int(util.parse_and_eval('&({})'.format(expr)))
            base, addr = mapper.map(inf, address)
            if base != addr.space:
                STATE.trace.create_overlay_space(base, addr.space)
            brkobj.set_value('_range', addr.extend(width))
        except Exception as e:
            print("Error: Could not get range for breakpoint: {}\n".format(e))
        else:  # I guess it's a catchpoint
            pass

    brkobj.set_value('_expression', expr)
    brkobj.set_value('_range', addr.extend(1))
    brkobj.set_value('_kinds', prot)
    brkobj.set_value('Pass Count', bp.GetPassCount())
    brkobj.set_value('Current Pass Count', bp.GetCurrentPassCount())
    brkobj.set_value('Enabled', status)
    brkobj.set_value('Flags', bp.GetFlags())
    if tid != None:
        brkobj.set_value('Match TID', tid)
    brkobj.set_value('Command', bp.GetCommand())
    brkobj.insert()

    k = PROC_BREAK_KEY_PATTERN.format(breaknum=bp.GetId())
    ikeys.append(k)



def put_breakpoints():
    target = util.get_target()
    nproc = util.selected_process()
    ibpath = PROC_BREAKS_PATTERN.format(procnum=nproc)
    ibobj = STATE.trace.create_object(ibpath)
    keys = []
    ikeys = []
    ids = [bpid for bpid in dbg().breakpoints]
    for bpid in ids:
        try:
            bp = dbg()._control.GetBreakpointById(bpid)
        except exception.E_NOINTERFACE_Error:
            dbg().breakpoints._remove_stale(bpid)
            continue
        keys.append(PROC_BREAK_KEY_PATTERN.format(breaknum=bpid))
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
    envobj.set_value('_debugger', 'pydbg')
    envobj.set_value('_arch', arch.get_arch())
    envobj.set_value('_os', arch.get_osabi())
    envobj.set_value('_endian', arch.get_endian())
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
        regions = dbg().memory_list()
    except Exception:
        regions = []
    if len(regions) == 0 and util.selected_thread() != None:
        regions = [util.REGION_INFO_READER.full_mem()]
    mapper = STATE.trace.memory_mapper
    keys = []
    # r : MEMORY_BASIC_INFORMATION64
    for r in regions:
        rpath = REGION_PATTERN.format(procnum=nproc, start=r.BaseAddress)
        keys.append(REGION_KEY_PATTERN.format(start=r.BaseAddress))
        regobj = STATE.trace.create_object(rpath)
        start_base, start_addr = mapper.map(nproc, r.BaseAddress)
        if start_base != start_addr.space:
            STATE.trace.create_overlay_space(start_base, start_addr.space)
        regobj.set_value('_range', start_addr.extend(r.RegionSize))
        regobj.set_value('_readable', r.Protect == None or r.Protect&0x66 != 0)
        regobj.set_value('_writable', r.Protect == None or r.Protect&0xCC != 0)
        regobj.set_value('_executable', r.Protect == None or r.Protect&0xF0 != 0)
        regobj.set_value('_offset', hex(r.BaseAddress))
        regobj.set_value('Base', hex(r.BaseAddress))
        regobj.set_value('Size', hex(r.RegionSize))
        regobj.set_value('AllocationBase', hex(r.AllocationBase))
        regobj.set_value('Protect', hex(r.Protect))
        regobj.set_value('Type', hex(r.Type))
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
    modules = dbg().module_list()
    mapper = STATE.trace.memory_mapper
    mod_keys = []
    for m in modules:
        name = m[0][0]
        # m[1] : _DEBUG_MODULE_PARAMETERS
        base = m[1].Base
        hbase = hex(base)
        size = m[1].Size
        flags = m[1].Flags
        mpath = MODULE_PATTERN.format(procnum=nproc, modpath=hbase)
        modobj = STATE.trace.create_object(mpath)
        mod_keys.append(MODULE_KEY_PATTERN.format(modpath=hbase))
        modobj.set_value('_module_name', name)
        base_base, base_addr = mapper.map(nproc, base)
        if base_base != base_addr.space:
            STATE.trace.create_overlay_space(base_base, base_addr.space)
        modobj.set_value('_range', base_addr.extend(size))
        modobj.set_value('Name', name)
        modobj.set_value('Base', hbase)
        modobj.set_value('Size', hex(size))
        modobj.set_value('Flags', hex(size))
        modobj.insert()
 
        # TODO:  would be nice to list sections, but currently we have no API for 
        #     it as far as I am aware
        # sec_keys = []
        # STATE.trace.proxy_object_path(
        #     mpath + SECTIONS_ADD_PATTERN).retain_values(sec_keys)
        
    STATE.trace.proxy_object_path(MODULES_PATTERN.format(
        procnum=nproc)).retain_values(mod_keys)


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


def convert_tid(t):
    if t[1] == 0:
        return t[2]
    return t[1]


def compute_thread_display(tidstr, t):
    return '[{} {}]'.format(tidstr, t[2])


def put_threads(running=False):
    radix = util.get_convenience_variable('output-radix')
    if radix == 'auto':
        radix = 16
    nproc = util.selected_process()
    if nproc == None:
        return
    keys = []
    for i, t in enumerate(util.thread_list(running)):
        tpath = THREAD_PATTERN.format(procnum=nproc, tnum=i)
        tobj = STATE.trace.create_object(tpath)
        keys.append(THREAD_KEY_PATTERN.format(tnum=i))
        #tobj.set_value('_state', convert_state(t))
        if running == False:
            tobj.set_value('_name', t[2])
            tid = t[0]
            tobj.set_value('_tid', tid)
            tidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(tid)
            tobj.set_value('_short_display', '[{}.{}:{}]'.format(
                nproc, i, tidstr))
            tobj.set_value('_display', compute_thread_display(tidstr, t))
            tobj.set_value('TEB', hex(t[1]))
            tobj.set_value('Name', t[2])
        tobj.insert()
    STATE.trace.proxy_object_path(
        THREADS_PATTERN.format(procnum=nproc)).retain_values(keys)


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
        base, pc = mapper.map(nproc, f.InstructionOffset)
        if base != pc.space:
            STATE.trace.create_overlay_space(base, pc.space)
        fobj.set_value('_pc', pc)
        fobj.set_value('InstructionOffset', hex(f.InstructionOffset))
        fobj.set_value('StackOffset', hex(f.StackOffset))
        fobj.set_value('ReturnOffset', hex(f.ReturnOffset))
        fobj.set_value('FrameOffset', hex(f.FrameOffset))
        fobj.set_value('_display', "#{} {}".format(f.FrameNumber, hex(f.InstructionOffset)))
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
        put_available()
        put_processes()
        put_environment()
        put_regions()
        put_modules()
        put_threads()
        put_frames()
        put_breakpoints()
        put_available()
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
            dbg().cmd(cmd, quiet=False)
            stat = dbg().exec_status()
            if stat != 'BREAK':
                dbg().wait()
            else:
                pass
                #dbg().dispatch_events()
        except KeyboardInterrupt as e:
            print("")
            print("You have left the dbgeng REPL and are now at the Python3 interpreter.")
            print("use repl() to re-enter.")
            return
        except:
            # Assume cmd() has already output the error
            pass
