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

from concurrent.futures import Future
from contextlib import contextmanager
import inspect
import os.path
import re
import socket
import sys
import time
from typing import Any, Dict, Generator, Iterable, List, Optional, Sequence, Tuple, Union

from ghidratrace import sch
from ghidratrace.client import (Client, Address, AddressRange, Lifespan, RegVal,
                                Schedule, Trace, TraceObject, TraceObjectValue,
                                Transaction)
from ghidratrace.display import print_tabular_values, wait

from x64dbg_automate.models import BreakpointType, HardwareBreakpointType, MemoryBreakpointType

from . import util, arch, methods, hooks

STILL_ACTIVE = 259
PAGE_SIZE = 4096

SESSION_PATH = 'Sessions[0]'  # Only ever one, it seems
AVAILABLES_PATH = SESSION_PATH + '.Available'
AVAILABLE_KEY_PATTERN = '[{pid}]'
AVAILABLE_PATTERN = AVAILABLES_PATH + AVAILABLE_KEY_PATTERN
PROCESSES_PATH = SESSION_PATH + '.Processes'
PROCESS_KEY_PATTERN = '[{procnum}]'
PROCESS_PATTERN = PROCESSES_PATH + PROCESS_KEY_PATTERN
PROC_DEBUG_PATTERN = PROCESS_PATTERN + '.Debug'
PROC_SBREAKS_PATTERN = PROC_DEBUG_PATTERN + '.Software Breakpoints'
PROC_HBREAKS_PATTERN = PROC_DEBUG_PATTERN + '.Hardware Breakpoints'
PROC_MBREAKS_PATTERN = PROC_DEBUG_PATTERN + '.Memory Breakpoints'
PROC_BREAK_KEY_PATTERN = '[{breaknum}]'
PROC_SBREAK_PATTERN = PROC_SBREAKS_PATTERN + PROC_BREAK_KEY_PATTERN
PROC_HBREAK_PATTERN = PROC_HBREAKS_PATTERN + PROC_BREAK_KEY_PATTERN
PROC_MBREAK_PATTERN = PROC_MBREAKS_PATTERN + PROC_BREAK_KEY_PATTERN
PROC_EVENTS_PATTERN = PROC_DEBUG_PATTERN + '.Events'
PROC_EVENT_KEY_PATTERN = '[{eventnum}]'
PROC_EVENT_PATTERN = PROC_EVENTS_PATTERN + PROC_EVENT_KEY_PATTERN
PROC_EXCS_PATTERN = PROC_DEBUG_PATTERN + '.Exceptions'
PROC_EXC_KEY_PATTERN = '[{eventnum}]'
PROC_EXC_PATTERN = PROC_EXCS_PATTERN + PROC_EXC_KEY_PATTERN
ENV_PATTERN = PROCESS_PATTERN + '.Environment'
THREADS_PATTERN = PROCESS_PATTERN + '.Threads'
THREAD_KEY_PATTERN = '[{tnum}]'
THREAD_PATTERN = THREADS_PATTERN + THREAD_KEY_PATTERN
STACK_PATTERN = THREAD_PATTERN + '.Stack.Frames'
FRAME_KEY_PATTERN = '[{level}]'
FRAME_PATTERN = STACK_PATTERN + FRAME_KEY_PATTERN
REGS_PATTERN = THREAD_PATTERN + '.Registers'
USER_REGS_PATTERN = THREAD_PATTERN + '.Registers.User'
MEMORY_PATTERN = PROCESS_PATTERN + '.Memory'
REGION_KEY_PATTERN = '[{start:08x}]'
REGION_PATTERN = MEMORY_PATTERN + REGION_KEY_PATTERN
MODULES_PATTERN = PROCESS_PATTERN + '.Modules'
MODULE_KEY_PATTERN = '[{modpath}]'
MODULE_PATTERN = MODULES_PATTERN + MODULE_KEY_PATTERN
SECTIONS_ADD_PATTERN = '.Sections'
SECTION_KEY_PATTERN = '[{secname}]'
SECTION_ADD_PATTERN = SECTIONS_ADD_PATTERN + SECTION_KEY_PATTERN
GENERIC_KEY_PATTERN = '[{key}]'
TTD_PATTERN = 'State.DebuggerVariables.{var}.TTD'


# TODO: Symbols


class ErrorWithCode(Exception):

    def __init__(self, code: int) -> None:
        self.code = code

    def __str__(self) -> str:
        return repr(self.code)


class Extra(object):
    def __init__(self) -> None:
        self.memory_mapper: Optional[arch.DefaultMemoryMapper] = None
        self.register_mapper: Optional[arch.DefaultRegisterMapper] = None

    def require_mm(self) -> arch.DefaultMemoryMapper:
        if self.memory_mapper is None:
            raise RuntimeError("No memory mapper")
        return self.memory_mapper

    def require_rm(self) -> arch.DefaultRegisterMapper:
        if self.register_mapper is None:
            raise RuntimeError("No register mapper")
        return self.register_mapper


class State(object):

    def __init__(self) -> None:
        self.reset_client()

    def require_client(self) -> Client:
        if self.client is None:
            raise RuntimeError("Not connected")
        return self.client

    def require_no_client(self) -> None:
        if self.client != None:
            raise RuntimeError("Already connected")

    def reset_client(self) -> None:
        self.client: Optional[Client] = None
        self.reset_trace()

    def require_trace(self) -> Trace[Extra]:
        if self.trace is None:
            raise RuntimeError("No trace active")
        return self.trace

    def require_no_trace(self) -> None:
        if self.trace != None:
            raise RuntimeError("Trace already started")

    def reset_trace(self) -> None:
        self.trace: Optional[Trace[Extra]] = None
        util.set_convenience_variable('_ghidra_tracing', "false")
        self.reset_tx()

    def require_tx(self) -> Tuple[Trace, Transaction]:
        trace = self.require_trace()
        if self.tx is None:
            raise RuntimeError("No transaction")
        return trace, self.tx

    def require_no_tx(self) -> None:
        if self.tx != None:
            raise RuntimeError("Transaction already started")

    def reset_tx(self) -> None:
        self.tx: Optional[Transaction] = None


STATE = State()


def ghidra_trace_connect(address: Optional[str] = None) -> None:
    """Connect Python to Ghidra for tracing.

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
        STATE.client = Client(c, "x64dbg", methods.REGISTRY)
        print(f"Connected to {STATE.client.description} at {address}")
    except ValueError:
        raise RuntimeError("port must be numeric")


def ghidra_trace_listen(address: str = '0.0.0.0:0') -> None:
    """Listen for Ghidra to connect for tracing.

    Takes an optional address for the host and port on which to listen.
    Either the form 'host:port' or just 'port'. If omitted, it will bind
    to an ephemeral port on all interfaces. If only the port is given,
    it will bind to that port on all interfaces. This command will block
    until the connection is established.
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
        print("Listening at {}:{}...".format(host, port))
        c, (chost, cport) = s.accept()
        s.close()
        print("Connection from {}:{}".format(chost, cport))
        STATE.client = Client(c, "x64dbg", methods.REGISTRY)
    except ValueError:
        raise RuntimeError("port must be numeric")


def ghidra_trace_disconnect() -> None:
    """Disconnect Python from Ghidra for tracing."""

    STATE.require_client().close()
    STATE.reset_client()


def compute_name(progname: Optional[str] = None) -> str:
    if progname is None:
        return 'x64dbg/noname'
    return 'x64dbg/' + re.split(r'/|\\', progname)[-1]


def start_trace(name: str) -> None:
    language, compiler = arch.compute_ghidra_lcsp()
    STATE.trace = STATE.require_client().create_trace(
        name, language, compiler, extra=Extra())
    STATE.trace.extra.memory_mapper = arch.compute_memory_mapper(language)
    STATE.trace.extra.register_mapper = arch.compute_register_mapper(language)

    frame = inspect.currentframe()
    if frame is None:
        raise AssertionError("cannot locate schema.xml")
    parent = os.path.dirname(inspect.getfile(frame))
    schema_fn = os.path.join(parent, 'schema.xml')
    with open(schema_fn, 'r') as schema_file:
        schema_xml = schema_file.read()
    with STATE.trace.open_tx("Create Root Object"):
        root = STATE.trace.create_root_object(schema_xml, 'X64DbgRoot')
        root.set_value('_display', util.DBG_VERSION.full +
                       ' via x64dbg_automate')
        STATE.trace.create_object(SESSION_PATH).insert()
    util.set_convenience_variable('_ghidra_tracing', "true")


def ghidra_trace_start(name: Optional[str] = None) -> None:
    """Start a Trace in Ghidra."""

    STATE.require_client()
    name = compute_name(name)
    STATE.require_no_trace()
    start_trace(name)


def ghidra_trace_stop() -> None:
    """Stop the Trace in Ghidra."""

    STATE.require_trace().close()
    STATE.reset_trace()


def ghidra_trace_restart(name: Optional[str] = None) -> None:
    """Restart or start the Trace in Ghidra."""

    STATE.require_client()
    if STATE.trace != None:
        STATE.trace.close()
        STATE.reset_trace()
    name = compute_name(name)
    start_trace(name)


def ghidra_trace_create(command: Optional[str] = None,
                        args: Optional[str] = '.',
                        initdir: Optional[str] = '.',
                        start_trace: bool = True,
                        wait: bool = False) -> None:
    """Create a session."""

    dbg = util.dbg.client
    if command != None:
        dbg.load_executable(command, cmdline=args, current_dir=initdir)
    if wait:
        try:
            dbg.wait_until_debugging()
        except KeyboardInterrupt as ki:
            dbg.interrupt()
    if start_trace:
        ghidra_trace_start(command)


def ghidra_trace_attach(pid: Optional[str] = None, 
                        start_trace: bool = True) -> None:
    """Create a session by attaching."""

    dbg = util.dbg.client
    if pid != None:
        dbg.attach(int(pid, 0))
        try:
            dbg.wait_until_debugging()
        except KeyboardInterrupt as ki:
            dbg.interrupt()
    if start_trace:
        ghidra_trace_start(f"pid_{pid}")


def ghidra_trace_connect_server(options: Union[str, bytes, None] = None) -> None:
    """Connect to a process server session."""

    dbg = util.dbg.client
    if options != None:
        if isinstance(options, str):
            enc_options = options.encode()
        #dbg._client.ConnectProcessServer(enc_options)


def ghidra_trace_open(command: Optional[str] = None,
                      start_trace: bool = True) -> None:
    """Create a session."""

    dbg = util.dbg.client
    if start_trace:
        ghidra_trace_start(command)


def ghidra_trace_kill() -> None:
    """Kill a session."""

    dbg = util.dbg.client
    dbg.unload_executable()


def ghidra_trace_info() -> None:
    """Get info about the Ghidra connection."""

    if STATE.client is None:
        print("Not connected to Ghidra")
        return
    host, port = STATE.client.s.getpeername()
    print(f"Connected to {STATE.client.description} at {host}:{port}")
    if STATE.trace is None:
        print("No trace")
        return
    print("Trace active")


def ghidra_trace_info_lcsp() -> None:
    """Get the selected Ghidra language-compiler-spec pair."""

    language, compiler = arch.compute_ghidra_lcsp()
    print("Selected Ghidra language: {}".format(language))
    print("Selected Ghidra compiler: {}".format(compiler))


def ghidra_trace_txstart(description: str = "tx") -> None:
    """Start a transaction on the trace."""

    STATE.require_no_tx()
    STATE.tx = STATE.require_trace().start_tx(description, undoable=False)


def ghidra_trace_txcommit() -> None:
    """Commit the current transaction."""

    STATE.require_tx()[1].commit()
    STATE.reset_tx()


def ghidra_trace_txabort() -> None:
    """Abort the current transaction.

    Use only in emergencies.
    """

    trace, tx = STATE.require_tx()
    print("Aborting trace transaction!")
    tx.abort()
    STATE.reset_tx()


@contextmanager
def open_tracked_tx(description: str) -> Generator[Transaction, None, None]:
    with STATE.require_trace().open_tx(description) as tx:
        STATE.tx = tx
        yield tx
    STATE.reset_tx()


def ghidra_trace_save() -> None:
    """Save the current trace."""

    STATE.require_trace().save()


def ghidra_trace_new_snap(description: Optional[str] = None,
                          time: Optional[Schedule] = None) -> Dict[str, int]:
    """Create a new snapshot.

    Subsequent modifications to machine state will affect the new
    snapshot.
    """

    description = str(description)
    trace, tx = STATE.require_tx()
    return {'snap': trace.snapshot(description, time=time)}


def quantize_pages(start: int, end: int) -> Tuple[int, int]:
    return (start // PAGE_SIZE * PAGE_SIZE, (end + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE)


def put_bytes(start: int, end: int, pages: bool,
              display_result: bool = False) -> Dict[str, int]:
    # print("PUT BYTES")
    # COLOSSAL HACK, but x32dbg will die if you access a 64-bit value
    bitness = util.dbg.client.debugee_bitness()
    if start > 1<<bitness:
        return {'count': 0}
        
    trace = STATE.require_trace()
    if pages:
        start, end = quantize_pages(start, end)
    if end - start <= 0:
        return {'count': 0}
    try:
        buf = util.dbg.client.read_memory(start, end - start)
    except Exception as e:
        return {'count': -1}

    count: Union[int, Future[int]] = 0
    if buf != None:
        nproc = util.selected_process()
        base, addr = trace.extra.require_mm().map(nproc, start)
        if base != addr.space:
            trace.create_overlay_space(base, addr.space)
        count = trace.put_bytes(addr, buf)
        if display_result:
            if isinstance(count, Future):
                count.add_done_callback(lambda c: print(f"Wrote {c} bytes"))
            else:
                print(f"Wrote {count} bytes")
        if isinstance(count, Future):
            return {'count': -1}
        else:
            return {'count': count}
    return {'count': 0}


def eval_address(address: Union[str, int]) -> int:
    try:
        result = util.parse_and_eval(address)
        if isinstance(result, int):
            return result
        raise ValueError(f"Value '{address}' does not evaluate to an int")
    except Exception:
        raise RuntimeError(f"Cannot convert '{address}' to address")


def eval_range(address: Union[str, int],
               length: Union[str, int]) -> Tuple[int, int]:
    start = eval_address(address)
    try:
        l = util.parse_and_eval(length)
    except Exception as e:
        raise RuntimeError(f"Cannot convert '{length}' to length")
    if not isinstance(l, int):
        raise ValueError(f"Value '{address}' does not evaluate to an int")
    end = start + l
    return start, end


def putmem(address: Union[str, int], length: Union[str, int],
           pages: bool = True, display_result: bool = True) -> Dict[str, int]:
    start, end = eval_range(address, length)
    return put_bytes(start, end, pages, display_result)


def ghidra_trace_putmem(address: Union[str, int], length: Union[str, int],
                        pages: bool = True) -> Dict[str, int]:
    """Record the given block of memory into the Ghidra trace."""

    STATE.require_tx()
    return putmem(address, length, pages, True)


def putmem_state(address: Union[str, int], length: Union[str, int], state: str,
                 pages: bool = True) -> None:
    trace = STATE.require_trace()
    trace.validate_state(state)
    start, end = eval_range(address, length)
    if pages:
        start, end = quantize_pages(start, end)
    nproc = util.selected_process()
    base, addr = trace.extra.require_mm().map(nproc, start)
    if base != addr.space and state != 'unknown':
        trace.create_overlay_space(base, addr.space)
    trace.set_memory_state(addr.extend(end - start), state)


def ghidra_trace_putmem_state(address: Union[str, int], length: Union[str, int],
                              state: str, pages: bool = True) -> None:
    """Set the state of the given range of memory in the Ghidra trace."""

    STATE.require_tx()
    return putmem_state(address, length, state, pages)


def ghidra_trace_delmem(address: Union[str, int],
                        length: Union[str, int]) -> None:
    """Delete the given range of memory from the Ghidra trace.

    Why would you do this? Keep in mind putmem quantizes to full pages
    by default, usually to take advantage of spatial locality. This
    command does not quantize. You must do that yourself, if necessary.
    """

    trace, tx = STATE.require_tx()
    start, end = eval_range(address, length)
    nproc = util.selected_process()
    base, addr = trace.extra.require_mm().map(nproc, start)
    # Do not create the space. We're deleting stuff.
    trace.delete_bytes(addr.extend(end - start))


def putreg() -> Dict[str, List[str]]:
    trace = STATE.require_trace()
    nproc = util.selected_process()
    if nproc is None:
        return {}
    nthrd = util.selected_thread()
    space = REGS_PATTERN.format(procnum=nproc, tnum=nthrd)
    trace.create_overlay_space('register', space)
    robj = trace.create_object(space)
    robj.insert()
    mapper = trace.extra.require_rm()
    values = []
    regs = util.dbg.client.get_regs()
    ctxt = regs.context
    for k in ctxt.model_fields.keys():
        name = k
        try:
            value = getattr(ctxt, k)
        except Exception:
            value = 0
        try:
            if type(value) is int:
                values.append(mapper.map_value(nproc, name, value))
                robj.set_value(name, hex(value))
            if type(value) is bytes:
                value = int.from_bytes(value, "little")
                values.append(mapper.map_value(nproc, name, value))
                robj.set_value(name, hex(value))
        except Exception:
            pass
    missing = trace.put_registers(space, values)
    if isinstance(missing, Future):
        return {'future': []}
    return {'missing': missing}


def ghidra_trace_putreg() -> None:
    """Record the given register group for the current frame into the Ghidra
    trace.

    If no group is specified, 'all' is assumed.
    """

    STATE.require_tx()
    putreg()


def ghidra_trace_delreg(group='all') -> None:
    """Delete the given register group for the curent frame from the Ghidra
    trace.

    Why would you do this? If no group is specified, 'all' is assumed.
    """

    trace, tx = STATE.require_tx()
    nproc = util.selected_process()
    nthrd = util.selected_thread()
    space = REGS_PATTERN.format(procnum=nproc, tnum=nthrd)
    mapper = trace.extra.require_rm()
    names = []
    regs = util.dbg.client.get_regs()
    ctxt = regs.context
    for i in ctxt.model_fields.keys():
        names.append(mapper.map_name(nproc, i))
    trace.delete_registers(space, names)


def ghidra_trace_create_obj(path: str) -> None:
    """Create an object in the Ghidra trace.

    The new object is in a detached state, so it may not be immediately
    recognized by the Debugger GUI. Use 'ghidra_trace_insert-obj' to
    finish the object, after all its required attributes are set.
    """

    trace, tx = STATE.require_tx()
    obj = trace.create_object(path)
    obj.insert()
    print(f"Created object: id={obj.id}, path='{obj.path}'")


def ghidra_trace_insert_obj(path: str) -> None:
    """Insert an object into the Ghidra trace."""

    # NOTE: id parameter is probably not necessary, since this command is for
    # humans.
    trace, tx = STATE.require_tx()
    span = trace.proxy_object_path(path).insert()
    print(f"Inserted object: lifespan={span}")


def ghidra_trace_remove_obj(path: str) -> None:
    """Remove an object from the Ghidra trace.

    This does not delete the object. It just removes it from the tree
    for the current snap and onwards.
    """

    trace, tx = STATE.require_tx()
    trace.proxy_object_path(path).remove()


def to_bytes(value: Sequence) -> bytes:
    return bytes(ord(value[i]) if type(value[i]) == str else int(value[i])
                 for i in range(0, len(value)))


def to_string(value: Sequence, encoding: str) -> str:
    b = to_bytes(value)
    return str(b, encoding)


def to_bool_list(value: Sequence) -> List[bool]:
    return [bool(value[i]) for i in range(0, len(value))]


def to_int_list(value: Sequence) -> List[int]:
    return [ord(value[i]) if type(value[i]) == str else int(value[i])
            for i in range(0, len(value))]


def to_short_list(value: Sequence) -> List[int]:
    return [ord(value[i]) if type(value[i]) == str else int(value[i])
            for i in range(0, len(value))]


def to_string_list(value: Sequence, encoding: str) -> List[str]:
    return [to_string(value[i], encoding) for i in range(0, len(value))]


def eval_value(value: Any, schema: Optional[sch.Schema] = None) -> Tuple[Union[
        bool, int, float, bytes, Tuple[str, Address], List[bool], List[int],
        List[str], str], Optional[sch.Schema]]:
    if (schema == sch.BYTE or schema == sch.SHORT or
            schema == sch.INT or schema == sch.LONG or schema == None):
        value = util.parse_and_eval(value)
        return value, schema
    if schema == sch.CHAR:
        value = util.parse_and_eval(ord(value))
        return value, schema
    if schema == sch.BOOL:
        value = util.parse_and_eval(value)
        return bool(value), schema
    if schema == sch.ADDRESS:
        value = util.parse_and_eval(value)
        nproc = util.selected_process()
        base, addr = STATE.require_trace().extra.require_mm().map(nproc, value)
        return (base, addr), sch.ADDRESS
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
        return to_string(value, 'utf-8'), schema
    if schema == sch.STRING:
        return to_string(value, 'utf-8'), schema

    return value, schema


def ghidra_trace_set_value(path: str, key: str, value: Any,
                           schema: Optional[str] = None) -> None:
    """Set a value (attribute or element) in the Ghidra trace's object tree.

    A void value implies removal.
    NOTE: The type of an expression may be subject to the x64dbg's current
    language, which current defaults to DEBUG_EXPR_CPLUSPLUS (vs DEBUG_EXPR_MASM).
    For most non-primitive cases, we are punting to the Python API.
    """
    real_schema = None if schema is None else sch.Schema(schema)
    trace, tx = STATE.require_tx()
    if real_schema == sch.OBJECT:
        val: Union[bool, int, float, bytes, Tuple[str, Address], List[bool],
                   List[int], List[str], str, TraceObject,
                   Address] = trace.proxy_object_path(value)
    else:
        val, real_schema = eval_value(value, real_schema)
        if real_schema == sch.ADDRESS and isinstance(val, tuple):
            base, addr = val
            val = addr
            if base != addr.space:
                trace.create_overlay_space(base, addr.space)
    trace.proxy_object_path(path).set_value(key, val, real_schema)


def ghidra_trace_retain_values(path: str, keys: str) -> None:
    """Retain only those keys listed, settings all others to null.

    Takes a list of keys to retain. The first argument may optionally be one of
    the following:

        --elements To set all other elements to null (default)
        --attributes To set all other attributes to null
        --both To set all other values (elements and attributes) to null

    If, for some reason, one of the keys to retain would be mistaken for this
    switch, then the switch is required. Only the first argument is taken as the
    switch. All others are taken as keys.
    """

    key_list = keys.split(" ")

    trace, tx = STATE.require_tx()
    kinds = 'elements'
    if key_list[0] == '--elements':
        kinds = 'elements'
        key_list = key_list[1:]
    elif key_list[0] == '--attributes':
        kinds = 'attributes'
        key_list = key_list[1:]
    elif key_list[0] == '--both':
        kinds = 'both'
        key_list = key_list[1:]
    elif key_list[0].startswith('--'):
        raise RuntimeError("Invalid argument: " + key_list[0])
    trace.proxy_object_path(path).retain_values(key_list, kinds=kinds)


def ghidra_trace_get_obj(path: str) -> None:
    """Get an object descriptor by its canonical path.

    This isn't the most informative, but it will at least confirm
    whether an object exists and provide its id.
    """

    trace = STATE.require_trace()
    object = trace.get_object(path)
    print(f"{object.id}\t{object.path}")


def ghidra_trace_get_values(pattern: str) -> None:
    """List all values matching a given path pattern."""

    trace = STATE.require_trace()
    values = wait(trace.get_values(pattern))
    print_tabular_values(values, print)


def ghidra_trace_get_values_rng(address: Union[str, int],
                                length: Union[str, int]) -> None:
    """List all values intersecting a given address range."""

    trace = STATE.require_trace()
    start, end = eval_range(address, length)
    nproc = util.selected_process()
    base, addr = trace.extra.require_mm().map(nproc, start)
    # Do not create the space. We're querying. No tx.
    values = wait(trace.get_values_intersecting(addr.extend(end - start)))
    print_tabular_values(values, print)


def activate(path: Optional[str] = None) -> None:
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
                #frame = util.selected_frame()
                #if frame is None:
                #    path = THREAD_PATTERN.format(procnum=nproc, tnum=nthrd)
                #else:
                #    path = FRAME_PATTERN.format(
                #        procnum=nproc, tnum=nthrd, level=frame)
    trace.proxy_object_path(path).activate()


def ghidra_trace_activate(path: Optional[str] = None) -> None:
    """Activate an object in Ghidra's GUI.

    This has no effect if the current trace is not current in Ghidra. If
    path is omitted, this will activate the current frame.
    """

    activate(path)


def ghidra_trace_disassemble(address: Union[str, int]) -> None:
    """Disassemble starting at the given seed.

    Disassembly proceeds linearly and terminates at the first branch or
    unknown memory encountered.
    """

    trace, tx = STATE.require_tx()
    start = eval_address(address)
    nproc = util.selected_process()
    base, addr = trace.extra.require_mm().map(nproc, start)
    if base != addr.space:
        trace.create_overlay_space(base, addr.space)

    length = trace.disassemble(addr)
    print("Disassembled {} bytes".format(length))


def compute_proc_state(nproc: Optional[int] = None) -> str:
    if nproc is None:
        return 'TERMINATED'
    try:
        if util.dbg.client.is_running():
            return 'RUNNING'
        return 'STOPPED'
    except Exception:
        return 'TERMINATED'


def put_processes(running: bool = False) -> None:
    # NB: This speeds things up, but desirable?
    if running:
        return

    trace = STATE.require_trace()

    keys = []
    # Set running=True to avoid process changes, even while stopped
    for i, p in enumerate(util.process_list0(running=True)):
        pid = p[0]
        ipath = PROCESS_PATTERN.format(procnum=pid)
        keys.append(PROCESS_KEY_PATTERN.format(procnum=pid))
        procobj = trace.create_object(ipath)

        istate = compute_proc_state(i)
        procobj.set_value('State', istate)
        procobj.set_value('PID', pid)
        procobj.set_value('_display', f'{i} {pid}')
        if len(p) > 1:
            procobj.set_value('Name', str(p[1]))
            #procobj.set_value('PEB', hex(int(p[2])))
        procobj.insert()
    trace.proxy_object_path(PROCESSES_PATH).retain_values(keys)


def put_state(event_process: int) -> None:
    state = compute_proc_state(event_process)
    if event_process is None:
        event_process = util.last_process
    ipath = PROCESS_PATTERN.format(procnum=event_process)
    trace = STATE.require_trace()
    procobj = trace.create_object(ipath)
    procobj.set_value('State', state)
    procobj.insert()
    tnum = util.selected_thread()
    if tnum is not None:
        ipath = THREAD_PATTERN.format(procnum=event_process, tnum=tnum)
        threadobj = trace.create_object(ipath)
        threadobj.set_value('State', state)
        threadobj.insert()


def ghidra_trace_put_processes() -> None:
    """Put the list of processes into the trace's Processes list."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_processes()


def put_available() -> None:
    trace = STATE.require_trace()
    keys = []
    for i, p in enumerate(util.process_list(running=True)):
        pid = p[0]
        ipath = AVAILABLE_PATTERN.format(pid=pid)
        keys.append(AVAILABLE_KEY_PATTERN.format(pid=pid))
        procobj = trace.create_object(ipath)
        procobj.set_value('PID', pid)
        procobj.set_value('_display', f'{i} {pid}')
        if len(p) > 1:
            name = str(p[1])
            procobj.set_value('Name', name)
            procobj.set_value('_display', f'{i} {pid} {name}')
        procobj.insert()
    trace.proxy_object_path(AVAILABLES_PATH).retain_values(keys)


def ghidra_trace_put_available() -> None:
    """Put the list of available processes into the trace's Available list."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_available()


def put_single_breakpoint(bp, bpath, nproc: int, ikeys: List[int]) -> None:
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    
    address = bp.addr
    brkobj = trace.create_object(bpath)

    brkobj.set_value('_display', f'{hex(address)}')
    if address is not None:  # Implies execution break
        base, addr = mapper.map(nproc, address)
        if base != addr.space:
            trace.create_overlay_space(base, addr.space)
        brkobj.set_value('Range', addr.extend(1))
    brkobj.set_value('Active', bp.active)
    brkobj.set_value('Enabled', bp.enabled)
    brkobj.set_value('Slot', str(bp.slot))
    brkobj.set_value('Type', str(bp.type))
    brkobj.set_value('TypeEx', str(bp.typeEx))
    if bp.fastResume is True:
        brkobj.set_value('FastResume', bp.fastResume)
    if bp.silent is True:
        brkobj.set_value('Silent', bp.silent)
    if bp.singleshoot is True:
        brkobj.set_value('SingleShot', bp.singleshoot)
    if bp.mod is not None:
        brkobj.set_value('Module', bp.mod)
    if bp.name is not None and bp.name != "":
        brkobj.set_value('Name', bp.name)
        brkobj.set_value('_display', f'{hex(address)} {bp.name}')
    if bp.commandText is not None and bp.commandText != "":
        brkobj.set_value('Command', bp.commandText)
    if bp.breakCondition is not None and bp.breakCondition != "":
        brkobj.set_value('Condition', bp.breakCondition)
    if bp.logText is not None and bp.logText != "":
        brkobj.set_value('LogText', bp.logText)
    if bp.logCondition is not None and bp.logCondition != "":
        brkobj.set_value('LogCondition', bp.logCondition)
    if bp.hwSize is not None and bp.hwSize != 0:
        brkobj.set_value('HW Size', bp.hwSize)
        brkobj.set_value('Range', addr.extend(bp.hwSize))
    brkobj.set_value('HitCount', bp.hitCount)
    if bp.type == BreakpointType.BpNormal:
        brkobj.set_value('Kinds', 'SW_EXECUTE')
    if bp.type == BreakpointType.BpHardware:
        prot = {0: 'READ', 1: 'WRITE', 2: 'HW_EXECUTE'}[bp.typeEx]
        brkobj.set_value('Kinds', prot)
    if bp.type == BreakpointType.BpMemory:
        prot = {0: 'READ', 1: 'WRITE', 2: 'HW_EXECUTE', 3: 'ACCESS'}[bp.typeEx]
        brkobj.set_value('Kinds', prot)
    brkobj.insert()

    k = PROC_BREAK_KEY_PATTERN.format(breaknum=address)
    ikeys.append(k)


def put_breakpoints(type: BreakpointType) -> None:
    nproc = util.selected_process()

    trace = STATE.require_trace()
    target = util.get_target()
    pattern = ''
    prot = ''
    if type == BreakpointType.BpNormal:
        pattern = PROC_SBREAKS_PATTERN
    if type == BreakpointType.BpHardware:
        pattern = PROC_HBREAKS_PATTERN
    if type == BreakpointType.BpMemory:
        pattern = PROC_MBREAKS_PATTERN
    ibpath = pattern.format(procnum=nproc)
    ibobj = trace.create_object(ibpath)
    keys: List[str] = []
    ikeys: List[int] = []
    for bp in util.dbg.client.get_breakpoints(type):
        bpath = ibpath + PROC_BREAK_KEY_PATTERN.format(breaknum=bp.addr)
        keys.append(bpath)
        put_single_breakpoint(bp, bpath, nproc, ikeys)
    ibobj.insert()
    trace.proxy_object_path(pattern).retain_values(keys)
    ibobj.retain_values(ikeys)


def ghidra_trace_put_breakpoints() -> None:
    """Put the current process's breakpoints into the trace."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_breakpoints(BreakpointType.BpNormal)
        put_breakpoints(BreakpointType.BpHardware)
        put_breakpoints(BreakpointType.BpMemory)


def put_environment() -> None:
    trace = STATE.require_trace()
    nproc = util.selected_process()
    epath = ENV_PATTERN.format(procnum=nproc)
    envobj = trace.create_object(epath)
    envobj.set_value('Debugger', 'x64dbg')
    envobj.set_value('Arch', arch.get_arch())
    envobj.set_value('OS', arch.get_osabi())
    envobj.set_value('Endian', arch.get_endian())
    envobj.insert()


def ghidra_trace_put_environment() -> None:
    """Put some environment indicators into the Ghidra trace."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_environment()


def put_regions() -> None:
    nproc = util.selected_process()
    try:
        regions = util.dbg.client.memmap()
    except Exception:
        regions = []
    #if len(regions) == 0:
    #    regions = util.full_mem()

    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    keys = []
    mod_keys = []
    # r : MemMap
    for r in regions:
        rpath = REGION_PATTERN.format(procnum=nproc, start=r.base_address)
        keys.append(REGION_KEY_PATTERN.format(start=r.base_address))
        regobj = trace.create_object(rpath)
        (start_base, start_addr) = map_address(r.base_address)
        regobj.set_value('Range', start_addr.extend(r.region_size))
        regobj.set_value('_readable', r.protect ==
                         None or r.protect & 0x66 != 0)
        regobj.set_value('_writable', r.protect ==
                         None or r.protect & 0xCC != 0)
        regobj.set_value('_executable', r.protect ==
                         None or r.protect & 0xF0 != 0)
        regobj.set_value('AllocationBase', hex(r.allocation_base))
        regobj.set_value('Protect', hex(r.protect))
        regobj.set_value('Type', hex(r.type))
        if hasattr(r, 'info') and r.info is not None:
            regobj.set_value('_display', r.info)
            base = util.dbg.eval('mod.base({})'.format(hex(r.base_address)))
            if base is not None and isinstance(base, int) is False:
                base = base[0]
            if base == r.base_address:
                name = r.info
                hbase = hex(base)
                mpath = MODULE_PATTERN.format(procnum=nproc, modpath=hbase)
                modobj = trace.create_object(mpath)
                mod_keys.append(MODULE_KEY_PATTERN.format(modpath=hbase))
                base_base, base_addr = mapper.map(nproc, base)
                if base_base != base_addr.space:
                    trace.create_overlay_space(base_base, base_addr.space)
                modsize = util.dbg.eval('mod.size({})'.format(hbase))
                if modsize is None or len(modsize) < 2:
                    size = 1
                else:
                    size = modsize[0]
                modobj.set_value('Range', base_addr.extend(size))
                modobj.set_value('Name', name)
                modentry = util.dbg.eval('mod.entry({})'.format(hbase))
                if modentry is not None and isinstance(modentry, int):
                    modobj.set_value('Entry', modentry)
                elif modentry is not None and len(modentry) > 0:
                    modobj.set_value('Entry', modentry[0])
                modobj.insert()
        regobj.insert()
    if STATE.trace is None:
        return
    STATE.trace.proxy_object_path(
        MEMORY_PATTERN.format(procnum=nproc)).retain_values(keys)
    STATE.trace.proxy_object_path(MODULES_PATTERN.format(
        procnum=nproc)).retain_values(mod_keys)


def ghidra_trace_put_regions() -> None:
    """Read the memory map, if applicable, and write to the trace's Regions."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_regions()


def put_modules() -> None:
    put_regions()


def ghidra_trace_put_modules() -> None:
    """Gather object files, if applicable, and write to the trace's Modules."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_modules()


def compute_thread_display(i: int, pid: Optional[int], tid: int, t) -> str:
    return f'{i} {pid}:{tid}'


def put_threads(running: bool = False) -> None:
    # NB: This speeds things up, but desirable?
    if running:
        return

    pid = util.selected_process()
    if pid is None:
        return
    trace = STATE.require_trace()

    mapper = trace.extra.require_mm()
    keys = []

    for i, t in enumerate(util.thread_list(running=False)):
        tid = int(t[0])
        tpath = THREAD_PATTERN.format(procnum=pid, tnum=tid)
        tobj = trace.create_object(tpath)
        keys.append(THREAD_KEY_PATTERN.format(tnum=tid))
    
        tobj.set_value('_short_display', f'{i} {pid}:{tid}')
        tobj.set_value('_display', compute_thread_display(i, pid, tid, t))
        tobj.set_value('TID', tid)
        if tid in util.threads:
            thread_data = util.threads[tid]
            base, offset_start = mapper.map(pid, thread_data.lpStartAddress)
            tobj.set_value('Start', offset_start)
            base, offset_base = mapper.map(pid, thread_data.lpThreadLocalBase)
            tobj.set_value('TLB', offset_base)
        tobj.insert()
    trace.proxy_object_path(THREADS_PATTERN.format(
        procnum=pid)).retain_values(keys)


def put_event_thread(nthrd: Optional[int] = None) -> None:
    trace = STATE.require_trace()
    nproc = util.selected_process()
    # Assumption: Event thread is selected by x64dbg upon stopping
    if nthrd is None:
        nthrd = util.selected_thread()
    if nthrd != None:
        tpath = THREAD_PATTERN.format(procnum=nproc, tnum=nthrd)
        tobj = trace.proxy_object_path(tpath)
    else:
        tobj = None
    trace.proxy_object_path('').set_value('_event_thread', tobj)


def ghidra_trace_put_threads() -> None:
    """Put the current process's threads into the Ghidra trace."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_threads()


# TODO: if eventually exposed...
# def put_frames() -> None:
#     nproc = util.selected_process()
#     if nproc < 0:
#         return
#     nthrd = util.selected_thread()
#     if nthrd is None:
#         return
#
#     trace = STATE.require_trace()
#
#     mapper = trace.extra.require_mm()
#     keys = []
#     # f : _DEBUG_STACK_FRAME
#     for f in util.dbg.client.backtrace_list():
#         fpath = FRAME_PATTERN.format(
#             procnum=nproc, tnum=nthrd, level=f.FrameNumber)
#         fobj = trace.create_object(fpath)
#         keys.append(FRAME_KEY_PATTERN.format(level=f.FrameNumber))
#         base, offset_inst = mapper.map(nproc, f.InstructionOffset)
#         if base != offset_inst.space:
#             trace.create_overlay_space(base, offset_inst.space)
#         fobj.set_value('Instruction Offset', offset_inst)
#         base, offset_stack = mapper.map(nproc, f.StackOffset)
#         if base != offset_stack.space:
#             trace.create_overlay_space(base, offset_stack.space)
#         base, offset_ret = mapper.map(nproc, f.ReturnOffset)
#         if base != offset_ret.space:
#             trace.create_overlay_space(base, offset_ret.space)
#         base, offset_frame = mapper.map(nproc, f.FrameOffset)
#         if base != offset_frame.space:
#             trace.create_overlay_space(base, offset_frame.space)
#         fobj.set_value('Stack Offset', offset_stack)
#         fobj.set_value('Return Offset', offset_ret)
#         fobj.set_value('Frame Offset', offset_frame)
#         fobj.set_value('_display', "#{} {}".format(
#             f.FrameNumber, offset_inst.offset))
#         fobj.insert()
#     trace.proxy_object_path(STACK_PATTERN.format(
#         procnum=nproc, tnum=nthrd)).retain_values(keys)


# def ghidra_trace_put_frames() -> None:
#     """Put the current thread's frames into the Ghidra trace."""
#
#     trace, tx = STATE.require_tx()
#     with trace.client.batch() as b:
#         put_frames()


def map_address(address: int) -> Tuple[str, Address]:
    nproc = util.selected_process()
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    base, addr = mapper.map(nproc, address)
    if base != addr.space:
        trace.create_overlay_space(base, addr.space)
    return base, addr


def ghidra_trace_put_all() -> None:
    """Put everything currently selected into the Ghidra trace."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        #util.dbg.client.wait_cmd_ready()
        try:
            put_processes()
            put_environment()
            put_threads()
            putreg()
            put_regions()
            putmem(util.get_pc(), 1)
            putmem(util.get_sp(), 1)
            put_breakpoints(BreakpointType.BpNormal)
            put_breakpoints(BreakpointType.BpHardware)
            put_breakpoints(BreakpointType.BpMemory)
            put_available()
            activate()
        except Exception as e:
            print(e)
            pass


def ghidra_trace_install_hooks() -> None:
    """Install hooks to trace in Ghidra."""

    hooks.install_hooks()


def ghidra_trace_remove_hooks() -> None:
    """Remove hooks to trace in Ghidra.

    Using this directly is not recommended, unless it seems the hooks
    are preventing x64dbg or other extensions from operating. Removing
    hooks will break trace synchronization until they are replaced.
    """

    hooks.remove_hooks()


def ghidra_trace_sync_enable() -> None:
    """Synchronize the current process with the Ghidra trace.

    This will automatically install hooks if necessary. The goal is to
    record the current frame, thread, and process into the trace
    immediately, and then to append the trace upon stopping and/or
    selecting new frames. This action is effective only for the current
    process. This command must be executed for each individual process
    you'd like to synchronize. In older versions of x64dbg, certain
    events cannot be hooked. In that case, you may need to execute
    certain "trace put" commands manually, or go without.

    This will have no effect unless or until you start a trace.
    """

    hooks.install_hooks()
    hooks.enable_current_process()


def ghidra_trace_sync_disable() -> None:
    """Cease synchronizing the current process with the Ghidra trace.

    This is the opposite of 'ghidra_trace_sync-disable', except it will
    not automatically remove hooks.
    """

    hooks.disable_current_process()


def get_prompt_text() -> str:
    try:
        return "dbg>"  #util.dbg.get_prompt_text()
    except util.DebuggeeRunningException:
        return 'Running>'


def exec_cmd(cmd: str) -> None:
    dbg = util.dbg
    dbg.cmd(cmd, quiet=False)
    stat = dbg.exec_status()  # type:ignore
    if stat != 'BREAK':
        dbg.wait()  # type:ignore


def repl() -> None:
    print("")
    print("This is the Windows Debugger REPL. To drop to Python, type .exit")
    while True:
        print(get_prompt_text(), end=' ')
        try:
            cmd = input().strip()
            if cmd == '':
                continue
            elif cmd == '.exit':
                break
            exec_cmd(cmd)
        except KeyboardInterrupt as e:
            util.dbg.interrupt()
        except BaseException as e:
            pass  # Error is printed by another mechanism
    print("")
    print("You have left the Windows Debugger REPL and are now at the Python "
          "interpreter.")
    print("To re-enter, type repl()")
