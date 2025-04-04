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
import code
from concurrent.futures import Future
from contextlib import contextmanager
import inspect
import os.path
import re
import socket
import sys
import time
from typing import Any, Dict, Generator, Iterable, List, Optional, Sequence, Tuple, Union

import drgn
import drgn.cli
from drgn import Program
from ghidratrace import sch
from ghidratrace.client import (Client, Address, AddressRange, Lifespan, RegVal,
                                Schedule, Trace, TraceObject, TraceObjectValue,
                                Transaction)
from ghidratrace.display import print_tabular_values, wait

from . import util, arch, methods, hooks


PAGE_SIZE = 4096

AVAILABLES_PATH = 'Available'
AVAILABLE_KEY_PATTERN = '[{pid}]'
AVAILABLE_PATTERN = AVAILABLES_PATH + AVAILABLE_KEY_PATTERN
PROCESSES_PATH = 'Processes'
PROCESS_KEY_PATTERN = '[{procnum}]'
PROCESS_PATTERN = PROCESSES_PATH + PROCESS_KEY_PATTERN
ENV_PATTERN = PROCESS_PATTERN + '.Environment'
THREADS_PATTERN = PROCESS_PATTERN + '.Threads'
THREAD_KEY_PATTERN = '[{tnum}]'
THREAD_PATTERN = THREADS_PATTERN + THREAD_KEY_PATTERN
STACK_PATTERN = THREAD_PATTERN + '.Stack'
FRAME_KEY_PATTERN = '[{level}]'
FRAME_PATTERN = STACK_PATTERN + FRAME_KEY_PATTERN
REGS_PATTERN = FRAME_PATTERN + '.Registers'
LOCALS_PATTERN = FRAME_PATTERN + '.Locals'
MEMORY_PATTERN = PROCESS_PATTERN + '.Memory'
REGION_KEY_PATTERN = '[{start:08x}]'
REGION_PATTERN = MEMORY_PATTERN + REGION_KEY_PATTERN
MODULES_PATTERN = PROCESS_PATTERN + '.Modules'
MODULE_KEY_PATTERN = '[{modpath}]'
MODULE_PATTERN = MODULES_PATTERN + MODULE_KEY_PATTERN
SECTIONS_PATTERN = MODULE_PATTERN + '.Sections'
SECTION_KEY_PATTERN = '[{secname}]'
SECTION_PATTERN = SECTIONS_PATTERN + SECTION_KEY_PATTERN
SYMBOLS_PATTERN = PROCESS_PATTERN + '.Symbols'
SYMBOL_KEY_PATTERN = '[{sid}]'
SYMBOL_PATTERN = SYMBOLS_PATTERN + SYMBOL_KEY_PATTERN

PROGRAMS = {}
prog: Program


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
        STATE.client = Client(c, "drgn", methods.REGISTRY)
        print(f"Connected to {STATE.client.description} at {address}")
    except ValueError:
        raise RuntimeError("port must be numeric")


def ghidra_trace_listen(address: str = '0.0.0.0:0') -> None:
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
        print("Listening at {}:{}...".format(host, port))
        c, (chost, cport) = s.accept()
        s.close()
        print("Connection from {}:{}".format(chost, cport))
        STATE.client = Client(c, "dbgeng.dll", methods.REGISTRY)
    except ValueError:
        raise RuntimeError("port must be numeric")


def ghidra_trace_disconnect() -> None:
    """Disconnect Python from Ghidra for tracing"""

    STATE.require_client().close()
    STATE.reset_client()


def start_trace(name: str) -> None:
    language, compiler = arch.compute_ghidra_lcsp()
    if name is None:
        name = 'drgn/noname'
    STATE.trace = STATE.require_client().create_trace(
        name, language, compiler, extra=Extra())
    # TODO: Is adding an attribute like this recommended in Python?
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
        root = STATE.trace.create_root_object(schema_xml, 'DrgnRoot')
        root.set_value('_display',  'drgn version ' + util.DRGN_VERSION.full)
    util.set_convenience_variable('_ghidra_tracing', "true")


def ghidra_trace_start(name: str = "drgn/noname") -> None:
    """Start a Trace in Ghidra"""

    STATE.require_client()
    STATE.require_no_trace()
    start_trace(name)


def ghidra_trace_stop() -> None:
    """Stop the Trace in Ghidra"""

    STATE.require_trace().close()
    STATE.reset_trace()


def ghidra_trace_restart(name: str) -> None:
    """Restart or start the Trace in Ghidra"""

    STATE.require_client()
    if STATE.trace != None:
        STATE.trace.close()
        STATE.reset_trace()
    start_trace(name)


def ghidra_trace_create(start_trace: bool = True) -> None:
    """
    Create a session.
    """

    global prog
    prog = Program()
    kind = os.getenv('OPT_TARGET_KIND')
    if kind == "kernel":
        prog.set_kernel()
    elif kind == "coredump":
        img = os.getenv('OPT_TARGET_IMG')
        if img is not None:
            prog.set_core_dump(img)
            if '/' in img:
                img = img[img.rindex('/')+1:]
    else:
        pid = os.getenv('OPT_TARGET_PID')
        if pid is not None:
            prog.set_pid(int(pid))
            util.selected_pid = int(pid)

    default_symbols = {"default": True, "main": True}
    try:
        prog.load_debug_info(None, **default_symbols)
    except drgn.MissingDebugInfoError as e:
        print(e)

    if hasattr(drgn, 'Module') or kind == "coredump":
        if kind == "kernel":
            img = prog.main_module().name  # type: ignore
            util.selected_tid = next(prog.threads()).tid
        elif kind == "coredump":
            util.selected_tid = prog.crashed_thread().tid
        else:
            img = prog.main_module().name  # type: ignore
            util.selected_tid = prog.main_thread().tid

    if start_trace and img is not None:
        ghidra_trace_start(img)

    PROGRAMS[util.selected_pid] = prog


def ghidra_trace_info() -> None:
    """Get info about the Ghidra connection"""

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
    """
    Get the selected Ghidra language-compiler-spec pair. 
    """

    language, compiler = arch.compute_ghidra_lcsp()
    print("Selected Ghidra language: {}".format(language))
    print("Selected Ghidra compiler: {}".format(compiler))


def ghidra_trace_txstart(description: str = "tx") -> None:
    """
    Start a transaction on the trace
    """

    STATE.require_no_tx()
    STATE.tx = STATE.require_trace().start_tx(description, undoable=False)


def ghidra_trace_txcommit() -> None:
    """
    Commit the current transaction
    """

    STATE.require_tx()[1].commit()
    STATE.reset_tx()


def ghidra_trace_txabort() -> None:
    """
    Abort the current transaction

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
    """
    Save the current trace
    """

    STATE.require_trace().save()


def ghidra_trace_new_snap(description: Optional[str] = None,
                          time: Optional[Schedule] = None) -> Dict[str, int]:
    """
    Create a new snapshot

    Subsequent modifications to machine state will affect the new snapshot.
    """

    description = str(description)
    if isinstance(time, int):
        time = Schedule(time)
    trace, tx = STATE.require_tx()
    return {'snap': trace.snapshot(description, time=time)}


def quantize_pages(start: int, end: int) -> Tuple[int, int]:
    return (start // PAGE_SIZE * PAGE_SIZE, (end + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE)


def put_bytes(start: int, end: int, pages: bool,
              display_result: bool = False) -> Dict[str, int]:
    trace = STATE.require_trace()
    if pages:
        start, end = quantize_pages(start, end)
    nproc = util.selected_process()
    if end - start <= 0:
        return {'count': 0}
    try:
        buf = prog.read(start, end - start)
    except Exception as e:
        return {'count': 0}

    count: Union[int, Future[int]] = 0
    if buf != None:
        base, addr = trace.extra.require_mm().map(nproc, start)
        if base != addr.space:
            trace.create_overlay_space(base, addr.space)
        count = trace.put_bytes(addr, buf)
        if display_result:
            print("Wrote {} bytes".format(count))
        if isinstance(count, Future):
            return {'count': -1}
        else:
            return {'count': count}
    return {'count': 0}


def eval_range(address: Union[str, int], length: Union[str, int]) -> Tuple[int, int]:
    start = int(address)
    try:
        end = start + int(length)
    except Exception as e:
        raise RuntimeError("Cannot convert '{}' to length".format(length))
    return start, end


def putmem(address: Union[str, int], length: Union[str, int],
           pages: bool = True, display_result: bool = True) -> Dict[str, int]:
    start, end = eval_range(address, length)
    return put_bytes(start, end, pages, display_result)


def ghidra_trace_putmem(address: Union[str, int], length: Union[str, int],
                        pages: bool = True) -> Dict[str, int]:
    """
    Record the given block of memory into the Ghidra trace.
    """

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
    """
    Set the state of the given range of memory in the Ghidra trace.
    """

    STATE.require_tx()
    return putmem_state(address, length, state, pages)


def ghidra_trace_delmem(address: Union[str, int],
                        length: Union[str, int]) -> None:
    """
    Delete the given range of memory from the Ghidra trace.

    Why would you do this? Keep in mind putmem quantizes to full pages by
    default, usually to take advantage of spatial locality. This command does
    not quantize. You must do that yourself, if necessary.
    """

    trace, tx = STATE.require_tx()
    start, end = eval_range(address, length)
    nproc = util.selected_process()
    base, addr = trace.extra.memory_mapper.map(nproc, start)
    # Do not create the space. We're deleting stuff.
    trace.delete_bytes(addr.extend(end - start))


def putreg() -> Dict[str, List[str]]:
    trace = STATE.require_trace()
    nproc = util.selected_process()
    if nproc < 0:
        return {}
    nthrd = util.selected_thread()
    if nthrd < 0:
        return {}
    nframe = util.selected_frame()
    if nframe < 0:
        return {}
    space = REGS_PATTERN.format(procnum=nproc, tnum=nthrd, level=nframe)
    trace.create_overlay_space('register', space)
    robj = trace.create_object(space)
    robj.insert()
    mapper = trace.extra.require_rm()

    thread = prog.thread(nthrd)
    try:
        frames = thread.stack_trace()
    except Exception as e:
        print(e)
        return {}

    regs = frames[nframe].registers()
    sz = int(int(arch.get_size())/8)
    values = []
    for key in regs.keys():
        try:
            value = regs[key]
        except Exception:
            value = 0
        try:
            rv = value.to_bytes(sz, "big")  # trace takes "big"
            values.append(mapper.map_value(nproc, key, rv))
            robj.set_value(key, hex(value))
        except Exception:
            pass
    missing = trace.put_registers(space, values)
    if isinstance(missing, Future):
        return {'future': []}
    return {'missing': missing}


def ghidra_trace_putreg() -> None:
    """
    Record the given register group for the current frame into the Ghidra trace.

    If no group is specified, 'all' is assumed.
    """

    STATE.require_tx()
    putreg()


def ghidra_trace_delreg() -> None:
    """
    Delete the given register group for the curent frame from the Ghidra trace.

    Why would you do this? If no group is specified, 'all' is assumed.
    """

    trace, tx = STATE.require_tx()
    nproc = util.selected_process()
    nthrd = util.selected_thread()
    if nthrd < 0:
        return
    nframe = util.selected_frame()
    if nframe < 0:
        return
    space = REGS_PATTERN.format(procnum=nproc, tnum=nthrd, level=nframe)

    thread = prog.thread(nthrd)
    try:
        frames = thread.stack_trace()
    except Exception as e:
        print(e)
        return

    regs = frames[nframe].registers()
    names = []
    for key in regs.keys():
        names.append(key)
    trace.delete_registers(space, names)


def put_object(lpath: str, key: str, value: Any):
    trace = STATE.require_trace()
    nproc = util.selected_process()
    lobj = trace.create_object(lpath+"."+key)
    lobj.insert()
    if hasattr(value, "type_"):
        vtype = value.type_
        vkind = vtype.kind
        lobj.set_value('_display', '{} [{}]'.format(key, vtype.type_name()))
        lobj.set_value('Kind', str(vkind))
        lobj.set_value('Type', str(vtype))
    else:
        lobj.set_value('_display', '{} [{}:{}]'.format(
            key, type(value), str(value)))
        lobj.set_value('Value', str(value))
        return

    if hasattr(value, "absent_"):
        if value.absent_:
            lobj.set_value('Value', '<absent>')
            return
    if hasattr(value, "address_"):
        vaddr = value.address_
        if vaddr is not None:
            base, addr = trace.extra.require_mm().map(nproc, vaddr)
            lobj.set_value('Address', addr)
    if hasattr(value, "value_"):
        vvalue = value.value_()

    if vkind is drgn.TypeKind.POINTER:
        base, addr = trace.extra.require_mm().map(nproc, vvalue)
        lobj.set_value('Address', addr)
        return
    if vkind is drgn.TypeKind.TYPEDEF:
        lobj.set_value('_display', '{} [{}:{}]'.format(
            key, type(vvalue), str(vvalue)))
        lobj.set_value('Value', str(vvalue))
        return
    if vkind is drgn.TypeKind.UNION or vkind is drgn.TypeKind.STRUCT or vkind is drgn.TypeKind.CLASS:
        for k in vvalue.keys():
            if isinstance(lobj.path, str):
                put_object(lobj.path+'.Members', k, vvalue[k])
        return

    lobj.set_value('_display', '{} [{}:{}]'.format(
        key, type(vvalue), str(vvalue)))
    lobj.set_value('Value', str(vvalue))


def put_objects(pobj: TraceObject, parent: Dict[str, TraceObject]) -> None:
    if isinstance(pobj.path, str):
        ppath = pobj.path + '.Members'
        for k in parent.keys():
            put_object(ppath, k, parent[k])


def put_locals() -> None:
    trace = STATE.require_trace()
    nproc = util.selected_process()
    if nproc < 0:
        return
    nthrd = util.selected_thread()
    if nthrd < 0:
        return
    nframe = util.selected_frame()
    if nframe < 0:
        return
    lpath = LOCALS_PATTERN.format(procnum=nproc, tnum=nthrd, level=nframe)
    lobj = trace.create_object(lpath)
    lobj.insert()

    thread = prog.thread(nthrd)
    frames = thread.stack_trace()
    frame = frames[nframe]
    locs = frame.locals()
    for key in locs:
        value = frame[key]
        put_object(lpath, key, value)


def ghidra_trace_put_locals() -> None:
    """
    Record the local vars for the current frame into the Ghidra trace.
    """

    STATE.require_tx()
    put_locals()


def ghidra_trace_create_obj(path: str):
    """
    Create an object in the Ghidra trace.

    The new object is in a detached state, so it may not be immediately
    recognized by the Debugger GUI. Use 'ghidra_trace_insert-obj' to finish the
    object, after all its required attributes are set.
    """

    trace, tx = STATE.require_tx()
    obj = trace.create_object(path)
    obj.insert()
    print("Created object: id={}, path='{}'".format(obj.id, obj.path))


def ghidra_trace_insert_obj(path: str) -> None:
    """
    Insert an object into the Ghidra trace.
    """

    # NOTE: id parameter is probably not necessary, since this command is for
    # humans.
    trace, tx = STATE.require_tx()
    span = trace.proxy_object_path(path).insert()
    print("Inserted object: lifespan={}".format(span))


def ghidra_trace_remove_obj(path: str) -> None:
    """
    Remove an object from the Ghidra trace.

    This does not delete the object. It just removes it from the tree for the
    current snap and onwards.
    """

    trace, tx = STATE.require_tx()
    trace.proxy_object_path(path).remove()


def to_bytes(value: Sequence) -> bytes:
    return bytes(ord(value[i]) if type(value[i]) == str else int(value[i]) for i in range(0, len(value)))


def to_string(value: Sequence, encoding: str) -> str:
    b = bytes(ord(value[i]) if type(value[i]) == str else int(
        value[i]) for i in range(0, len(value)))
    return str(b, encoding)


def to_bool_list(value: Sequence) -> List[bool]:
    return [bool(value[i]) for i in range(0, len(value))]


def to_int_list(value: Sequence) -> List[int]:
    return [ord(value[i]) if type(value[i]) == str else int(value[i]) for i in range(0, len(value))]


def to_short_list(value: Sequence) -> List[int]:
    return [ord(value[i]) if type(value[i]) == str else int(value[i]) for i in range(0, len(value))]


def to_string_list(value: Sequence, encoding: str) -> List[str]:
    return [to_string(value[i], encoding) for i in range(0, len(value))]


def eval_value(value: Any, schema: Optional[sch.Schema] = None) -> Tuple[Union[
        bool, int, float, bytes, Tuple[str, Address], List[bool], List[int],
        List[str], str], Optional[sch.Schema]]:
    if schema == sch.CHAR:
        return bytes(value, 'utf-8')[0], schema
    if schema == sch.BYTE or schema == sch.SHORT or schema == sch.INT or schema == sch.LONG:
        return int(value, 0), schema
    if schema == sch.ADDRESS:
        nproc = util.selected_process()
        trace = STATE.require_trace()
        base, addr = trace.extra.require_mm().map(nproc, value)
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


def ghidra_trace_set_value(path: str, key: str, value: Any,
                           schema: Optional[str] = None) -> None:
    """
    Set a value (attribute or element) in the Ghidra trace's object tree.

    A void value implies removal. 
    NOTE: The type of an expression may be subject to the dbgeng's current 
    language. which current defaults to DEBUG_EXPR_CPLUSPLUS (vs DEBUG_EXPR_MASM). 
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

    key_list = keys.split(" ")

    trace, tx = STATE.require_tx()
    kinds = 'elements'
    if key_list[0] == '--elements':
        kinds = 'elements'
        key_list = key_list[1:]
    elif keys[0] == '--attributes':
        kinds = 'attributes'
        key_list = key_list[1:]
    elif keys[0] == '--both':
        kinds = 'both'
        key_list = key_list[1:]
    elif key_list[0].startswith('--'):
        raise RuntimeError("Invalid argument: " + key_list[0])
    trace.proxy_object_path(path).retain_values(key_list, kinds=kinds)


def ghidra_trace_get_obj(path: str) -> None:
    """
    Get an object descriptor by its canonical path.

    This isn't the most informative, but it will at least confirm whether an
    object exists and provide its id.
    """

    trace = STATE.require_trace()
    object = trace.get_object(path)
    print("{}\t{}".format(object.id, object.path))


def ghidra_trace_get_values(pattern: str) -> None:
    """
    List all values matching a given path pattern.
    """

    trace = STATE.require_trace()
    values = wait(trace.get_values(pattern))
    print_tabular_values(values, print)


def ghidra_trace_get_values_rng(address: Union[str, int],
                                length: Union[str, int]) -> None:
    """
    List all values intersecting a given address range.
    """

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
                frame = util.selected_frame()
                if frame is None:
                    path = THREAD_PATTERN.format(procnum=nproc, tnum=nthrd)
                else:
                    path = FRAME_PATTERN.format(
                        procnum=nproc, tnum=nthrd, level=frame)
    trace.proxy_object_path(path).activate()


def ghidra_trace_activate(path: Optional[str] = None) -> None:
    """
    Activate an object in Ghidra's GUI.

    This has no effect if the current trace is not current in Ghidra. If path is
    omitted, this will activate the current frame.
    """

    activate(path)


def ghidra_trace_disassemble(address: Union[str, int]) -> None:
    """
    Disassemble starting at the given seed.

    Disassembly proceeds linearly and terminates at the first branch or unknown
    memory encountered.
    """

    trace, tx = STATE.require_tx()
    nproc = util.selected_process()
    base, addr = trace.extra.memory_mapper.map(nproc, address)
    if base != addr.space:
        trace.create_overlay_space(base, addr.space)

    length = trace.disassemble(addr)
    print("Disassembled {} bytes".format(length))


def put_processes() -> None:
    trace = STATE.require_trace()
    keys = []
    # Set running=True to avoid process changes, even while stopped
    for key in PROGRAMS.keys():
        ppath = PROCESS_PATTERN.format(procnum=key)
        keys.append(PROCESS_KEY_PATTERN.format(procnum=key))
        procobj = trace.create_object(ppath)

        p = PROGRAMS[key]
        procobj.set_value('State', str(p.flags))
        procobj.set_value('PID', key)
        procobj.set_value('_display', '[{:x}]'.format(key))
        procobj.insert()
    trace.proxy_object_path(PROCESSES_PATH).retain_values(keys)


def ghidra_trace_put_processes() -> None:
    """
    Put the list of processes into the trace's Processes list.
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_processes()


def put_environment() -> None:
    trace = STATE.require_trace()
    nproc = util.selected_process()
    epath = ENV_PATTERN.format(procnum=nproc)
    envobj = trace.create_object(epath)
    envobj.set_value('Debugger', 'drgn')
    envobj.set_value('Arch', arch.get_arch())
    envobj.set_value('OS', arch.get_osabi())
    envobj.set_value('Endian', arch.get_endian())
    envobj.insert()


def ghidra_trace_put_environment() -> None:
    """
    Put some environment indicators into the Ghidra trace
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_environment()


# Detect whether this is supported before defining the command
if hasattr(drgn, 'RelocatableModule'):
    def put_regions() -> None:
        trace = STATE.require_trace()
        nproc = util.selected_process()
        if nproc is None:
            return

        try:
            regions = prog.loaded_modules()  # type: ignore
        except Exception as e:
            regions = []
        # if len(regions) == 0:
        #    regions = util.full_mem()

        mapper = trace.extra.require_mm()
        keys = []
        # r : MEMORY_BASIC_INFORMATION64
        for r in regions:
            start = r[0].address_range[0]
            end = r[0].address_range[1]
            size = end - start + 1
            rpath = REGION_PATTERN.format(procnum=nproc, start=start)
            keys.append(REGION_KEY_PATTERN.format(start=start))
            regobj = trace.create_object(rpath)
            (start_base, start_addr) = mapper.map(nproc, start)
            regobj.set_value('Range', start_addr.extend(size))
            regobj.set_value('Name', r[0].name)
            regobj.set_value('Object File', r[0].loaded_file_path)
            regobj.set_value('_readable', True)
            regobj.set_value('_writable', True)
            regobj.set_value('_executable', True)
            regobj.set_value('_display', '{:x} {}'.format(start, r[0].name))
            regobj.insert()
        trace.proxy_object_path(
            MEMORY_PATTERN.format(procnum=nproc)).retain_values(keys)

    def ghidra_trace_put_regions() -> None:
        """
        Read the memory map, if applicable, and write to the trace's Regions
        """

        trace, tx = STATE.require_tx()
        with trace.client.batch() as b:
            put_regions()


# Detect whether this is supported before defining the command
if hasattr(drgn, 'RelocatableModule'):
    def put_modules() -> None:
        trace = STATE.require_trace()
        nproc = util.selected_process()
        if nproc is None:
            return

        try:
            modules = prog.modules()  # type: ignore
        except Exception as e:
            return

        mapper = trace.extra.require_mm()
        mod_keys = []
        for m in modules:
            name = m.name
            # m[1] : _DEBUG_MODULE_PARAMETERS
            base = m.address_range[0]
            hbase = hex(base)
            size = m.address_range[1] - base
            mpath = MODULE_PATTERN.format(procnum=nproc, modpath=hbase)
            modobj = trace.create_object(mpath)
            mod_keys.append(MODULE_KEY_PATTERN.format(modpath=hbase))
            base_base, base_addr = mapper.map(nproc, base)
            if base_base != base_addr.space:
                trace.create_overlay_space(base_base, base_addr.space)
            modobj.set_value('Range', base_addr.extend(size))
            modobj.set_value('Name', name)
            modobj.set_value('_display', '{:x} {}'.format(base, name))
            modobj.insert()
            attrobj = trace.create_object(mpath+".Attributes")
            attrobj.set_value('BuildId', m.build_id)
            attrobj.set_value('DebugBias', m.debug_file_bias)
            attrobj.set_value('DebugPath', m.debug_file_path)
            attrobj.set_value('DebugStatus', str(m.debug_file_status))
            attrobj.set_value('LoadBias', m.loaded_file_bias)
            attrobj.set_value('LoadPath', m.loaded_file_path)
            attrobj.set_value('LoadStatus', str(m.loaded_file_status))
            attrobj.insert()
            if type(m) == drgn.RelocatableModule:  # type: ignore
                secobj = trace.create_object(mpath+".Sections")
                secobj.insert()
        trace.proxy_object_path(MODULES_PATTERN.format(
            procnum=nproc)).retain_values(mod_keys)

    def ghidra_trace_put_modules() -> None:
        """
        Gather object files, if applicable, and write to the trace's Modules
        """

        trace, tx = STATE.require_tx()
        with trace.client.batch() as b:
            put_modules()


# Detect whether this is supported before defining the command
if hasattr(drgn, 'RelocatableModule'):
    def put_sections(m: drgn.RelocatableModule) -> None:  # type: ignore
        nproc = util.selected_process()
        if nproc is None:
            return

        trace = STATE.require_trace()
        mapper = trace.extra.require_mm()
        section_keys = []
        sections = m.section_addresses
        maddr = hex(m.address_range[0])
        for key in sections.keys():
            value = sections[key]
            spath = SECTION_PATTERN.format(
                procnum=nproc, modpath=maddr, secname=key)
            sobj = trace.create_object(spath)
            section_keys.append(SECTION_KEY_PATTERN.format(
                modpath=maddr, secname=key))
            base_base, base_addr = mapper.map(nproc, value)
            if base_base != base_addr.space:
                trace.create_overlay_space(base_base, base_addr.space)
            sobj.set_value('Address', base_addr)
            sobj.set_value('Range', base_addr.extend(1))
            sobj.set_value('Name', key)
            sobj.insert()
        trace.proxy_object_path(SECTIONS_PATTERN.format(
            procnum=nproc, modpath=maddr)).retain_values(section_keys)


def convert_state(t) -> str:
    if t.IsSuspended():
        return 'SUSPENDED'
    if t.IsStopped():
        return 'STOPPED'
    return 'RUNNING'


def put_threads(running: bool = False) -> None:
    nproc = util.selected_process()
    if nproc is None:
        return

    trace = STATE.require_trace()
    keys = []
    # Set running=True to avoid thread changes, even while stopped
    threads = prog.threads()
    for i, t in enumerate(threads):
        nthrd = t.tid
        tpath = THREAD_PATTERN.format(procnum=nproc, tnum=nthrd)
        tobj = trace.create_object(tpath)
        keys.append(THREAD_KEY_PATTERN.format(tnum=nthrd))

        tobj.set_value('TID', nthrd)
        short = '{:d} {:x}:{:x}'.format(i, nproc, nthrd)
        tobj.set_value('_short_display', short)
        if hasattr(t, 'name'):
            tobj.set_value('_display', '{:x} {:x}:{:x} {}'.format(
                i, nproc, nthrd, t.name))
            tobj.set_value('Name', t.name)
        else:
            tobj.set_value('_display', short)
        # tobj.set_value('Object', t.object)
        tobj.insert()
        stackobj = trace.create_object(tpath+".Stack")
        stackobj.insert()
    trace.proxy_object_path(
        THREADS_PATTERN.format(procnum=nproc)).retain_values(keys)


def ghidra_trace_put_threads() -> None:
    """
    Put the current process's threads into the Ghidra trace
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_threads()


def put_frames() -> None:
    nproc = util.selected_process()
    if nproc < 0:
        return
    nthrd = util.selected_thread()
    if nthrd is None:
        return
    thread = prog.thread(nthrd)
    if thread is None:
        return

    try:
        stack = thread.stack_trace()
    except Exception as e:
        return

    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    keys = []
    for i, f in enumerate(stack):
        fpath = FRAME_PATTERN.format(
            procnum=nproc, tnum=nthrd, level=i)
        fobj = trace.create_object(fpath)
        keys.append(FRAME_KEY_PATTERN.format(level=i))
        base, offset_inst = mapper.map(nproc, f.pc)
        if base != offset_inst.space:
            trace.create_overlay_space(base, offset_inst.space)
        base, offset_stack = mapper.map(nproc, f.sp)
        if base != offset_stack.space:
            trace.create_overlay_space(base, offset_stack.space)
        fobj.set_value('PC', offset_inst)
        fobj.set_value('SP', offset_stack)
        fobj.set_value('Name', f.name)
        fobj.set_value('_display', "#{} {} {}".format(
            i, hex(offset_inst.offset), f.name))
        fobj.insert()
        aobj = trace.create_object(fpath+".Attributes")
        aobj.insert()
        aobj.set_value('Inline', f.is_inline)
        aobj.set_value('Interrupted', f.interrupted)
        aobj.insert()
        lobj = trace.create_object(fpath+".Locals")
        lobj.insert()
        robj = trace.create_object(fpath+".Registers")
        robj.insert()
        try:
            src = f.source()
            srcobj = trace.create_object(fpath+".Source")
            srcobj.set_value('Filename', src[0])
            srcobj.set_value('Line', src[1])
            srcobj.set_value('Column', src[2])
            srcobj.insert()
        except Exception as e:
            pass
    trace.proxy_object_path(STACK_PATTERN.format(
        procnum=nproc, tnum=nthrd)).retain_values(keys)


def ghidra_trace_put_frames() -> None:
    """
    Put the current thread's frames into the Ghidra trace
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_frames()


def put_symbols(pattern: Optional[str] = None) -> None:
    nproc = util.selected_process()
    if nproc is None:
        return

    trace = STATE.require_trace()
    # keys = []
    symbols = prog.symbols(pattern)
    for s in symbols:
        spath = SYMBOL_PATTERN.format(procnum=nproc, sid=hash(str(s)))
        sobj = trace.create_object(spath)
        # keys.append(SYMBOL_KEY_PATTERN.format(sid=i))

        short = '{:x}'.format(s.address)
        sobj.set_value('_short_display', short)
        if hasattr(s, 'name'):
            long = '{:x} {}'.format(s.address, s.name)
            sobj.set_value('_display', long)
            sobj.set_value('Name', s.name)
        else:
            sobj.set_value('_display', short)
        mapper = trace.extra.require_mm()
        base, offset = mapper.map(nproc, s.address)
        if base != offset.space:
            trace.create_overlay_space(base, offset.space)
        sobj.set_value('Address', offset)
        sobj.set_value('Size', s.size)
        sobj.set_value('Binding', str(s.binding))
        sobj.set_value('Kind', str(s.kind))
        sobj.insert()
    # trace.proxy_object_path(
    #    SYMBOLS_PATTERN.format(procnum=nproc)).retain_values(keys)


def ghidra_trace_put_symbols() -> None:
    """
    Put the current process's threads into the Ghidra trace
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_symbols()


def ghidra_trace_put_all() -> None:
    """
    Put everything currently selected into the Ghidra trace
    """

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_environment()
        if hasattr(drgn, 'RelocatableModule'):
            put_regions()
            put_modules()
        syms = SYMBOLS_PATTERN.format(procnum=util.selected_process())
        sobj = trace.create_object(syms)
        sobj.insert()
        # put_symbols()
        put_threads()
        put_frames()
        ghidra_trace_putreg()
        ghidra_trace_putmem(get_pc(), 1)
        ghidra_trace_putmem(get_sp(), 1)


def ghidra_trace_install_hooks() -> None:
    """
    Install hooks to trace in Ghidra
    """

    hooks.install_hooks()


def ghidra_trace_remove_hooks() -> None:
    """
    Remove hooks to trace in Ghidra

    Using this directly is not recommended, unless it seems the hooks are
    preventing pydbg or other extensions from operating. Removing hooks will break
    trace synchronization until they are replaced.
    """

    hooks.remove_hooks()


def ghidra_trace_sync_enable() -> None:
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


def ghidra_trace_sync_disable() -> None:
    """
    Cease synchronizing the current process with the Ghidra trace

    This is the opposite of 'ghidra_trace_sync-disable', except it will not
    automatically remove hooks.
    """

    hooks.disable_current_process()


def get_pc() -> int:
    try:
        thread = prog.thread(util.selected_thread())
        stack = thread.stack_trace()
    except Exception as e:
        return 0

    frame = stack[util.selected_frame()]
    return frame.pc


def get_sp() -> int:
    try:
        thread = prog.thread(util.selected_thread())
        stack = thread.stack_trace()
    except Exception as e:
        return 0

    frame = stack[util.selected_frame()]
    return frame.sp
