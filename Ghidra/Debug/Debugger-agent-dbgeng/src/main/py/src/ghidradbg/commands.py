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

# from ctypes import *
from comtypes import c_ulong  # type: ignore
from ghidratrace import sch
from ghidratrace.client import (Client, Address, AddressRange, Lifespan, RegVal,
                                Schedule, Trace, TraceObject, TraceObjectValue,
                                Transaction)
from ghidratrace.display import print_tabular_values, wait
from pybag import pydbg, userdbg, kerneldbg  # type: ignore
from pybag.dbgeng import core as DbgEng  # type: ignore
from pybag.dbgeng import exception  # type: ignore

from . import util, arch, methods, hooks
from .dbgmodel.imodelobject import ModelObject, ModelObjectKind

if util.is_exdi():
    from .exdi import exdi_commands, exdi_methods

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
PROC_BREAKS_PATTERN = PROC_DEBUG_PATTERN + '.Breakpoints'
PROC_BREAK_KEY_PATTERN = '[{breaknum}]'
PROC_BREAK_PATTERN = PROC_BREAKS_PATTERN + PROC_BREAK_KEY_PATTERN
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
        STATE.client = Client(c, "dbgeng.dll", methods.REGISTRY)
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
        STATE.client = Client(c, "dbgeng.dll", methods.REGISTRY)
    except ValueError:
        raise RuntimeError("port must be numeric")


def ghidra_trace_disconnect() -> None:
    """Disconnect Python from Ghidra for tracing."""

    STATE.require_client().close()
    STATE.reset_client()


def compute_name(progname: Optional[str] = None) -> str:
    if progname is None:
        try:
            progname = util.GetCurrentProcessExecutableName()
        except Exception:
            return 'pydbg/noname'
    return 'pydbg/' + re.split(r'/|\\', progname)[-1]


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
    if util.is_exdi():
        schema_fn = os.path.join(parent, 'schema_exdi.xml')
    else:
        schema_fn = os.path.join(parent, 'schema.xml')
    with open(schema_fn, 'r') as schema_file:
        schema_xml = schema_file.read()
    using_dbgmodel = os.getenv('OPT_USE_DBGMODEL') == "true"
    variant = " (dbgmodel)" if using_dbgmodel else " (dbgeng)"
    with STATE.trace.open_tx("Create Root Object"):
        root = STATE.trace.create_root_object(schema_xml, 'DbgRoot')
        root.set_value('_display', util.DBG_VERSION.full +
                       ' via pybag' + variant)
        STATE.trace.create_object(SESSION_PATH).insert()
        if util.dbg.use_generics:
            put_generic(root)
        if util.dbg.IS_TRACE:
            root.set_value('_time_support', 'SNAP_EVT_STEPS')
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


@util.dbg.eng_thread
def ghidra_trace_create(command: Optional[str] = None,
                        initial_break: bool = True,
                        timeout: int = DbgEng.WAIT_INFINITE,
                        start_trace: bool = True,
                        wait: bool = False) -> None:
    """Create a session."""

    dbg = util.dbg._base
    if command != None:
        dbg._client.CreateProcess(command, DbgEng.DEBUG_PROCESS)
        if initial_break:
            dbg._control.AddEngineOptions(DbgEng.DEBUG_ENGINITIAL_BREAK)
    if wait:
        try:
            dbg.wait()
        except KeyboardInterrupt as ki:
            dbg.interrupt()
    if start_trace:
        ghidra_trace_start(command)


@util.dbg.eng_thread
def ghidra_trace_create_ext(command: Optional[str] = None,
                            initialDirectory: Optional[str] = '.',
                            envVariables: Optional[str] = "\0\0",
                            create_flags: int = 1, create_flags_eng: int = 0,
                            verifier_flags: int = 0, engine_options: int = 0x20,
                            timeout: int = DbgEng.WAIT_INFINITE,
                            start_trace: bool = True,
                            wait: bool = False) -> None:
    """Create a session."""

    dbg = util.dbg._base
    if command != None:
        if create_flags == "":
            create_flags = 1
        if create_flags_eng == "":
            create_flags_eng = 0
        if verifier_flags == "":
            verifier_flags = 0
        options = DbgEng._DEBUG_CREATE_PROCESS_OPTIONS()
        options.CreateFlags = c_ulong(int(create_flags))
        options.EngCreateFlags = c_ulong(int(create_flags_eng))
        options.VerifierFlags = c_ulong(int(verifier_flags))
        options.Reserved = c_ulong(int(0))
        if initialDirectory == "":
            initialDirectory = None
        if envVariables == "":
            envVariables = None
        if envVariables is not None and envVariables.endswith("/0/0") is False:
            envVariables += "/0/0"
        dbg._client.CreateProcess2(
            command, options, initialDirectory, envVariables)
        dbg._control.AddEngineOptions(int(engine_options))
    if wait:
        try:
            dbg.wait()
        except KeyboardInterrupt as ki:
            dbg.interrupt()
    if start_trace:
        ghidra_trace_start(command)


@util.dbg.eng_thread
def ghidra_trace_attach(pid: Optional[str] = None, attach_flags: str = '0',
                        initial_break: bool = True,
                        timeout: int = DbgEng.WAIT_INFINITE,
                        start_trace: bool = True) -> None:
    """Create a session by attaching."""

    dbg = util.dbg._base
    if initial_break:
        dbg._control.AddEngineOptions(DbgEng.DEBUG_ENGINITIAL_BREAK)
    if attach_flags == None:
        attach_flags = '0'
    if pid != None:
        dbg._client.AttachProcess(int(pid, 0), int(attach_flags, 0))
    if start_trace:
        ghidra_trace_start(f"pid_{pid}")


@util.dbg.eng_thread
def ghidra_trace_attach_kernel(command: Optional[str] = None,
                               flags: int = DbgEng.DEBUG_ATTACH_KERNEL_CONNECTION,
                               initial_break: bool = True,
                               timeout: int = DbgEng.WAIT_INFINITE,
                               start_trace: bool = True) -> None:
    """Create a session."""

    dbg = util.dbg._base
    util.set_kernel(True)
    if flags == 2:
        util.set_exdi(True)
    if initial_break:
        dbg._control.AddEngineOptions(DbgEng.DEBUG_ENGINITIAL_BREAK)
    if command != None:
        dbg._client.AttachKernel(command, flags=int(flags))
    if start_trace:
        ghidra_trace_start(command)


@util.dbg.eng_thread
def ghidra_trace_connect_server(options: Union[str, bytes, None] = None) -> None:
    """Connect to a process server session."""

    dbg = util.dbg._base
    if options != None:
        if isinstance(options, str):
            enc_options = options.encode()
        dbg._client.ConnectProcessServer(enc_options)


@util.dbg.eng_thread
def ghidra_trace_open(command: Optional[str] = None,
                      start_trace: bool = True) -> None:
    """Create a session."""

    dbg = util.dbg._base
    if command != None:
        util.open_trace_or_dump(command)
    if start_trace:
        ghidra_trace_start(command)


@util.dbg.eng_thread
def ghidra_trace_kill() -> None:
    """Kill a session."""

    dbg = util.dbg._base
    dbg._client.TerminateCurrentProcess()
    try:
        dbg.wait()
    except exception.E_UNEXPECTED_Error:
        # Expect the unexpected, I guess.
        pass


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


@util.dbg.eng_thread
def put_bytes(start: int, end: int, pages: bool,
              display_result: bool = False) -> Dict[str, int]:
    trace = STATE.require_trace()
    if pages:
        start, end = quantize_pages(start, end)
    nproc = util.selected_process()
    if end - start <= 0:
        return {'count': 0}
    try:
        buf = util.dbg._base.read(start, end - start)
    except OSError:
        return {'count': 0}

    count: Union[int, Future[int]] = 0
    if buf != None:
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


@util.dbg.eng_thread
def putreg() -> Dict[str, List[str]]:
    trace = STATE.require_trace()
    if util.dbg.use_generics:
        nproc = util.selected_process()
        if nproc < 0:
            return {}
        nthrd = util.selected_thread()
        rpath = REGS_PATTERN.format(procnum=nproc, tnum=nthrd)
        create_generic(rpath)
        trace.create_overlay_space('register', rpath)
        path = USER_REGS_PATTERN.format(procnum=nproc, tnum=nthrd)
        result = create_generic(path)
        if result is None:
            return {}
        values, keys = result
        nframe = util.selected_frame()
        # NB: We're going to update the Register View for non-zero stack frames
        if nframe == 0:
            missing = trace.put_registers(rpath, values)
            if isinstance(missing, Future):
                return {'future': []}
            return {'missing': missing}

    nproc = util.selected_process()
    if nproc < 0:
        return {}
    nthrd = util.selected_thread()
    space = REGS_PATTERN.format(procnum=nproc, tnum=nthrd)
    trace.create_overlay_space('register', space)
    robj = trace.create_object(space)
    robj.insert()
    mapper = trace.extra.require_rm()
    values = []
    regs = util.dbg._base.reg
    for i in range(0, len(regs)):
        name = regs._reg.GetDescription(i)[0]
        try:
            value = regs._get_register_by_index(i)
        except Exception:
            value = 0
        try:
            values.append(mapper.map_value(nproc, name, value))
            if util.dbg.use_generics is False:
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


@util.dbg.eng_thread
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
    regs = util.dbg._base.reg
    for i in range(0, len(regs)):
        name = regs._reg.GetDescription(i)[0]
        names.append(mapper.map_name(nproc, name))
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
    if (schema == sch.CHAR or schema == sch.BYTE or schema == sch.SHORT or
            schema == sch.INT or schema == sch.LONG or schema == None):
        value = util.parse_and_eval(value)
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
    NOTE: The type of an expression may be subject to the dbgeng's current
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
                frame = util.selected_frame()
                if frame is None:
                    path = THREAD_PATTERN.format(procnum=nproc, tnum=nthrd)
                else:
                    path = FRAME_PATTERN.format(
                        procnum=nproc, tnum=nthrd, level=frame)
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


@util.dbg.eng_thread
def compute_proc_state(nproc: Optional[int] = None) -> str:
    exit_code = util.GetExitCode()
    if exit_code is not None and exit_code != STILL_ACTIVE:
        return 'TERMINATED'
    status = util.dbg._base._control.GetExecutionStatus()
    if status == DbgEng.DEBUG_STATUS_BREAK:
        return 'STOPPED'
    return 'RUNNING'


def put_processes(running: bool = False) -> None:
    # | always displays PID in hex
    # TODO: I'm not sure about the engine id

    # NB: This speeds things up, but desirable?
    if running:
        return

    trace = STATE.require_trace()
    if util.dbg.use_generics and not running:
        ppath = PROCESSES_PATH
        result = create_generic(ppath)
        if result is None:
            return
        values, keys = result
        trace.proxy_object_path(PROCESSES_PATH).retain_values(keys)
        return

    keys = []
    # Set running=True to avoid process changes, even while stopped
    for i, p in enumerate(util.process_list(running=True)):
        ipath = PROCESS_PATTERN.format(procnum=i)
        keys.append(PROCESS_KEY_PATTERN.format(procnum=i))
        procobj = trace.create_object(ipath)

        istate = compute_proc_state(i)
        procobj.set_value('State', istate)
        pid = p[0]
        procobj.set_value('PID', pid)
        procobj.set_value('_display', f'{i:x} {pid:x}')
        if len(p) > 1:
            procobj.set_value('Name', str(p[1]))
            procobj.set_value('PEB', hex(int(p[2])))
        procobj.insert()
    trace.proxy_object_path(PROCESSES_PATH).retain_values(keys)


def put_state(event_process: int) -> None:
    ipath = PROCESS_PATTERN.format(procnum=event_process)
    trace = STATE.require_trace()
    procobj = trace.create_object(ipath)
    state = compute_proc_state(event_process)
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


@util.dbg.eng_thread
def put_available() -> None:
    trace = STATE.require_trace()
    radix = util.get_convenience_variable('output-radix')
    keys = []
    result = util.dbg._base.cmd(".tlist")
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
        procobj = trace.create_object(ppath)
        keys.append(AVAILABLE_KEY_PATTERN.format(pid=id))
        pidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(id)
        procobj.set_value('PID', id)
        procobj.set_value('Name', name)
        procobj.set_value('_display', '{} {}'.format(pidstr, name))
        procobj.insert()
    trace.proxy_object_path(AVAILABLES_PATH).retain_values(keys)


def ghidra_trace_put_available() -> None:
    """Put the list of available processes into the trace's Available list."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_available()


@util.dbg.eng_thread
def put_single_breakpoint(bp, ibobj, nproc: int, ikeys: List[str]) -> None:
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    bpath = PROC_BREAK_PATTERN.format(procnum=nproc, breaknum=bp.GetId())
    brkobj = trace.create_object(bpath)
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
        expr = util.dbg._base.get_name_by_offset(address)
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
        prot = 'SW_EXECUTE'

    if address is not None:  # Implies execution break
        base, addr = mapper.map(nproc, address)
        if base != addr.space:
            trace.create_overlay_space(base, addr.space)
        brkobj.set_value('Range', addr.extend(1))
    elif expr is not None:  # Implies watchpoint
        try:
            address = int(util.parse_and_eval('&({})'.format(expr)))
            base, addr = mapper.map(nproc, address)
            if base != addr.space:
                trace.create_overlay_space(base, addr.space)
            brkobj.set_value('Range', addr.extend(width))
        except Exception as e:
            print("Error: Could not get range for breakpoint: {}".format(e))
        else:  # I guess it's a catchpoint
            pass

    brkobj.set_value('Expression', expr)
    brkobj.set_value('Range', addr.extend(1))
    brkobj.set_value('Kinds', prot)
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


@util.dbg.eng_thread
def put_breakpoints() -> None:
    nproc = util.selected_process()

    # NB: Am leaving this code here in case we change our minds, but the cost
    #  of using put_generic here outweighs the advantage of uniformity
    #
    # if util.dbg.use_generics:
    #    path = PROC_BREAKS_PATTERN.format(procnum=nproc)
    #    (values, keys) = create_generic(path)
    #    STATE.trace.proxy_object_path(path).retain_values(keys)
    #    return

    trace = STATE.require_trace()
    target = util.get_target()
    ibpath = PROC_BREAKS_PATTERN.format(procnum=nproc)
    ibobj = trace.create_object(ibpath)
    keys: List[str] = []
    ikeys: List[str] = []
    ids = [bpid for bpid in util.dbg._base.breakpoints]
    for bpid in ids:
        try:
            bp = util.dbg._base._control.GetBreakpointById(bpid)
        except exception.E_NOINTERFACE_Error:
            util.dbg._base.breakpoints._remove_stale(bpid)
            continue
        keys.append(PROC_BREAK_KEY_PATTERN.format(breaknum=bpid))
        put_single_breakpoint(bp, ibobj, nproc, ikeys)
    ibobj.insert()
    trace.proxy_object_path(PROC_BREAKS_PATTERN).retain_values(keys)
    ibobj.retain_values(ikeys)


def ghidra_trace_put_breakpoints() -> None:
    """Put the current process's breakpoints into the trace."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_breakpoints()


def put_environment() -> None:
    trace = STATE.require_trace()
    nproc = util.selected_process()
    epath = ENV_PATTERN.format(procnum=nproc)
    envobj = trace.create_object(epath)
    envobj.set_value('Debugger', 'pydbg')
    envobj.set_value('Arch', arch.get_arch())
    envobj.set_value('OS', arch.get_osabi())
    envobj.set_value('Endian', arch.get_endian())
    envobj.insert()


def ghidra_trace_put_environment() -> None:
    """Put some environment indicators into the Ghidra trace."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_environment()


@util.dbg.eng_thread
def put_regions() -> None:
    nproc = util.selected_process()
    try:
        regions = util.dbg._base.memory_list()
    except Exception:
        regions = []
    if len(regions) == 0:
        regions = util.full_mem()

    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    keys = []
    # r : MEMORY_BASIC_INFORMATION64
    for r in regions:
        rpath = REGION_PATTERN.format(procnum=nproc, start=r.BaseAddress)
        keys.append(REGION_KEY_PATTERN.format(start=r.BaseAddress))
        regobj = trace.create_object(rpath)
        (start_base, start_addr) = map_address(r.BaseAddress)
        regobj.set_value('Range', start_addr.extend(r.RegionSize))
        regobj.set_value('_readable', r.Protect ==
                         None or r.Protect & 0x66 != 0)
        regobj.set_value('_writable', r.Protect ==
                         None or r.Protect & 0xCC != 0)
        regobj.set_value('_executable', r.Protect ==
                         None or r.Protect & 0xF0 != 0)
        regobj.set_value('AllocationBase', hex(r.AllocationBase))
        regobj.set_value('Protect', hex(r.Protect))
        regobj.set_value('Type', hex(r.Type))
        if hasattr(r, 'Name') and r.Name is not None:
            regobj.set_value('_display', r.Name)
        regobj.insert()
    # STATE.trace.proxy_object_path(
    #    MEMORY_PATTERN.format(procnum=nproc)).retain_values(keys)


def ghidra_trace_put_regions() -> None:
    """Read the memory map, if applicable, and write to the trace's Regions."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_regions()


@util.dbg.eng_thread
def put_modules() -> None:
    trace = STATE.require_trace()
    nproc = util.selected_process()
    if util.dbg.use_generics:
        mpath = MODULES_PATTERN.format(procnum=nproc)
        result = create_generic(mpath)
        if result is None:
            return
        values, keys = result
        trace.proxy_object_path(
            MODULES_PATTERN.format(procnum=nproc)).retain_values(keys)
        return

    target = util.get_target()
    modules = util.dbg._base.module_list()
    mapper = trace.extra.require_mm()
    mod_keys = []
    for m in modules:
        name = m[0][0]
        # m[1] : _DEBUG_MODULE_PARAMETERS
        base = m[1].Base
        hbase = hex(base)
        size = m[1].Size
        flags = m[1].Flags
        mpath = MODULE_PATTERN.format(procnum=nproc, modpath=hbase)
        modobj = trace.create_object(mpath)
        mod_keys.append(MODULE_KEY_PATTERN.format(modpath=hbase))
        base_base, base_addr = mapper.map(nproc, base)
        if base_base != base_addr.space:
            trace.create_overlay_space(base_base, base_addr.space)
        modobj.set_value('Range', base_addr.extend(size))
        modobj.set_value('Name', name)
        modobj.set_value('Flags', hex(size))
        modobj.insert()

        # TODO:  would be nice to list sections, but currently we have no API for
        #     it as far as I am aware
        # sec_keys = []
        # STATE.trace.proxy_object_path(
        #     mpath + SECTIONS_ADD_PATTERN).retain_values(sec_keys)

    trace.proxy_object_path(MODULES_PATTERN.format(
        procnum=nproc)).retain_values(mod_keys)


def get_module(key: str, mod) -> TraceObject:
    trace = STATE.require_trace()
    nproc = util.selected_process()
    modmap = util.get_attributes(mod)
    base = util.get_value(modmap["Address"])
    size = util.get_value(modmap["Size"])
    name = util.get_value(modmap["Name"])
    mpath = MODULE_PATTERN.format(procnum=nproc, modpath=hex(base))
    modobj = trace.create_object(mpath)
    mapper = trace.extra.require_mm()
    base_base, base_addr = mapper.map(nproc, base)
    if base_base != base_addr.space:
        trace.create_overlay_space(base_base, base_addr.space)
    modobj.set_value('Range', base_addr.extend(size))
    modobj.set_value('Name', name)
    modobj.set_value('_display', f'{key} {base:x} {name}')
    return modobj


def ghidra_trace_put_modules() -> None:
    """Gather object files, if applicable, and write to the trace's Modules."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_modules()


def convert_state(t) -> str:
    if t.IsSuspended():
        return 'SUSPENDED'
    if t.IsStopped():
        return 'STOPPED'
    return 'RUNNING'


def compute_thread_display(i: int, pid: Optional[int], tid: int, t) -> str:
    if len(t) > 1:
        return f'{i:x} {pid:x}:{tid:x} {t[2]}'
    return f'{i:x} {pid:x}:{tid:x}'


def put_threads(running: bool = False) -> None:
    # ~ always displays PID:TID in hex
    # TODO: I'm not sure about the engine id

    # NB: This speeds things up, but desirable?
    if running:
        return

    nproc = util.selected_process()
    if nproc is None:
        return
    trace = STATE.require_trace()
    if util.dbg.use_generics and not running:
        tpath = THREADS_PATTERN.format(procnum=nproc)
        result = create_generic(tpath)
        if result is None:
            return
        values, keys = result
        trace.proxy_object_path(
            THREADS_PATTERN.format(procnum=nproc)).retain_values(keys)
        return

    pid = util.dbg.pid

    keys = []
    # Set running=True to avoid thread changes, even while stopped
    for i, t in enumerate(util.thread_list(running=True)):
        tpath = THREAD_PATTERN.format(procnum=nproc, tnum=i)
        tobj = trace.create_object(tpath)
        keys.append(THREAD_KEY_PATTERN.format(tnum=i))

        tid = int(t[0])
        tobj.set_value('TID', tid)
        tobj.set_value('_short_display', f'{i:x} {pid:x}:{tid:x}')
        tobj.set_value('_display', compute_thread_display(i, pid, tid, t))
        if len(t) > 1:
            tobj.set_value('TEB', hex(int(t[1])))
            tobj.set_value('Name', t[2])
        tobj.insert()
    trace.proxy_object_path(THREADS_PATTERN.format(
        procnum=nproc)).retain_values(keys)


def put_event_thread(nthrd: Optional[int] = None) -> None:
    trace = STATE.require_trace()
    nproc = util.selected_process()
    # Assumption: Event thread is selected by pydbg upon stopping
    if nthrd is None:
        nthrd = util.selected_thread()
    if nthrd != None:
        tpath = THREAD_PATTERN.format(procnum=nproc, tnum=nthrd)
        tobj = trace.proxy_object_path(tpath)
    else:
        tobj = None
    trace.proxy_object_path('').set_value('_event_thread', tobj)


def get_thread(key: str, thread: ModelObject) -> TraceObject:
    pid = util.selected_process()
    tmap = util.get_attributes(thread)
    tid = int(key[1:len(key)-1])
    radix = util.get_convenience_variable('output-radix')
    if radix == 'auto':
        radix = 16
    tpath = THREAD_PATTERN.format(procnum=pid, tnum=tid)
    trace = STATE.require_trace()
    tobj = trace.create_object(tpath)
    tobj.set_value('TID', tid, span=Lifespan(0))
    tidstr = ('0x{:x}' if radix == 16 else '0{:o}' if radix ==
              8 else '{}').format(tid)
    tobj.set_value('_short_display', '[{}:{}]'.format(
        pid, tidstr), span=Lifespan(0))
    tobj.set_value('_display', '[{}]'.format(tidstr), span=Lifespan(0))
    return tobj


def ghidra_trace_put_threads() -> None:
    """Put the current process's threads into the Ghidra trace."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_threads()


@util.dbg.eng_thread
def put_frames() -> None:
    nproc = util.selected_process()
    if nproc < 0:
        return
    nthrd = util.selected_thread()
    if nthrd is None:
        return

    trace = STATE.require_trace()

    if util.dbg.use_generics:
        path = STACK_PATTERN.format(procnum=nproc, tnum=nthrd)
        result = create_generic(path)
        if result is None:
            return
        values, keys = result
        trace.proxy_object_path(path).retain_values(keys)
        # NB: some flavors of dbgmodel lack Attributes, so we grab Instruction Offset regardless
        # return

    mapper = trace.extra.require_mm()
    keys = []
    # f : _DEBUG_STACK_FRAME
    for f in util.dbg._base.backtrace_list():
        fpath = FRAME_PATTERN.format(
            procnum=nproc, tnum=nthrd, level=f.FrameNumber)
        fobj = trace.create_object(fpath)
        keys.append(FRAME_KEY_PATTERN.format(level=f.FrameNumber))
        base, offset_inst = mapper.map(nproc, f.InstructionOffset)
        if base != offset_inst.space:
            trace.create_overlay_space(base, offset_inst.space)
        fobj.set_value('Instruction Offset', offset_inst)
        if not util.dbg.use_generics:
            base, offset_stack = mapper.map(nproc, f.StackOffset)
            if base != offset_stack.space:
                trace.create_overlay_space(base, offset_stack.space)
            base, offset_ret = mapper.map(nproc, f.ReturnOffset)
            if base != offset_ret.space:
                trace.create_overlay_space(base, offset_ret.space)
            base, offset_frame = mapper.map(nproc, f.FrameOffset)
            if base != offset_frame.space:
                trace.create_overlay_space(base, offset_frame.space)
            fobj.set_value('Stack Offset', offset_stack)
            fobj.set_value('Return Offset', offset_ret)
            fobj.set_value('Frame Offset', offset_frame)
        fobj.set_value('_display', "#{} {}".format(
            f.FrameNumber, offset_inst.offset))
        fobj.insert()
    trace.proxy_object_path(STACK_PATTERN.format(
        procnum=nproc, tnum=nthrd)).retain_values(keys)


def ghidra_trace_put_frames() -> None:
    """Put the current thread's frames into the Ghidra trace."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_frames()


@util.dbg.eng_thread
def put_events() -> None:
    nproc = util.selected_process()
    if nproc < 0:
        return

    trace = STATE.require_trace()
    evtspath = PROC_EVENTS_PATTERN.format(procnum=nproc)
    keys = []
    (n_events, n_spec_exc, n_arb_exc) = util.GetNumberEventFilters()
    params = util.GetSpecificFilterParameters(0, n_events)
    for i in range(0, n_events):
        epath = PROC_EVENT_PATTERN.format(procnum=nproc, eventnum=i)
        eobj = trace.create_object(epath)
        keys.append(PROC_EVENT_KEY_PATTERN.format(eventnum=i))
        p = params[i]
        event_name = util.GetEventFilterText(i, p.TextSize)
        event_cmd = util.GetEventFilterCommand(i, p.CommandSize)
        event_arg = util.GetSpecificFilterArgument(i, p.ArgumentSize)
        eobj.set_value('Name', event_name)
        contobj = trace.create_object(epath+".Cont")
        contobj.set_value('_display', "Cont: {}".format(
            util.continue_options[p.ContinueOption]))
        contobj.insert()
        execobj = trace.create_object(epath+".Exec")
        execobj.set_value('_display', "Exec: {}".format(
            util.execution_options[p.ExecutionOption]))
        execobj.insert()
        if event_cmd is not None:
            eobj.set_value('Cmd', event_cmd)
        if event_arg is not None and event_arg != "":
            eobj.set_value('Arg', event_arg)
        eobj.set_value('_display', "{} {}".format(i, event_name))
        eobj.insert()
    trace.proxy_object_path(
        PROC_EVENTS_PATTERN.format(procnum=nproc)).retain_values(keys)


def ghidra_trace_put_events() -> None:
    """
    Put the event set into the Ghidra trace
    """

    client = STATE.require_client()
    with client.batch() as b:
        put_events()


@util.dbg.eng_thread
def put_exceptions() -> None:
    nproc = util.selected_process()
    if nproc < 0:
        return

    trace = STATE.require_trace()
    evtspath = PROC_EXCS_PATTERN.format(procnum=nproc)
    keys = []
    (n_events, n_spec_exc, n_arb_exc) = util.GetNumberEventFilters()
    params = util.GetExceptionFilterParameters(
        n_events, None, n_spec_exc+n_arb_exc)
    for i in range(0, n_spec_exc+n_arb_exc):
        epath = PROC_EXC_PATTERN.format(procnum=nproc, eventnum=i)
        eobj = trace.create_object(epath)
        keys.append(PROC_EXC_KEY_PATTERN.format(eventnum=i))
        p = params[i]
        put_single_exception(eobj, epath, p, n_events, i, i < n_spec_exc)
    trace.proxy_object_path(
        PROC_EXCS_PATTERN.format(procnum=nproc)).retain_values(keys)


@util.dbg.eng_thread
def put_single_exception(obj: TraceObject, objpath: str, 
                         p: DbgEng._DEBUG_EXCEPTION_FILTER_PARAMETERS, 
                         offset: int, index: int, specific: bool) -> None:
    exc_name = "None"
    if specific is True:
        exc_name = util.GetEventFilterText(offset + index, p.TextSize)
        obj.set_value('Name', exc_name)
    exc_cmd = util.GetEventFilterCommand(offset + index, p.CommandSize)
    exc_cmd2 = util.GetExceptionFilterSecondCommand(
        offset + index, p.SecondCommandSize)
    exc_code = hex(p.ExceptionCode)
    obj.set_value('Code', exc_code)
    trace = STATE.require_trace()
    contobj = trace.create_object(objpath+".Cont")
    contobj.set_value('_display', "Cont: {}".format(
        util.continue_options[p.ContinueOption]))
    contobj.insert()
    execobj = trace.create_object(objpath+".Exec")
    execobj.set_value('_display', "Exec: {}".format(
        util.execution_options[p.ExecutionOption]))
    execobj.insert()
    if exc_cmd is not None:
        obj.set_value('Cmd', exc_cmd)
    if exc_cmd2 is not None:
        obj.set_value('Cmd2', exc_cmd2)
    obj.set_value('_display', "{} {} [{}]".format(index, exc_name, exc_code))
    obj.insert()


def ghidra_trace_put_exceptions() -> None:
    """
    Put the event set into the Ghidra trace
    """

    client = STATE.require_client()
    with client.batch() as b:
        put_exceptions()


def toggle_evt_cont_option(n: int, events: List[DbgEng._DEBUG_SPECIFIC_FILTER_PARAMETERS]) -> None:
    """
    Toggle the event continue option
    """

    client = STATE.require_client()
    with client.batch() as b:
        option = events[0].ContinueOption
        option = (option+1) % 2
        events[0].ContinueOption = option
        util.SetSpecificFilterParameters(n, 1, events)


def toggle_evt_exec_option(n: int, events: List[DbgEng._DEBUG_SPECIFIC_FILTER_PARAMETERS]) -> None:
    """
    Toggle the event execution option
    """

    client = STATE.require_client()
    with client.batch() as b:
        option = events[0].ExecutionOption
        option = (option+1) % 4
        events[0].ExecutionOption = option
        util.SetSpecificFilterParameters(n, 1, events)


def toggle_exc_cont_option(n: int, events: List[DbgEng._DEBUG_EXCEPTION_FILTER_PARAMETERS]) -> None:
    """
    Toggle the event continue option
    """

    client = STATE.require_client()
    with client.batch() as b:
        option = events[0].ContinueOption
        option = (option+1) % 2
        events[0].ContinueOption = option
        util.SetExceptionFilterParameters(1, events)


def toggle_exc_exec_option(n: int, events: List[DbgEng._DEBUG_EXCEPTION_FILTER_PARAMETERS]) -> None:
    """
    Toggle the event execution option
    """

    client = STATE.require_client()
    with client.batch() as b:
        option = events[0].ExecutionOption
        option = (option+1) % 4
        events[0].ExecutionOption = option
        util.SetExceptionFilterParameters(1, events)


def update_key(np: str, keyval: Tuple[int, ModelObject]) -> Union[int, str]:
    """This should set the modified key."""
    key: Union[int, str] = keyval[0]
    if np.endswith("Modules"):
        key = f'[{key:d}]'
        mo = util.get_object(np+key+".BaseAddress")
        if mo is None:
            return keyval[0]
        key = hex(util.get_value(mo))
    return key


def update_by_container(np: str, keyval: Tuple[int, ModelObject],
                        to: TraceObject) -> None:
    """Sets non-generic variables by container."""
    topath = to.str_path()
    key = keyval[0]
    disp = ''
    if np.endswith("Processes") or np.endswith("Threads"):
        istate = compute_proc_state(key)
        to.set_value('State', istate)
    if np.endswith("Sessions"):
        disp = '[{:x}]'.format(key)
    if np.endswith("Processes"):
        create_generic(topath)
        to.set_value('PID', key)
        create_generic(to.str_path() + ".Memory")
        if util.is_kernel():
            disp = '[{:x}]'.format(key)
        else:
            id = util.get_proc_id(key)
            disp = f'{id:x} [{key:x}]'
    if np.endswith("Breakpoints"):
        create_generic(topath)
    if np.endswith("Threads"):
        create_generic(topath)
        to.set_value('TID', key)
        if util.is_kernel():
            disp = f'[{key:x}]'
        else:
            id = util.get_thread_id(key)
            disp = f'{id:x} [{key:x}]'
    if np.endswith("Frames"):
        mo = util.get_object(to.str_path())
        if mo is not None:
            map = util.get_attributes(mo)
            if 'Attributes' in map:
                attr = map["Attributes"]
                if attr is not None:
                    map = util.get_attributes(attr)
                    pc = util.get_value(map["InstructionOffset"])
                    pc_base, pc_addr = map_address(pc)
                    to.set_value('Instruction Offset', pc_addr)
                    disp = '#{:x} 0x{:x}'.format(key, pc)
    if np.endswith("Modules"):
        modobjpath = np+'[{:d}]'.format(key)
        create_generic(topath, modobjpath=modobjpath)
        mo = util.get_object(modobjpath)
        if mo is not None:
            map = util.get_attributes(mo)
            base = util.get_value(map["BaseAddress"])
            size = util.get_value(map["Size"])
            name = util.get_value(map["Name"])
            to.set_value('Name', '{}'.format(name))
            base_base, base_addr = map_address(base)
            to.set_value('Range', base_addr.extend(size))
            disp = '{:x} {:x} {}'.format(key, base, name)
    disp0 = util.to_display_string(keyval[1])
    if disp0 is not None:
        disp += " " + disp0
    if disp is not None and disp != "":
        to.set_value('_display', disp)


def create_generic(path: str, modobjpath: Optional[str] = None) -> Optional[
        Tuple[List[RegVal], List[str]]]:
    obj = STATE.require_trace().create_object(path)
    result = put_generic(obj, modobjpath)
    obj.insert()
    return result


def put_generic_from_node(node: TraceObject):
    obj = STATE.require_trace().create_object(node.str_path())
    result = put_generic(obj, None)
    obj.insert()
    return result


def put_generic(node: TraceObject, modobjpath: Optional[str] = None) -> Optional[
        Tuple[List[RegVal], List[str]]]:
    """Populate a TraceObject with the generic contents of a ModelObject.

    The returned tuple has two parts. If applicable, the first contains the
    register values, as derived from the attributes of the .User node. The
    second part is the list of element keys.
    """
    # print(f"put_generic: {node}")
    nproc = util.selected_process()
    if nproc is None:
        return None
    nthrd = util.selected_thread()

    nodepath = node.str_path()
    if modobjpath is None:
        mo = util.get_object(nodepath)
    else:
        mo = util.get_object(modobjpath)
    trace = STATE.require_trace()
    mapper = trace.extra.require_rm()

    if mo is None:
        print(f"No such object: {nodepath} (override={modobjpath})")
        return None

    attributes = util.get_attributes(mo)
    # print(f"ATTR={attributes}")
    values: List[RegVal] = []
    if attributes is not None:
        for key, value in attributes.items():
            kind = util.get_kind(value)
            if kind == ModelObjectKind.METHOD.value:
                continue
            # print(f"key={key} kind={kind}")
            if kind != ModelObjectKind.INTRINSIC.value:
                apath = nodepath + '.' + key
                aobj = trace.create_object(apath)
                set_display(key, value, aobj)
                aobj.insert()
            else:
                val = util.get_value(value)
                try:
                    if nodepath.endswith('.User'):
                        # print(f"PUT_REG: {key} {val}")
                        values.append(mapper.map_value(nproc, key, val))
                        node.set_value(key, hex(val))
                    elif isinstance(val, int):
                        v_base, v_addr = map_address(val)
                        node.set_value(
                            key, v_addr, schema=sch.ADDRESS)
                    else:
                        node.set_value(key, val)
                except Exception as e:
                    print(f"Attribute exception for {key} {type(val)}: {e}")
    elements = util.get_elements(mo)
    # print(f"ELEM={elements}")
    keys = []
    if elements is not None:
        for el in elements:
            key = GENERIC_KEY_PATTERN.format(key=update_key(nodepath, el))
            lpath = nodepath + key
            lobj = trace.create_object(lpath)
            update_by_container(nodepath, el, lobj)
            lobj.insert()
            keys.append(key)
        node.retain_values(keys)
    return values, keys


def set_display(key: str, value: ModelObject, obj: TraceObject) -> None:
    kind = util.get_kind(value)
    vstr = util.get_value(value)
    # istr = util.get_intrinsic_value(value)
    if kind == ModelObjectKind.TARGET_OBJECT.value:
        hloc = util.get_location(value)
        ti = util.get_type_info(value)
        if ti is not None:
            name = util.get_name(ti)
            if name is not None:
                key += " : " + name
                obj.set_value('_display', key)
        if hloc is not None:
            key += " @ " + str(hloc)
            obj.set_value('_display', key)
            (hloc_base, hloc_addr) = map_address(int(hloc, 0))
            obj.set_value('_address', hloc_addr, schema=sch.ADDRESS)
    if vstr is not None:
        key += " : " + str(vstr)
        obj.set_value('_display', key)


def map_address(address: int) -> Tuple[str, Address]:
    nproc = util.selected_process()
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    base, addr = mapper.map(nproc, address)
    if base != addr.space:
        trace.create_overlay_space(base, addr.space)
    return base, addr


def ghidra_trace_put_generic(node: TraceObject) -> None:
    """Put the current thread's frames into the Ghidra trace."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_generic_from_node(node)


def init_ttd() -> None:
    # print(f"put_events: {node}")
    trace = STATE.require_trace()
    with open_tracked_tx('Init TTDState'):
        ttd = util.ttd
        nproc = util.selected_process()
        path = TTD_PATTERN.format(var="curprocess") + ".Lifetime"
        result = create_generic(path)
        if result is None:
            raise AssertionError("No process in TTD mode?")
        lifetime = util.get_object(path)
        if lifetime is None:
            raise AssertionError("No lifetime in TTD mode?")
        map = util.get_attributes(lifetime)
        ttd._first = util.pos2split(map["MinPosition"])
        ttd._last = util.pos2split(map["MaxPosition"])
        ttd._lastpos = ttd._first
        ttd.MAX_STEP = 0xFFFFFFFFFFFFFFFE
        time = util.split2schedule(ttd._first)
        description = util.compute_description(time, "First")
        trace.snapshot(description, time=time)


def put_trace_events() -> None:
    trace = STATE.require_trace()
    ttd = util.ttd
    nproc = util.selected_process()
    path = TTD_PATTERN.format(var="curprocess")+".Events"
    result = create_generic(path)
    if result is None:
        raise AssertionError("No process in TTD mode?")
    values, keys = result
    for k in keys:
        event = util.get_object(path+k)
        if event is None:
            raise AssertionError("Iterated key ought to be valid")
        map = util.get_attributes(event)
        type = util.get_value(map["Type"])
        pos = util.pos2split(map["Position"])
        ttd.evttypes[pos] = type

        time = util.split2schedule(pos)
        major, minor = pos
        snap = trace.snapshot(util.DESCRIPTION_PATTERN.format(
            major=major, minor=minor, type=type), time=time)
        if type == "ModuleLoaded" or type == "ModuleUnloaded":
            mod = map["Module"]
            mobj = get_module(k, mod)
            if type == "ModuleLoaded":
                mobj.insert(span=Lifespan(snap))
            else:
                mobj.remove(span=Lifespan(snap))
        if type == "ThreadCreated" or type == "ThreadTerminated":
            t = map["Thread"]
            tobj = get_thread(k, t)
            if type == "ThreadCreated":
                tobj.insert(span=Lifespan(snap))
            else:
                tobj.remove(span=Lifespan(snap))
    hooks.on_stop()


def ghidra_trace_put_trace_events() -> None:
    """Put the event set the Ghidra trace."""
    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_trace_events()


def put_trace_events_custom(prefix: str, cmd: str) -> None:
    result = util.dbg.cmd("{prefix}.{cmd}".format(prefix=prefix, cmd=cmd))
    if result.startswith("Error"):
        print(result)
        return
    trace = STATE.require_trace()
    nproc = util.selected_process()
    mapper = trace.extra.require_mm()
    path = TTD_PATTERN.format(var="cursession")+".CustomEvents"
    obj = trace.create_object(path)
    index = 0
    addr = size = start = stop = None
    attrs = {}
    keys = []
    for l in result.split('\n'):
        split = l.split(":")
        id = split[0].strip()
        if id == "Address":
            addr = int(split[1].strip(), 16)
        elif id == "Size":
            size = int(split[1].strip(), 16)
        elif id == "TimeStart":
            start = util.mm2schedule(int(split[1], 16), int(split[2], 16))
        elif id == "TimeEnd":
            stop = util.mm2schedule(int(split[1], 16), int(split[2], 16))
        elif " : " in l:
            attrs[id] = l[l.index(":"):].strip()
        if addr is not None and size is not None and start is not None and stop is not None:
            with open_tracked_tx('Populate events'):
                key = f"[{addr:x}]"
                trace.snapshot(
                    f"[{start.snap:x}] EventCreated {key} ", time=start)
                if start.snap > stop.snap:
                    print(f"ERROR: {start}--{stop}")
                    continue
                span = Lifespan(start.snap, stop.snap)
                rpath = REGION_PATTERN.format(procnum=nproc, start=addr)
                keys.append(REGION_KEY_PATTERN.format(start=addr))
                regobj = trace.create_object(rpath)
                start_base, start_addr = map_address(addr)
                rng = start_addr.extend(size)
                regobj.set_value('Range', rng, span=span)
                regobj.set_value('_range', rng, span=span)
                regobj.set_value('_display', hex(addr), span=span)
                regobj.set_value('_cmd', cmd)
                for (k, v) in attrs.items():
                    regobj.set_value(k, v, span=span)
                regobj.insert(span=span)
                keys.append(key)
            index += 1
            addr = size = start = stop = None
            attrs = {}
    obj.insert()
    trace.proxy_object_path(TTD_PATTERN.format(
        var="cursession")).retain_values(keys)
    hooks.on_stop()


def ghidra_trace_put_trace_events_custom(prefix: str, cmd: str) -> None:
    """Generate events by cmd and put them into the Ghidra trace."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_trace_events_custom(prefix, cmd)


def ghidra_trace_put_all() -> None:
    """Put everything currently selected into the Ghidra trace."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
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
        ghidra_trace_putmem(util.get_pc(), 1)
        ghidra_trace_putmem(util.get_sp(), 1)


def ghidra_trace_install_hooks() -> None:
    """Install hooks to trace in Ghidra."""

    hooks.install_hooks()


def ghidra_trace_remove_hooks() -> None:
    """Remove hooks to trace in Ghidra.

    Using this directly is not recommended, unless it seems the hooks
    are preventing pydbg or other extensions from operating. Removing
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
    you'd like to synchronize. In older versions of pydbg, certain
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
        return util.dbg.get_prompt_text()
    except util.DebuggeeRunningException:
        return 'Running>'


@util.dbg.eng_thread
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
        except util.DebuggeeRunningException as e:
            print("")
            print("Debuggee is Running. Use Ctrl-C to interrupt.")
        except BaseException as e:
            pass  # Error is printed by another mechanism
    print("")
    print("You have left the Windows Debugger REPL and are now at the Python "
          "interpreter.")
    print("To re-enter, type repl()")
