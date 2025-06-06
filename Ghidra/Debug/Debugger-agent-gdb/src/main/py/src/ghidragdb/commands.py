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
import socket
import time
from typing import (Any, Callable, Dict, Generator, List, Optional, Sequence,
                    Tuple, Type, TypeVar, Union)

try:
    import psutil
except ImportError:
    print(f"Unable to import 'psutil' - check that it has been installed")

from ghidratrace import sch
from ghidratrace.client import (Client, Address, AddressRange, Lifespan,
                                Schedule, Trace, TraceObject, TraceObjectValue,
                                Transaction)
from ghidratrace.display import print_tabular_values, wait, wait_opt

import gdb

from . import arch, hooks, methods, util

T = TypeVar('T')
U = TypeVar('U')
C = TypeVar('C', bound=Callable)

PAGE_SIZE = 4096

AVAILABLES_PATH = 'Available'
AVAILABLE_KEY_PATTERN = '[{pid}]'
AVAILABLE_PATTERN = AVAILABLES_PATH + AVAILABLE_KEY_PATTERN
BREAKPOINTS_PATH = 'Breakpoints'
BREAKPOINT_KEY_PATTERN = '[{breaknum}]'
BREAKPOINT_PATTERN = BREAKPOINTS_PATH + BREAKPOINT_KEY_PATTERN
BREAK_LOC_KEY_PATTERN = '[{locnum}]'
INFERIORS_PATH = 'Inferiors'
INFERIOR_KEY_PATTERN = '[{infnum}]'
INFERIOR_PATTERN = INFERIORS_PATH + INFERIOR_KEY_PATTERN
INF_BREAKS_PATTERN = INFERIOR_PATTERN + '.Breakpoints'
INF_BREAK_KEY_PATTERN = '[{breaknum}.{locnum}]'
ENV_PATTERN = INFERIOR_PATTERN + '.Environment'
THREADS_PATTERN = INFERIOR_PATTERN + '.Threads'
THREAD_KEY_PATTERN = '[{tnum}]'
THREAD_PATTERN = THREADS_PATTERN + THREAD_KEY_PATTERN
STACK_PATTERN = THREAD_PATTERN + '.Stack'
FRAME_KEY_PATTERN = '[{level}]'
FRAME_PATTERN = STACK_PATTERN + FRAME_KEY_PATTERN
REGS_PATTERN = FRAME_PATTERN + '.Registers'
MEMORY_PATTERN = INFERIOR_PATTERN + '.Memory'
REGION_KEY_PATTERN = '[{start:08x}]'
REGION_PATTERN = MEMORY_PATTERN + REGION_KEY_PATTERN
MODULES_PATTERN = INFERIOR_PATTERN + '.Modules'
MODULE_KEY_PATTERN = '[{modpath}]'
MODULE_PATTERN = MODULES_PATTERN + MODULE_KEY_PATTERN
SECTIONS_ADD_PATTERN = '.Sections'
SECTION_KEY_PATTERN = '[{secname}]'
SECTION_ADD_PATTERN = SECTIONS_ADD_PATTERN + SECTION_KEY_PATTERN


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
            raise gdb.GdbError("Not connected")
        return self.client

    def require_no_client(self) -> None:
        if self.client is not None:
            raise gdb.GdbError("Already connected")

    def reset_client(self) -> None:
        self.client: Optional[Client] = None
        self.reset_trace()

    def require_trace(self) -> Trace[Extra]:
        if self.trace is None:
            raise gdb.GdbError("No trace active")
        return self.trace

    def require_no_trace(self) -> None:
        if self.trace is not None:
            raise gdb.GdbError("Trace already started")

    def reset_trace(self) -> None:
        self.trace: Optional[Trace[Extra]] = None
        gdb.set_convenience_variable('_ghidra_tracing', False)
        self.reset_tx()

    def require_tx(self) -> Tuple[Trace[Extra], Transaction]:
        trace = self.require_trace()
        if self.tx is None:
            raise gdb.GdbError("No transaction")
        return trace, self.tx

    def require_no_tx(self) -> None:
        if self.tx is not None:
            raise gdb.GdbError("Transaction already started")

    def reset_tx(self) -> None:
        self.tx: Optional[Transaction] = None


STATE = State()


def install(cmd: Callable) -> None:
    cmd()


@install
class GhidraPrefix(gdb.Command):
    """Commands for connecting to Ghidra."""

    def __init__(self) -> None:
        super().__init__('ghidra', gdb.COMMAND_SUPPORT, prefix=True)


@install
class GhidraTracePrefix(gdb.Command):
    """Commands for exporting data to a Ghidra trace."""

    def __init__(self) -> None:
        super().__init__('ghidra trace', gdb.COMMAND_DATA, prefix=True)


@install
class GhidraUtilPrefix(gdb.Command):
    """Utility commands for testing with Ghidra."""

    def __init__(self) -> None:
        super().__init__('ghidra util', gdb.COMMAND_NONE, prefix=True)


def cmd(cli_name: str, mi_name: str, cli_class: int, cli_repeat: bool) -> Callable[[C], C]:

    def _cmd(func: C) -> C:

        class _CLICmd(gdb.Command):

            def __init__(self) -> None:
                super().__init__(cli_name, cli_class)

            def invoke(self, argument: str, from_tty: bool) -> None:
                if not cli_repeat:
                    self.dont_repeat()
                argv = gdb.string_to_argv(argument)
                try:
                    func(*argv, is_mi=False, from_tty=from_tty)
                except TypeError as e:
                    # TODO: This is a bit of a hack, but it works nicely
                    raise gdb.GdbError(
                        e.args[0].replace(func.__name__ + "()", "'" + cli_name + "'"))

        _CLICmd.__doc__ = func.__doc__
        _CLICmd()

        if hasattr(gdb, 'MICommand'):
            class _MICmd(gdb.MICommand):

                def __init__(self) -> None:
                    super().__init__(mi_name)

                def invoke(self, argv) -> Any:
                    try:
                        return func(*argv, is_mi=True)
                    except TypeError as e:
                        raise gdb.GdbError(e.args[0].replace(func.__name__ + "()",
                                           mi_name))

            _MICmd.__doc__ = func.__doc__
            _MICmd()
        return func

    return _cmd


@cmd('ghidra trace connect', '-ghidra-trace-connect', gdb.COMMAND_SUPPORT,
     False)
def ghidra_trace_connect(address: str, *, is_mi: bool, **kwargs) -> None:
    """Connect GDB to Ghidra for tracing.

    Address must be of the form 'host:port'
    """

    STATE.require_no_client()
    parts = address.split(':')
    if len(parts) != 2:
        raise gdb.GdbError("address must be in the form 'host:port'")
    host, port = parts
    try:
        c = socket.socket()
        c.connect((host, int(port)))
        STATE.client = Client(
            c, "gdb-" + util.GDB_VERSION.full, methods.REGISTRY)
        print(f"Connected to {STATE.client.description} at {address}")
    except ValueError:
        raise gdb.GdbError("port must be numeric")


@cmd('ghidra trace listen', '-ghidra-trace-listen', gdb.COMMAND_SUPPORT, False)
def ghidra_trace_listen(address: Optional[str] = None, *, is_mi: bool,
                        **kwargs) -> None:
    """Listen for Ghidra to connect for tracing.

    Takes an optional address for the host and port on which to listen.
    Either the form 'host:port' or just 'port'. If omitted, it will bind
    to an ephemeral port on all interfaces. If only the port is given,
    it will bind to that port on all interfaces. This command will block
    until the connection is established.
    """

    STATE.require_no_client()
    host: str
    port: Union[str, int]
    if address is not None:
        parts = address.split(':')
        if len(parts) == 1:
            host, port = '0.0.0.0', parts[0]
        elif len(parts) == 2:
            host, port = parts
        else:
            raise gdb.GdbError("address must be 'port' or 'host:port'")
    else:
        host, port = '0.0.0.0', 0
    try:
        s = socket.socket()
        s.bind((host, int(port)))
        host, port = s.getsockname()
        s.listen(1)
        gdb.write(f"Listening at {host}:{port}...\n")
        c, (chost, cport) = s.accept()
        s.close()
        gdb.write(f"Connection from {chost}:{cport}\n")
        STATE.client = Client(
            c, "gdb-" + util.GDB_VERSION.full, methods.REGISTRY)
    except ValueError:
        raise gdb.GdbError("port must be numeric")


@cmd('ghidra trace disconnect', '-ghidra-trace-disconnect', gdb.COMMAND_SUPPORT,
     False)
def ghidra_trace_disconnect(*, is_mi: bool, **kwargs) -> None:
    """Disconnect GDB from Ghidra for tracing."""

    STATE.require_client().close()
    STATE.reset_client()


def compute_name() -> str:
    progname = gdb.selected_inferior().progspace.filename
    if progname is None:
        return 'gdb/noname'
    else:
        return 'gdb/' + progname.split('/')[-1]


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
        root = STATE.trace.create_root_object(schema_xml, 'GdbSession')
        root.set_value('_display', 'GNU gdb ' + util.GDB_VERSION.full)
        STATE.trace.create_object(AVAILABLES_PATH).insert()
        STATE.trace.create_object(BREAKPOINTS_PATH).insert()
        STATE.trace.create_object(INFERIORS_PATH).insert()
    gdb.set_convenience_variable('_ghidra_tracing', True)


@cmd('ghidra trace start', '-ghidra-trace-start', gdb.COMMAND_DATA, False)
def ghidra_trace_start(name: Optional[str] = None, *, is_mi: bool,
                       **kwargs) -> None:
    """Start a Trace in Ghidra."""

    STATE.require_client()
    if name is None:
        name = compute_name()
    STATE.require_no_trace()
    start_trace(name)


@cmd('ghidra trace stop', '-ghidra-trace-stop', gdb.COMMAND_DATA, False)
def ghidra_trace_stop(*, is_mi: bool, **kwargs) -> None:
    """Stop the Trace in Ghidra."""

    STATE.require_trace().close()
    STATE.reset_trace()


@cmd('ghidra trace restart', '-ghidra-trace-restart', gdb.COMMAND_DATA, False)
def ghidra_trace_restart(name: Optional[str] = None, *, is_mi: bool,
                         **kwargs) -> None:
    """Restart or start the Trace in Ghidra."""

    STATE.require_client()
    if STATE.trace is not None:
        STATE.trace.close()
        STATE.reset_trace()
    if name is None:
        name = compute_name()
    start_trace(name)


@cmd('ghidra trace info', '-ghidra-trace-info', gdb.COMMAND_STATUS, True)
def ghidra_trace_info(*, is_mi: bool, **kwargs) -> Dict[str, Any]:
    """Get info about the Ghidra connection."""

    result: Dict[str, Any] = {}
    if STATE.client is None:
        if not is_mi:
            gdb.write("Not connected to Ghidra\n")
        return result
    host, port = STATE.client.s.getpeername()
    if is_mi:
        result['description'] = STATE.client.description
        result['address'] = f"{host}:{port}"
    else:
        gdb.write(
            f"Connected to {STATE.client.description} at {host}:{port}\n")
    if STATE.trace is None:
        if is_mi:
            result['tracing'] = False
        else:
            gdb.write("No trace\n")
        return result
    if is_mi:
        result['tracing'] = True
    else:
        gdb.write("Trace active\n")
    return result


@cmd('ghidra trace lcsp', '-ghidra-trace-lcsp', gdb.COMMAND_STATUS, True)
def ghidra_trace_info_lcsp(*, is_mi: bool, **kwargs) -> Dict[str, str]:
    """Get the selected Ghidra language-compiler-spec pair.

    Even when 'show ghidra language' is 'auto' and/or 'show ghidra
    compiler' is 'auto', this command provides the current actual
    language and compiler spec.
    """

    language, compiler = arch.compute_ghidra_lcsp()
    if is_mi:
        return {'language': language, 'compiler': compiler}
    else:
        gdb.write(f"Selected Ghidra language: {language}\n")
        gdb.write(f"Selected Ghidra compiler: {compiler}\n")
        return {}


@cmd('ghidra trace tx-start', '-ghidra-trace-tx-start', gdb.COMMAND_DATA, False)
def ghidra_trace_txstart(description: str, *, is_mi: bool, **kwargs) -> None:
    """Start a transaction on the trace."""

    STATE.require_no_tx()
    STATE.tx = STATE.require_trace().start_tx(description, undoable=False)


@cmd('ghidra trace tx-commit', '-ghidra-trace-tx-commit', gdb.COMMAND_DATA,
     False)
def ghidra_trace_txcommit(*, is_mi: bool, **kwargs) -> None:
    """Commit the current transaction."""

    STATE.require_tx()[1].commit()
    STATE.reset_tx()


@cmd('ghidra trace tx-abort', '-ghidra-trace-tx-abort', gdb.COMMAND_DATA, False)
def ghidra_trace_txabort(*, is_mi: bool, **kwargs) -> None:
    """Abort the current transaction.

    Use only in emergencies.
    """

    trace, tx = STATE.require_tx()
    gdb.write("Aborting trace transaction!\n")
    tx.abort()
    STATE.reset_tx()


@contextmanager
def open_tracked_tx(description: str) -> Generator[Transaction, None, None]:
    with STATE.require_trace().open_tx(description) as tx:
        STATE.tx = tx
        yield tx
    STATE.reset_tx()


@cmd('ghidra trace tx-open', '-ghidra-trace-tx-open', gdb.COMMAND_DATA, False)
def ghidra_trace_tx(description: str, command: str, *, is_mi: bool,
                    **kwargs) -> None:
    """Run a command with an open transaction.

    If possible, use this in the following idiom to ensure your transactions
    are closed:

       define my-cmd
         ghidra trace put...
         ghidra trace put...
       end
       ghidra trace tx-open "My tx" "my-cmd"

    If you instead do:

       ghidra trace tx-start "My tx"
       ghidra trace put...
       ghidra trace put...
       ghidra trace tx-commit

    and something goes wrong with one of the puts, the transaction may never be
    closed, leading to further crashes when trying to start a new transaction.
    """

    with open_tracked_tx(description):
        gdb.execute(command)


@cmd('ghidra trace save', '-ghidra-trace-save', gdb.COMMAND_DATA, False)
def ghidra_trace_save(*, is_mi: bool, **kwargs) -> None:
    """Save the current trace."""

    STATE.require_trace().save()


@cmd('ghidra trace new-snap', '-ghidra-trace-new-snap', gdb.COMMAND_DATA, False)
def ghidra_trace_new_snap(snap: str, description: Optional[str] = None, *,
                          is_mi: bool, **kwargs) -> Dict[str, int]:
    """Create a new snapshot.

    Subsequent modifications to machine state will affect the new
    snapshot.
    """

    if description is None:
        description = snap
        time = None
    else:
        time = Schedule(int(snap))
    STATE.require_tx()
    return {'snap': STATE.require_trace().snapshot(description, time=time)}


# TODO: A convenience var for the current snapshot
# Will need to update it on:
#     ghidra trace snapshot/set-snap
#     inferior ? (only if per-inferior tracing.... I don't think I'm doing that.)
#     ghidra trace trace start/stop/restart


def quantize_pages(start: int, end: int) -> Tuple[int, int]:
    return (start // PAGE_SIZE * PAGE_SIZE, (end+PAGE_SIZE-1) // PAGE_SIZE*PAGE_SIZE)


def put_bytes(start: int, end: int, pages: bool, is_mi: bool,
              from_tty: bool) -> Dict[str, int]:
    trace = STATE.require_trace()
    if pages:
        start, end = quantize_pages(start, end)
    inf = gdb.selected_inferior()
    buf = bytes(inf.read_memory(start, end - start))

    base, addr = trace.extra.require_mm().map(inf, start)
    if base != addr.space:
        trace.create_overlay_space(base, addr.space)

    count = trace.put_bytes(addr, buf)
    if from_tty and not is_mi:
        if isinstance(count, Future):
            count.add_done_callback(lambda c: gdb.write(f"Wrote {c} bytes\n"))
        else:
            gdb.write(f"Wrote {count} bytes\n")
    if isinstance(count, Future):
        return {'count': -1}
    else:
        return {'count': count}


def eval_address(address: str) -> int:
    max_addr = util.compute_max_addr()
    if isinstance(address, int):
        return address & max_addr
    try:
        return int(gdb.parse_and_eval(address)) & max_addr
    except gdb.error as e:
        raise gdb.GdbError(f"Cannot convert '{address}' to address")


def eval_range(address: str, length: str) -> Tuple[int, int]:
    start = eval_address(address)
    if isinstance(length, int):
        end = start + length
    else:
        try:
            end = start + int(gdb.parse_and_eval(length))
        except gdb.error as e:
            raise gdb.GdbError(f"Cannot convert '{length}' to length")
    return start, end


def putmem(address: str, length: str, pages: bool = True, is_mi: bool = False,
           from_tty: bool = True) -> Dict[str, int]:
    start, end = eval_range(address, length)
    return put_bytes(start, end, pages, is_mi, from_tty)


@cmd('ghidra trace putmem', '-ghidra-trace-putmem', gdb.COMMAND_DATA, True)
def ghidra_trace_putmem(address: str, length: str, pages: bool = True, *,
                        is_mi: bool, from_tty: bool = True,
                        **kwargs) -> Dict[str, int]:
    """Record the given block of memory into the Ghidra trace."""

    STATE.require_tx()
    return putmem(address, length, pages, is_mi, from_tty)


@cmd('ghidra trace putval', '-ghidra-trace-putval', gdb.COMMAND_DATA, True)
def ghidra_trace_putval(value: str, pages: bool = True, *, is_mi: bool,
                        from_tty: bool = True, **kwargs) -> Dict[str, int]:
    """Record the given value into the Ghidra trace, if it's in memory."""

    STATE.require_tx()
    val = gdb.parse_and_eval(value)
    try:
        start = int(val.address)
    except gdb.error as e:
        raise gdb.GdbError(f"Value '{value}' has no address")
    end = start + int(val.dynamic_type.sizeof)
    return put_bytes(start, end, pages, is_mi, from_tty)


def putmem_state(address: str, length: str, state: str,
                 pages: bool = True) -> None:
    trace = STATE.require_trace()
    trace.validate_state(state)
    start, end = eval_range(address, length)
    if pages:
        start, end = quantize_pages(start, end)
    inf = gdb.selected_inferior()
    base, addr = trace.extra.require_mm().map(inf, start)
    if base != addr.space:
        trace.create_overlay_space(base, addr.space)
    trace.set_memory_state(addr.extend(end - start), state)


@cmd('ghidra trace putmem-state', '-ghidra-trace-putmem-state',
     gdb.COMMAND_DATA, True)
def ghidra_trace_putmem_state(address: str, length: str, state: str, *,
                              is_mi: bool, **kwargs) -> None:
    """Set the state of the given range of memory in the Ghidra trace."""

    STATE.require_tx()
    putmem_state(address, length, state, True)


@cmd('ghidra trace delmem', '-ghidra-trace-delmem', gdb.COMMAND_DATA, True)
def ghidra_trace_delmem(address: str, length: str, *, is_mi: bool,
                        **kwargs) -> None:
    """Delete the given range of memory from the Ghidra trace.

    Why would you do this? Keep in mind putmem quantizes to full pages
    by default, usually to take advantage of spatial locality. This
    command does not quantize. You must do that yourself, if necessary.
    """

    trace, tx = STATE.require_tx()
    start, end = eval_range(address, length)
    inf = gdb.selected_inferior()
    base, addr = trace.extra.require_mm().map(inf, start)
    # Do not create the space. We're deleting stuff.
    trace.delete_bytes(addr.extend(end - start))


def putreg(frame: gdb.Frame, reg_descs: Sequence[
    Union[util.RegisterDesc, gdb.RegisterDescriptor]
]) -> Dict[str, List[str]]:
    inf = gdb.selected_inferior()
    space = REGS_PATTERN.format(infnum=inf.num, tnum=gdb.selected_thread().num,
                                level=util.get_level(frame))
    trace = STATE.require_trace()
    trace.create_overlay_space('register', space)
    cobj = trace.create_object(space)
    cobj.insert()
    mapper = trace.extra.require_rm()

    keys = []
    values = []
    # NB: This command will fail if the process is running
    for desc in reg_descs:
        v = frame.read_register(desc.name)
        rv = mapper.map_value(inf, desc.name, v)
        values.append(rv)
        # Mapper has converted to big endian.
        # Display value should interpret it as such.
        value = hex(int.from_bytes(rv.value, byteorder='big'))
        cobj.set_value(desc.name, str(value))
        keys.append(desc.name)
    cobj.retain_values(keys)
    # TODO: Memorize registers that failed for this arch, and omit later.
    missing = trace.put_registers(space, values)
    if isinstance(missing, Future):
        return {'future': []}
    return {'missing': missing}


@cmd('ghidra trace putreg', '-ghidra-trace-putreg', gdb.COMMAND_DATA, True)
def ghidra_trace_putreg(group: str = 'all', *, is_mi: bool,
                        **kwargs) -> Dict[str, List[str]]:
    """Record the given register group for the current frame into the Ghidra
    trace.

    If no group is specified, 'all' is assumed.
    """

    trace, tx = STATE.require_tx()
    frame = util.selected_frame()
    if frame is None:
        return {}
    with trace.client.batch() as b:
        return putreg(frame, util.get_register_descs(frame.architecture(), group))


@cmd('ghidra trace delreg', '-ghidra-trace-delreg', gdb.COMMAND_DATA, True)
def ghidra_trace_delreg(group: str = 'all', *, is_mi: bool, **kwargs) -> None:
    """Delete the given register group for the curent frame from the Ghidra
    trace.

    Why would you do this? If no group is specified, 'all' is assumed.
    """

    trace, tx = STATE.require_tx()
    inf = gdb.selected_inferior()
    frame = util.selected_frame()
    if frame is None:
        return
    space = REGS_PATTERN.format(infnum=inf.num, tnum=gdb.selected_thread().num,
                                level=util.get_level(frame))
    mapper = trace.extra.require_rm()
    names = []
    for desc in util.get_register_descs(frame.architecture(), group):
        names.append(mapper.map_name(inf, desc.name))
    trace.delete_registers(space, names)


def mi_or_future(key: str, val: Union[None, T, Future[T]],
                 func: Callable[[T], U], fall: U) -> Dict[str, U]:
    if val is None:
        return {}
    elif isinstance(val, Future):
        if val.done():
            return {key: func(val.result())}
        else:
            return {f'future_{key}': fall}
    else:
        return {key: func(val)}


@cmd('ghidra trace create-obj', '-ghidra-trace-create-obj', gdb.COMMAND_DATA,
     False)
def ghidra_trace_create_obj(path: str, *, is_mi: bool, from_tty: bool = True,
                            **kwargs) -> Dict[str, Union[str, int]]:
    """Create an object in the Ghidra trace.

    The new object is in a detached state, so it may not be immediately
    recognized by the Debugger GUI. Use 'ghidra trace insert-obj' to
    finish the object, after all its required attributes are set.
    """

    trace, tx = STATE.require_tx()
    obj = trace.create_object(path)
    if from_tty and not is_mi:
        gdb.write(
            f"Created object: id={wait_opt(obj.id)}, path={wait_opt(obj.path)}\n")
    result: Dict[str, Union[str, int]] = {}
    result.update(**mi_or_future('id', obj.id, lambda t: t, -1))
    result.update(**mi_or_future('path', obj.path, lambda t: t, ''))
    return result


@cmd('ghidra trace insert-obj', '-ghidra-trace-insert-obj', gdb.COMMAND_DATA,
     True)
def ghidra_trace_insert_obj(path: str, *, is_mi: bool, from_tty: bool = True,
                            **kwargs) -> Dict[str, Tuple[int, int]]:
    """Insert an object into the Ghidra trace."""

    # NOTE: id parameter is probably not necessary, since this command is for
    # humans.
    trace, tx = STATE.require_tx()
    span = trace.proxy_object_path(path).insert()
    if from_tty and not is_mi:
        gdb.write(f"Inserted object: lifespan={wait(span)}\n")

    # For some reason, inlining this is irritating mypy
    span2tuple: Callable[[Lifespan],
                         Tuple[int, int]] = lambda s: (s.min, s.max)
    return mi_or_future('lifespan', span, span2tuple, (0, -1))


@cmd('ghidra trace remove-obj', '-ghidra-trace-remove-obj', gdb.COMMAND_DATA,
     True)
def ghidra_trace_remove_obj(path: str, *, is_mi: bool, from_tty: bool = True,
                            **kwargs) -> None:
    """Remove an object from the Ghidra trace.

    This does not delete the object. It just removes it from the tree
    for the current snap and onwards.
    """

    # NOTE: id parameter is probably not necessary, since this command is for
    # humans.
    trace, tx = STATE.require_tx()
    trace.proxy_object_path(path).remove()


def to_bytes(value: gdb.Value, type: gdb.Type) -> bytes:
    min, max = type.range()
    return bytes(int(value[i]) for i in range(min, max + 1))


def to_string(value: gdb.Value, type: gdb.Type, encoding: str,
              full: bool) -> str:
    if full:
        min, max = type.range()
        return value.string(encoding=encoding, length=max - min + 1)
    else:
        return value.string(encoding=encoding)


def to_bool_list(value: gdb.Value, type: gdb.Type) -> List[bool]:
    min, max = type.range()
    return [bool(value[i]) for i in range(min, max + 1)]


def to_int_list(value: gdb.Value, type: gdb.Type) -> List[int]:
    min, max = type.range()
    return [int(value[i]) for i in range(min, max + 1)]


def eval_value(value: str, schema: Optional[sch.Schema] = None) -> Tuple[Union[
        bool, int, float, bytes, Tuple[str, Address], List[bool], List[int],
        str, None], Optional[sch.Schema]]:
    try:
        val = gdb.parse_and_eval(value)
    except gdb.error as e:
        raise gdb.error(f"Could not evaluate '{value}': {e}")
    type = val.dynamic_type.strip_typedefs()
    if type.code == gdb.TYPE_CODE_VOID:
        return None, sch.VOID
    elif type.code == gdb.TYPE_CODE_BOOL:
        return bool(val), sch.BOOL
    elif type.code == gdb.TYPE_CODE_INT:
        if schema is not None:
            return int(val), schema
        # These sizes are defined by the Trace database, i.e., Java types
        elif type.sizeof == 1:
            return int(val), sch.BYTE
        elif type.sizeof == 2:
            return int(val), sch.SHORT
        elif type.sizeof == 4:
            return int(val), sch.INT
        elif type.sizeof == 8:
            return int(val), sch.LONG
    elif type.code == gdb.TYPE_CODE_CHAR:
        return chr(int(val)), sch.CHAR
    elif type.code == gdb.TYPE_CODE_ARRAY:
        etype = type.target().strip_typedefs()
        if etype.code == gdb.TYPE_CODE_BOOL:
            return to_bool_list(val, type), sch.BOOL_ARR
        elif etype.code == gdb.TYPE_CODE_INT:
            if etype.sizeof == 1:
                if schema == sch.BYTE_ARR:
                    return to_bytes(val, type), schema
                elif schema == sch.CHAR_ARR:
                    return to_string(val, type, 'utf-8', full=True), schema
                return to_string(val, type, 'utf-8', full=False), sch.STRING
            elif etype.sizeof == 2:
                if schema is None:
                    if etype.name == 'wchar_t':
                        return to_string(val, type, 'utf-16', full=False), sch.STRING
                    schema = sch.SHORT_ARR
                elif schema == sch.CHAR_ARR:
                    return to_string(val, type, 'utf-16', full=True), schema
                return to_int_list(val, type), schema
            elif etype.sizeof == 4:
                if schema is None:
                    if etype.name == 'wchar_t':
                        return to_string(val, type, 'utf-32', full=False), sch.STRING
                    schema = sch.INT_ARR
                elif schema == sch.CHAR_ARR:
                    return to_string(val, type, 'utf-32', full=True), schema
                return to_int_list(val, type), schema
            elif schema is not None:
                return to_int_list(val, type), schema
            elif etype.sizeof == 8:
                return to_int_list(val, type), sch.LONG_ARR
        elif etype.code == gdb.TYPE_CODE_STRING:
            raise ValueError("Conversion of string arrays unimplemented")
        # TODO: Array of C strings?
    elif type.code == gdb.TYPE_CODE_STRING:
        return val.string(), sch.STRING
    elif type.code == gdb.TYPE_CODE_PTR:
        offset = int(val)
        inf = gdb.selected_inferior()
        base, addr = STATE.require_trace().extra.require_mm().map(inf, offset)
        return (base, addr), sch.ADDRESS
    raise ValueError(f"Cannot convert ({schema}): '{value}', value='{val}'")


@cmd('ghidra trace set-value', '-ghidra-trace-set-value', gdb.COMMAND_DATA, True)
def ghidra_trace_set_value(path: str, key: str, value: str,
                           schema: Optional[str] = None, *, is_mi: bool,
                           **kwargs) -> None:
    """Set a value (attribute or element) in the Ghidra trace's object tree.

    A void value implies removal. NOTE: The type of an expression may be
    subject to GDB's current language. e.g., there is no 'bool' in C.
    You may have to change to C++ if you need this type. Alternatively,
    you can use the Python API.
    """

    # NOTE: id parameter is probably not necessary, since this command is for
    # humans.
    # TODO: path and key are two separate parameters.... This is mostly to
    # spare me from porting path parsing to Python, but it may also be useful
    # if we ever allow ids here, since the id would be for the object, not the
    # complete value path.
    real_schema = None if schema is None else sch.Schema(schema)
    trace, tx = STATE.require_tx()
    if real_schema == sch.OBJECT:
        val: Union[bool, int, float, bytes, Tuple[str, Address], List[bool],
                   List[int], str, TraceObject, Address,
                   None] = trace.proxy_object_path(value)
    else:
        val, real_schema = eval_value(value, real_schema)
        if real_schema == sch.ADDRESS and isinstance(val, tuple):
            base, addr = val
            val = addr
            if base != addr.space:
                trace.create_overlay_space(base, addr.space)
    trace.proxy_object_path(path).set_value(key, val, real_schema)


@cmd('ghidra trace retain-values', '-ghidra-trace-retain-values',
     gdb.COMMAND_DATA, True)
def ghidra_trace_retain_values(path: str, *keys, is_mi: bool, **kwargs) -> None:
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

    trace, tx = STATE.require_tx()
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
        raise gdb.GdbError("Invalid argument: " + keys[0])
    trace.proxy_object_path(path).retain_values(keys, kinds=kinds)


@cmd('ghidra trace get-obj', '-ghidra-trace-get-obj', gdb.COMMAND_DATA, True)
def ghidra_trace_get_obj(path: str, *, is_mi: bool, **kwargs) -> TraceObject:
    """Get an object descriptor by its canonical path.

    This isn't the most informative, but it will at least confirm
    whether an object exists and provide its id.
    """

    trace = STATE.require_trace()
    object = trace.get_object(path)
    if not is_mi:
        gdb.write(f"{object.id}\t{object.path}\n")
    return object


@cmd('ghidra trace get-values', '-ghidra-trace-get-values', gdb.COMMAND_DATA,
     True)
def ghidra_trace_get_values(pattern: str, *, is_mi,
                            **kwargs) -> List[TraceObjectValue]:
    """List all values matching a given path pattern.

    NOTE: Even in batch mode, this request will block for the result.
    """

    trace = STATE.require_trace()
    values = wait(trace.get_values(pattern))
    if not is_mi:
        print_tabular_values(values, lambda ln: gdb.write(ln+'\n'))
    return values


@cmd('ghidra trace get-values-rng', '-ghidra-trace-get-values-rng',
     gdb.COMMAND_DATA, True)
def ghidra_trace_get_values_rng(address: str, length: str, *, is_mi: bool,
                                **kwargs) -> List[TraceObjectValue]:
    """List all values intersecting a given address range.

    This can only retrieve values of type ADDRESS or RANGE.
    NOTE: Even in batch mode, this request will block for the result.
    """

    trace = STATE.require_trace()
    start, end = eval_range(address, length)
    inf = gdb.selected_inferior()
    base, addr = trace.extra.require_mm().map(inf, start)
    # Do not create the space. We're querying. No tx.
    values = wait(trace.get_values_intersecting(addr.extend(end - start)))
    if not is_mi:
        print_tabular_values(values, lambda ln: gdb.write(ln+'\n'))
    return values


def activate(path: Optional[str] = None) -> None:
    trace = STATE.require_trace()
    if path is None:
        inf = gdb.selected_inferior()
        t = gdb.selected_thread()
        frame = util.selected_frame()
        if frame is not None:
            path = FRAME_PATTERN.format(
                infnum=inf.num, tnum=t.num, level=util.get_level(frame))
        elif t is not None:
            path = THREAD_PATTERN.format(infnum=inf.num, tnum=t.num)
        else:
            path = INFERIOR_PATTERN.format(infnum=inf.num)
    trace.proxy_object_path(path).activate()


@cmd('ghidra trace activate', '-ghidra-trace-activate', gdb.COMMAND_STATUS,
     True)
def ghidra_trace_activate(path: Optional[str] = None, *, is_mi: bool,
                          **kwargs) -> None:
    """Activate an object in Ghidra's GUI.

    This has no effect if the current trace is not current in Ghidra. If
    path is omitted, this will activate the current frame.
    """

    activate(path)


@cmd('ghidra trace disassemble', '-ghidra-trace-disassemble', gdb.COMMAND_DATA,
     True)
def ghidra_trace_disassemble(address: str, *, is_mi: bool,
                             from_tty: bool = True, **kwargs) -> Dict[str, int]:
    """Disassemble starting at the given seed.

    Disassembly proceeds linearly and terminates at the first branch or
    unknown memory encountered.
    """

    trace, tx = STATE.require_tx()
    start = eval_address(address)
    inf = gdb.selected_inferior()
    base, addr = trace.extra.require_mm().map(inf, start)
    if base != addr.space:
        trace.create_overlay_space(base, addr.space)

    length = trace.disassemble(addr)
    if from_tty and not is_mi:
        gdb.write(f"Disassembled {wait(length)} bytes\n")
    return mi_or_future('length', length, lambda t: t, -1)


def compute_inf_state(inf: gdb.Inferior) -> str:
    threads = inf.threads()
    if not threads:
        # TODO: Distinguish INACTIVE from TERMINATED
        return 'INACTIVE'
    for t in threads:
        if t.is_running():
            return 'RUNNING'
    return 'STOPPED'


def put_inferior_state(inf: gdb.Inferior) -> None:
    trace = STATE.require_trace()
    ipath = INFERIOR_PATTERN.format(infnum=inf.num)
    infobj = trace.proxy_object_path(ipath)
    istate = compute_inf_state(inf)
    infobj.set_value('State', istate)
    for t in inf.threads():
        tpath = THREAD_PATTERN.format(infnum=inf.num, tnum=t.num)
        tobj = trace.proxy_object_path(tpath)
        tobj.set_value('State', convert_state(t))


def put_inferiors() -> None:
    # TODO: Attributes like _exit_code, _state?
    #     _state would be derived from threads
    trace = STATE.require_trace()
    keys = []
    for inf in gdb.inferiors():
        ipath = INFERIOR_PATTERN.format(infnum=inf.num)
        keys.append(INFERIOR_KEY_PATTERN.format(infnum=inf.num))
        infobj = trace.create_object(ipath)
        istate = compute_inf_state(inf)
        infobj.set_value('State', istate)
        infobj.insert()
    trace.proxy_object_path(INFERIORS_PATH).retain_values(keys)


@cmd('ghidra trace put-inferiors', '-ghidra-trace-put-inferiors',
     gdb.COMMAND_DATA, True)
def ghidra_trace_put_inferiors(*, is_mi: bool, **kwargs) -> None:
    """Put the list of inferiors into the trace's Inferiors list."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_inferiors()


def put_available() -> None:
    # TODO: Compared to -list-thread-groups --available:
    #     Is that always from the host, or can that pslist a remote target?
    #     psutil will always be from the host.
    trace = STATE.require_trace()
    keys = []
    for proc in psutil.process_iter():
        ppath = AVAILABLE_PATTERN.format(pid=proc.pid)
        procobj = trace.create_object(ppath)
        keys.append(AVAILABLE_KEY_PATTERN.format(pid=proc.pid))
        procobj.set_value('PID', proc.pid)
        procobj.set_value('_display', f'{proc.pid} {proc.name()}')
        procobj.insert()
    trace.proxy_object_path(AVAILABLES_PATH).retain_values(keys)


@cmd('ghidra trace put-available', '-ghidra-trace-put-available',
     gdb.COMMAND_DATA, True)
def ghidra_trace_put_available(*, is_mi: bool, **kwargs) -> None:
    """Put the list of available processes into the trace's Available list."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_available()


def put_single_breakpoint(b: gdb.Breakpoint, ibobj: TraceObject,
                          inf: gdb.Inferior, ikeys: List[str]) -> None:
    trace = STATE.require_trace()
    mapper = trace.extra.require_mm()
    bpath = BREAKPOINT_PATTERN.format(breaknum=b.number)
    brkobj = trace.create_object(bpath)
    brkobj.set_value('Enabled', b.enabled)
    if b.type == gdb.BP_BREAKPOINT:
        brkobj.set_value('Expression', b.location)
        brkobj.set_value('Kinds', 'SW_EXECUTE')
    elif b.type == gdb.BP_HARDWARE_BREAKPOINT:
        brkobj.set_value('Expression', b.location)
        brkobj.set_value('Kinds', 'HW_EXECUTE')
    elif b.type == gdb.BP_WATCHPOINT:
        brkobj.set_value('Expression', b.expression)
        brkobj.set_value('Kinds', 'WRITE')
    elif b.type == gdb.BP_HARDWARE_WATCHPOINT:
        brkobj.set_value('Expression', b.expression)
        brkobj.set_value('Kinds', 'WRITE')
    elif b.type == gdb.BP_READ_WATCHPOINT:
        brkobj.set_value('Expression', b.expression)
        brkobj.set_value('Kinds', 'READ')
    elif b.type == gdb.BP_ACCESS_WATCHPOINT:
        brkobj.set_value('Expression', b.expression)
        brkobj.set_value('Kinds', 'READ,WRITE')
    else:
        brkobj.set_value('Expression', '(unknown)')
        brkobj.set_value('Kinds', '')
    brkobj.set_value('Commands', b.commands)
    brkobj.set_value('Condition', b.condition)
    brkobj.set_value('Hit Count', b.hit_count)
    brkobj.set_value('Ignore Count', b.ignore_count)
    brkobj.set_value('Pending', b.pending)
    brkobj.set_value('Silent', b.silent)
    brkobj.set_value('Temporary', b.temporary)
    # TODO: "_threads"?
    keys = []
    locs = util.BREAKPOINT_LOCATION_INFO_READER.get_locations(b)
    hooks.BRK_STATE.update_brkloc_count(b, len(locs))
    for i, l in enumerate(locs):
        # Retain the key, even if not for this inferior
        k = BREAK_LOC_KEY_PATTERN.format(locnum=i+1)
        keys.append(k)
        if inf.num not in l.thread_groups:
            continue
        locobj = trace.create_object(bpath + k)
        locobj.set_value('Enabled', l.enabled)
        ik = INF_BREAK_KEY_PATTERN.format(breaknum=b.number, locnum=i+1)
        ikeys.append(ik)
        if b.location is not None:  # Implies execution break
            base, addr = mapper.map(inf, l.address)
            if base != addr.space:
                trace.create_overlay_space(base, addr.space)
            locobj.set_value('Range', addr.extend(1))
        elif b.expression is not None:  # Implies watchpoint
            expr = b.expression
            if expr.startswith('-location '):
                expr = expr[len('-location '):]
            try:
                address = int(gdb.parse_and_eval(f'&({expr})'))
                base, addr = mapper.map(inf, address)
                if base != addr.space:
                    trace.create_overlay_space(base, addr.space)
                size = int(gdb.parse_and_eval(f'sizeof({expr})'))
                locobj.set_value('Range', addr.extend(size))
            except Exception as e:
                gdb.write(
                    f"Error: Could not get range for breakpoint {ik}: {e}\n",
                    stream=gdb.STDERR)
        else:  # I guess it's a catchpoint
            pass
        locobj.insert()
        ibobj.set_value(ik, locobj)
    brkobj.retain_values(keys)
    brkobj.insert()


def put_breakpoints() -> None:
    trace = STATE.require_trace()
    inf = gdb.selected_inferior()
    ibpath = INF_BREAKS_PATTERN.format(infnum=inf.num)
    ibobj = trace.create_object(ibpath)
    keys = []
    ikeys: List[str] = []
    for b in gdb.breakpoints():
        keys.append(BREAKPOINT_KEY_PATTERN.format(breaknum=b.number))
        put_single_breakpoint(b, ibobj, inf, ikeys)
    ibobj.insert()
    trace.proxy_object_path(BREAKPOINTS_PATH).retain_values(keys)
    ibobj.retain_values(ikeys)


@cmd('ghidra trace put-breakpoints', '-ghidra-trace-put-breakpoints',
     gdb.COMMAND_DATA, True)
def ghidra_trace_put_breakpoints(*, is_mi: bool, **kwargs) -> None:
    """Put the current inferior's breakpoints into the trace."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_breakpoints()


def put_environment() -> None:
    inf = gdb.selected_inferior()
    epath = ENV_PATTERN.format(infnum=inf.num)
    envobj = STATE.require_trace().create_object(epath)
    envobj.set_value('Debugger', 'gdb')
    envobj.set_value('Arch', arch.get_arch())
    envobj.set_value('OS', arch.get_osabi())
    envobj.set_value('Endian', arch.get_endian())
    envobj.insert()


@cmd('ghidra trace put-environment', '-ghidra-trace-put-environment',
     gdb.COMMAND_DATA, True)
def ghidra_trace_put_environment(*, is_mi: bool, **kwargs) -> None:
    """Put some environment indicators into the Ghidra trace."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_environment()


def put_regions(regions: Optional[List[util.Region]] = None) -> List[util.Region]:
    trace = STATE.require_trace()
    inf = gdb.selected_inferior()
    if regions is None:
        try:
            regions = util.REGION_INFO_READER.get_regions()
        except Exception:
            regions = []
    if len(regions) == 0 and gdb.selected_thread() is not None:
        regions = [util.REGION_INFO_READER.full_mem()]
    mapper = trace.extra.require_mm()
    keys = []
    for r in regions:
        rpath = REGION_PATTERN.format(infnum=inf.num, start=r.start)
        keys.append(REGION_KEY_PATTERN.format(start=r.start))
        regobj = trace.create_object(rpath)
        start_base, start_addr = mapper.map(inf, r.start)
        if start_base != start_addr.space:
            trace.create_overlay_space(start_base, start_addr.space)
        regobj.set_value('Range', start_addr.extend(r.end - r.start))
        if r.perms != None:
            regobj.set_value('Permissions', r.perms)
        regobj.set_value('_readable', r.perms == None or 'r' in r.perms)
        regobj.set_value('_writable', r.perms == None or 'w' in r.perms)
        regobj.set_value('_executable', r.perms == None or 'x' in r.perms)
        regobj.set_value('Offset', hex(r.offset))
        regobj.set_value('Object File', r.objfile)
        regobj.set_value(
            '_display', f'{r.objfile} (0x{r.start:x}-0x{r.end:x})')
        regobj.insert()
    trace.proxy_object_path(
        MEMORY_PATTERN.format(infnum=inf.num)).retain_values(keys)
    return regions


@cmd('ghidra trace put-regions', '-ghidra-trace-put-regions', gdb.COMMAND_DATA,
     True)
def ghidra_trace_put_regions(*, is_mi: bool, **kwargs) -> None:
    """Read the memory map, if applicable, and write to the trace's Regions."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_regions()


def put_modules(modules: Optional[Dict[str, util.Module]] = None,
                sections: bool = False) -> None:
    trace = STATE.require_trace()
    inf = gdb.selected_inferior()
    if modules is None:
        modules = util.MODULE_INFO_READER.get_modules()
    mapper = trace.extra.require_mm()
    mod_keys = []
    for mk, m in modules.items():
        mpath = MODULE_PATTERN.format(infnum=inf.num, modpath=mk)
        modobj = trace.create_object(mpath)
        mod_keys.append(MODULE_KEY_PATTERN.format(modpath=mk))
        modobj.set_value('Name', m.name)
        base_base, base_addr = mapper.map(inf, m.base)
        if base_base != base_addr.space:
            trace.create_overlay_space(base_base, base_addr.space)
        modobj.set_value('Range', base_addr.extend(m.max - m.base))
        if sections:
            sec_keys = []
            for sk, s in m.sections.items():
                spath = mpath + SECTION_ADD_PATTERN.format(secname=sk)
                secobj = trace.create_object(spath)
                sec_keys.append(SECTION_KEY_PATTERN.format(secname=sk))
                start_base, start_addr = mapper.map(inf, s.start)
                if start_base != start_addr.space:
                    trace.create_overlay_space(
                        start_base, start_addr.space)
                if s.end == s.start:
                    secobj.set_value('Address', start_addr)
                else:
                    secobj.set_value('Range', start_addr.extend(s.end - s.start))
                secobj.set_value('Offset', hex(s.offset))
                secobj.set_value('Attrs', s.attrs, schema=sch.STRING_ARR)
                secobj.insert()
            trace.proxy_object_path(
                mpath + SECTIONS_ADD_PATTERN).retain_values(sec_keys)

        scpath = mpath + SECTIONS_ADD_PATTERN
        sec_container_obj = trace.create_object(scpath)
        sec_container_obj.insert()
    if not sections:
        trace.proxy_object_path(MODULES_PATTERN.format(
            infnum=inf.num)).retain_values(mod_keys)


@cmd('ghidra trace put-modules', '-ghidra-trace-put-modules', gdb.COMMAND_DATA,
     True)
def ghidra_trace_put_modules(*, is_mi: bool, **kwargs) -> None:
    """Gather object files, if applicable, and write to the trace's Modules."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_modules()


@cmd('ghidra trace put-sections', '-ghidra-trace-put-sections',
     gdb.COMMAND_DATA, True)
def ghidra_trace_put_sections(module_name: str, *, is_mi: bool,
                              **kwargs) -> None:
    """Write the sections of the given module or all modules."""

    modules = None
    if module_name != '-all-objects':
        modules = {mk: m for mk, m in util.MODULE_INFO_READER.get_modules(
        ).items() if mk == module_name}
        if len(modules) == 0:
            raise gdb.GdbError(f"No module / object named {module_name}")

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_modules(modules, True)


def convert_state(t: gdb.InferiorThread) -> str:
    if t.is_exited():
        return 'TERMINATED'
    if t.is_running():
        return 'RUNNING'
    if t.is_stopped():
        return 'STOPPED'
    return 'INACTIVE'


def convert_tid(t: tuple[int, int, int]) -> int:
    if t[1] == 0:
        return t[2]
    return t[1]


@contextmanager
def restore_frame() -> Generator[None, None, None]:
    f = util.selected_frame()
    yield
    if f is not None:
        f.select()


def newest_frame(f: gdb.Frame) -> gdb.Frame:
    while True:
        n = f.newer()
        if n is None:
            return f
        f = n


def compute_thread_display(t: gdb.InferiorThread) -> str:
    out = gdb.execute(f'info thread {t.num}', to_string=True)
    line = out.strip().split('\n')[-1].strip().replace('\\s+', ' ')
    if line.startswith('*'):
        line = line[1:].strip()
    return line


def put_threads() -> None:
    trace = STATE.require_trace()
    radix = gdb.parameter('output-radix')
    inf = gdb.selected_inferior()
    keys = []
    for t in inf.threads():
        tpath = THREAD_PATTERN.format(infnum=inf.num, tnum=t.num)
        tobj = trace.create_object(tpath)
        keys.append(THREAD_KEY_PATTERN.format(tnum=t.num))
        tobj.set_value('State', convert_state(t))
        tobj.set_value('Name', t.name)
        tid = convert_tid(t.ptid)
        tobj.set_value('TID', tid)
        tidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(tid)
        tobj.set_value('_short_display', f'[{inf.num}.{t.num}:{tidstr}]')
        tobj.set_value('_display', compute_thread_display(t))
        tobj.insert()
    trace.proxy_object_path(
        THREADS_PATTERN.format(infnum=inf.num)).retain_values(keys)


def put_event_thread() -> None:
    trace = STATE.require_trace()
    inf = gdb.selected_inferior()
    # Assumption: Event thread is selected by gdb upon stopping
    t = gdb.selected_thread()
    if t is not None:
        tpath = THREAD_PATTERN.format(infnum=inf.num, tnum=t.num)
        tobj = trace.proxy_object_path(tpath)
    else:
        tobj = None
    trace.proxy_object_path('').set_value('_event_thread', tobj)


@cmd('ghidra trace put-threads', '-ghidra-trace-put-threads', gdb.COMMAND_DATA,
     True)
def ghidra_trace_put_threads(*, is_mi: bool, **kwargs) -> None:
    """Put the current inferior's threads into the Ghidra trace."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_threads()


def put_frames() -> None:
    trace = STATE.require_trace()
    inf = gdb.selected_inferior()
    mapper = trace.extra.require_mm()
    t = gdb.selected_thread()
    if t is None:
        return
    # NB: This command will fail if the process is running
    bt = gdb.execute('bt', to_string=True).strip().split('\n')
    f = util.selected_frame()
    if f is None:
        return
    f = newest_frame(f)
    keys = []
    level = 0
    while f is not None:
        fpath = FRAME_PATTERN.format(
            infnum=inf.num, tnum=t.num, level=level)
        fobj = trace.create_object(fpath)
        keys.append(FRAME_KEY_PATTERN.format(level=level))
        base, pc = mapper.map(inf, int(f.pc()))
        if base != pc.space:
            trace.create_overlay_space(base, pc.space)
        fobj.set_value('PC', pc)
        fobj.set_value('Function', str(f.function()))
        fobj.set_value(
            '_display', bt[level].strip().replace('\\s+', ' '))
        f = f.older()
        level += 1
        fobj.insert()
        robj = trace.create_object(fpath+".Registers")
        robj.insert()
    trace.proxy_object_path(STACK_PATTERN.format(
        infnum=inf.num, tnum=t.num)).retain_values(keys)


@cmd('ghidra trace put-frames', '-ghidra-trace-put-frames', gdb.COMMAND_DATA,
     True)
def ghidra_trace_put_frames(*, is_mi: bool, **kwargs) -> None:
    """Put the current thread's frames into the Ghidra trace."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        put_frames()


@cmd('ghidra trace put-all', '-ghidra-trace-put-all', gdb.COMMAND_DATA, True)
def ghidra_trace_put_all(*, is_mi: bool, **kwargs) -> None:
    """Put everything currently selected into the Ghidra trace."""

    trace, tx = STATE.require_tx()
    with trace.client.batch() as b:
        ghidra_trace_putreg(is_mi=is_mi)
        ghidra_trace_putmem("$pc", "1", is_mi=is_mi)
        ghidra_trace_putmem("$sp", "1", is_mi=is_mi)
        put_inferiors()
        put_environment()
        put_modules()
        put_regions()
        put_threads()
        put_frames()
        put_breakpoints()


@cmd('ghidra trace install-hooks', '-ghidra-trace-install-hooks',
     gdb.COMMAND_SUPPORT, False)
def ghidra_trace_install_hooks(*, is_mi: bool, **kwargs) -> None:
    """Install hooks to trace in Ghidra."""

    hooks.install_hooks()


@cmd('ghidra trace remove-hooks', '-ghidra-trace-remove-hooks',
     gdb.COMMAND_SUPPORT, False)
def ghidra_trace_remove_hooks(*, is_mi: bool, **kwargs) -> None:
    """Remove hooks to trace in Ghidra.

    Using this directly is not recommended, unless it seems the hooks
    are preventing gdb or other extensions from operating. Removing
    hooks will break trace synchronization until they are replaced.
    """

    hooks.remove_hooks()


@cmd('ghidra trace sync-enable', '-ghidra-trace-sync-enable',
     gdb.COMMAND_SUPPORT, True)
def ghidra_trace_sync_enable(*, is_mi: bool, **kwargs) -> None:
    """Synchronize the current inferior with the Ghidra trace.

    This will automatically install hooks if necessary. The goal is to
    record the current frame, thread, and inferior into the trace
    immediately, and then to append the trace upon stopping and/or
    selecting new frames. This action is effective only for the current
    inferior. This command must be executed for each individual inferior
    you'd like to synchronize. In older versions of gdb, certain events
    cannot be hooked. In that case, you may need to execute certain
    "trace put" commands manually, or go without.

    This will have no effect unless or until you start a trace.
    """

    hooks.install_hooks()
    hooks.enable_current_inferior()


@cmd('ghidra trace sync-disable', '-ghidra-trace-sync-disable',
     gdb.COMMAND_SUPPORT, True)
def ghidra_trace_sync_disable(*, is_mi: bool, **kwargs) -> None:
    """Cease synchronizing the current inferior with the Ghidra trace.

    This is the opposite of 'ghidra trace sync-enable', except it will
    not automatically remove hooks.
    """

    hooks.disable_current_inferior()


@cmd('ghidra trace sync-synth-stopped', '-ghidra-trace-sync-synth-stopped',
     gdb.COMMAND_SUPPORT, False)
def ghidra_trace_sync_synth_stopped(*, is_mi: bool, **kwargs) -> None:
    """Act as though the target has just stopped.

    This may need to be invoked immediately after 'ghidra trace sync-
    enable', to ensure the first snapshot displays the initial/current
    target state.
    """

    hooks.on_stop(None)


@cmd('ghidra util wait-stopped', '-ghidra-util-wait-stopped', gdb.COMMAND_NONE,
     False)
def ghidra_util_wait_stopped(timeout: Union[str, int] = '1', *, is_mi: bool,
                             **kwargs) -> None:
    """Spin wait until the selected thread is stopped."""

    timeout = int(timeout)
    start = time.time()
    t = gdb.selected_thread()
    if t is None:
        return
    while t.is_running():
        t = gdb.selected_thread()  # I suppose it could change
        time.sleep(0.1)
        if time.time() - start > timeout:
            raise gdb.GdbError('Timed out waiting for thread to stop')
