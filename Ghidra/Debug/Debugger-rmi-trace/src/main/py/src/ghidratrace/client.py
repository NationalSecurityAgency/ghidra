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

try:
    from . import trace_rmi_pb2 as bufs
except Exception as e:
    from .setuputils import prompt_and_mitigate_dependencies
    prompt_and_mitigate_dependencies("Debug/Debugger-rmi-trace")

from collections import deque
from concurrent.futures import Executor, Future
from contextlib import contextmanager
from dataclasses import dataclass
import inspect
import socket
import sys
from threading import Thread, Lock, RLock
import traceback
from typing import (Annotated, Any, Callable, Collection, Dict, Generator,
                    Generic, Iterable, List, MutableSequence, Optional,
                    Sequence, Tuple, TypeVar, Union)
from typing import get_args, get_origin

from google.protobuf.internal.containers import (
    RepeatedCompositeFieldContainer as RCFC)

from . import sch
from .util import send_delimited, recv_delimited


# This need not be incremented every Ghidra release. When a breaking protocol
# change is made, this should be updated to match the first Ghidra release that
# includes the change.
#
# Other places to change:
# * every pyproject.toml file (incl. deps)
# * TraceRmiHandler.VERSION
VERSION = '11.4'


E = TypeVar('E')
T = TypeVar('T')
U = TypeVar('U')


class RemoteResult(Future[U], Generic[T, U]):
    __slots__ = ('field_name', 'handler')

    def __init__(self, field_name: str, handler: Callable[[T], U]) -> None:
        super().__init__()
        self.field_name: str = field_name
        self.handler: Callable[[T], U] = handler


class TraceRmiError(Exception):
    pass


class ProtocolError(Exception):
    pass


@dataclass(frozen=True)
class RegVal:
    name: str
    value: bytes


@dataclass(frozen=True)
class Address:
    space: str
    offset: int

    def extend(self, length: int) -> 'AddressRange':
        return AddressRange.extend(self, length)


@dataclass(frozen=True)
class AddressRange:
    space: str
    min: int
    max: int

    @classmethod
    def extend(cls, min: Address, length: int) -> 'AddressRange':
        return cls(min.space, min.offset, min.offset + length - 1)

    def length(self) -> int:
        return self.max - self.min + 1


LIFESPAN_MIN = -1 << 63
LIFESPAN_MAX = (1 << 63) - 1


@dataclass(frozen=True)
class Lifespan:
    min: int = LIFESPAN_MIN
    max: int = LIFESPAN_MAX

    def __post_init__(self) -> None:
        if self.min < LIFESPAN_MIN:
            raise ValueError("min out of range of int64")
        if self.max > LIFESPAN_MAX:
            raise ValueError("max out of range of int64")
        if self.min > self.max and not (self.min == 0 and self.max == -1):
            raise ValueError("min cannot exceed max")

    def is_empty(self) -> bool:
        return self.min == 0 and self.max == -1

    def __str__(self) -> str:
        if self.is_empty():
            return "(EMPTY)"
        min = '(-inf' if self.min == LIFESPAN_MIN else f'[{self.min}'
        max = '+inf)' if self.max == LIFESPAN_MAX else f'{self.max}]'
        return f'{min},{max}'

    def __repr__(self) -> str:
        return 'Lifespan' + self.__str__()


@dataclass
class Schedule:
    """A more constrained form of TraceSchedule from our Java code.

    Until we have need more capable schedules here, we'll just keep it
    at this. TODO: We might need another flag to indicate the kind of
    steps here. It seems in Microsoft TTD, it's the number of
    instructions executed since the last event. However, in rr/gdb, it
    seems it's the number of branch instructions encountered.
    """
    snap: int
    steps: int = 0

    @staticmethod
    def parse(s: str) -> 'Schedule':
        parts = s.split(':')
        if len(parts) == 1:
            return Schedule(int(parts[0]))
        elif len(parts) == 2:
            return Schedule(int(parts[0]), int(parts[1]))
        else:
            raise ValueError(
                f"Schedule must be in form [snap]:[steps]. Got '{s}'")

    def __str__(self) -> str:
        if self.steps == 0:
            return f"{self.snap}"
        return f"{self.snap}:{self.steps}"


@dataclass(frozen=True)
class DetachedObject:
    id: int
    path: str


@dataclass(frozen=True)
class TraceObject:
    """A proxy for a TraceObject."""
    trace: 'Trace'
    id: Union[int, Future[int], None]
    path: Union[str, Future[str], None]

    @classmethod
    def from_id(cls, trace: 'Trace', id: int) -> 'TraceObject':
        return cls(trace=trace, id=id, path=None)

    @classmethod
    def from_path(cls, trace: 'Trace', path: str) -> 'TraceObject':
        return cls(trace=trace, id=None, path=path)

    def str_path(self) -> str:
        if self.path is None:
            return '<ProxyById>'
        elif isinstance(self.path, str):
            return self.path
        elif self.path.done():
            return self.path.result()
        else:
            return '<Future>'

    def insert(self, span: Optional[Lifespan] = None,
               resolution: str = 'adjust') -> Union[
            Lifespan, RemoteResult[Any, Lifespan]]:
        if span is None:
            span = Lifespan(self.trace.snap())
        return self.trace._insert_object(self, span, resolution)

    def remove(self, span: Optional[Lifespan] = None,
               tree: bool = False) -> Union[None, RemoteResult[Any, None]]:
        if span is None:
            span = Lifespan(self.trace.snap())
        return self.trace._remove_object(self, span, tree)

    def set_value(self, key: str, value: Any,
                  schema: Optional[sch.Schema] = None,
                  span: Optional[Lifespan] = None,
                  resolution: str = 'adjust') -> Union[
            Lifespan, RemoteResult[Any, Lifespan]]:
        if span is None:
            span = Lifespan(self.trace.snap())
        return self.trace._set_value(self, span, key, value, schema, resolution)

    def retain_values(self, keys: Collection[str],
                      span: Optional[Lifespan] = None,
                      kinds: str = 'elements') -> Union[
            None, RemoteResult[Any, None]]:
        if span is None:
            span = Lifespan(self.trace.snap())
        return self.trace._retain_values(self, span, kinds, keys)

    def activate(self) -> None:
        self.trace._activate_object(self)


@dataclass(frozen=True)
class TraceObjectValue:
    """A record of a TraceObjectValue."""
    parent: TraceObject
    span: Lifespan
    key: str
    value: Any
    schema: sch.Schema


class Trace(Generic[E]):

    def __init__(self, client: 'Client', id: int, extra: E) -> None:
        self.extra: E = extra
        self._next_tx: int = 0
        self._txlock: Lock = Lock()

        self.closed: bool = False
        self.client: Client = client
        self.id: int = id
        self.overlays: set[str] = set()

        self._time: Optional[Schedule] = None
        self._snap: Optional[int] = None
        self._snlock: RLock = RLock()

    def __repr__(self) -> str:
        return "<Trace id={} closed={}>".format(self.id, self.closed)

    def close(self) -> None:
        if self.closed:
            return
        self.client._close_trace(self.id)
        self.closed = True

    def save(self) -> Union[None, RemoteResult[Any, None]]:
        return self.client._save_trace(self.id)

    def start_tx(self, description: str,
                 undoable: bool = False) -> 'Transaction':
        with self._txlock:
            txid = self._next_tx
            self._next_tx += 1
        self.client._start_tx(self.id, description, undoable, txid)
        return Transaction(self, txid)

    @contextmanager
    def open_tx(self, description: str,
                undoable: bool = False) -> Generator['Transaction', None, None]:
        tx = self.start_tx(description, undoable)
        yield tx
        tx.commit()

    def _end_tx(self, txid: int, abort: bool) -> Union[
            None, RemoteResult[Any, None]]:
        return self.client._end_tx(self.id, txid, abort)

    def _next_snap(self) -> Schedule:
        with self._snlock:
            if self._time is None:
                self._time = Schedule(0, 0)
            else:
                self._time = Schedule(self._time.snap + 1, 0)
            self._snap = self._time.snap
            return self._time

    def snapshot(self, description: str, datetime: Optional[str] = None,
                 time: Optional[Schedule] = None) -> int:
        """Create a snapshot.

        Future state operations implicitly modify this new snapshot. If
        the time argument is omitted, this creates a snapshot
        immediately after the last created snapshot. For a snap-only
        schedule, this creates the given snapshot. If there are steps,
        it creates a snapshot in scratch space with the given schedule.

        NOTE: If the schedule includes steps, this method will block
        until a response is received, so that the client knows the
        actual snapshot, even in batch mode.

        :param description: The description of the snapshot to appear in
            the "Time" table.
        :param datetime: The real time of the snapshot in ISO-8601
            instant form. If not given, the back end will use its
            current time.
        :param time: For time-travel / timeless debugging, the time in
            the trace.
        :return: the snap actually created
        """

        with self._snlock:
            if time is None:
                time = self._next_snap()
            else:
                self._time = time
            id_or_fut = self.client._snapshot(self.id, description, datetime,
                                              time)
            if time.steps == 0:
                self._snap = time.snap
            elif isinstance(id_or_fut, int):
                self._snap = id_or_fut
            else:
                self._snap = None
                self._snap = id_or_fut.result()
            return self._snap

    def time(self) -> Schedule:
        with self._snlock:
            return self._time or Schedule(0, 0)

    def snap(self) -> int:
        with self._snlock:
            return self._snap or 0

    def create_overlay_space(self, base: str, name: str) -> Union[
            None, RemoteResult[Any, None]]:
        if name in self.overlays:
            return None
        result = self.client._create_overlay_space(self.id, base, name)
        self.overlays.add(name)
        return result

    def put_bytes(self, address: Address, data: bytes,
                  snap: Optional[int] = None) -> Union[
            int, RemoteResult[Any, int]]:
        if snap is None:
            snap = self.snap()
        return self.client._put_bytes(self.id, snap, address, data)

    @staticmethod
    def validate_state(state) -> None:
        if not state in ('unknown', 'known', 'error'):
            raise ValueError("Invalid memory state: {}".format(state))

    def set_memory_state(self, range: AddressRange, state: str,
                         snap: Optional[int] = None) -> Union[
            None, RemoteResult[Any, None]]:
        if snap is None:
            snap = self.snap()
        return self.client._set_memory_state(self.id, snap, range, state)

    def delete_bytes(self, range: AddressRange, snap:
                     Optional[int] = None) -> Union[
            None, RemoteResult[Any, None]]:
        if snap is None:
            snap = self.snap()
        return self.client._delete_bytes(self.id, snap, range)

    def put_registers(self, space: str, values: Iterable[RegVal],
                      snap: Optional[int] = None) -> Union[
            List[str], RemoteResult[Any, List[str]]]:
        """Set register values at the given time on.

        values is a dictionary, where each key is a register name, and
        the value is a byte array. No matter the target architecture,
        the value is given in big-endian byte order.
        """

        if snap is None:
            snap = self.snap()
        return self.client._put_registers(self.id, snap, space, values)

    def delete_registers(self, space: str, names: Iterable[str],
                         snap: Optional[int] = None) -> Union[
            None, RemoteResult[Any, None]]:
        if snap is None:
            snap = self.snap()
        return self.client._delete_registers(self.id, snap, space, names)

    def create_root_object(self, xml_context: str, schema: str) -> TraceObject:
        return TraceObject(self, self.client._create_root_object(
            self.id, xml_context, schema), "")

    def create_object(self, path: str) -> TraceObject:
        return TraceObject(self, self.client._create_object(
            self.id, path), path)

    def _insert_object(self, object: TraceObject, span: Lifespan,
                       resolution: str) -> Union[
            Lifespan, RemoteResult[Any, Lifespan]]:
        return self.client._insert_object(self.id, object, span, resolution)

    def _remove_object(self, object: TraceObject, span: Lifespan,
                       tree: bool) -> Union[None, RemoteResult[Any, None]]:
        return self.client._remove_object(self.id, object, span, tree)

    def _set_value(self, object: TraceObject, span: Lifespan, key: str,
                   value: Any, schema: Optional[sch.Schema],
                   resolution: str) -> Union[
            Lifespan, RemoteResult[Any, Lifespan]]:
        return self.client._set_value(self.id, object, span, key, value, schema,
                                      resolution)

    def _retain_values(self, object: TraceObject, span: Lifespan, kinds: str,
                       keys: Iterable[str]) -> Union[
            None, RemoteResult[Any, None]]:
        return self.client._retain_values(self.id, object, span, kinds, keys)

    def proxy_object_id(self, id: int) -> TraceObject:
        return TraceObject.from_id(self, id)

    def proxy_object_path(self, path: str) -> TraceObject:
        return TraceObject.from_path(self, path)

    def proxy_object(self, id: Optional[int] = None,
                     path: Optional[str] = None) -> TraceObject:
        if id is None and path is None:
            raise ValueError("Must have id or path")
        return TraceObject(self, id, path)

    def get_object(self, path_or_id: Union[int, str]) -> TraceObject:
        fut_or_d_obj = self.client._get_object(self.id, path_or_id)
        if isinstance(fut_or_d_obj, DetachedObject):
            return TraceObject(self, fut_or_d_obj.id, fut_or_d_obj.path)

        if isinstance(path_or_id, int):
            fut_path: Future[str] = Future()

            def _done(fut_d_obj: Future[DetachedObject]) -> None:
                fut_path.set_result(fut_d_obj.result().path)

            fut_or_d_obj.add_done_callback(_done)
            return TraceObject(self, path_or_id, fut_path)

        if isinstance(path_or_id, str):
            fut_id: Future[int] = Future()

            def _done(fut_d_obj: Future[DetachedObject]) -> None:
                fut_id.set_result(fut_d_obj.result().id)

            fut_or_d_obj.add_done_callback(_done)
            return TraceObject(self, fut_id, path_or_id)

    def _fix_value(self, value: Any, schema: sch.Schema) -> Any:
        if schema != sch.OBJECT:
            return value
        elif isinstance(value, DetachedObject):
            return TraceObject(self, value.id, value.path)
        elif isinstance(value, TraceObject):
            return value
        else:
            raise ValueError(f"Cannot convert: {value:r}")

    def _make_values(self, values: Iterable[Tuple[
            DetachedObject, Lifespan, str, Tuple[Any, sch.Schema]
    ]]) -> List[TraceObjectValue]:
        return [
            TraceObjectValue(TraceObject(self, d_obj.id, d_obj.path),
                             span, key, self._fix_value(value, schema), schema)
            for d_obj, span, key, (value, schema) in values
        ]

    def _convert_values(self, results: Union[
        List[Tuple[DetachedObject, Lifespan, str, Tuple[Any, sch.Schema]]],
        Future[List[
            Tuple[DetachedObject, Lifespan, str, Tuple[Any, sch.Schema]]]]]):
        if isinstance(results, List):
            return self._make_values(results)

        fut_values: Future[List[TraceObjectValue]] = Future()

        def _done(fut: Future[List[Tuple[DetachedObject, Lifespan, str,
                                         Tuple[Any, sch.Schema]]]]) -> None:
            fut_values.set_result(self._make_values(fut.result()))

        return fut_values

    def get_values(self, pattern: str,
                   span: Optional[Lifespan] = None) -> Union[
            List[TraceObjectValue], Future[List[TraceObjectValue]]]:
        if span is None:
            # "at" for getters
            span = Lifespan(self.snap(), self.snap())
        results = self.client._get_values(self.id, span, pattern)
        return self._convert_values(results)

    def get_values_intersecting(self, rng: AddressRange,
                                span: Optional[Lifespan] = None,
                                key: str = "") -> Union[
            List[TraceObjectValue], Future[List[TraceObjectValue]]]:
        if span is None:
            # "at" for getters
            span = Lifespan(self.snap(), self.snap())
        results = self.client._get_values_intersecting(self.id, span, rng, key)
        return self._convert_values(results)

    def _activate_object(self, object: TraceObject) -> None:
        self.client._activate_object(self.id, object)

    def disassemble(self, start: Address,
                    snap: Optional[int] = None) -> Union[
            int, RemoteResult[Any, int]]:
        if snap is None:
            snap = self.snap()
        return self.client._disassemble(self.id, snap, start)


class Transaction(object):

    def __init__(self, trace: Trace, id: int):
        self.closed: bool = False
        self.trace: Trace = trace
        self.id: int = id
        self.lock: Lock = Lock()

    def __repr__(self) -> str:
        return "<Transaction id={} trace={} closed={}>".format(
            self.id, self.trace, self.closed)

    def commit(self) -> None:
        with self.lock:
            if self.closed:
                return
            self.closed = True
        self.trace._end_tx(self.id, abort=False)

    def abort(self) -> None:
        with self.lock:
            if self.closed:
                return
            self.closed = True
        self.trace._end_tx(self.id, abort=True)


@dataclass(frozen=True)
class RemoteParameter:
    name: str
    schema: sch.Schema
    required: bool
    default: Any
    display: str
    description: str


# Use instances as type annotations
@dataclass(frozen=True)
class ParamDesc:
    display: str = ""
    schema: sch.Schema = sch.UNSPECIFIED
    description: str = ""


@dataclass(frozen=True)
class RemoteMethod:
    name: str
    action: str
    display: Optional[str]
    icon: Optional[str]
    ok_text: Optional[str]
    description: Optional[str]
    parameters: List[RemoteParameter]
    return_schema: sch.Schema
    callback: Callable


C = TypeVar('C', bound=Callable)


def unopt_type(t: type) -> type:
    if not get_origin(t) is Union:
        return t
    sub = [a for a in get_args(t) if a is not type(None)]
    if len(sub) != 1:
        raise TypeError("Unions not allowed except with None (for Optional)")
    return unopt_type(sub[0])


def find_metadata(annotation: Any, cls: type[T]) -> Tuple[Any, Optional[T]]:
    if not hasattr(annotation, '__metadata__'):
        return unopt_type(annotation), None
    for m in annotation.__metadata__:
        if isinstance(m, cls):
            return unopt_type(annotation.__origin__), m
    return unopt_type(annotation.__origin__), None


class MethodRegistry(object):

    def __init__(self, executor: Executor) -> None:
        self._methods: Dict[str, RemoteMethod] = {}
        self._executor: Executor = executor

    def register_method(self, method: RemoteMethod) -> None:
        self._methods[method.name] = method

    # Don't care t have p, except that I need it to get p.empty
    @classmethod
    def _to_schema(cls, p: inspect.Signature, annotation: Any) -> sch.Schema:
        if annotation is p.empty:
            return sch.ANY
        t, desc = find_metadata(annotation, ParamDesc)
        # print(f"---t={t}, p={p}---", file=sys.stderr)
        if desc is not None and desc.schema is not sch.UNSPECIFIED:
            return desc.schema
        elif t is None:
            return sch.VOID
        elif t is Any:
            return sch.ANY
        elif t is bool:
            return sch.BOOL
        elif t is int:
            return sch.LONG
        elif t is str:
            return sch.STRING
        elif t is bytes:
            return sch.BYTE_ARR
        elif t is Address:
            return sch.ADDRESS
        elif t is AddressRange:
            return sch.RANGE
        elif t is TraceObject:
            return sch.OBJECT
        elif isinstance(t, type) and issubclass(t, TraceObject):
            return sch.Schema(t.__name__)
        raise TypeError(f"Cannot get schema for {annotation}")

    @classmethod
    def _to_display(cls, annotation: Any) -> str:
        _, desc = find_metadata(annotation, ParamDesc)
        if desc is not None:
            return desc.display
        return ''

    @classmethod
    def _to_description(cls, annotation: Any) -> str:
        _, desc = find_metadata(annotation, ParamDesc)
        if desc is not None:
            return desc.description
        return ''

    @classmethod
    def _make_param(cls, s: inspect.Signature, p: inspect.Parameter) -> RemoteParameter:
        schema = cls._to_schema(s, p.annotation)
        required = p.default is p.empty
        return RemoteParameter(
            p.name, schema, required, None if required else p.default,
            cls._to_display(p.annotation), cls._to_description(p.annotation))

    @classmethod
    def create_method(cls, func: Callable, name: Optional[str] = None,
                      action: Optional[str] = None,
                      display: Optional[str] = None,
                      icon: Optional[str] = None,
                      ok_text: Optional[str] = None,
                      description: Optional[str] = None) -> RemoteMethod:
        if name is None:
            name = func.__name__
        if action is None:
            action = name
        if description is None:
            description = func.__doc__
        sig = inspect.signature(func)
        params = []
        for p in sig.parameters.values():
            params.append(cls._make_param(sig, p))
        return_schema = cls._to_schema(sig, sig.return_annotation)
        return RemoteMethod(name, action, display, icon, ok_text, description,
                            params, return_schema, func)

    def method(self, *,
               name: Optional[str] = None, action: Optional[str] = None,
               display: Optional[str] = None, icon: Optional[str] = None,
               ok_text: Optional[str] = None, description: Optional[str] = None,
               condition: bool = True) -> Callable[[C], C]:

        def _method(func: C) -> C:
            if condition:
                method = self.create_method(func, name, action, display,
                                            icon, ok_text, description)
                self.register_method(method)
            return func
        return _method


class Batch(object):

    def __init__(self) -> None:
        self.futures: List[RemoteResult] = []
        self.count: int = 0

    def inc(self) -> int:
        self.count += 1
        return self.count

    def dec(self) -> int:
        self.count -= 1
        return self.count

    def append(self, fut: RemoteResult) -> None:
        self.futures.append(fut)

    @staticmethod
    def _get_result(f: RemoteResult[Any, T],
                    timeout: Optional[int]) -> Union[T, BaseException]:
        try:
            return f.result(timeout)
        except BaseException as e:
            print(f"Exception in batch operation: {repr(e)}")
            return e

    def results(self, timeout: Optional[int] = None) -> List[Any]:
        return [self._get_result(f, timeout) for f in self.futures]


class Client(object):

    @staticmethod
    def _write_address(to: bufs.Addr, address: Address) -> None:
        to.space = address.space
        to.offset = address.offset

    @staticmethod
    def _read_address(msg: bufs.Addr) -> Address:
        return Address(msg.space, msg.offset)

    @staticmethod
    def _write_range(to: bufs.AddrRange, range: AddressRange) -> None:
        to.space = range.space
        to.offset = range.min
        to.extend = range.length() - 1

    @staticmethod
    def _read_range(msg: bufs.AddrRange) -> AddressRange:
        return Address(msg.space, msg.offset).extend(msg.extend + 1)

    @staticmethod
    def _write_span(to: bufs.Span, span: Lifespan) -> None:
        to.min = span.min
        to.max = span.max

    @staticmethod
    def _read_span(msg: bufs.Span) -> Lifespan:
        return Lifespan(msg.min, msg.max)

    @staticmethod
    def _write_obj_spec(to: bufs.ObjSpec, obj: Union[
            str, int, DetachedObject, TraceObject]) -> None:
        if isinstance(obj, int):
            to.id = obj
        elif isinstance(obj, str):
            to.path.path = obj
        elif isinstance(obj, DetachedObject):
            to.id = obj.id
        elif isinstance(obj.id, int):
            to.id = obj.id
        elif isinstance(obj.id, RemoteResult) and obj.id.done():
            to.id = obj.id.result()
        elif isinstance(obj.path, str):
            to.path.path = obj.path
        else:
            raise ValueError(
                "Object/proxy has neither id nor path!: {}".format(obj))

    @staticmethod
    def _read_obj_desc(msg: bufs.ObjDesc) -> DetachedObject:
        return DetachedObject(msg.id, msg.path.path)

    @staticmethod
    def _write_value(to: bufs.Value, value: Any,
                     schema: Optional[sch.Schema] = None) -> None:
        if value is None:
            to.null_value.SetInParent()
            return
        elif isinstance(value, bool):
            to.bool_value = value
            return
        elif isinstance(value, int):
            if schema == sch.BYTE:
                to.byte_value = value
                return
            elif schema == sch.CHAR:
                to.char_value = value
                return
            elif schema == sch.SHORT:
                to.short_value = value
                return
            elif schema == sch.INT:
                to.int_value = value
                return
            elif schema == sch.LONG:
                to.long_value = value
                return
            elif schema is None:
                to.long_value = value
                return
        elif isinstance(value, str):
            if schema == sch.CHAR_ARR:
                to.char_arr_value = value
                return
            to.string_value = value
            return
        elif isinstance(value, bytes):
            to.bytes_value = value
            return
        elif isinstance(value, Address):
            Client._write_address(to.address_value, value)
            return
        elif isinstance(value, AddressRange):
            Client._write_range(to.range_value, value)
            return
        elif isinstance(value, TraceObject):
            Client._write_obj_spec(to.child_spec, value)
            return
        Client._try_write_array(to, value, schema)

    @staticmethod
    def _try_write_array(to: bufs.Value, value: Iterable,
                         schema: Optional[sch.Schema]) -> None:
        if schema == sch.BOOL_ARR:
            to.bool_arr_value.arr[:] = value
            return
        elif schema == sch.SHORT_ARR:
            to.short_arr_value.arr[:] = value
            return
        elif schema == sch.INT_ARR:
            to.int_arr_value.arr[:] = value
            return
        elif schema == sch.LONG_ARR:
            to.long_arr_value.arr[:] = value
            return
        elif schema == sch.STRING_ARR:
            to.string_arr_value.arr[:] = value
            return
        raise ValueError(
            f"Cannot write Value: {schema}, {value}, {type(value)}")

    @staticmethod
    def _write_parameter(to: bufs.MethodParameter, p: RemoteParameter) -> None:
        to.name = p.name
        to.type.name = p.schema.name
        to.required = p.required
        Client._write_value(to.default_value, p.default)
        to.display = p.display
        to.description = p.description

    @staticmethod
    def _write_parameters(to: RCFC[bufs.MethodParameter],
                          parameters: Iterable[RemoteParameter]) -> None:
        for i, p in enumerate(parameters):
            to.add()
            Client._write_parameter(to[i], p)

    @staticmethod
    def _write_method(to: bufs.Method, method: RemoteMethod) -> None:
        to.name = method.name
        to.action = method.action
        to.display = method.display or ''
        to.icon = method.icon or ''
        to.ok_text = method.ok_text or ''
        to.description = method.description or ''
        Client._write_parameters(to.parameters, method.parameters)
        to.return_type.name = method.return_schema.name

    @staticmethod
    def _write_methods(to: RCFC[bufs.Method],
                       methods: Iterable[RemoteMethod]) -> None:
        for i, method in enumerate(methods):
            to.add()
            Client._write_method(to[i], method)

    @staticmethod
    def _read_value(msg: bufs.Value) -> Tuple[Any, sch.Schema]:
        name = msg.WhichOneof('value')
        if name == 'null_value':
            return None, sch.VOID
        if name == 'bool_value':
            return msg.bool_value, sch.BOOL
        if name == 'byte_value':
            return msg.byte_value, sch.BYTE
        if name == 'char_value':
            return chr(msg.char_value), sch.CHAR
        if name == 'short_value':
            return msg.short_value, sch.SHORT
        if name == 'int_value':
            return msg.int_value, sch.INT
        if name == 'long_value':
            return msg.long_value, sch.LONG
        if name == 'string_value':
            return msg.string_value, sch.STRING
        if name == 'bool_arr_value':
            return list(msg.bool_arr_value.arr), sch.BOOL_ARR
        if name == 'bytes_value':
            return msg.bytes_value, sch.BYTE_ARR
        if name == 'char_arr_value':
            return msg.char_arr_value, sch.CHAR_ARR
        if name == 'short_arr_value':
            return list(msg.short_arr_value.arr), sch.SHORT_ARR
        if name == 'int_arr_value':
            return list(msg.int_arr_value.arr), sch.INT_ARR
        if name == 'long_arr_value':
            return list(msg.long_arr_value.arr), sch.LONG_ARR
        if name == 'string_arr_value':
            return list(msg.string_arr_value.arr), sch.STRING_ARR
        if name == 'address_value':
            return Client._read_address(msg.address_value), sch.ADDRESS
        if name == 'range_value':
            return Client._read_range(msg.range_value), sch.RANGE
        if name == 'child_desc':
            return Client._read_obj_desc(msg.child_desc), sch.OBJECT
        raise ValueError("Could not read value: {}".format(msg))

    def __init__(self, s, description: str, method_registry: MethodRegistry):
        self._traces: Dict[int, Trace] = {}
        self._next_trace_id: int = 1
        self.tlock: Lock = Lock()

        self.receiver: Receiver = Receiver(self)
        self.cur_batch: Optional[Batch] = None
        self._block: Lock = Lock()
        self.s: socket.socket = s
        self.slock: Lock = Lock()
        self.receiver.start()
        self._method_registry: MethodRegistry = method_registry
        self.description: str = self._negotiate(description)

    def __repr__(self) -> str:
        return f"<ghidratrace.Client {self.s}>"

    def close(self) -> None:
        self.s.close()
        self.receiver.shutdown()

    def start_batch(self) -> Batch:
        with self._block:
            if self.cur_batch is None:
                self.cur_batch = Batch()
            self.cur_batch.inc()
            return self.cur_batch

    def end_batch(self) -> Optional[List[Any]]:
        cb = None
        with self._block:
            cb = self.cur_batch
            if cb is None:
                raise ValueError("No batch to end")
            if 0 == cb.dec():
                self.cur_batch = None
                return cb.results()
        return None

    @contextmanager
    def batch(self) -> Generator[Batch, None, Optional[List[Any]]]:
        """Execute a number of RMI calls in an asynchronous batch.

        This returns a context manager, meant to be used as follows:

           with client.batch():
               trace.set_value(...)
               trace.set_value(...)
               ...

        This is highly recommended when you know you will be making many rapid
        RMI calls. All calls to the API that could involve RMI will instead
        return a future within this context manager. The RMI message is sent
        immediately, but the handling of the reply is off-loaded to a
        background executor. Upon exiting the context, all futures created in
        that context will be joined, so that every returned value is guaranteed
        to be finished, notwithstanding catastrophic errors. Without this
        context manager, every call will require a round trip, which will slow
        things down. With the context, all the messages can be sent in rapid
        succession, and then all the results awaited at once.
        """

        batch = self.start_batch()
        yield batch
        return self.end_batch()

    def _batch_or_now(self, root: bufs.RootMessage, field_name: str,
                      handler: Callable[[T], U]) -> Union[U, RemoteResult[T, U]]:
        with self.slock:
            fut = self._recv(field_name, handler)
            send_delimited(self.s, root)
        if self.cur_batch is None:
            return fut.result()
        self.cur_batch.append(fut)
        return fut

    def _now(self, root: bufs.RootMessage, field_name: str,
             handler: Callable[[T], U]) -> U:
        with self.slock:
            fut = self._recv(field_name, handler)
            send_delimited(self.s, root)
        return fut.result()

    def _send(self, root: bufs.RootMessage) -> None:
        with self.slock:
            send_delimited(self.s, root)

    def _recv(self, name: str, handler: Callable[[T], U]) -> RemoteResult[T, U]:
        return self.receiver._recv(name, handler)

    def create_trace(self, path: str, language: str,
                     compiler: str = 'default', *, extra: E) -> Trace:
        root = bufs.RootMessage()
        root.request_create_trace.path.path = path
        root.request_create_trace.language.id = language
        root.request_create_trace.compiler.id = compiler
        with self.tlock:
            root.request_create_trace.oid.id = self._next_trace_id
            self._next_trace_id += 1
            trace = Trace(self, root.request_create_trace.oid.id, extra)
            self._traces[trace.id] = trace

        def _handle(reply: bufs.ReplyCreateTrace) -> None:
            pass
        self._batch_or_now(root, 'reply_create_trace', _handle)
        return trace

    def _close_trace(self, id: int) -> Union[None, RemoteResult[Any, None]]:
        root = bufs.RootMessage()
        root.request_close_trace.oid.id = id
        del self._traces[id]

        def _handle(reply: bufs.ReplyCloseTrace) -> None:
            pass
        return self._batch_or_now(root, 'reply_close_trace', _handle)

    def _save_trace(self, id: int) -> Union[None, RemoteResult[Any, None]]:
        root = bufs.RootMessage()
        root.request_save_trace.oid.id = id

        def _handle(reply: bufs.ReplySaveTrace) -> None:
            pass
        return self._batch_or_now(root, 'reply_save_trace', _handle)

    def _start_tx(self, id: int, description: str, undoable: bool,
                  txid: int) -> Union[None, RemoteResult[Any, None]]:
        root = bufs.RootMessage()
        root.request_start_tx.oid.id = id
        root.request_start_tx.undoable = undoable
        root.request_start_tx.description = description
        root.request_start_tx.txid.id = txid

        def _handle(reply: bufs.ReplyStartTx) -> None:
            pass
        return self._batch_or_now(root, 'reply_start_tx', _handle)

    def _end_tx(self, id: int, txid: int,
                abort: bool) -> Union[None, RemoteResult[Any, None]]:
        root = bufs.RootMessage()
        root.request_end_tx.oid.id = id
        root.request_end_tx.txid.id = txid
        root.request_end_tx.abort = abort

        def _handle(reply: bufs.ReplyEndTx) -> None:
            pass
        return self._batch_or_now(root, 'reply_end_tx', _handle)

    def _snapshot(self, id: int, description: str, datetime: Optional[str],
                  time: Schedule) -> Union[int, RemoteResult[Any, int]]:
        root = bufs.RootMessage()
        root.request_snapshot.oid.id = id
        root.request_snapshot.description = description
        root.request_snapshot.datetime = "" if datetime is None else datetime
        root.request_snapshot.schedule.schedule = str(time)

        def _handle(reply: bufs.ReplySnapshot) -> int:
            return reply.snap.snap
        return self._batch_or_now(root, 'reply_snapshot', _handle)

    def _create_overlay_space(self, id: int, base: str, name: str) -> Union[
            None, RemoteResult[Any, None]]:
        root = bufs.RootMessage()
        root.request_create_overlay.oid.id = id
        root.request_create_overlay.baseSpace = base
        root.request_create_overlay.name = name

        def _handle(reply: bufs.ReplyCreateOverlaySpace) -> None:
            pass
        return self._batch_or_now(root, 'reply_create_overlay', _handle)

    def _put_bytes(self, id: int, snap: int, start: Address,
                   data: bytes) -> Union[int, RemoteResult[Any, int]]:
        root = bufs.RootMessage()
        root.request_put_bytes.oid.id = id
        root.request_put_bytes.snap.snap = snap
        self._write_address(root.request_put_bytes.start, start)
        root.request_put_bytes.data = data

        def _handle(reply: bufs.ReplyPutBytes) -> int:
            return reply.written
        return self._batch_or_now(root, 'reply_put_bytes', _handle)

    def _set_memory_state(self, id: int, snap: int, range: AddressRange,
                          state: str) -> Union[None, RemoteResult[Any, None]]:
        root = bufs.RootMessage()
        root.request_set_memory_state.oid.id = id
        root.request_set_memory_state.snap.snap = snap
        self._write_range(root.request_set_memory_state.range, range)
        root.request_set_memory_state.state = getattr(
            bufs, 'MS_' + state.upper())

        def _handle(reply: bufs.ReplySetMemoryState) -> None:
            pass
        return self._batch_or_now(root, 'reply_set_memory_state', _handle)

    def _delete_bytes(self, id: int, snap: int, range: AddressRange) -> Union[
            None, RemoteResult[Any, None]]:
        root = bufs.RootMessage()
        root.request_delete_bytes.oid.id = id
        root.request_delete_bytes.snap.snap = snap
        self._write_range(root.request_delete_bytes.range, range)

        def _handle(reply: bufs.ReplyDeleteBytes) -> None:
            pass
        return self._batch_or_now(root, 'reply_delete_bytes', _handle)

    def _put_registers(self, id: int, snap: int, space: str,
                       values: Iterable[RegVal]) -> Union[
            List[str], RemoteResult[Any, List[str]]]:
        root = bufs.RootMessage()
        root.request_put_register_value.oid.id = id
        root.request_put_register_value.snap.snap = snap
        root.request_put_register_value.space = space
        for v in values:
            rv = bufs.RegVal()
            rv.name = v.name
            rv.value = v.value
            root.request_put_register_value.values.append(rv)

        def _handle(reply: bufs.ReplyPutRegisterValue) -> List[str]:
            return list(reply.skipped_names)
        return self._batch_or_now(root, 'reply_put_register_value', _handle)

    def _delete_registers(self, id: int, snap: int, space: str,
                          names: Iterable[str]) -> Union[
            None, RemoteResult[Any, None]]:
        root = bufs.RootMessage()
        root.request_delete_register_value.oid.id = id
        root.request_delete_register_value.snap.snap = snap
        root.request_delete_register_value.space = space
        root.request_delete_register_value.names.extend(names)

        def _handle(reply: bufs.ReplyDeleteRegisterValue) -> None:
            pass
        return self._batch_or_now(root, 'reply_delete_register_value', _handle)

    def _create_root_object(self, id: int, xml_context: str,
                            schema: str) -> Union[int, RemoteResult[Any, int]]:
        # TODO: An actual SchemaContext class?
        root = bufs.RootMessage()
        root.request_create_root_object.oid.id = id
        root.request_create_root_object.schema_context = xml_context
        root.request_create_root_object.root_schema = schema

        def _handle(reply: bufs.ReplyCreateObject) -> int:
            return reply.object.id
        return self._batch_or_now(root, 'reply_create_object', _handle)

    def _create_object(self, id: int,
                       path: str) -> Union[int, RemoteResult[Any, int]]:
        root = bufs.RootMessage()
        root.request_create_object.oid.id = id
        root.request_create_object.path.path = path

        def _handle(reply: bufs.ReplyCreateObject) -> int:
            return reply.object.id
        return self._batch_or_now(root, 'reply_create_object', _handle)

    def _insert_object(self, id: int, object: TraceObject, span: Lifespan,
                       resolution: str) -> Union[
            Lifespan, RemoteResult[Any, Lifespan]]:
        root = bufs.RootMessage()
        root.request_insert_object.oid.id = id
        self._write_obj_spec(root.request_insert_object.object, object)
        self._write_span(root.request_insert_object.span, span)
        root.request_insert_object.resolution = getattr(
            bufs, 'CR_' + resolution.upper())

        def _handle(reply: bufs.ReplyInsertObject) -> Lifespan:
            return self._read_span(reply.span)
        return self._batch_or_now(root, 'reply_insert_object', _handle)

    def _remove_object(self, id: int, object: TraceObject, span: Lifespan,
                       tree: bool) -> Union[None, RemoteResult[Any, None]]:
        root = bufs.RootMessage()
        root.request_remove_object.oid.id = id
        self._write_obj_spec(root.request_remove_object.object, object)
        self._write_span(root.request_remove_object.span, span)
        root.request_remove_object.tree = tree

        def _handle(reply: bufs.ReplyRemoveObject) -> None:
            pass
        return self._batch_or_now(root, 'reply_remove_object', _handle)

    def _set_value(self, id: int, object: TraceObject, span: Lifespan,
                   key: str, value: Any, schema: Optional[sch.Schema],
                   resolution: str) -> Union[
            Lifespan, RemoteResult[Any, Lifespan]]:
        root = bufs.RootMessage()
        root.request_set_value.oid.id = id
        self._write_obj_spec(root.request_set_value.value.parent, object)
        self._write_span(root.request_set_value.value.span, span)
        root.request_set_value.value.key = key
        self._write_value(root.request_set_value.value.value, value, schema)
        root.request_set_value.resolution = getattr(
            bufs, 'CR_' + resolution.upper())

        def _handle(reply: bufs.ReplySetValue) -> Lifespan:
            return self._read_span(reply.span)
        return self._batch_or_now(root, 'reply_set_value', _handle)

    def _retain_values(self, id: int, object: TraceObject, span: Lifespan,
                       kinds: str, keys: Iterable[str]) -> Union[
            None, RemoteResult[Any, None]]:
        root = bufs.RootMessage()
        root.request_retain_values.oid.id = id
        self._write_obj_spec(root.request_retain_values.object, object)
        self._write_span(root.request_retain_values.span, span)
        root.request_retain_values.kinds = getattr(
            bufs, 'VK_' + kinds.upper())
        root.request_retain_values.keys[:] = keys

        def _handle(reply: bufs.ReplyRetainValues) -> None:
            pass
        return self._batch_or_now(root, 'reply_retain_values', _handle)

    def _get_object(self, id: int, path_or_id: Union[str, int]) -> Union[
            DetachedObject, RemoteResult[Any, DetachedObject]]:
        root = bufs.RootMessage()
        root.request_get_object.oid.id = id
        self._write_obj_spec(root.request_get_object.object, path_or_id)

        def _handle(reply: bufs.ReplyGetObject) -> DetachedObject:
            return self._read_obj_desc(reply.object)
        return self._batch_or_now(root, 'reply_get_object', _handle)

    @staticmethod
    def _read_values(reply: bufs.ReplyGetValues) -> List[Tuple[
            DetachedObject, Lifespan, str, Tuple[Any, sch.Schema]]]:
        return [
            (Client._read_obj_desc(v.parent), Client._read_span(v.span),
             v.key, Client._read_value(v.value))
            for v in reply.values
        ]

    @staticmethod
    def _read_argument(arg: bufs.MethodArgument,
                       trace: Optional[Trace]) -> Tuple[str, Any]:
        name = arg.name
        value, schema = Client._read_value(arg.value)
        if schema is sch.OBJECT:
            if trace is None:
                raise TypeError("Method requires trace binding")
            if not isinstance(value, DetachedObject):
                raise TypeError(
                    "Internal: sch.OBJECT expects DetachedObject in args")
            id, path = value.id, value.path
            return name, trace.proxy_object(id=id, path=path)
        return name, value

    @staticmethod
    def _read_arguments(arguments: Iterable[bufs.MethodArgument],
                        trace: Optional[Trace]) -> Dict[str, Any]:
        kwargs = {}
        for arg in arguments:
            name, value = Client._read_argument(arg, trace)
            kwargs[name] = value
        return kwargs

    def _get_values(self, id: int, span: Lifespan, pattern: str) -> Union[
        List[Tuple[DetachedObject, Lifespan, str, Tuple[Any, sch.Schema]]],
            RemoteResult[Any, List[Tuple[DetachedObject, Lifespan, str,
                                         Tuple[Any, sch.Schema]]]]]:
        root = bufs.RootMessage()
        root.request_get_values.oid.id = id
        self._write_span(root.request_get_values.span, span)
        root.request_get_values.pattern.path = pattern

        def _handle(reply: bufs.ReplyGetValues) -> List[Any]:
            return self._read_values(reply)
        return self._batch_or_now(root, 'reply_get_values', _handle)

    def _get_values_intersecting(self, id: int, span: Lifespan,
                                 rng: AddressRange, key: str) -> Union[
            List[Any], RemoteResult[Any, List[Any]]]:
        root = bufs.RootMessage()
        root.request_get_values_intersecting.oid.id = id
        self._write_span(root.request_get_values_intersecting.box.span, span)
        self._write_range(root.request_get_values_intersecting.box.range, rng)
        root.request_get_values_intersecting.key = key

        def _handle(reply: bufs.ReplyGetValues) -> List[Any]:
            return self._read_values(reply)
        return self._batch_or_now(root, 'reply_get_values', _handle)

    def _activate_object(self, id: int, object: TraceObject) -> Union[
            None, RemoteResult[Any, None]]:
        root = bufs.RootMessage()
        root.request_activate.oid.id = id
        self._write_obj_spec(root.request_activate.object, object)

        def _handle(reply: bufs.ReplyActivate) -> None:
            pass
        return self._batch_or_now(root, 'reply_activate', _handle)

    def _disassemble(self, id: int, snap: int, start: Address) -> Union[
            int, RemoteResult[Any, int]]:
        root = bufs.RootMessage()
        root.request_disassemble.oid.id = id
        root.request_disassemble.snap.snap = snap
        self._write_address(root.request_disassemble.start, start)

        def _handle(reply: bufs.ReplyDisassemble) -> int:
            return reply.length
        return self._batch_or_now(root, 'reply_disassemble', _handle)

    def _negotiate(self, description: str) -> str:
        root = bufs.RootMessage()
        root.request_negotiate.version = VERSION
        root.request_negotiate.description = description
        self._write_methods(root.request_negotiate.methods,
                            self._method_registry._methods.values())

        def _handle(reply: bufs.ReplyNegotiate) -> str:
            return reply.description
        return self._now(root, 'reply_negotiate', _handle)

    def _handle_invoke_method(self, request: bufs.XRequestInvokeMethod) -> Any:
        if request.HasField('oid'):
            if request.oid.id not in self._traces:
                raise KeyError(f"Invalid domain object id: {request.oid.id}")
            trace = self._traces[request.oid.id]
        else:
            trace = None
        name = request.name
        if not name in self._method_registry._methods:
            raise KeyError(f"Invalid method name: {name}")
        method = self._method_registry._methods[name]
        kwargs = self._read_arguments(request.arguments, trace)
        return method.callback(**kwargs)


class Receiver(Thread):
    __slots__ = ('client', 'req_queue', '_is_shutdown')

    def __init__(self, client: Client) -> None:
        super().__init__(daemon=True)
        self.client: Client = client
        self.req_queue: deque[RemoteResult[Any, Any]] = deque()
        self.qlock: Lock = Lock()
        self._is_shutdown: bool = False

    def shutdown(self) -> None:
        self._is_shutdown = True

    def _handle_invoke_method(self, request: bufs.XRequestInvokeMethod) -> None:
        reply = bufs.RootMessage()
        try:
            result = self.client._handle_invoke_method(request)
            Client._write_value(
                reply.xreply_invoke_method.return_value, result)
        except BaseException as e:
            print(f"Error caused by front end: {e}")
            # TODO: Add a field to error for stacktrace, log it at front-end
            # traceback.print_exc()
            reply.xreply_invoke_method.error = repr(e)
        self.client._send(reply)

    def _handle_reply(self, reply: bufs.RootMessage) -> None:
        with self.qlock:
            request = self.req_queue.popleft()
        if reply.HasField('error'):
            request.set_exception(TraceRmiError(reply.error.message))
        elif not reply.HasField(request.field_name):
            request.set_exception(ProtocolError(
                'expected {}, but got {}'.format(request.field_name,
                                                 reply.WhichOneof('msg'))))
        else:
            try:
                result = request.handler(
                    getattr(reply, request.field_name))
                request.set_result(result)
            except BaseException as e:
                request.set_exception(e)

    def _recv(self, field_name: str,
              handler: Callable[[T], U]) -> RemoteResult[T, U]:
        fut = RemoteResult(field_name, handler)
        with self.qlock:
            self.req_queue.append(fut)
        return fut

    def run(self) -> None:
        dbg_seq = 0
        while not self._is_shutdown:
            # print("Receiving message")
            try:
                reply = recv_delimited(
                    self.client.s, bufs.RootMessage(), dbg_seq)
            except BaseException as e:
                self._is_shutdown = True
                return
            # print(f"Got one: {reply.WhichOneof('msg')}")
            dbg_seq += 1
            try:
                if reply.HasField('xrequest_invoke_method'):
                    self.client._method_registry._executor.submit(
                        self._handle_invoke_method, reply.xrequest_invoke_method)
                else:
                    self._handle_reply(reply)
            except:
                traceback.print_exc()
