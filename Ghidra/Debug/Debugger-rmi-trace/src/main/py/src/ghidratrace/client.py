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
from collections import deque, namedtuple
from concurrent.futures import Future
from contextlib import contextmanager
from dataclasses import dataclass
import inspect
import sys
from threading import Thread, Lock
import traceback
from typing import Any, List

from . import sch
from . import trace_rmi_pb2 as bufs
from .util import send_delimited, recv_delimited

# This need not be incremented every Ghidra release. When a breaking protocol
# change is made, this should be updated to match the first Ghidra release that
# includes the change.
VERSION = '10.4'


class RemoteResult(Future):
    __slots__ = ('field_name', 'handler')

    def __init__(self, field_name, handler):
        super().__init__()
        self.field_name = field_name
        self.handler = handler


class Receiver(Thread):
    __slots__ = ('client', 'req_queue', '_is_shutdown')

    def __init__(self, client):
        super().__init__(daemon=True)
        self.client = client
        self.req_queue = deque()
        self.qlock = Lock()
        self._is_shutdown = False

    def shutdown(self):
        self._is_shutdown = True

    def _handle_invoke_method(self, request):
        reply = bufs.RootMessage()
        try:
            result = self.client._handle_invoke_method(request)
            Client._write_value(
                reply.xreply_invoke_method.return_value, result)
        except Exception as e:
            reply.xreply_invoke_method.error = ''.join(
                traceback.format_exc())
        self.client._send(reply)

    def _handle_reply(self, reply):
        with self.qlock:
            request = self.req_queue.popleft()
        if reply.HasField('error'):
            request.set_exception(TraceRmiError(reply.error.message))
        elif not reply.HasField(request.field_name):
            request.set_exception(ProtocolError('expected {}, but got {}'.format(
                request.field_name, reply.WhichOneof('msg'))))
        else:
            try:
                result = request.handler(
                    getattr(reply, request.field_name))
                request.set_result(result)
            except Exception as e:
                request.set_exception(e)

    def _recv(self, field_name, handler):
        fut = RemoteResult(field_name, handler)
        with self.qlock:
            self.req_queue.append(fut)
        return fut

    def run(self):
        dbg_seq = 0
        while not self._is_shutdown:
            #print("Receiving message")
            reply = recv_delimited(self.client.s, bufs.RootMessage(), dbg_seq)
            #print(f"Got one: {reply.WhichOneof('msg')}")
            dbg_seq += 1
            try:
                if reply.HasField('xrequest_invoke_method'):
                    self.client._method_registry._executor.submit(
                        self._handle_invoke_method, reply.xrequest_invoke_method)
                else:
                    self._handle_reply(reply)
            except:
                traceback.print_exc()


class TraceRmiError(Exception):
    pass


class ProtocolError(Exception):
    pass


class Transaction(object):

    def __init__(self, trace, id):
        self.closed = False
        self.trace = trace
        self.id = id
        self.lock = Lock()

    def __repr__(self):
        return "<Transaction id={} trace={} closed={}>".format(
            self.id, self.trace, self.close)

    def commit(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
        self.trace._end_tx(self.id, abort=False)

    def abort(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
        self.trace._end_tx(self.id, abort=True)


RegVal = namedtuple('RegVal', ['name', 'value'])


class Address(namedtuple('BaseAddress', ['space', 'offset'])):

    def extend(self, length):
        return AddressRange.extend(self, length)


class AddressRange(namedtuple('BaseAddressRange', ['space', 'min', 'max'])):

    @classmethod
    def extend(cls, min, length):
        return cls(min.space, min.offset, min.offset + length - 1)

    def length(self):
        return self.max - self.min + 1


class Lifespan(namedtuple('BaseLifespan', ['min', 'max'])):

    def __new__(cls, min, max=None):
        if min is None:
            min = -1 << 63
        if max is None:
            max = (1 << 63) - 1
        if min > max and not (min == 0 and max == -1):
            raise ValueError("min cannot exceed max")
        return super().__new__(cls, min, max)

    def is_empty(self):
        return self.min == 0 and self.max == -1

    def __str__(self):
        if self.is_empty():
            return "(EMPTY)"
        min = '(-inf' if self.min == -1 << 63 else '[{}'.format(self.min)
        max = '+inf)' if self.max == (1 << 63) - 1 else '{}]'.format(self.max)
        return '{},{}'.format(min, max)

    def __repr__(self):
        return 'Lifespan' + self.__str__()


DetachedObject = namedtuple('DetachedObject', ['id', 'path'])


class TraceObject(namedtuple('BaseTraceObject', ['trace', 'id', 'path'])):
    """
    A proxy for a TraceObject
    """
    __slots__ = ()

    @classmethod
    def from_id(cls, trace, id):
        return cls(trace=trace, id=id, path=None)

    @classmethod
    def from_path(cls, trace, path):
        return cls(trace=trace, id=None, path=path)

    def insert(self, span=None, resolution='adjust'):
        if span is None:
            span = Lifespan(self.trace.snap())
        return self.trace._insert_object(self, span, resolution)

    def remove(self, span=None, tree=False):
        if span is None:
            span = Lifespan(self.trace.snap())
        return self.trace._remove_object(self, span, tree)

    def set_value(self, key, value, schema=None, span=None, resolution='adjust'):
        if span is None:
            span = Lifespan(self.trace.snap())
        return self.trace._set_value(self, span, key, value, schema, resolution)

    def retain_values(self, keys, span=None, kinds='elements'):
        if span is None:
            span = Lifespan(self.trace.snap())
        return self.trace._retain_values(self, span, kinds, keys)

    def activate(self):
        self.trace._activate_object(self)


class TraceObjectValue(namedtuple('BaseTraceObjectValue', [
        'parent', 'span', 'key', 'value', 'schema'])):
    """
    A record of a TraceObjectValue
    """
    __slots__ = ()


class Trace(object):

    def __init__(self, client, id):
        self._next_tx = 0
        self._txlock = Lock()

        self.closed = False
        self.client = client
        self.id = id
        self.overlays = set()

        self._snap = None
        self._snlock = Lock()

    def __repr__(self):
        return "<Trace id={} closed={}>".format(self.id, self.closed)

    def close(self):
        if self.closed:
            return
        self.client._close_trace(self.id)
        self.closed = True

    def save(self):
        return self.client._save_trace(self.id)

    def start_tx(self, description, undoable=False):
        with self._txlock:
            txid = self._next_tx
            self._next_tx += 1
        self.client._start_tx(self.id, description, undoable, txid)
        return Transaction(self, txid)

    @contextmanager
    def open_tx(self, description, undoable=False):
        tx = self.start_tx(description, undoable)
        yield tx
        tx.commit()

    def _end_tx(self, txid, abort):
        return self.client._end_tx(self.id, txid, abort)

    def _next_snap(self):
        with self._snlock:
            if self._snap is None:
                self._snap = 0
            else:
                self._snap += 1
            return self._snap

    def snapshot(self, description, datetime=None):
        """
        Create a snapshot.

        Future state operations implicitly modify this new snapshot.
        """

        snap = self._next_snap()
        self.client._snapshot(self.id, description, datetime, snap)
        return snap

    def snap(self):
        return self._snap or 0

    def set_snap(self, snap):
        self._snap = snap

    def create_overlay_space(self, base, name):
        if name in self.overlays:
            return
        result = self.client._create_overlay_space(self.id, base, name)
        self.overlays.add(name)
        return result

    def put_bytes(self, address, data, snap=None):
        if snap is None:
            snap = self.snap()
        return self.client._put_bytes(self.id, snap, address, data)

    @staticmethod
    def validate_state(state):
        if not state in ('unknown', 'known', 'error'):
            raise gdb.GdbError("Invalid memory state: {}".format(state))

    def set_memory_state(self, range, state, snap=None):
        if snap is None:
            snap = self.snap()
        return self.client._set_memory_state(self.id, snap, range, state)

    def delete_bytes(self, range, snap=None):
        if snap is None:
            snap = self.snap()
        return self.client._delete_bytes(self.id, snap, range)

    def put_registers(self, space, values, snap=None):
        if snap is None:
            snap = self.snap()
        return self.client._put_registers(self.id, snap, space, values)

    def delete_registers(self, space, names, snap=None):
        if snap is None:
            snap = self.snap()
        return self.client._delete_registers(self.id, snap, space, names)

    def create_root_object(self, xml_context, schema):
        return TraceObject(self, self.client._create_root_object(self.id, xml_context, schema), "")

    def create_object(self, path):
        return TraceObject(self, self.client._create_object(self.id, path), path)

    def _insert_object(self, object, span, resolution):
        return self.client._insert_object(self.id, object, span, resolution)

    def _remove_object(self, object, span, tree):
        return self.client._remove_object(self.id, object, span, tree)

    def _set_value(self, object, span, key, value, schema, resolution):
        return self.client._set_value(self.id, object, span, key, value, schema, resolution)

    def _retain_values(self, object, span, kinds, keys):
        return self.client._retain_values(self.id, object, span, kinds, keys)

    def proxy_object_id(self, id):
        return TraceObject.from_id(self, id)

    def proxy_object_path(self, path):
        return TraceObject.from_path(self, path)

    def proxy_object(self, id=None, path=None):
        if id is None and path is None:
            raise ValueError("Must have id or path")
        return TraceObject(self, id, path)

    def get_object(self, path_or_id):
        id, path = self.client._get_object(self.id, path_or_id)
        return TraceObject(self, id, path)

    def _fix_value(self, value, schema):
        if schema != sch.OBJECT:
            return value
        id, path = value
        return TraceObject(self, id, path)

    def _make_values(self, values):
        return [
            TraceObjectValue(TraceObject(self, id, path),
                             span, key, self._fix_value(value, schema), schema)
            for (id, path), span, key, (value, schema) in values
        ]

    def get_values(self, pattern, span=None):
        if span is None:
            # singleton for getters
            span = Lifespan(self.snap(), self.snap())
        return self._make_values(self.client._get_values(self.id, span, pattern))

    def get_values_intersecting(self, rng, span=None, key=""):
        if span is None:
            span = Lifespan(self.snap(), self.snap())
        return self._make_values(self.client._get_values_intersecting(self.id, span, rng, key))

    def _activate_object(self, object):
        self.client._activate_object(self.id, object)

    def disassemble(self, start, snap=None):
        if snap is None:
            snap = self.snap()
        return self.client._disassemble(self.id, snap, start)


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
    type: Any
    display: str
    description: str = ""


@dataclass(frozen=True)
class RemoteMethod:
    name: str
    action: str
    description: str
    parameters: List[RemoteParameter]
    return_schema: sch.Schema
    callback: Any


class MethodRegistry(object):

    def __init__(self, executor):
        self._methods = {}
        self._executor = executor

    def register_method(self, method: RemoteMethod):
        self._methods[method.name] = method

    @classmethod
    def _to_schema(cls, p, annotation):
        if isinstance(annotation, ParamDesc):
            annotation = annotation.type
        if isinstance(annotation, sch.Schema):
            return annotation
        elif isinstance(annotation, str):
            return sch.Schema(annotation)
        elif annotation is p.empty:
            return sch.ANY
        elif annotation is bool:
            return sch.BOOL
        elif annotation is int:
            return sch.LONG
        elif annotation is str:
            return sch.STRING
        elif annotation is bytes:
            return sch.BYTE_ARR
        elif annotation is Address:
            return sch.ADDRESS
        elif annotation is AddressRange:
            return sch.RANGE

    @classmethod
    def _to_display(cls, annotation):
        if isinstance(annotation, ParamDesc):
            return annotation.display
        return ''

    @classmethod
    def _to_description(cls, annotation):
        if isinstance(annotation, ParamDesc):
            return annotation.description
        return ''

    @classmethod
    def _make_param(cls, p):
        schema = cls._to_schema(p, p.annotation)
        required = p.default is p.empty
        return RemoteParameter(
            p.name, schema, required, None if required else p.default,
            cls._to_display(p.annotation), cls._to_description(p.annotation))

    @classmethod
    def create_method(cls, function, name=None, action=None, description=None) -> RemoteMethod:
        if name is None:
            name = function.__name__
        if action is None:
            action = name
        if description is None:
            description = function.__doc__ or ''
        sig = inspect.signature(function)
        params = []
        for p in sig.parameters.values():
            params.append(cls._make_param(p))
        return_schema = cls._to_schema(sig, sig.return_annotation)
        return RemoteMethod(name, action, description, params, return_schema, function)

    def method(self, func=None, *, name=None, action=None, description='',
               condition=True):

        def _method(func):
            if condition:
                method = self.create_method(func, name, action, description)
                self.register_method(method)
            return func

        if func is not None:
            return _method(func)
        return _method


class Batch(object):

    def __init__(self):
        self.futures = []
        self.count = 0

    def inc(self):
        self.count += 1
        return self.count

    def dec(self):
        self.count -= 1
        return self.count

    def append(self, fut):
        self.futures.append(fut)

    def results(self, timeout=None):
        return [f.result(timeout) for f in self.futures]


class Client(object):

    @staticmethod
    def _write_address(to, address):
        to.space = address.space
        to.offset = address.offset

    @staticmethod
    def _read_address(msg):
        return Address(msg.space, msg.offset)

    @staticmethod
    def _write_range(to, range):
        to.space = range.space
        to.offset = range.min
        to.extend = range.length() - 1

    @staticmethod
    def _read_range(msg):
        return Address(msg.space, msg.offset).extend(msg.extend + 1)

    @staticmethod
    def _write_span(to, span):
        to.min = span.min
        to.max = span.max

    @staticmethod
    def _read_span(msg):
        return Lifespan(msg.min, msg.max)

    @staticmethod
    def _write_obj_spec(to, path_or_id):
        if isinstance(path_or_id, int):
            to.id = path_or_id
        elif isinstance(path_or_id, str):
            to.path.path = path_or_id
        elif isinstance(path_or_id.id, Future) and path_or_id.id.done():
            to.id = path_or_id.id.result()
        elif isinstance(path_or_id.id, int):
            to.id = path_or_id.id
        elif path_or_id.path is not None:
            to.path.path = path_or_id.path
        else:
            raise ValueError(
                "Object/proxy has neither id nor path!: {}".format(path_or_id))

    @staticmethod
    def _read_obj_desc(msg):
        return DetachedObject(msg.id, msg.path.path)

    @staticmethod
    def _write_value(to, value, schema=None):
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
    def _try_write_array(to, value, schema):
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
    def _write_parameter(to, p):
        to.name = p.name
        to.type.name = p.schema.name
        to.required = p.required
        Client._write_value(to.default_value, p.default)
        to.display = p.display
        to.description = p.description

    @staticmethod
    def _write_parameters(to, parameters):
        for i, p in enumerate(parameters):
            to.add()
            Client._write_parameter(to[i], p)

    @staticmethod
    def _write_method(to: bufs.Method, method: RemoteMethod):
        to.name = method.name
        to.action = method.action
        to.description = method.description
        Client._write_parameters(to.parameters, method.parameters)
        to.return_type.name = method.return_schema.name

    @staticmethod
    def _write_methods(to, methods):
        for i, method in enumerate(methods):
            to.add()
            Client._write_method(to[i], method)

    @staticmethod
    def _read_value(msg):
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
        self._traces = {}
        self._next_trace_id = 1
        self.tlock = Lock()

        self.receiver = Receiver(self)
        self.cur_batch = None
        self._block = Lock()
        self.s = s
        self.slock = Lock()
        self.receiver.start()
        self._method_registry = method_registry
        self.description = self._negotiate(description)

    def close(self):
        self.s.close()
        self.receiver.shutdown()

    def start_batch(self):
        with self._block:
            if self.cur_batch is None:
                self.cur_batch = Batch()
            self.cur_batch.inc()
            return self.cur_batch

    def end_batch(self):
        cb = None
        with self._block:
            if 0 == self.cur_batch.dec():
                cb = self.cur_batch
                self.cur_batch = None
        return cb.results() if cb else None

    @contextmanager
    def batch(self):
        """
        Execute a number of RMI calls in an asynchronous batch.

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

        self.start_batch()
        yield self.cur_batch
        return self.end_batch()

    def _batch_or_now(self, root, field_name, handler):
        with self.slock:
            fut = self._recv(field_name, handler)
            send_delimited(self.s, root)
        if self.cur_batch is None:
            return fut.result()
        self.cur_batch.append(fut)
        return fut

    def _now(self, root, field_name, handler):
        with self.slock:
            fut = self._recv(field_name, handler)
            send_delimited(self.s, root)
        return fut.result()

    def _send(self, root):
        with self.slock:
            send_delimited(self.s, root)

    def _recv(self, name, handler):
        return self.receiver._recv(name, handler)

    def create_trace(self, path, language, compiler='default'):
        root = bufs.RootMessage()
        root.request_create_trace.path.path = path
        root.request_create_trace.language.id = language
        root.request_create_trace.compiler.id = compiler
        with self.tlock:
            root.request_create_trace.oid.id = self._next_trace_id
            self._next_trace_id += 1
            trace = Trace(self, root.request_create_trace.oid.id)
            self._traces[trace.id] = trace

        def _handle(reply):
            pass
        self._batch_or_now(root, 'reply_create_trace', _handle)
        return trace

    def _close_trace(self, id):
        root = bufs.RootMessage()
        root.request_close_trace.oid.id = id
        del self._traces[id]

        def _handle(reply):
            pass
        return self._batch_or_now(root, 'reply_close_trace', _handle)

    def _save_trace(self, id):
        root = bufs.RootMessage()
        root.request_save_trace.oid.id = id

        def _handle(reply):
            pass
        return self._batch_or_now(root, 'reply_save_trace', _handle)

    def _start_tx(self, id, description, undoable, txid):
        root = bufs.RootMessage()
        root.request_start_tx.oid.id = id
        root.request_start_tx.undoable = undoable
        root.request_start_tx.description = description
        root.request_start_tx.txid.id = txid

        def _handle(reply):
            pass
        return self._batch_or_now(root, 'reply_start_tx', _handle)

    def _end_tx(self, id, txid, abort):
        root = bufs.RootMessage()
        root.request_end_tx.oid.id = id
        root.request_end_tx.txid.id = txid
        root.request_end_tx.abort = abort

        def _handle(reply):
            pass
        return self._batch_or_now(root, 'reply_end_tx', _handle)

    def _snapshot(self, id, description, datetime, snap):
        root = bufs.RootMessage()
        root.request_snapshot.oid.id = id
        root.request_snapshot.description = description
        root.request_snapshot.datetime = "" if datetime is None else datetime
        root.request_snapshot.snap.snap = snap

        def _handle(reply):
            pass
        return self._batch_or_now(root, 'reply_snapshot', _handle)

    def _create_overlay_space(self, id, base, name):
        root = bufs.RootMessage()
        root.request_create_overlay.oid.id = id
        root.request_create_overlay.baseSpace = base
        root.request_create_overlay.name = name

        def _handle(reply):
            pass
        return self._batch_or_now(root, 'reply_create_overlay', _handle)

    def _put_bytes(self, id, snap, start, data):
        root = bufs.RootMessage()
        root.request_put_bytes.oid.id = id
        root.request_put_bytes.snap.snap = snap
        self._write_address(root.request_put_bytes.start, start)
        root.request_put_bytes.data = data

        def _handle(reply):
            return reply.written
        return self._batch_or_now(root, 'reply_put_bytes', _handle)

    def _set_memory_state(self, id, snap, range, state):
        root = bufs.RootMessage()
        root.request_set_memory_state.oid.id = id
        root.request_set_memory_state.snap.snap = snap
        self._write_range(root.request_set_memory_state.range, range)
        root.request_set_memory_state.state = getattr(
            bufs, 'MS_' + state.upper())

        def _handle(reply):
            pass
        return self._batch_or_now(root, 'reply_set_memory_state', _handle)

    def _delete_bytes(self, id, snap, range):
        root = bufs.RootMessage()
        root.request_delete_bytes.oid.id = id
        root.request_delete_bytes.snap.snap = snap
        self._write_range(root.request_delete_bytes.range, range)

        def _handle(reply):
            pass
        return self._batch_or_now(root, 'reply_delete_bytes', _handle)

    def _put_registers(self, id, snap, space, values):
        root = bufs.RootMessage()
        root.request_put_register_value.oid.id = id
        root.request_put_register_value.snap.snap = snap
        root.request_put_register_value.space = space
        for v in values:
            rv = bufs.RegVal()
            rv.name = v.name
            rv.value = v.value
            root.request_put_register_value.values.append(rv)

        def _handle(reply):
            return list(reply.skipped_names)
        return self._batch_or_now(root, 'reply_put_register_value', _handle)

    def _delete_registers(self, id, snap, space, names):
        root = bufs.RootMessage()
        root.request_delete_register_value.oid.id = id
        root.request_delete_register_value.snap.snap = snap
        root.request_delete_register_value.space = space
        root.request_delete_register_value.names.extend(names)

        def _handle(reply):
            pass
        return self._batch_or_now(root, 'reply_delete_register_value', _handle)

    def _create_root_object(self, id, xml_context, schema):
        # TODO: An actual SchemaContext class?
        root = bufs.RootMessage()
        root.request_create_root_object.oid.id = id
        root.request_create_root_object.schema_context = xml_context
        root.request_create_root_object.root_schema = schema

        def _handle(reply):
            return reply.object.id
        return self._batch_or_now(root, 'reply_create_object', _handle)

    def _create_object(self, id, path):
        root = bufs.RootMessage()
        root.request_create_object.oid.id = id
        root.request_create_object.path.path = path

        def _handle(reply):
            return reply.object.id
        return self._batch_or_now(root, 'reply_create_object', _handle)

    def _insert_object(self, id, object, span, resolution):
        root = bufs.RootMessage()
        root.request_insert_object.oid.id = id
        self._write_obj_spec(root.request_insert_object.object, object)
        self._write_span(root.request_insert_object.span, span)
        root.request_insert_object.resolution = getattr(
            bufs, 'CR_' + resolution.upper())

        def _handle(reply):
            return self._read_span(reply.span)
        return self._batch_or_now(root, 'reply_insert_object', _handle)

    def _remove_object(self, id, object, span, tree):
        root = bufs.RootMessage()
        root.request_remove_object.oid.id = id
        self._write_obj_spec(root.request_remove_object.object, object)
        self._write_span(root.request_remove_object.span, span)
        root.request_remove_object.tree = tree

        def _handle(reply):
            pass
        return self._batch_or_now(root, 'reply_remove_object', _handle)

    def _set_value(self, id, object, span, key, value, schema, resolution):
        root = bufs.RootMessage()
        root.request_set_value.oid.id = id
        self._write_obj_spec(root.request_set_value.value.parent, object)
        self._write_span(root.request_set_value.value.span, span)
        root.request_set_value.value.key = key
        self._write_value(root.request_set_value.value.value, value, schema)
        root.request_set_value.resolution = getattr(
            bufs, 'CR_' + resolution.upper())

        def _handle(reply):
            return Lifespan(reply.span.min, reply.span.max)
        return self._batch_or_now(root, 'reply_set_value', _handle)

    def _retain_values(self, id, object, span, kinds, keys):
        root = bufs.RootMessage()
        root.request_retain_values.oid.id = id
        self._write_obj_spec(root.request_retain_values.object, object)
        self._write_span(root.request_retain_values.span, span)
        root.request_retain_values.kinds = getattr(
            bufs, 'VK_' + kinds.upper())
        root.request_retain_values.keys[:] = keys

        def _handle(reply):
            pass
        return self._batch_or_now(root, 'reply_retain_values', _handle)

    def _get_object(self, id, path_or_id):
        root = bufs.RootMessage()
        root.request_get_object.oid.id = id
        self._write_obj_spec(root.request_get_object.object, path_or_id)

        def _handle(reply):
            return self._read_obj_desc(reply.object)
        return self._batch_or_now(root, 'reply_get_object', _handle)

    @staticmethod
    def _read_values(reply):
        return [
            (Client._read_obj_desc(v.parent), Client._read_span(v.span),
             v.key, Client._read_value(v.value))
            for v in reply.values
        ]

    @staticmethod
    def _read_argument(arg, trace):
        name = arg.name
        value, schema = Client._read_value(arg.value)
        if schema is sch.OBJECT:
            if trace is None:
                raise TypeError("Method requires trace binding")
            id, path = value
            return name, trace.proxy_object(id=id, path=path)
        return name, value

    @staticmethod
    def _read_arguments(arguments, trace):
        kwargs = {}
        for arg in arguments:
            name, value = Client._read_argument(arg, trace)
            kwargs[name] = value
        return kwargs

    def _get_values(self, id, span, pattern):
        root = bufs.RootMessage()
        root.request_get_values.oid.id = id
        self._write_span(root.request_get_values.span, span)
        root.request_get_values.pattern.path = pattern

        def _handle(reply):
            return self._read_values(reply)
        return self._batch_or_now(root, 'reply_get_values', _handle)

    def _get_values_intersecting(self, id, span, rng, key):
        root = bufs.RootMessage()
        root.request_get_values_intersecting.oid.id = id
        self._write_span(root.request_get_values_intersecting.box.span, span)
        self._write_range(root.request_get_values_intersecting.box.range, rng)
        root.request_get_values_intersecting.key = key

        def _handle(reply):
            return self._read_values(reply)
        return self._batch_or_now(root, 'reply_get_values', _handle)

    def _activate_object(self, id, object):
        root = bufs.RootMessage()
        root.request_activate.oid.id = id
        self._write_obj_spec(root.request_activate.object, object)

        def _handle(reply):
            pass
        return self._batch_or_now(root, 'reply_activate', _handle)

    def _disassemble(self, id, snap, start):
        root = bufs.RootMessage()
        root.request_disassemble.oid.id = id
        root.request_disassemble.snap.snap = snap
        self._write_address(root.request_disassemble.start, start)

        def _handle(reply):
            return reply.length
        return self._batch_or_now(root, 'reply_disassemble', _handle)

    def _negotiate(self, description: str):
        root = bufs.RootMessage()
        root.request_negotiate.version = VERSION
        root.request_negotiate.description = description
        self._write_methods(root.request_negotiate.methods,
                            self._method_registry._methods.values())

        def _handle(reply):
            return reply.description
        return self._now(root, 'reply_negotiate', _handle)

    def _handle_invoke_method(self, request):
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
