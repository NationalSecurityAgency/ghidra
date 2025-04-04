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
from comtypes.automation import VARIANT  # type: ignore

from ghidratrace.client import Schedule
from .dbgmodel.imodelobject import ModelObject
from capstone import CsInsn  # type: ignore
from _winapi import STILL_ACTIVE
from collections import namedtuple
from concurrent.futures import Future
import concurrent.futures
from ctypes import POINTER, byref, c_ulong, c_ulonglong, create_string_buffer
import functools
import io
import os
import queue
import re
import sys
import threading
import traceback
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, TypeVar, Union, cast

from comtypes import CoClass, GUID  # type: ignore
import comtypes  # type: ignore
from comtypes.gen import DbgMod  # type: ignore
from comtypes.hresult import S_OK, S_FALSE  # type: ignore
from ghidradbg.dbgmodel.ihostdatamodelaccess import HostDataModelAccess
from ghidradbg.dbgmodel.imodelmethod import ModelMethod
from pybag import pydbg, userdbg, kerneldbg, crashdbg  # type: ignore
from pybag.dbgeng import core as DbgEng  # type: ignore
from pybag.dbgeng import exception  # type: ignore
from pybag.dbgeng import util as DbgUtil  # type: ignore
from pybag.dbgeng.callbacks import DbgEngCallbacks  # type: ignore
from pybag.dbgeng.idebugclient import DebugClient  # type: ignore

DESCRIPTION_PATTERN = '[{major:X}:{minor:X}] {type}'

DbgVersion = namedtuple('DbgVersion', ['full', 'name', 'dotted', 'arch'])


class StdInputCallbacks(CoClass):
    # This is the UUID listed for IDebugInputCallbacks in DbgEng.h
    # See https://github.com/tpn/winsdk-10/blob/master/Include/10.0.10240.0/um/DbgEng.h
    # Accessed 9 Jan 2024
    _reg_clsid_ = GUID("{9f50e42c-f136-499e-9a97-73036c94ed2d}")
    _reg_threading_ = "Both"
    _reg_progid_ = "dbgeng.DbgEngInputCallbacks.1"
    _reg_novers_progid_ = "dbgeng.DbgEngInputCallbacks"
    _reg_desc_ = "InputCallbacks"
    _reg_clsctx_ = comtypes.CLSCTX_INPROC_SERVER

    _com_interfaces_ = [DbgEng.IDebugInputCallbacks,
                        comtypes.typeinfo.IProvideClassInfo2,
                        comtypes.errorinfo.ISupportErrorInfo,
                        comtypes.connectionpoints.IConnectionPointContainer]

    def __init__(self, ghidra_dbg):
        self.ghidra_dbg = ghidra_dbg
        self.expecting_input = False

    def IDebugInputCallbacks_StartInput(self, buffer_size):
        try:
            self.expecting_input = True
            self.buffer_size = buffer_size
            print('Input>', end=' ')
            line = input()
            self.ghidra_dbg.return_input(line)
            return S_OK
        except:
            traceback.print_exc()
            raise

    def IDebugInputCallbacks_EndInput(self):
        self.expecting_input = False


class _Worker(threading.Thread):

    def __init__(self, new_base, work_queue, dispatch):
        super().__init__(name='DbgWorker', daemon=True)
        self.new_base = new_base
        self.work_queue = work_queue
        self.dispatch = dispatch

    def run(self):
        self.new_base()
        while True:
            try:
                work_item = self.work_queue.get_nowait()
            except queue.Empty:
                work_item = None
            if work_item is None:
                # HACK to avoid lockup on race condition
                try:
                    self.dispatch(100)
                except exception.DbgEngTimeout:
                    # This is routine :/
                    pass
            else:
                work_item.run()


# Derived from Python core library
# https://github.com/python/cpython/blob/main/Lib/concurrent/futures/thread.py
# accessed 9 Jan 2024
class _WorkItem(object):

    def __init__(self, future, fn, args, kwargs):
        self.future = future
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
        except BaseException as exc:
            self.future.set_exception(exc)
            # Python core lib does this, I presume for good reason
            self = None
        else:
            self.future.set_result(result)


class DebuggeeRunningException(BaseException):
    pass


T = TypeVar('T')


class DbgExecutor(object):

    def __init__(self, ghidra_dbg: 'GhidraDbg') -> None:
        self._ghidra_dbg = ghidra_dbg
        self._work_queue: queue.SimpleQueue = queue.SimpleQueue()
        self._thread = _Worker(ghidra_dbg._new_base,
                               self._work_queue, ghidra_dbg._dispatch_events)
        self._thread.start()
        self._executing = False

    def submit(self, fn: Callable[..., T], /, *args, **kwargs) -> Future[T]:
        f = self._submit_no_exit(fn, *args, **kwargs)
        self._ghidra_dbg.exit_dispatch()
        return f

    def _submit_no_exit(self, fn: Callable[..., T], /,
                        *args, **kwargs) -> Future[T]:
        f: Future[T] = Future()
        if self._executing and self._ghidra_dbg.IS_REMOTE == False:
            f.set_exception(DebuggeeRunningException("Debuggee is Running"))
            return f
        w = _WorkItem(f, fn, args, kwargs)
        self._work_queue.put(w)
        return f

    def _clear_queue(self) -> None:
        while True:
            try:
                work_item = self._work_queue.get_nowait()
            except queue.Empty:
                return
            work_item.future.set_exception(
                DebuggeeRunningException("Debuggee is Running"))

    def _state_execute(self) -> None:
        self._executing = True
        if self._ghidra_dbg.IS_REMOTE == False:
            self._clear_queue()

    def _state_break(self) -> None:
        self._executing = False


class WrongThreadException(BaseException):
    pass


class AllDbg(pydbg.DebuggerBase):
    # Steal user-mode methods
    proc_list = userdbg.UserDbg.proc_list
    ps = userdbg.UserDbg.ps
    pids_by_name = userdbg.UserDbg.pids_by_name
    create_proc = userdbg.UserDbg.create
    attach_proc = userdbg.UserDbg.attach
    reattach_proc = userdbg.UserDbg.reattach
    detach_proc = userdbg.UserDbg.detach
    abandon_proc = userdbg.UserDbg.abandon
    terminate_proc = userdbg.UserDbg.terminate
    handoff_proc = userdbg.UserDbg.handoff
    connect_proc = userdbg.UserDbg.connect
    disconnect_proc = userdbg.UserDbg.disconnect

    # Steal kernel-mode methods
    attach_kernel = kerneldbg.KernelDbg.attach
    detach_kernel = kerneldbg.KernelDbg.detach

    # Steal crash methods
    load_dump = crashdbg.CrashDbg.load_dump


C = TypeVar('C', bound=Callable[..., Any])


class GhidraDbg(object):

    def __init__(self) -> None:
        self._queue = DbgExecutor(self)
        self._thread = self._queue._thread
        # Wait for the executor to be operational before getting base
        self._queue._submit_no_exit(lambda: None).result()
        self._install_stdin()
        self.use_generics = os.getenv('OPT_USE_DBGMODEL') == "true"

        base = self._protected_base
        for name in ['set_output_mask', 'get_output_mask',
                     'exec_status', 'go', 'goto', 'go_handled', 'go_nothandled',
                     'stepi', 'stepo', 'stepbr', 'stepto', 'stepout',
                     'trace', 'traceto',
                     'wait',
                     'bitness',
                     'read', 'readstr', 'readptr', 'poi',
                     'write', 'writeptr',
                     'memory_list', 'address',
                     'instruction_at', 'disasm',
                     'pc', 'r', 'registers',
                     'get_name_by_offset', 'symbol', 'find_symbol',
                     'whereami',
                     'dd', 'dp', 'ds',
                     'bl', 'bc', 'bd', 'be', 'bp', 'ba',
                     'handle_list', 'handles',
                     'get_thread', 'set_thread', 'apply_threads', 'thread_list', 'threads',
                     'teb_addr', 'teb', 'peb_addr', 'peb',
                     'backtrace_list', 'backtrace',
                     'module_list', 'lm', 'exports', 'imports',
                     # User-mode
                     'proc_list', 'ps', 'pids_by_name',
                     'create_proc', 'attach_proc', 'reattach_proc',
                     'detach_proc', 'abandon_proc', 'terminate_proc', 'handoff_proc',
                     'connect_proc', 'disconnect_proc',
                     # Kernel-model
                     'attach_kernel', 'detach_kernel',
                     # Crash dump
                     'load_dump'
                     ]:
            setattr(self, name, self.eng_thread(getattr(base, name)))
        self.IS_KERNEL = False
        self.IS_EXDI = False
        self.IS_REMOTE: bool = os.getenv('OPT_CONNECT_STRING') is not None
        self.IS_TRACE: bool = os.getenv('USE_TTD') == "true"

    def _new_base(self) -> None:
        remote = os.getenv('OPT_CONNECT_STRING')
        if remote is not None:
            remote_client = DbgEng.DebugConnect(remote)
            debug_client = self._generate_client(remote_client)
            self._protected_base = AllDbg(client=debug_client)
        else:
            self._protected_base = AllDbg()

    def _generate_client(self, original: DebugClient) -> DebugClient:
        cli = POINTER(DbgEng.IDebugClient)()
        cliptr = POINTER(POINTER(DbgEng.IDebugClient))(cli)
        hr = original.CreateClient(cliptr)
        exception.check_err(hr)
        return DebugClient(client=cli)

    @property
    def _base(self) -> AllDbg:
        if threading.current_thread() is not self._thread:
            raise WrongThreadException("Was {}. Want {}".format(
                threading.current_thread(), self._thread))
        return self._protected_base

    def run(self, fn: Callable[..., T], *args, **kwargs) -> T:
        # TODO: Remove this check?
        if hasattr(self, '_thread') and threading.current_thread() is self._thread:
            raise WrongThreadException()
        future = self._queue.submit(fn, *args, **kwargs)
        # https://stackoverflow.com/questions/72621731/is-there-any-graceful-way-to-interrupt-a-python-concurrent-future-result-call gives an alternative
        while True:
            try:
                return future.result(0.5)
            except concurrent.futures.TimeoutError:
                pass

    def run_async(self, fn: Callable[..., T], *args, **kwargs) -> Future[T]:
        return self._queue.submit(fn, *args, **kwargs)

    @staticmethod
    def check_thread(func: C) -> C:
        """For methods inside of GhidraDbg, ensure it runs on the dbgeng
        thread."""

        @functools.wraps(func)
        def _func(self, *args, **kwargs) -> Any:
            if threading.current_thread() is self._thread:
                return func(self, *args, **kwargs)
            else:
                return self.run(func, self, *args, **kwargs)

        return cast(C, _func)

    def eng_thread(self, func: C) -> C:
        """For methods and functions outside of GhidraDbg, ensure it runs on
        this GhidraDbg's dbgeng thread."""

        @functools.wraps(func)
        def _func(*args, **kwargs) -> Any:
            if threading.current_thread() is self._thread:
                return func(*args, **kwargs)
            else:
                return self.run(func, *args, **kwargs)

        return cast(C, _func)

    def _ces_exec_status(self, argument: int):
        if argument & 0xfffffff == DbgEng.DEBUG_STATUS_BREAK:
            self._queue._state_break()
        else:
            self._queue._state_execute()

    @check_thread
    def _install_stdin(self) -> None:
        self.input = StdInputCallbacks(self)
        self._base._client.SetInputCallbacks(self.input)

    # Manually decorated to preserve undecorated
    def _dispatch_events(self, timeout: int = DbgEng.WAIT_INFINITE) -> None:
        # NB: pybag's impl doesn't heed standalone
        self._protected_base._client.DispatchCallbacks(timeout)

    dispatch_events = check_thread(_dispatch_events)

    # no check_thread. Must allow reentry
    def exit_dispatch(self) -> None:
        self._protected_base._client.ExitDispatch()

    @check_thread
    def cmd(self, cmdline: str, quiet: bool = True) -> str:
        # NB: pybag's impl always captures.
        # Here, we let it print without capture if quiet is False
        if quiet:
            try:
                buffer = io.StringIO()
                self._base.callbacks.stdout = buffer
                self._base._control.Execute(cmdline)
                buffer.seek(0)
                return buffer.read()
            finally:
                self._base.callbacks.reset_stdout()
        else:
            return self._base._control.Execute(cmdline)

    @check_thread
    def return_input(self, input: str) -> None:
        # TODO: Contribute fix upstream (check_hr -> check_err)
        # return self._base._control.ReturnInput(input.encode())
        hr = self._base._control._ctrl.ReturnInput(input.encode())
        exception.check_err(hr)

    def interrupt(self) -> None:
        # Contribute upstream?
        # NOTE: This can be called from any thread
        self._protected_base._control.SetInterrupt(
            DbgEng.DEBUG_INTERRUPT_ACTIVE)

    @check_thread
    def get_current_system_id(self) -> int:
        # TODO: upstream?
        sys_id = c_ulong()
        hr = self._base._systems._sys.GetCurrentSystemId(byref(sys_id))
        exception.check_err(hr)
        return sys_id.value

    @check_thread
    def get_prompt_text(self) -> str:
        # TODO: upstream?
        size = c_ulong()
        hr = self._base._control._ctrl.GetPromptText(None, 0, byref(size))
        prompt_buf = create_string_buffer(size.value)
        hr = self._base._control._ctrl.GetPromptText(prompt_buf, size, None)
        return prompt_buf.value.decode()

    @check_thread
    def get_actual_processor_type(self) -> int:
        return self._base._control.GetActualProcessorType()

    @property
    @check_thread
    def pid(self) -> Optional[int]:
        try:
            if is_kernel():
                return 0
            return self._base._systems.GetCurrentProcessSystemId()
        except exception.E_UNEXPECTED_Error:
            # There is no process
            return None


class TTDState(object):

    def __init__(self) -> None:
        self._first: Optional[Tuple[int, int]] = None
        self._last: Optional[Tuple[int, int]] = None
        self._lastpos: Optional[Tuple[int, int]] = None
        self.evttypes: Dict[Tuple[int, int], str] = {}
        self.MAX_STEP: int


dbg = GhidraDbg()
ttd = TTDState()


@dbg.eng_thread
def compute_pydbg_ver() -> DbgVersion:
    pat = re.compile(
        '(?P<name>.*Debugger.*) Version (?P<dotted>[\\d\\.]*) (?P<arch>\\w*)')
    blurb = dbg.cmd('version')
    matches_opt = [pat.match(l) for l in blurb.splitlines()]
    matches = [m for m in matches_opt if m is not None]
    if len(matches) == 0:
        return DbgVersion('Unknown', 'Unknown', '0', 'Unknown')
    m = matches[0]
    return DbgVersion(full=m.group(), **m.groupdict())


DBG_VERSION = compute_pydbg_ver()


def get_target():
    return dbg.get_current_system_id()


@dbg.eng_thread
def disassemble1(addr: int) -> CsInsn:
    data = dbg.read(addr, 15)  # type:ignore
    return DbgUtil.disassemble_instruction(dbg._base.bitness(), addr, data)


def get_inst(addr: int) -> str:
    return str(disassemble1(addr))


def get_inst_sz(addr: int) -> int:
    return int(disassemble1(addr).size)


@dbg.eng_thread
def get_breakpoints() -> Iterable[Tuple[str, str, str, str, str]]:
    ids = [bpid for bpid in dbg._base.breakpoints]
    offset_set: List[str] = []
    expr_set: List[str] = []
    prot_set: List[str] = []
    width_set: List[str] = []
    stat_set: List[str] = []
    for bpid in ids:
        try:
            bp = dbg._base._control.GetBreakpointById(bpid)
        except exception.E_NOINTERFACE_Error:
            continue

        if bp.GetFlags() & DbgEng.DEBUG_BREAKPOINT_DEFERRED:
            offset = "[Deferred]"
            expr = bp.GetOffsetExpression()
        else:
            offset = "%016x" % bp.GetOffset()
            expr = dbg._base.get_name_by_offset(bp.GetOffset())

        if bp.GetType()[0] == DbgEng.DEBUG_BREAKPOINT_DATA:
            width, prot = bp.GetDataParameters()
            width = ' sz={}'.format(str(width))
            prot = {4: 'type=x', 3: 'type=rw', 2: 'type=w', 1: 'type=r'}[prot]
        else:
            width = ''
            prot = ''

        if bp.GetFlags() & DbgEng.DEBUG_BREAKPOINT_ENABLED:
            status = 'enabled'
        else:
            status = 'disabled'

        offset_set.append(offset)
        expr_set.append(expr)
        prot_set.append(prot)
        width_set.append(width)
        stat_set.append(status)
    return zip(offset_set, expr_set, prot_set, width_set, stat_set)


@dbg.eng_thread
def selected_process() -> int:
    try:
        if is_exdi():
            return 0
        if is_kernel():
            do = dbg._base._systems.GetCurrentProcessDataOffset()
            id = c_ulong()
            offset = c_ulonglong(do)
            nproc = dbg._base._systems._sys.GetProcessIdByDataOffset(
                offset, byref(id))
            return id.value
        if dbg.use_generics:
            return dbg._base._systems.GetCurrentProcessSystemId()
        return dbg._base._systems.GetCurrentProcessId()
    except (exception.E_UNEXPECTED_Error, exception.E_NOTIMPL_Error) as e:
        # NB: we're intentionally returning 0 instead of None
        return 0


@dbg.eng_thread
def selected_process_space() -> int:
    try:
        if is_exdi():
            return 0
        if is_kernel():
            return dbg._base._systems.GetCurrentProcessDataOffset()
        return selected_process()
    except (exception.E_UNEXPECTED_Error, exception.E_NOTIMPL_Error) as e:
        # NB: we're intentionally returning 0 instead of None
        return 0


@dbg.eng_thread
def selected_thread() -> Optional[int]:
    try:
        if is_kernel():
            return 0
        if dbg.use_generics:
            return dbg._base._systems.GetCurrentThreadSystemId()
        return dbg._base._systems.GetCurrentThreadId()
    except (exception.E_UNEXPECTED_Error, exception.E_NOTIMPL_Error) as e:
        return None


@dbg.eng_thread
def selected_frame() -> Optional[int]:
    try:
        line = dbg.cmd('.frame').strip()
        if not line:
            return None
        num_str = line.split(sep=None, maxsplit=1)[0]
        return int(num_str, 16)
    except OSError:
        return None
    except ValueError:
        return None


def require(t: Optional[T]) -> T:
    if t is None:
        raise ValueError("Unexpected None")
    return t


@dbg.eng_thread
def select_process(id: int) -> None:
    if is_kernel():
        # TODO: Ideally this should get the data offset from the id and then call
        #  SetImplicitProcessDataOffset
        return
    if dbg.use_generics:
        id = require(get_proc_id(id))
    return dbg._base._systems.SetCurrentProcessId(id)


@dbg.eng_thread
def select_thread(id: int) -> None:
    if is_kernel():
        # TODO: Ideally this should get the data offset from the id and then call
        #  SetImplicitThreadDataOffset
        return
    if dbg.use_generics:
        id = require(get_thread_id(id))
    return dbg._base._systems.SetCurrentThreadId(id)


@dbg.eng_thread
def select_frame(id: int) -> str:
    return dbg.cmd('.frame /c {}'.format(id))


@dbg.eng_thread
def reset_frames() -> str:
    return dbg.cmd('.cxr')


@dbg.eng_thread
def parse_and_eval(expr: Union[str, int],
                   type: Optional[int] = None) -> Union[int, float, bytes]:
    if isinstance(expr, int):
        return expr
    # TODO: This could be contributed upstream
    ctrl = dbg._base._control._ctrl
    ctrl.SetExpressionSyntax(1)
    value = DbgEng._DEBUG_VALUE()
    index = c_ulong()
    if type == None:
        type = DbgEng.DEBUG_VALUE_INT64
    hr = ctrl.Evaluate(Expression=expr.encode(), DesiredType=type,
                       Value=byref(value), RemainderIndex=byref(index))
    exception.check_err(hr)
    if type == DbgEng.DEBUG_VALUE_INT8:
        return value.u.I8
    if type == DbgEng.DEBUG_VALUE_INT16:
        return value.u.I16
    if type == DbgEng.DEBUG_VALUE_INT32:
        return value.u.I32
    if type == DbgEng.DEBUG_VALUE_INT64:
        return value.u.I64.I64
    if type == DbgEng.DEBUG_VALUE_FLOAT32:
        return value.u.F32
    if type == DbgEng.DEBUG_VALUE_FLOAT64:
        return value.u.F64
    if type == DbgEng.DEBUG_VALUE_FLOAT80:
        return value.u.F80Bytes
    if type == DbgEng.DEBUG_VALUE_FLOAT82:
        return value.u.F82Bytes
    if type == DbgEng.DEBUG_VALUE_FLOAT128:
        return value.u.F128Bytes
    raise ValueError(
        f"Could not evaluate '{expr}' or convert result '{value}'")


@dbg.eng_thread
def get_pc() -> int:
    return dbg._base.reg.get_pc()


@dbg.eng_thread
def get_sp() -> int:
    return dbg._base.reg.get_sp()


@dbg.eng_thread
def GetProcessIdsByIndex(count: int = 0) -> Tuple[List[int], List[int]]:
    # TODO: This could be contributed upstream?
    if count == 0:
        try:
            count = dbg._base._systems.GetNumberProcesses()
        except Exception:
            count = 0
    ids = (c_ulong * count)()
    sysids = (c_ulong * count)()
    if count != 0:
        hr = dbg._base._systems._sys.GetProcessIdsByIndex(
            0, count, ids, sysids)
        exception.check_err(hr)
    return (list(ids), list(sysids))


@dbg.eng_thread
def GetCurrentProcessExecutableName() -> str:
    # TODO: upstream?
    _dbg = dbg._base
    size = c_ulong()
    exesize = c_ulong()
    hr = _dbg._systems._sys.GetCurrentProcessExecutableName(
        None, size, byref(exesize))
    exception.check_err(hr)
    buffer = create_string_buffer(exesize.value)
    size = exesize
    hr = _dbg._systems._sys.GetCurrentProcessExecutableName(buffer, size, None)
    exception.check_err(hr)
    return buffer.value.decode()


@dbg.eng_thread
def GetCurrentProcessPeb() -> int:
    # TODO: upstream?
    _dbg = dbg._base
    offset = c_ulonglong()
    if is_kernel():
        hr = _dbg._systems._sys.GetCurrentProcessDataOffset(byref(offset))
    else:
        hr = _dbg._systems._sys.GetCurrentProcessPeb(byref(offset))
    exception.check_err(hr)
    return offset.value


@dbg.eng_thread
def GetCurrentThreadTeb() -> int:
    # TODO: upstream?
    _dbg = dbg._base
    offset = c_ulonglong()
    if is_kernel():
        hr = _dbg._systems._sys.GetCurrentThreadDataOffset(byref(offset))
    else:
        hr = _dbg._systems._sys.GetCurrentThreadTeb(byref(offset))
    exception.check_err(hr)
    return offset.value


@dbg.eng_thread
def GetExitCode() -> int:
    # TODO: upstream?
    if is_kernel():
        return STILL_ACTIVE
    exit_code = c_ulong()
    hr = dbg._base._client._cli.GetExitCode(byref(exit_code))
    # DebugConnect targets return E_UNEXPECTED but the target is STILL_ACTIVE
    if hr != S_OK and hr != S_FALSE:
        return STILL_ACTIVE
    return exit_code.value


@dbg.eng_thread
def GetNumberEventFilters() -> Tuple[int, int, int]:
    n_events = c_ulong()
    n_spec_exc = c_ulong()
    n_arb_exc = c_ulong()
    hr = dbg._base._control._ctrl.GetNumberEventFilters(
        byref(n_events), byref(n_spec_exc), byref(n_arb_exc))
    exception.check_err(hr)
    return (n_events.value, n_spec_exc.value, n_arb_exc.value)


@dbg.eng_thread
def GetEventFilterText(index: int, sz: int) -> str:
    if sz == 0:
        return "Unknown"
    len = c_ulong()
    val = create_string_buffer(sz)
    hr = dbg._base._control._ctrl.GetEventFilterText(
        index, val, sz, byref(len))
    # exception.check_err(hr)
    if hr != 0:
        return "Unknown"
    return val.value[:len.value].decode()


@dbg.eng_thread
def GetEventFilterCommand(index: int, sz: int) -> Union[str, None]:
    if sz == 0:
        return None
    len = c_ulong()
    val = create_string_buffer(sz)
    hr = dbg._base._control._ctrl.GetEventFilterCommand(
        index, val, sz, byref(len))
    exception.check_err(hr)
    return val.value[:len.value].decode()


@dbg.eng_thread
def GetExceptionFilterSecondCommand(index: int, sz: int) -> Union[str, None]:
    if sz == 0:
        return None
    len = c_ulong()
    val = create_string_buffer(sz)
    hr = dbg._base._control._ctrl.GetExceptionFilterSecondCommand(
        index, val, sz, byref(len))
    exception.check_err(hr)
    return val.value[:len.value].decode()


@dbg.eng_thread
def GetSpecificFilterArgument(index: int, sz: int) -> Union[str, None]:
    if sz == 0:
        return None
    len = c_ulong()
    val = create_string_buffer(sz)
    hr = dbg._base._control._ctrl.GetSpecificFilterArgument(
        index, val, sz, byref(len))
    exception.check_err(hr)
    return val.value[:len.value].decode()


execution_options = ['enabled', 'disabled', 'output', 'ignore']
continue_options = ['handled', 'not handled', 'unknown']


@dbg.eng_thread
def GetSpecificFilterParameters(start: int, count: int) -> List[DbgEng._DEBUG_SPECIFIC_FILTER_PARAMETERS]:
    # For reference, this is how you pass an array of structures!
    params = (DbgEng._DEBUG_SPECIFIC_FILTER_PARAMETERS * count)()
    hr = dbg._base._control._ctrl.GetSpecificFilterParameters(
        start, count, params)
    exception.check_err(hr)
    return params


@dbg.eng_thread
def SetSpecificFilterParameters(start: int, count: int, parray: List[DbgEng._DEBUG_SPECIFIC_FILTER_PARAMETERS]) -> None:
    hr = dbg._base._control._ctrl.SetSpecificFilterParameters(
        start, count, parray)
    exception.check_err(hr)


@dbg.eng_thread
def GetExceptionFilterParameters(start: int, codes, count: int) -> List[DbgEng._DEBUG_EXCEPTION_FILTER_PARAMETERS]:
    # For reference, this is how you pass an array of structures!
    params = (DbgEng._DEBUG_EXCEPTION_FILTER_PARAMETERS * count)()
    hr = dbg._base._control._ctrl.GetExceptionFilterParameters(
        count, codes, start, params)
    exception.check_err(hr)
    return params


@dbg.eng_thread
def SetExceptionFilterParameters(count: int, parray: List[DbgEng._DEBUG_EXCEPTION_FILTER_PARAMETERS]) -> None:
    hr = dbg._base._control._ctrl.SetExceptionFilterParameters(count, parray)
    exception.check_err(hr)


@dbg.eng_thread
def process_list(running: bool = False) -> Union[
        Iterable[Tuple[int, str, int]], Iterable[Tuple[int]]]:
    """Get the list of all processes."""
    _dbg = dbg._base
    ids, sysids = GetProcessIdsByIndex()
    pebs = []
    names = []

    curid = selected_process()
    try:
        if running:
            return zip(sysids)
        else:
            for id in ids:
                _dbg._systems.SetCurrentProcessId(id)
                names.append(GetCurrentProcessExecutableName())
                pebs.append(GetCurrentProcessPeb())
            return zip(sysids, names, pebs)
    except Exception:
        return zip(sysids)
    finally:
        if not running and curid is not None:
            try:
                _dbg._systems.SetCurrentProcessId(curid)
            except Exception as e:
                print(f"Couldn't restore current process: {e}")


@dbg.eng_thread
def thread_list(running: bool = False) -> Union[
        Iterable[Tuple[int, int, str]], Iterable[Tuple[int]]]:
    """Get the list of all threads."""
    _dbg = dbg._base
    try:
        ids, sysids = _dbg._systems.GetThreadIdsByIndex()
    except Exception:
        return zip([])
    tebs = []
    syms = []

    curid = selected_thread()
    try:
        if running:
            return zip(sysids)
        else:
            for id in ids:
                _dbg._systems.SetCurrentThreadId(id)
                tebs.append(_dbg._systems.GetCurrentThreadTeb())
                addr = _dbg.reg.get_pc()
                syms.append(_dbg.get_name_by_offset(addr))
            return zip(sysids, tebs, syms)
    except Exception:
        return zip(sysids)
    finally:
        if not running and curid is not None:
            _dbg._systems.SetCurrentThreadId(curid)


@dbg.eng_thread
def get_proc_id(pid: int) -> Optional[int]:
    """Get the id for the given system process id."""
    # TODO: Implement GetProcessIdBySystemId and replace this logic
    _dbg = dbg._base
    map = {}
    try:
        x = _dbg._systems.GetProcessIdsByIndex()
        for i in range(0, len(x[0])):
            map[x[1][i]] = x[0][i]
        return map[pid]
    except Exception:
        pass
    return None


def full_mem() -> List[DbgEng._MEMORY_BASIC_INFORMATION64]:
    info = DbgEng._MEMORY_BASIC_INFORMATION64()
    info.BaseAddress = 0
    info.RegionSize = (1 << 64) - 1
    info.Protect = 0xFFF
    info.Name = "full memory"
    return [info]


@dbg.eng_thread
def get_thread_id(tid: int) -> Optional[int]:
    """Get the id for the given system thread id."""
    # TODO: Implement GetThreadIdBySystemId and replace this logic
    _dbg = dbg._base
    map = {}
    try:
        x = _dbg._systems.GetThreadIdsByIndex()
        for i in range(0, len(x[0])):
            map[x[1][i]] = x[0][i]
        return map[tid]
    except Exception:
        pass
    return None


@dbg.eng_thread
def open_trace_or_dump(filename: Union[str, bytes]) -> None:
    """Open a trace or dump file."""
    _cli = dbg._base._client._cli
    if isinstance(filename, str):
        filename = filename.encode()
    hr = _cli.OpenDumpFile(filename)
    exception.check_err(hr)


def split_path(pathString: str) -> List[str]:
    list = []
    segs = pathString.split(".")
    for s in segs:
        if s.endswith("]"):
            if "[" not in s:
                print(f"Missing terminator: {s}")
            index = s.index("[")
            list.append(s[:index])
            list.append(s[index:])
        else:
            list.append(s)
    return list


def IHostDataModelAccess() -> HostDataModelAccess:
    return HostDataModelAccess(dbg._base._client._cli.QueryInterface(
        interface=DbgMod.IHostDataModelAccess))


def IModelMethod(method_ptr) -> ModelMethod:
    return ModelMethod(method_ptr.GetIntrinsicValue().value.QueryInterface(
        interface=DbgMod.IModelMethod))


@dbg.eng_thread
def get_object(relpath: str) -> Optional[ModelObject]:
    """Get the model object at the given path."""
    _cli = dbg._base._client._cli
    access = HostDataModelAccess(_cli.QueryInterface(
        interface=DbgMod.IHostDataModelAccess))
    mgr, host = access.GetDataModel()
    root = mgr.GetRootNamespace()
    pathstr = "Debugger"
    if relpath != '':
        pathstr += "." + relpath
    path = split_path(pathstr)
    # print(f"PATH: {pathstr}")
    return root.GetOffspring(path)


@dbg.eng_thread
def get_method(context_path: str, method_name: str) -> Optional[ModelMethod]:
    """Get method for the given object (path) and name."""
    obj = get_object(context_path)
    if obj is None:
        return None
    keys = obj.EnumerateKeys()
    k, v = keys.GetNext()
    while k is not None:
        if k.value == method_name:
            break
        (k, v) = keys.GetNext()
    if k is None:
        return None
    return IModelMethod(v)


@dbg.eng_thread
def get_attributes(obj: ModelObject) -> Dict[str, ModelObject]:
    """Get the list of attributes."""
    if obj is None:
        return None
    return obj.GetAttributes()


@dbg.eng_thread
def get_elements(obj: ModelObject) -> List[Tuple[int, ModelObject]]:
    """Get the list of elements."""
    if obj is None:
        return None
    return obj.GetElements()


@dbg.eng_thread
def get_kind(obj) -> Optional[int]:
    """Get the kind."""
    if obj is None:
        return None
    kind = obj.GetKind()
    if kind is None:
        return None
    return obj.GetKind().value


# DOESN'T WORK YET
# @dbg.eng_thread
# def get_type(obj: ModelObject):
#    """Get the type."""
#    if obj is None:
#        return None
#    return obj.GetTypeKind()


@dbg.eng_thread
def get_value(obj: ModelObject) -> Any:
    """Get the value."""
    if obj is None:
        return None
    return obj.GetValue()


@dbg.eng_thread
def get_intrinsic_value(obj: ModelObject) -> VARIANT:
    """Get the intrinsic value."""
    if obj is None:
        return None
    return obj.GetIntrinsicValue()


@dbg.eng_thread
def get_target_info(obj: ModelObject) -> ModelObject:
    """Get the target info."""
    if obj is None:
        return None
    return obj.GetTargetInfo()


@dbg.eng_thread
def get_type_info(obj: ModelObject) -> ModelObject:
    """Get the type info."""
    if obj is None:
        return None
    return obj.GetTypeInfo()


@dbg.eng_thread
def get_name(obj: ModelObject) -> str:
    """Get the name."""
    if obj is None:
        return None
    return obj.GetName().value


@dbg.eng_thread
def to_display_string(obj: ModelObject) -> str:
    """Get the display string."""
    if obj is None:
        return None
    return obj.ToDisplayString()


@dbg.eng_thread
def get_location(obj: ModelObject) -> Optional[str]:
    """Get the location."""
    if obj is None:
        return None
    try:
        loc = obj.GetLocation()
        if loc is None:
            return None
        return hex(loc.Offset)
    except:
        return None


conv_map: Dict[str, str] = {}


def get_convenience_variable(id: str) -> Any:
    if id not in conv_map:
        return "auto"
    val = conv_map[id]
    if val is None:
        return "auto"
    return val


def get_last_position() -> Optional[Tuple[int, int]]:
    return ttd._lastpos


def set_last_position(pos: Tuple[int, int]) -> None:
    ttd._lastpos = pos


def get_event_type(pos: Tuple[int, int]) -> Optional[str]:
    if ttd.evttypes.__contains__(pos):
        return ttd.evttypes[pos]
    return None


def split2schedule(pos: Tuple[int, int]) -> Schedule:
    major, minor = pos
    return mm2schedule(major, minor)


def schedule2split(time: Schedule) -> Tuple[int, int]:
    return time.snap, time.steps


def mm2schedule(major: int, minor: int) -> Schedule:
    index = int(major)
    if index < 0 or hasattr(ttd, 'MAX_STEP') and index >= ttd.MAX_STEP:
        return Schedule(require(ttd._last)[0])
    if index >= 1 << 63:
        return Schedule((1 << 63) - 1)
    return Schedule(index, minor)


def pos2split(pos: ModelObject) -> Tuple[int, int]:
    pmap = get_attributes(pos)
    major = get_value(pmap["Sequence"])
    minor = get_value(pmap["Steps"])
    return (major, minor)


def schedule2ss(time: Schedule) -> str:
    return f'{time.snap:x}:{time.steps:x}'


def compute_description(time: Optional[Schedule], fallback: str) -> str:
    if time is None:
        return fallback
    evt_type = get_event_type(schedule2split(time))
    evt_str = evt_type or fallback
    return DESCRIPTION_PATTERN.format(major=time.snap, minor=time.steps,
                                      type=evt_str)


def set_convenience_variable(id: str, value: Any) -> None:
    conv_map[id] = value


def set_kernel(value: bool) -> None:
    dbg.IS_KERNEL = value


def is_kernel() -> bool:
    return dbg.IS_KERNEL


def set_exdi(value: bool) -> None:
    dbg.IS_EXDI = value


def is_exdi() -> bool:
    return dbg.IS_EXDI


def set_remote(value: bool) -> None:
    dbg.IS_REMOTE = value


def is_remote() -> bool:
    return dbg.IS_REMOTE


def set_trace(value: bool) -> None:
    dbg.IS_TRACE = value


def is_trace() -> bool:
    return dbg.IS_TRACE
