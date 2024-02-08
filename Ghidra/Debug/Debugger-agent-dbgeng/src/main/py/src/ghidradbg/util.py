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
from collections import namedtuple
from concurrent.futures import Future
import concurrent.futures
from ctypes import *
import functools
import io
import os
import queue
import re
import sys
import threading
import traceback

from comtypes import CoClass, GUID
import comtypes
from comtypes.hresult import S_OK
from pybag import pydbg, userdbg, kerneldbg, crashdbg
from pybag.dbgeng import core as DbgEng
from pybag.dbgeng import exception
from pybag.dbgeng import util as DbgUtil
from pybag.dbgeng.callbacks import DbgEngCallbacks


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


class DbgExecutor(object):
    def __init__(self, ghidra_dbg):
        self._ghidra_dbg = ghidra_dbg
        self._work_queue = queue.SimpleQueue()
        self._thread = _Worker(ghidra_dbg._new_base,
                               self._work_queue, ghidra_dbg._dispatch_events)
        self._thread.start()
        self._executing = False

    def submit(self, fn, / , *args, **kwargs):
        f = self._submit_no_exit(fn, *args, **kwargs)
        self._ghidra_dbg.exit_dispatch()
        return f

    def _submit_no_exit(self, fn, / , *args, **kwargs):
        f = Future()
        if self._executing:
            f.set_exception(DebuggeeRunningException("Debuggee is Running"))
            return f
        w = _WorkItem(f, fn, args, kwargs)
        self._work_queue.put(w)
        return f

    def _clear_queue(self):
        while True:
            try:
                work_item = self._work_queue.get_nowait()
            except queue.Empty:
                return
            work_item.future.set_exception(
                DebuggeeRunningException("Debuggee is Running"))

    def _state_execute(self):
        self._executing = True
        self._clear_queue()

    def _state_break(self):
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


class GhidraDbg(object):
    def __init__(self):
        self._queue = DbgExecutor(self)
        self._thread = self._queue._thread
        # Wait for the executor to be operational before getting base
        self._queue._submit_no_exit(lambda: None).result()
        self._install_stdin()

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

    def _new_base(self):
        self._protected_base = AllDbg()

    @property
    def _base(self):
        if threading.current_thread() is not self._thread:
            raise WrongThreadException("Was {}. Want {}".format(
                threading.current_thread(), self._thread))
        return self._protected_base

    def run(self, fn, *args, **kwargs):
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

    def run_async(self, fn, *args, **kwargs):
        return self._queue.submit(fn, *args, **kwargs)

    @staticmethod
    def check_thread(func):
        '''
        For methods inside of GhidraDbg, ensure it runs on the dbgeng
        thread
        '''
        @functools.wraps(func)
        def _func(self, *args, **kwargs):
            if threading.current_thread() is self._thread:
                return func(self, *args, **kwargs)
            else:
                return self.run(func, self, *args, **kwargs)
        return _func

    def eng_thread(self, func):
        '''
        For methods and functions outside of GhidraDbg, ensure it
        runs on this GhidraDbg's dbgeng thread
        '''
        @functools.wraps(func)
        def _func(*args, **kwargs):
            if threading.current_thread() is self._thread:
                return func(*args, **kwargs)
            else:
                return self.run(func, *args, **kwargs)
        return _func

    def _ces_exec_status(self, argument):
        if argument & 0xfffffff == DbgEng.DEBUG_STATUS_BREAK:
            self._queue._state_break()
        else:
            self._queue._state_execute()

    @check_thread
    def _install_stdin(self):
        self.input = StdInputCallbacks(self)
        self._base._client.SetInputCallbacks(self.input)

    # Manually decorated to preserve undecorated
    def _dispatch_events(self, timeout=DbgEng.WAIT_INFINITE):
        # NB: pybag's impl doesn't heed standalone
        self._protected_base._client.DispatchCallbacks(timeout)
    dispatch_events = check_thread(_dispatch_events)

    # no check_thread. Must allow reentry
    def exit_dispatch(self):
        self._protected_base._client.ExitDispatch()

    @check_thread
    def cmd(self, cmdline, quiet=True):
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
    def return_input(self, input):
        # TODO: Contribute fix upstream (check_hr -> check_err)
        # return self._base._control.ReturnInput(input.encode())
        hr = self._base._control._ctrl.ReturnInput(input.encode())
        exception.check_err(hr)

    def interrupt(self):
        # Contribute upstream?
        # NOTE: This can be called from any thread
        self._protected_base._control.SetInterrupt(
            DbgEng.DEBUG_INTERRUPT_ACTIVE)

    @check_thread
    def get_current_system_id(self):
        # TODO: upstream?
        sys_id = c_ulong()
        hr = self._base._systems._sys.GetCurrentSystemId(byref(sys_id))
        exception.check_err(hr)
        return sys_id.value

    @check_thread
    def get_prompt_text(self):
        # TODO: upstream?
        size = c_ulong()
        hr = self._base._control._ctrl.GetPromptText(None, 0, byref(size))
        prompt_buf = create_string_buffer(size.value)
        hr = self._base._control._ctrl.GetPromptText(prompt_buf, size, None)
        return prompt_buf.value.decode()

    @check_thread
    def get_actual_processor_type(self):
        return self._base._control.GetActualProcessorType()

    @property
    @check_thread
    def pid(self):
        try:
            return self._base._systems.GetCurrentProcessSystemId()
        except exception.E_UNEXPECTED_Error:
            # There is no process
            return None


dbg = GhidraDbg()


@dbg.eng_thread
def compute_pydbg_ver():
    pat = re.compile(
        '(?P<name>.*Debugger.*) Version (?P<dotted>[\\d\\.]*) (?P<arch>\\w*)')
    blurb = dbg.cmd('version')
    matches = [pat.match(l) for l in blurb.splitlines() if pat.match(l)]
    if len(matches) == 0:
        return DbgVersion('Unknown', 'Unknown', '0', 'Unknown')
    m = matches[0]
    return DbgVersion(full=m.group(), **m.groupdict())
    name, dotted_and_arch = full.split(' Version ')


DBG_VERSION = compute_pydbg_ver()


def get_target():
    return dbg.get_current_system_id()


@dbg.eng_thread
def disassemble1(addr):
    return DbgUtil.disassemble_instruction(dbg._base.bitness(), addr, dbg.read(addr, 15))


def get_inst(addr):
    return str(disassemble1(addr))


def get_inst_sz(addr):
    return int(disassemble1(addr).size)


@dbg.eng_thread
def get_breakpoints():
    ids = [bpid for bpid in dbg._base.breakpoints]
    offset_set = []
    expr_set = []
    prot_set = []
    width_set = []
    stat_set = []
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
def selected_process():
    try:
        return dbg._base._systems.GetCurrentProcessId()
    except exception.E_UNEXPECTED_Error:
        return None


@dbg.eng_thread
def selected_thread():
    try:
        return dbg._base._systems.GetCurrentThreadId()
    except exception.E_UNEXPECTED_Error:
        return None


@dbg.eng_thread
def selected_frame():
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


@dbg.eng_thread
def select_process(id: int):
    return dbg._base._systems.SetCurrentProcessId(id)


@dbg.eng_thread
def select_thread(id: int):
    return dbg._base._systems.SetCurrentThreadId(id)


@dbg.eng_thread
def select_frame(id: int):
    return dbg.cmd('.frame 0x{:x}'.format(id))


@dbg.eng_thread
def parse_and_eval(expr, type=None):
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


@dbg.eng_thread
def get_pc():
    return dbg._base.reg.get_pc()


@dbg.eng_thread
def get_sp():
    return dbg._base.reg.get_sp()


@dbg.eng_thread
def GetProcessIdsByIndex(count=0):
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
    return (tuple(ids), tuple(sysids))


@dbg.eng_thread
def GetCurrentProcessExecutableName():
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
    buffer = buffer[:size.value]
    buffer = buffer.rstrip(b'\x00')
    return buffer


@dbg.eng_thread
def GetCurrentProcessPeb():
    # TODO: upstream?
    _dbg = dbg._base
    offset = c_ulonglong()
    hr = _dbg._systems._sys.GetCurrentProcessPeb(byref(offset))
    exception.check_err(hr)
    return offset.value


@dbg.eng_thread
def GetExitCode():
    # TODO: upstream?
    exit_code = c_ulong()
    hr = dbg._base._client._cli.GetExitCode(byref(exit_code))
    return exit_code.value


@dbg.eng_thread
def process_list(running=False):
    """Get the list of all processes"""
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
            _dbg._systems.SetCurrentProcessId(curid)


@dbg.eng_thread
def thread_list(running=False):
    """Get the list of all threads"""
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


conv_map = {}


def get_convenience_variable(id):
    if id not in conv_map:
        return "auto"
    val = conv_map[id]
    if val is None:
        return "auto"
    return val


def set_convenience_variable(id, value):
    conv_map[id] = value
