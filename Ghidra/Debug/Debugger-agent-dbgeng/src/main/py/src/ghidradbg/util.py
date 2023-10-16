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
import os
import re
import sys

from ctypes import *
from pybag import pydbg
from pybag.dbgeng import core as DbgEng
from pybag.dbgeng import exception
from pybag.dbgeng import util as DbgUtil

base = pydbg.DebuggerBase()
DbgVersion = namedtuple('DbgVersion', ['full', 'major', 'minor'])


def _compute_pydbg_ver():
    blurb = "" #base._control.GetActualProcessorType()
    full = ""
    major = 0
    minor = 0
    return DbgVersion(full, int(major), int(minor))


DBG_VERSION = _compute_pydbg_ver()


def get_debugger():
    return base

def get_target():
    return 0 #get_debugger()._systems.GetCurrentSystemId()

def get_inst(addr):
    dbg = get_debugger()
    ins = DbgUtil.disassemble_instruction(dbg.bitness(), addr, dbg.read(addr, 15))
    return str(ins)

def get_inst_sz(addr):
    dbg = get_debugger()
    ins = DbgUtil.disassemble_instruction(dbg.bitness(), addr, dbg.read(addr, 15))
    return str(ins.size)

def get_breakpoints():
    ids = [bpid for bpid in get_debugger().breakpoints]
    offset_set = []
    expr_set = []
    prot_set = []
    width_set = []
    stat_set = []
    for bpid in ids:
        try:
            bp = get_debugger()._control.GetBreakpointById(bpid)
        except exception.E_NOINTERFACE_Error:
            continue
        
        if bp.GetFlags() & DbgEng.DEBUG_BREAKPOINT_DEFERRED:
            offset = "[Deferred]"
            expr = bp.GetOffsetExpression()
        else:
            offset = "%016x" % bp.GetOffset()
            expr = get_debugger().get_name_by_offset(bp.GetOffset())
            
        if bp.GetType()[0] == DbgEng.DEBUG_BREAKPOINT_DATA:
            width, prot = bp.GetDataParameters()
            width = ' sz={}'.format(str(width))
            prot = {4: 'type=x', 3: 'type=rw', 2: 'type=w', 1: 'type=r'}[prot] 
        else:
            width = ''
            prot  = ''

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

def selected_process():
    try:
        return get_debugger()._systems.GetCurrentProcessId()
        #return current_process
    except Exception:
        return None
    
def selected_thread():    
    try:
        return get_debugger()._systems.GetCurrentThreadId()
    except Exception:
        return None

def selected_frame():
    return 0 #selected_thread().GetSelectedFrame()

def select_process(id: int):
    return get_debugger()._systems.SetCurrentProcessId(id)

def select_thread(id: int):
    return get_debugger()._systems.SetCurrentThreadId(id)

def select_frame(id: int):
    #TODO: this needs to be fixed
    return id 

def parse_and_eval(expr):
    regs = get_debugger().reg
    if expr == "$pc":
        return regs.get_pc()
    if expr == "$sp":
        return regs.get_sp()
    return get_eval(expr)

def get_eval(expr, type=None):
    ctrl = get_debugger()._control._ctrl
    ctrl.SetExpressionSyntax(1)
    value = DbgEng._DEBUG_VALUE()
    index = c_ulong()
    if type == None:
        type = DbgEng.DEBUG_VALUE_INT64
    hr = ctrl.Evaluate(Expression="{}".format(expr).encode(),DesiredType=type,Value=byref(value),RemainderIndex=byref(index))
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

def GetProcessIdsByIndex(count=0):
    if count == 0:
        try :
            count = get_debugger()._systems.GetNumberProcesses()
        except Exception:
            count = 0
    ids = (c_ulong * count)()
    sysids = (c_ulong * count)()
    if count != 0:
        hr = get_debugger()._systems._sys.GetProcessIdsByIndex(0, count, ids, sysids)
        exception.check_err(hr)
    return (tuple(ids), tuple(sysids))


def GetCurrentProcessExecutableName():
    dbg = get_debugger()
    size = c_ulong()
    exesize = c_ulong()
    hr = dbg._systems._sys.GetCurrentProcessExecutableName(None, size, byref(exesize))
    exception.check_err(hr)
    buffer = create_string_buffer(exesize.value)
    size = exesize
    hr = dbg._systems._sys.GetCurrentProcessExecutableName(buffer, size, None)
    exception.check_err(hr)
    buffer = buffer[:size.value]
    buffer = buffer.rstrip(b'\x00')
    return buffer


def GetCurrentProcessPeb():
    dbg = get_debugger()
    offset = c_ulonglong()
    hr = dbg._systems._sys.GetCurrentProcessPeb(byref(offset))
    exception.check_err(hr)
    return offset.value


def GetExitCode():
    exit_code = c_ulong()
    hr = get_debugger()._client._cli.GetExitCode(byref(exit_code))
    return exit_code.value


def process_list(running=False):
    """process_list() -> list of all processes"""
    dbg = get_debugger()
    ids, sysids = GetProcessIdsByIndex()
    pebs = []
    names = []
    
    try :
        curid = dbg._systems.GetCurrentProcessId()
        if running == False:
            for id in ids:
                dbg._systems.SetCurrentProcessId(id)
                names.append(GetCurrentProcessExecutableName())
                pebs.append(GetCurrentProcessPeb())
        if running == False:
            dbg._systems.SetCurrentProcessId(curid)
            return zip(sysids, names, pebs)
    except Exception:
        pass
    return zip(sysids)

def thread_list(running=False):
    """thread_list() -> list of all threads"""
    dbg = get_debugger()
    try :
        ids, sysids = dbg._systems.GetThreadIdsByIndex()
    except Exception:
        return zip([])
    tebs = []
    syms = []
    
    curid = dbg._systems.GetCurrentThreadId()
    if running == False:
        for id in ids:
            dbg._systems.SetCurrentThreadId(id)
            tebs.append(dbg._systems.GetCurrentThreadTeb())
            addr = dbg.reg.get_pc()
            syms.append(dbg.get_name_by_offset(addr))
    if running == False:
        dbg._systems.SetCurrentThreadId(curid)
        return zip(sysids, tebs, syms)
    return zip(sysids)

conv_map = {}

def get_convenience_variable(id):
    #val = get_target().GetEnvironment().Get(id)
    if id not in conv_map:
        return "auto"
    val = conv_map[id]
    if val is None:
        return "auto"
    return val

def set_convenience_variable(id, value):
    #env = get_target().GetEnvironment()
    #return env.Set(id, value, True)
    conv_map[id] = value
