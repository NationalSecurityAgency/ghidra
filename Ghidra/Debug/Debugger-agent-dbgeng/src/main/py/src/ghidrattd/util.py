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

from pyttd import pyTTD

#from pybag import pydbg
#from pybag.dbgeng import core as DbgEng
#from pybag.dbgeng import exception
#from pybag.dbgeng import util as DbgUtil

base = False
eng = False
first = False
last = False
breakpoints = []
events = {}
evttypes = {}
starts = {}
stops = {}
lastpos = False
DbgVersion = namedtuple('DbgVersion', ['full', 'major', 'minor'])


class Watchpoint(object):
    def __init__(self, addr, size, flags, id, bp):
        self.addr = addr
        self.size = size
        self.flags = flags
        self.id = id
        self.bp = bp
        self.expr = None


def _compute_pydbg_ver():
    blurb = "" #get_debugger()._control.GetActualProcessorType()
    full = ""
    major = 0
    minor = 0
    return DbgVersion(full, int(major), int(minor))


DBG_VERSION = _compute_pydbg_ver()


def get_debugger():
    return base


def get_target():
    return 0  # get_debugger()._systems.GetCurrentSystemId()


def get_inst(addr):
    dbg = get_debugger()
    ins = DbgUtil.disassemble_instruction(
        dbg.bitness(), addr, dbg.read_mem(addr, 15))
    return str(ins)


def get_inst_sz(addr):
    dbg = get_debugger()
    ins = DbgUtil.disassemble_instruction(
        dbg.bitness(), addr, dbg.read_mem(addr, 15))
    return str(ins.size)


def get_breakpoints():
    return None


def selected_process():
    try:
        return 0
        # return current_process
    except Exception:
        return None


def selected_thread():
    try:
        dbg = get_debugger()
        current = dbg.get_thread_info()
        return current.threadid
    except Exception:
        return None


def selected_frame():
    return 0  # selected_thread().GetSelectedFrame()


def select_process(id: int):
    return None


def select_thread(id: int):
    return None


def select_frame(id: int):
    # TODO: this needs to be fixed
    return None


def parse_and_eval(expr):
    dbg = get_debugger()
    if expr == "$pc":
        return dbg.get_program_counter()
    if expr == "$sp":
        return dbg.get_context_x86_64().rsp
    return int(expr)


def get_eval(expr, type=None):
    ctrl = get_debugger()._control._ctrl
    ctrl.SetExpressionSyntax(1)
    value = DbgEng._DEBUG_VALUE()
    index = c_ulong()
    if type == None:
        type = DbgEng.DEBUG_VALUE_INT64
    hr = ctrl.Evaluate(Expression="{}".format(expr).encode(
    ), DesiredType=type, Value=byref(value), RemainderIndex=byref(index))
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


def process_list(running=False):
    """process_list() -> list of all processes"""
    sysids = [0]
    return sysids


def thread_list():
    """thread_list() -> list of all threads"""
    dbg = get_debugger()
    return dbg.get_thread_list()


def module_list():
    """thread_list() -> list of all threads"""
    dbg = get_debugger()
    return dbg.get_module_list()


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
    # return env.Set(id, value, True)
    conv_map[id] = value


def pos2snap(pos: int):
    index = int(pos.major)
    if index < 0 or index >= pyTTD.MAX_STEP:
        return int(last.major)*1000
    return index*1000+int(pos.minor)
