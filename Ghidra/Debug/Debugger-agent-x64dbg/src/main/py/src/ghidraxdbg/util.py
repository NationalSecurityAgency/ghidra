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

from ghidratrace.client import Schedule
from collections import namedtuple
from ctypes import POINTER, byref, c_ulong, c_ulonglong, create_string_buffer
import functools
import io
import os
import queue
import psutil
import re
import sys
import threading
import traceback
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, TypeVar, Union, cast

from x64dbg_automate import X64DbgClient
from x64dbg_automate.events import CreateThreadEventData
from x64dbg_automate.models import Context32, Context64, Instruction, MemPage, RegDump

DbgVersion = namedtuple('DbgVersion', ['full', 'name', 'dotted', 'arch'])
conv_map: Dict[str, str] = {}
threads: Dict[int, CreateThreadEventData] = {}

class DebuggeeRunningException(BaseException):
    pass

class GhidraDbg(object):

    def __init__(self) -> None:
        self._new_base()
        client = self._client
        client.start_session()

    def _new_base(self) -> None:
        executable = os.getenv('OPT_X64DBG_EXE')
        if executable is None:
            return
        self._client = X64DbgClient(executable)

    @property
    def client(self) -> X64DbgClient:
        return self._client

    def cmd(self, cmdline: str, quiet: bool = True) -> str:
         # Here, we let it print without capture if quiet is False
        if quiet:
            buffer = io.StringIO()
            #self.client.callbacks.stdout = buffer
            self.client.cmd_sync(cmdline)
            return "completed"
        else:
            self.client.cmd_sync(cmdline)
            return ""

    def wait(self) -> None:
        self._client.wait_until_stopped()
        
    def interrupt(self) -> None:
        self._client.pause()

    def eval(self, input: str) -> Optional[list[int]]:
        try:
            return self._client.eval_sync(input)
        except:
            return None

    def get_actual_processor_type(self) -> int:
        return self.client.debugee_bitness()

    @property
    def pid(self) -> Optional[int]:
        try:
            return self.client.get_debugger_pid()
        except:
            # There is no process
            return None


dbg = GhidraDbg()


def compute_dbg_ver() -> DbgVersion:
    ver = dbg.client.get_debugger_version()
    executable = os.getenv('OPT_X64DBG_EXE')
    bitness = dbg.client.debugee_bitness()
    return DbgVersion('Unknown', 'Unknown', ver, 'x{}'.format(bitness))


DBG_VERSION = compute_dbg_ver()
last_process = None


def get_target():
    return 0 #dbg.get_current_system_id()


def disassemble1(addr: int) -> Instruction | None:
    return dbg.client.disassemble_at(addr)


def get_inst(addr: int) -> Instruction | None:
    return disassemble1(addr)


def get_inst_sz(addr: int) -> int:
    inst = disassemble1(addr)
    if inst is None:
        return 0
    return int(inst.instr_size)


def selected_process() -> int:
    global last_process
    try:
        pid = dbg.client.debugee_pid()
        if pid is not None:
            last_process = pid
        return pid
    except:
        return None


def selected_process_space() -> int:
    try:
        return selected_process()
    except:
        # NB: we're intentionally returning 0 instead of None
        return 0


def selected_thread() -> Optional[int]:
    try:
        ev = dbg.eval('tid()')
        if ev is None:
            return None
        return ev[0]
    except:
        return None


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


def select_thread(id: int) -> bool:
    return dbg.client.switch_thread(id)


def select_frame(id: int) -> str:
    return dbg.cmd('.frame /c {}'.format(id))


def reset_frames() -> str:
    return dbg.cmd('.cxr')


def parse_and_eval(expr: Union[str, int],
                   type: Optional[int] = None) -> Union[int, float, bytes]:
    if isinstance(expr, int):
        return expr
    return int(expr, 16)


def get_pc() -> int:
    ctxt = dbg.client.get_regs().context
    if hasattr(ctxt, 'rip'):
        return ctxt.rip
    else:
        return ctxt.eip


def get_sp() -> int:
    ctxt = dbg.client.get_regs().context
    if hasattr(ctxt, 'rsp'):
        return ctxt.rsp
    else:
        return ctxt.esp


def process_list0(running: bool = False) -> Union[
        Iterable[Tuple[int, str, int]], Iterable[Tuple[int]]]:
    """Get the list of all processes."""
    nproc = selected_process()
    sysids = []
    names = []
    if nproc is None:
        return zip(sysids)

    try:
        proc = psutil.Process(nproc)
        sysids.append(nproc)
        names.append(proc.name())
        return zip(sysids, names)
    except Exception:
        return zip(sysids)


def process_list(running: bool = False) -> Union[
        Iterable[Tuple[int, str, int]], Iterable[Tuple[int]]]:
    """Get the list of all processes."""
    sysids = []
    names = []

    try:
        for pid in psutil.pids():
            sysids.append(pid)
            proc = psutil.Process(pid)
            names.append(proc.name())
        return zip(sysids, names)
    except Exception:
        return zip(sysids)


def thread_list(running: bool = False) -> Union[
        Iterable[Tuple[int, int, str]], Iterable[Tuple[int]]]:
    """Get the list of all threads."""
    nproc = selected_process()
    proc = psutil.Process(nproc)
    sysids = []

    try:
        for t in proc.threads():
            sysids.append(t.id)
        return zip(sysids)
    except Exception:
        return zip(sysids)


def full_mem() -> List[MemPage]:
    return []


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


def get_kind(obj) -> Optional[int]:
    """Get the kind."""
    if obj is None:
        return None
    kind = obj.GetKind()
    if kind is None:
        return None
    return obj.GetKind().value


def terminate_session() -> None:
    dbg.client.terminate_session()


def get_convenience_variable(id: str) -> Any:
    if id not in conv_map:
        return "auto"
    val = conv_map[id]
    if val is None:
        return "auto"
    return val


def set_convenience_variable(id: str, value: Any) -> None:
    conv_map[id] = value

