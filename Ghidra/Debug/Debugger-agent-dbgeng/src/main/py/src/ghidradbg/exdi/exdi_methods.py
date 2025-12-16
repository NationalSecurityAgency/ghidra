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
import re

from ghidratrace import sch
from ghidratrace.client import (MethodRegistry, ParamDesc, Address,
                                AddressRange, TraceObject)
from ghidradbg import util, commands, methods
from ghidradbg.methods import REGISTRY, SESSIONS_PATTERN, SESSION_PATTERN, extre

from . import exdi_commands

XPROCESSES_PATTERN = extre(SESSION_PATTERN, '\\.ExdiProcesses')
XPROCESS_PATTERN = extre(XPROCESSES_PATTERN, '\\[(?P<procnum>\\d*)\\]')
XTHREADS_PATTERN = extre(XPROCESS_PATTERN, '\\.Threads')


def find_pid_by_pattern(pattern, object, err_msg):
    mat = pattern.fullmatch(object.path)
    if mat is None:
        raise TypeError(f"{object} is not {err_msg}")
    pid = int(mat['procnum'])
    return pid


def find_pid_by_obj(object):
    return find_pid_by_pattern(XTHREADS_PATTERN, object, "an ExdiThreadsContainer")


class ExdiProcessContainer(TraceObject):
    pass


class ExdiThreadContainer(TraceObject):
    pass


@REGISTRY.method(action='refresh', display="Refresh Target Processes")
def refresh_exdi_processes(node: ExdiProcessContainer) -> None:
    """Refresh the list of processes in the target kernel."""
    with commands.open_tracked_tx('Refresh Processes'):
        exdi_commands.ghidra_trace_put_processes_exdi()


@REGISTRY.method(action='refresh', display="Refresh Process Threads")
def refresh_exdi_threads(node: ExdiThreadContainer) -> None:
    """Refresh the list of threads in the process."""
    pid = find_pid_by_obj(node)
    with commands.open_tracked_tx('Refresh Threads'):
        exdi_commands.ghidra_trace_put_threads_exdi(pid)
