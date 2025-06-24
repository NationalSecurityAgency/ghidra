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
from collections import namedtuple
from dataclasses import dataclass
import os
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

import drgn
import drgn.cli


DrgnVersion = namedtuple('DrgnVersion', ['display', 'full'])

selected_pid = 0
selected_tid = 0
selected_level = 0


def _compute_drgn_ver() -> DrgnVersion:
    blurb = drgn.cli.version_header()
    top = blurb.split('\n')[0]
    full = top.split()[1]    # "drgn x.y.z"
    return DrgnVersion(top, full)


DRGN_VERSION = _compute_drgn_ver()


@dataclass(frozen=True)
class Region:
    start: int
    end: int
    offset: int
    perms: Optional[str]
    objfile: str


def full_mem(self) -> Region:
    return Region(0, 1 << 64, 0, None, 'full memory')


def get_debugger():
    return drgn


def selected_process() -> int:
    return selected_pid


def selected_thread() -> int:
    return selected_tid


def selected_frame() -> int:
    return selected_level


def select_process(id: int) -> int:
    global selected_pid
    selected_pid = id
    return selected_pid


def select_thread(id: int) -> int:
    global selected_tid
    selected_tid = id
    return selected_tid


def select_frame(id: int) -> int:
    global selected_level
    selected_level = id
    return selected_level


conv_map: Dict[str, Any] = {}


def get_convenience_variable(id: str):
    # val = get_target().GetEnvironment().Get(id)
    if id not in conv_map:
        return "auto"
    val = conv_map[id]
    if val is None:
        return "auto"
    return val


def set_convenience_variable(id: str, value: Any) -> None:
    # env = get_target().GetEnvironment()
    # return env.Set(id, value, True)
    conv_map[id] = value


def escape_ansi(line: str) -> str:
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
    return ansi_escape.sub('', line)


def debracket(init: str) -> str:
    val = init
    val = val.replace("[", "(")
    val = val.replace("]", ")")
    return val
