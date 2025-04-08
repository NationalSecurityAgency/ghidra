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
from typing import Any, Dict, List, Optional, Union

import lldb


@dataclass(frozen=True)
class LldbVersion:
    display: str
    full: str
    major: int
    minor: int


def _compute_lldb_ver() -> LldbVersion:
    blurb = lldb.debugger.GetVersionString()
    top = blurb.split('\n')[0]
    if ' version ' in top:
        full = top.split(' ')[2]    # "lldb version x.y.z"
    else:
        full = top.split('-')[1]    # "lldb-x.y.z"
    major, minor = full.split('.')[:2]
    return LldbVersion(top, full, int(major), int(minor))


LLDB_VERSION = _compute_lldb_ver()

GNU_DEBUGDATA_PREFIX = ".gnu_debugdata for "


@dataclass
class Section:
    name: str
    start: int
    end: int
    offset: int
    attrs: List[str]

    def better(self, other: 'Section') -> 'Section':
        start = self.start if self.start != 0 else other.start
        end = self.end if self.end != 0 else other.end
        offset = self.offset if self.offset != 0 else other.offset
        attrs = dict.fromkeys(self.attrs)
        attrs.update(dict.fromkeys(other.attrs))
        return Section(self.name, start, end, offset, list(attrs))


@dataclass(frozen=True)
class Module:
    name: str
    base: int
    max: int
    sections: Dict[str, Section]


# AFAICT, Objfile does not give info about load addresses :(
class ModuleInfoReader(object):
    def section_from_sbsection(self, s: lldb.SBSection) -> Section:
        start = s.GetLoadAddress(get_target())
        if start >= sys.maxsize*2:
            start = 0
        end = start + s.GetFileByteSize()
        offset = s.GetFileOffset()
        name = s.GetName()
        attrs = s.GetPermissions()
        return Section(name, start, end, offset, attrs)

    def finish_module(self, name: str, sections: Dict[str, Section]) -> Module:
        alloc = {k: s for k, s in sections.items()}
        if len(alloc) == 0:
            return Module(name, 0, 0, alloc)
        # TODO: This may not be the module base, depending on headers
        all_zero = True
        for s in alloc.values():
            if s.start != 0:
                all_zero = False
        if all_zero:
            base_addr = 0
        else:
            base_addr = min(s.start for s in alloc.values() if s.start != 0)
        max_addr = max(s.end for s in alloc.values())
        return Module(name, base_addr, max_addr, alloc)

    def get_modules(self) -> Dict[str, Module]:
        modules = {}
        name = None
        sections: Dict[str, Section] = {}
        for i in range(0, get_target().GetNumModules()):
            module = get_target().GetModuleAtIndex(i)
            fspec = module.GetFileSpec()
            name = debracket(fspec.GetFilename())
            sections = {}
            for i in range(0, module.GetNumSections()):
                s = self.section_from_sbsection(module.GetSectionAtIndex(i))
                sname = debracket(s.name)
                sections[sname] = s
            modules[name] = self.finish_module(name, sections)
        return modules


def _choose_module_info_reader() -> ModuleInfoReader:
    return ModuleInfoReader()


MODULE_INFO_READER = _choose_module_info_reader()


@dataclass
class Region:
    start: int
    end: int
    offset: int
    perms: Optional[str]
    objfile: str


class RegionInfoReader(object):
    def region_from_sbmemreg(self, info: lldb.SBMemoryRegionInfo) -> Region:
        start = info.GetRegionBase()
        end = info.GetRegionEnd()
        offset = info.GetRegionBase()
        if offset >= sys.maxsize:
            offset = 0
        perms = ""
        if info.IsReadable():
            perms += 'r'
        if info.IsWritable():
            perms += 'w'
        if info.IsExecutable():
            perms += 'x'
        objfile = info.GetName()
        return Region(start, end, offset, perms, objfile)

    def get_regions(self) -> List[Region]:
        regions = []
        reglist = get_process().GetMemoryRegions()
        for i in range(0, reglist.GetSize()):
            module = get_target().GetModuleAtIndex(i)
            info = lldb.SBMemoryRegionInfo()
            success = reglist.GetMemoryRegionAtIndex(i, info)
            if success:
                r = self.region_from_sbmemreg(info)
                regions.append(r)
        return regions

    def full_mem(self) -> Region:
        # TODO: This may not work for Harvard architectures
        try:
            sizeptr = int(parse_and_eval('sizeof(void*)')) * 8
            return Region(0, 1 << sizeptr, 0, None, 'full memory')
        except ValueError:
            return Region(0, 1 << 64, 0, None, 'full memory')


def _choose_region_info_reader() -> RegionInfoReader:
    return RegionInfoReader()


REGION_INFO_READER = _choose_region_info_reader()


BREAK_LOCS_CMD = 'breakpoint list {}'
BREAK_PATTERN = re.compile('')
BREAK_LOC_PATTERN = re.compile('')


class BreakpointLocationInfoReader(object):
    def get_locations(self, breakpoint: lldb.SBBreakpoint) -> List[
            lldb.SBBreakpointLocation]:
        return breakpoint.locations


def _choose_breakpoint_location_info_reader() -> BreakpointLocationInfoReader:
    return BreakpointLocationInfoReader()


BREAKPOINT_LOCATION_INFO_READER = _choose_breakpoint_location_info_reader()


def get_debugger() -> lldb.SBDebugger:
    return lldb.SBDebugger.FindDebuggerWithID(1)


def get_target() -> lldb.SBTarget:
    return get_debugger().GetTargetAtIndex(0)


def get_process() -> lldb.SBProcess:
    return get_target().GetProcess()


def selected_thread() -> lldb.SBThread:
    return get_process().GetSelectedThread()


def selected_frame() -> lldb.SBFrame:
    return selected_thread().GetSelectedFrame()


def parse_and_eval(expr: str, signed: bool = False) -> int:
    if signed is True:
        return get_eval(expr).GetValueAsSigned()
    return get_eval(expr).GetValueAsUnsigned()


def get_eval(expr: str) -> lldb.SBValue:
    eval = get_target().EvaluateExpression(expr)
    if eval.GetError().Fail():
        raise ValueError(eval.GetError().GetCString())
    return eval


def get_description(object: Union[
        lldb.SBThread, lldb.SBBreakpoint, lldb.SBWatchpoint, lldb.SBEvent],
        level: Optional[int] = None) -> str:
    stream = lldb.SBStream()
    if level is None:
        object.GetDescription(stream)
    elif isinstance(object, lldb.SBWatchpoint):
        object.GetDescription(stream, level)
    else:
        raise ValueError(f"Object {object} does not support description level")
    return escape_ansi(stream.GetData())


conv_map: Dict[str, str] = {}


def get_convenience_variable(id: str) -> str:
    # val = get_target().GetEnvironment().Get(id)
    if id not in conv_map:
        return "auto"
    val = conv_map[id]
    if val is None:
        return "auto"
    return val


def set_convenience_variable(id: str, value: str) -> None:
    # env = get_target().GetEnvironment()
    # return env.Set(id, value, True)
    conv_map[id] = value


def escape_ansi(line: str) -> str:
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
    return ansi_escape.sub('', line)


def debracket(init: Optional[str]) -> str:
    if init is None:
        return ""
    val = init
    val = val.replace("[", "(")
    val = val.replace("]", ")")
    return val
