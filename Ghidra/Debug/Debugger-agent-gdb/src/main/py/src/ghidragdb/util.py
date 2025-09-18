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
from abc import abstractmethod
from collections import namedtuple
import bisect
from dataclasses import dataclass
import re
from typing import Callable, Dict, List, Optional, Set, Tuple, Union

import gdb


@dataclass(frozen=True)
class GdbVersion:
    full: str
    major: int
    minor: int


def _compute_gdb_ver() -> GdbVersion:
    blurb = gdb.execute('show version', to_string=True)
    top = blurb.split('\n')[0]
    full = top.split(' ')[-1]
    major, minor = full.split('.')[:2]
    if '-' in minor:
        minor = minor[:minor.find('-')]
    return GdbVersion(full, int(major), int(minor))


GDB_VERSION = _compute_gdb_ver()
IS_TRACE = gdb.convenience_variable('use_trace') == True

MODULES_CMD_V8 = 'maintenance info sections ALLOBJ'
MODULES_CMD_V11 = 'maintenance info sections -all-objects'
OBJFILE_PATTERN_V8 = re.compile("\\s*Object file: (?P<name>.*)")
OBJFILE_PATTERN_V11 = re.compile(
    "\\s*((Object)|(Exec)) file: `(?P<name>.*)', file type (?P<type>.*)")
OBJFILE_SECTION_PATTERN_V8 = re.compile("\\s*" +
                                        "0x(?P<vmaS>[0-9A-Fa-f]+)\\s*->\\s*" +
                                        "0x(?P<vmaE>[0-9A-Fa-f]+)\\s+at\\s+" +
                                        "0x(?P<offset>[0-9A-Fa-f]+)\\s*:\\s*" +
                                        "(?P<name>\\S+)\\s+" +
                                        "(?P<attrs>.*)")
OBJFILE_SECTION_PATTERN_V9 = re.compile("\\s*" +
                                        "\\[\\s*(?P<idx>\\d+)\\]\\s+" +
                                        "0x(?P<vmaS>[0-9A-Fa-f]+)\\s*->\\s*" +
                                        "0x(?P<vmaE>[0-9A-Fa-f]+)\\s+at\\s+" +
                                        "0x(?P<offset>[0-9A-Fa-f]+)\\s*:\\s*" +
                                        "(?P<name>\\S+)\\s+" +
                                        "(?P<attrs>.*)")
GNU_DEBUGDATA_PREFIX = ".gnu_debugdata for "


@dataclass(frozen=True)
class Region:
    start: int
    end: int
    offset: int
    perms: Optional[str]
    objfile: str


@dataclass(frozen=True)
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


class Index:
    def __init__(self, regions: List[Region]) -> None:
        self.regions: Dict[int, Region] = {}
        self.bases: List[int] = []
        for r in regions:
            self.regions[r.start] = r
            self.bases.append(r.start)

    def compute_base(self, address: int) -> int:
        index = bisect.bisect_right(self.bases, address) - 1
        if index == -1:
            return address
        floor = self.bases[index]
        if floor == None:
            return address
        else:
            region = self.regions[floor]
            if region.objfile == None or region.end <= address:
                return address
            else:
                return region.start


def try_hexint(val: str, name: str) -> int:
    try:
        return int(val, 16)
    except ValueError:
        gdb.write(f"Invalid {name}: {val}\n", stream=gdb.STDERR)
        return 0


# AFAICT, Objfile does not give info about load addresses :(
class ModuleInfoReader(object):
    cmd: str
    objfile_pattern: re.Pattern
    section_pattern: re.Pattern

    def name_from_line(self, line: str) -> Optional[str]:
        mat = self.objfile_pattern.fullmatch(line)
        if mat is None:
            return None
        n = mat['name']
        return None if mat is None else mat['name']

    def section_from_line(self, line: str, max_addr: int) -> Optional[Section]:
        mat = self.section_pattern.fullmatch(line)
        if mat is None:
            return None
        start = try_hexint(mat['vmaS'], 'section start') & max_addr
        end = try_hexint(mat['vmaE'], 'section end') & max_addr
        offset = try_hexint(mat['offset'], 'section offset')
        name = mat['name']
        attrs = [a for a in mat['attrs'].split(' ') if a != '']
        return Section(name, start, end, offset, attrs)

    def finish_module(self, name: str, sections: Dict[str, Section],
                      index: Index) -> Module:
        alloc = {k: s for k, s in sections.items() if 'ALLOC' in s.attrs}
        if len(alloc) == 0:
            return Module(name, 0, 0, alloc)
        base_addr = min(index.compute_base(s.start) for s in alloc.values())
        max_addr = max(s.end for s in alloc.values())
        return Module(name, base_addr, max_addr, alloc)

    def get_modules(self) -> Dict[str, Module]:
        modules = {}
        index = Index(REGION_INFO_READER.get_regions())
        out = gdb.execute(self.cmd, to_string=True)
        max_addr = compute_max_addr()
        name = None
        sections: Dict[str, Section] = {}
        for line in out.split('\n'):
            n = self.name_from_line(line)
            if n is not None:
                if name is not None and not name.startswith(GNU_DEBUGDATA_PREFIX):
                    modules[name] = self.finish_module(name, sections, index)
                name = n
                sections = {}
                continue
            if name is None:
                # Don't waste time parsing if no module
                continue
            s = self.section_from_line(line, max_addr)
            if s is not None:
                if s.name in sections:
                    s = s.better(sections[s.name])
                sections[s.name] = s
        if name is not None and not name.startswith(GNU_DEBUGDATA_PREFIX):
            modules[name] = self.finish_module(name, sections, index)
        return modules


class ModuleInfoReaderV8(ModuleInfoReader):
    cmd = MODULES_CMD_V8
    objfile_pattern = OBJFILE_PATTERN_V8
    section_pattern = OBJFILE_SECTION_PATTERN_V8


class ModuleInfoReaderV9(ModuleInfoReader):
    cmd = MODULES_CMD_V8
    objfile_pattern = OBJFILE_PATTERN_V8
    section_pattern = OBJFILE_SECTION_PATTERN_V9


class ModuleInfoReaderV11(ModuleInfoReader):
    cmd = MODULES_CMD_V11
    objfile_pattern = OBJFILE_PATTERN_V11
    section_pattern = OBJFILE_SECTION_PATTERN_V9


def _choose_module_info_reader() -> ModuleInfoReader:
    if GDB_VERSION.major == 8:
        return ModuleInfoReaderV8()
    elif GDB_VERSION.major == 9:
        return ModuleInfoReaderV9()
    elif GDB_VERSION.major == 10:
        return ModuleInfoReaderV9()
    elif GDB_VERSION.major == 11:
        return ModuleInfoReaderV11()
    elif GDB_VERSION.major == 12:
        return ModuleInfoReaderV11()
    elif GDB_VERSION.major > 12:
        return ModuleInfoReaderV11()
    else:
        raise gdb.GdbError(
            "GDB version not recognized by ghidragdb: " + GDB_VERSION.full)


MODULE_INFO_READER = _choose_module_info_reader()


REGIONS_CMD = 'info proc mappings'
REGION_PATTERN = re.compile("\\s*" +
                            "0x(?P<start>[0-9,A-F,a-f]+)\\s+" +
                            "0x(?P<end>[0-9,A-F,a-f]+)\\s+" +
                            "0x(?P<size>[0-9,A-F,a-f]+)\\s+" +
                            "0x(?P<offset>[0-9,A-F,a-f]+)\\s+" +
                            "((?P<perms>[rwsxp\\-]+)?\\s+)?" +
                            "(?P<objfile>.*)")


class RegionInfoReader(object):
    cmd = REGIONS_CMD
    region_pattern = REGION_PATTERN

    def region_from_line(self, line: str, max_addr: int) -> Optional[Region]:
        mat = self.region_pattern.fullmatch(line)
        if mat is None:
            return None
        start = try_hexint(mat['start'], 'region start') & max_addr
        end = try_hexint(mat['end'], 'region end') & max_addr
        offset = try_hexint(mat['offset'], 'region offset')
        perms = self.get_region_perms(mat)
        objfile = mat['objfile']
        return Region(start, end, offset, perms, objfile)

    def get_regions(self) -> List[Region]:
        regions: List[Region] = []
        try:
            out = gdb.execute(self.cmd, to_string=True)
            max_addr = compute_max_addr()
        except:
            return regions
        for line in out.split('\n'):
            r = self.region_from_line(line, max_addr)
            if r is None:
                continue
            regions.append(r)
        return regions

    def full_mem(self) -> Region:
        # TODO: This may not work for Harvard architectures
        max_addr = compute_max_addr()
        return Region(0, max_addr+1, 0, None, 'full memory')

    def have_changed(self, regions: List[Region]) -> Tuple[bool, Optional[List[Region]]]:
        if len(regions) == 1 and regions[0].objfile == 'full memory':
            return False, None
        new_regions = self.get_regions()
        if new_regions == regions and len(new_regions) > 0:
            return False, None
        return True, new_regions

    def get_region_perms(self, mat):
        return mat['perms']


def _choose_region_info_reader() -> RegionInfoReader:
    if 8 <= GDB_VERSION.major:
        return RegionInfoReader()
    else:
        raise gdb.GdbError(
            "GDB version not recognized by ghidragdb: " + GDB_VERSION.full)


REGION_INFO_READER = _choose_region_info_reader()


BREAK_LOCS_CMD = 'info break {}'
BREAK_PATTERN = re.compile('')
BREAK_LOC_PATTERN = re.compile('')


@dataclass(frozen=True)
class BreakpointLocation:
    address: int
    enabled: bool
    thread_groups: List[int]


# Quite a hack, but only needed for type annotations
if not hasattr(gdb, 'BreakpointLocation'):
    gdb.BreakpointLocation = BreakpointLocation


class BreakpointLocationInfoReader(object):
    @abstractmethod
    def get_locations(self, breakpoint: gdb.Breakpoint) -> List[Union[
            BreakpointLocation, gdb.BreakpointLocation]]:
        pass


class BreakpointLocationInfoReaderV8(BreakpointLocationInfoReader):
    def get_locations(self, breakpoint: gdb.Breakpoint) -> List[Union[
            BreakpointLocation, gdb.BreakpointLocation]]:
        inf = gdb.selected_inferior()
        thread_groups = [inf.num]
        if breakpoint.location is not None and breakpoint.location.startswith("*0x"):
            address = int(breakpoint.location[1:], 16)
            loc = BreakpointLocation(
                address, breakpoint.enabled, thread_groups)
            return [loc]
        return []


class BreakpointLocationInfoReaderV9(BreakpointLocationInfoReader):
    def get_locations(self, breakpoint: gdb.Breakpoint) -> List[Union[
            BreakpointLocation, gdb.BreakpointLocation]]:
        inf = gdb.selected_inferior()
        thread_groups = [inf.num]
        if breakpoint.location is None:
            return []
        try:
            address = int(gdb.parse_and_eval(
                breakpoint.location).address) & compute_max_addr()
            loc = BreakpointLocation(
                address, breakpoint.enabled, thread_groups)
            return [loc]
        except Exception as e:
            print(f"Error parsing bpt location = {breakpoint.location}")
        return []


class BreakpointLocationInfoReaderV13(BreakpointLocationInfoReader):
    def get_locations(self, breakpoint: gdb.Breakpoint) -> List[Union[
            BreakpointLocation, gdb.BreakpointLocation]]:
        return breakpoint.locations


def _choose_breakpoint_location_info_reader() -> BreakpointLocationInfoReader:
    if GDB_VERSION.major >= 13:
        return BreakpointLocationInfoReaderV13()
    if GDB_VERSION.major >= 9:
        return BreakpointLocationInfoReaderV9()
    if GDB_VERSION.major >= 8:
        return BreakpointLocationInfoReaderV8()
    else:
        raise gdb.GdbError(
            "GDB version not recognized by ghidragdb: " + GDB_VERSION.full)


BREAKPOINT_LOCATION_INFO_READER = _choose_breakpoint_location_info_reader()


def set_bool_param_by_api(name: str, value: bool) -> None:
    gdb.set_parameter(name, value)


def set_bool_param_by_cmd(name: str, value: bool) -> None:
    val = 'on' if value else 'off'
    gdb.execute(f'set {name} {val}')


def choose_set_parameter() -> Callable[[str, bool], None]:
    if GDB_VERSION.major >= 13:
        return set_bool_param_by_api
    else:
        return set_bool_param_by_cmd


set_bool_param = choose_set_parameter()


def get_level(frame: gdb.Frame) -> int:
    if hasattr(frame, "level"):
        return frame.level()
    else:
        level = -1
        f: Optional[gdb.Frame] = frame
        while f is not None:
            level += 1
            f = f.newer()
        return level


@dataclass(frozen=True)
class RegisterDesc:
    name: str


def get_register_descs(arch: gdb.Architecture, group: str = 'all') -> List[
        Union[RegisterDesc, gdb.RegisterDescriptor]]:
    if hasattr(arch, "registers"):
        try:
            return list(arch.registers(group))
        except ValueError:  # No such group, or version too old
            return list(arch.registers())
    else:
        descs: List[Union[RegisterDesc, gdb.RegisterDescriptor]] = []
        try:
            regset = gdb.execute(
                f"info registers {group}", to_string=True).strip().split('\n')
        except Exception as e:
            regset = gdb.execute(
                f"info registers", to_string=True).strip().split('\n')
        for line in regset:
            if not line.startswith(" "):
                tokens = line.strip().split()
                descs.append(RegisterDesc(tokens[0]))
        return descs


def selected_frame() -> Optional[gdb.Frame]:
    try:
        return gdb.selected_frame()
    except Exception as e:
        print("No selected frame")
        return None


def compute_max_addr() -> int:
    return (1 << (int(gdb.parse_and_eval("sizeof(void*)")) * 8)) - 1
