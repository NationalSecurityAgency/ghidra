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
import bisect
import re

import gdb


GdbVersion = namedtuple('GdbVersion', ['full', 'major', 'minor'])


def _compute_gdb_ver():
    blurb = gdb.execute('show version', to_string=True)
    top = blurb.split('\n')[0]
    full = top.split(' ')[-1]
    major, minor = full.split('.')[:2]
    return GdbVersion(full, int(major), int(minor))


GDB_VERSION = _compute_gdb_ver()

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


class Module(namedtuple('BaseModule', ['name', 'base', 'max', 'sections'])):
    pass

class Index:
    def __init__(self, regions):
        self.regions = {}
        self.bases = []
        for r in regions:
            self.regions[r.start] = r
            self.bases.append(r.start)
    def compute_base(self, address):
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

class Section(namedtuple('BaseSection', ['name', 'start', 'end', 'offset', 'attrs'])):
    def better(self, other):
        start = self.start if self.start != 0 else other.start
        end = self.end if self.end != 0 else other.end
        offset = self.offset if self.offset != 0 else other.offset
        attrs = dict.fromkeys(self.attrs)
        attrs.update(dict.fromkeys(other.attrs))
        return Section(self.name, start, end, offset, list(attrs))


def try_hexint(val, name):
    try:
        return int(val, 16)
    except ValueError:
        gdb.write("Invalid {}: {}".format(name, val), stream=gdb.STDERR)
        return 0


# AFAICT, Objfile does not give info about load addresses :(
class ModuleInfoReader(object):
    def name_from_line(self, line):
        mat = self.objfile_pattern.fullmatch(line)
        if mat is None:
            return None
        n = mat['name']
        if n.startswith(GNU_DEBUGDATA_PREFIX):
            return None
        return None if mat is None else mat['name']

    def section_from_line(self, line):
        mat = self.section_pattern.fullmatch(line)
        if mat is None:
            return None
        start = try_hexint(mat['vmaS'], 'section start')
        end = try_hexint(mat['vmaE'], 'section end')
        offset = try_hexint(mat['offset'], 'section offset')
        name = mat['name']
        attrs = [a for a in mat['attrs'].split(' ') if a != '']
        return Section(name, start, end, offset, attrs)

    def finish_module(self, name, sections, index):
        alloc = {k: s for k, s in sections.items() if 'ALLOC' in s.attrs}
        if len(alloc) == 0:
            return Module(name, 0, 0, alloc)
        base_addr = min(index.compute_base(s.start) for s in alloc.values())
        max_addr = max(s.end for s in alloc.values())
        return Module(name, base_addr, max_addr, alloc)

    def get_modules(self):
        modules = {}
        index = Index(REGION_INFO_READER.get_regions())
        out = gdb.execute(self.cmd, to_string=True)
        name = None
        sections = None
        for line in out.split('\n'):
            n = self.name_from_line(line)
            if n is not None:
                if name is not None:
                    modules[name] = self.finish_module(name, sections, index)
                name = n
                sections = {}
                continue
            if name is None:
                # Don't waste time parsing if no module
                continue
            s = self.section_from_line(line)
            if s is not None:
                if s.name in sections:
                    s = s.better(sections[s.name])
                sections[s.name] = s
        if name is not None:
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


def _choose_module_info_reader():
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
REGION_PATTERN_V8 = re.compile("\\s*" +
                               "0x(?P<start>[0-9,A-F,a-f]+)\\s+" +
                               "0x(?P<end>[0-9,A-F,a-f]+)\\s+" +
                               "0x(?P<size>[0-9,A-F,a-f]+)\\s+" +
                               "0x(?P<offset>[0-9,A-F,a-f]+)\\s+" +
                               "(?P<objfile>.*)")
REGION_PATTERN_V12 = re.compile("\\s*" +
                                "0x(?P<start>[0-9,A-F,a-f]+)\\s+" +
                                "0x(?P<end>[0-9,A-F,a-f]+)\\s+" +
                                "0x(?P<size>[0-9,A-F,a-f]+)\\s+" +
                                "0x(?P<offset>[0-9,A-F,a-f]+)\\s+" +
                                "(?P<perms>[rwsxp\\-]+)\\s+" +
                                "(?P<objfile>.*)")


class Region(namedtuple('BaseRegion', ['start', 'end', 'offset', 'perms', 'objfile'])):
    pass


class RegionInfoReader(object):
    def region_from_line(self, line):
        mat = self.region_pattern.fullmatch(line)
        if mat is None:
            return None
        start = try_hexint(mat['start'], 'region start')
        end = try_hexint(mat['end'], 'region end')
        offset = try_hexint(mat['offset'], 'region offset')
        perms = self.get_region_perms(mat)
        objfile = mat['objfile']
        return Region(start, end, offset, perms, objfile)

    def get_regions(self):
        regions = []
        try:
            out = gdb.execute(self.cmd, to_string=True)
        except:
            return regions
        for line in out.split('\n'):
            r = self.region_from_line(line)
            if r is None:
                continue
            regions.append(r)
        return regions

    def full_mem(self):
        # TODO: This may not work for Harvard architectures
        sizeptr = int(gdb.parse_and_eval('sizeof(void*)')) * 8
        return Region(0, 1 << sizeptr, 0, None, 'full memory')


class RegionInfoReaderV8(RegionInfoReader):
    cmd = REGIONS_CMD
    region_pattern = REGION_PATTERN_V8

    def get_region_perms(self, mat):
        return None


class RegionInfoReaderV12(RegionInfoReader):
    cmd = REGIONS_CMD
    region_pattern = REGION_PATTERN_V12

    def get_region_perms(self, mat):
        return mat['perms']


def _choose_region_info_reader():
    if 8 <= GDB_VERSION.major < 12:
        return RegionInfoReaderV8()
    elif GDB_VERSION.major >= 12:
        return RegionInfoReaderV12()
    else:
        raise gdb.GdbError(
            "GDB version not recognized by ghidragdb: " + GDB_VERSION.full)


REGION_INFO_READER = _choose_region_info_reader()


BREAK_LOCS_CMD = 'info break {}'
BREAK_PATTERN = re.compile('')
BREAK_LOC_PATTERN = re.compile('')


class BreakpointLocation(namedtuple('BaseBreakpointLocation', ['address', 'enabled', 'thread_groups'])):
    pass


class BreakpointLocationInfoReaderV8(object):
    def breakpoint_from_line(self, line):
        pass

    def location_from_line(self, line):
        pass

    def get_locations(self, breakpoint):
        pass


class BreakpointLocationInfoReaderV13(object):
    def get_locations(self, breakpoint):
        return breakpoint.locations


def _choose_breakpoint_location_info_reader():
    if 8 <= GDB_VERSION.major < 13:
        return BreakpointLocationInfoReaderV8()
    elif GDB_VERSION.major >= 13:
        return BreakpointLocationInfoReaderV13()
    else:
        raise gdb.GdbError(
            "GDB version not recognized by ghidragdb: " + GDB_VERSION.full)


BREAKPOINT_LOCATION_INFO_READER = _choose_breakpoint_location_info_reader()
