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

import lldb


LldbVersion = namedtuple('LldbVersion', ['display', 'full', 'major', 'minor'])


def _compute_lldb_ver():
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


class Module(namedtuple('BaseModule', ['name', 'base', 'max', 'sections'])):
    pass


class Section(namedtuple('BaseSection', ['name', 'start', 'end', 'offset', 'attrs'])):
    def better(self, other):
        start = self.start if self.start != 0 else other.start
        end = self.end if self.end != 0 else other.end
        offset = self.offset if self.offset != 0 else other.offset
        attrs = dict.fromkeys(self.attrs)
        attrs.update(dict.fromkeys(other.attrs))
        return Section(self.name, start, end, offset, list(attrs))


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

    def section_from_sbsection(self, s):
        start = s.GetLoadAddress(get_target())
        if start >= sys.maxsize*2:
            start = 0
        end = start + s.GetFileByteSize()
        offset = s.GetFileOffset()
        name = s.GetName()
        attrs = s.GetPermissions()
        return Section(name, start, end, offset, attrs)

    def finish_module(self, name, sections):
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

    def get_modules(self):
        modules = {}
        name = None
        sections = {}
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


def _choose_module_info_reader():
    return ModuleInfoReader()


MODULE_INFO_READER = _choose_module_info_reader()


class Region(namedtuple('BaseRegion', ['start', 'end', 'offset', 'perms', 'objfile'])):
    pass


class RegionInfoReader(object):
    def region_from_sbmemreg(self, info):
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

    def get_regions(self):
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

    def full_mem(self):
        # TODO: This may not work for Harvard architectures
        try:
            sizeptr = int(parse_and_eval('sizeof(void*)')) * 8
            return Region(0, 1 << sizeptr, 0, None, 'full memory')
        except ValueError:
            return Region(0, 1 << 64, 0, None, 'full memory')


def _choose_region_info_reader():
    return RegionInfoReader()


REGION_INFO_READER = _choose_region_info_reader()


BREAK_LOCS_CMD = 'breakpoint list {}'
BREAK_PATTERN = re.compile('')
BREAK_LOC_PATTERN = re.compile('')


class BreakpointLocation(namedtuple('BaseBreakpointLocation', ['address', 'enabled', 'thread_groups'])):
    pass


class BreakpointLocationInfoReader(object):
    def get_locations(self, breakpoint):
        return breakpoint.locations


def _choose_breakpoint_location_info_reader():
    return BreakpointLocationInfoReader()


BREAKPOINT_LOCATION_INFO_READER = _choose_breakpoint_location_info_reader()


def get_debugger():
    return lldb.SBDebugger.FindDebuggerWithID(1)


def get_target():
    return get_debugger().GetTargetAtIndex(0)


def get_process():
    return get_target().GetProcess()


def selected_thread():
    return get_process().GetSelectedThread()


def selected_frame():
    return selected_thread().GetSelectedFrame()


def parse_and_eval(expr, signed=False):
    if signed is True:
        return get_eval(expr).GetValueAsSigned()
    return get_eval(expr).GetValueAsUnsigned()


def get_eval(expr):
    eval = get_target().EvaluateExpression(expr)
    if eval.GetError().Fail():
        raise ValueError(eval.GetError().GetCString())
    return eval


def get_description(object, level=None):
    stream = lldb.SBStream()
    if level is None:
        object.GetDescription(stream)
    else:
        object.GetDescription(stream, level)
    return escape_ansi(stream.GetData())


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


def escape_ansi(line):
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
    return ansi_escape.sub('', line)


def debracket(init):
    val = init
    val = val.replace("[", "(")
    val = val.replace("]", ")")
    return val
