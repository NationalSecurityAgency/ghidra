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
from ghidradbg import arch, commands, util
from ghidratrace import sch
from ghidratrace.client import Client, Address, AddressRange, Trace, TraceObject

PAGE_SIZE = 4096


SESSION_PATH = 'Sessions[0]'
PROCESSES_PATH = SESSION_PATH + '.ExdiProcesses'
PROCESS_KEY_PATTERN = '[{pid}]'
PROCESS_PATTERN = PROCESSES_PATH + PROCESS_KEY_PATTERN
PROC_BREAKS_PATTERN = PROCESS_PATTERN + '.Breakpoints'
PROC_BREAK_KEY_PATTERN = '[{breaknum}.{locnum}]'
THREADS_PATTERN = PROCESS_PATTERN + '.Threads'
THREAD_KEY_PATTERN = '[{tnum}]'
THREAD_PATTERN = THREADS_PATTERN + THREAD_KEY_PATTERN
MEMORY_PATH = SESSION_PATH + '.Memory'
REGION_KEY_PATTERN = '[{start}]'
REGION_PATTERN = MEMORY_PATH + REGION_KEY_PATTERN
KMODULES_PATH = SESSION_PATH + '.Modules'
KMODULE_KEY_PATTERN = '[{modpath}]'
KMODULE_PATTERN = KMODULES_PATH + KMODULE_KEY_PATTERN
MODULES_PATTERN = PROCESS_PATTERN + '.Modules'
MODULE_KEY_PATTERN = '[{modpath}]'
MODULE_PATTERN = MODULES_PATTERN + MODULE_KEY_PATTERN
SECTIONS_ADD_PATTERN = '.Sections'
SECTION_KEY_PATTERN = '[{secname}]'
SECTION_ADD_PATTERN = SECTIONS_ADD_PATTERN + SECTION_KEY_PATTERN


@util.dbg.eng_thread
def ghidra_trace_put_processes_exdi() -> None:
    """Put the list of processes into the trace's processes list."""

    radix = util.get_convenience_variable('output-radix')
    trace, tx = commands.STATE.require_tx()
    with trace.client.batch() as b:
        put_processes_exdi(trace, radix)


@util.dbg.eng_thread
def ghidra_trace_put_regions_exdi() -> None:
    """Read the memory map, if applicable, and write to the trace's Regions."""

    trace, tx = commands.STATE.require_tx()
    with trace.client.batch() as b:
        put_regions_exdi(trace)


@util.dbg.eng_thread
def ghidra_trace_put_kmodules_exdi() -> None:
    """Gather object files, if applicable, and write to the trace's Modules."""

    trace, tx = commands.STATE.require_tx()
    with trace.client.batch() as b:
        put_kmodules_exdi(trace)


@util.dbg.eng_thread
def ghidra_trace_put_threads_exdi(pid: int) -> None:
    """Put the current process's threads into the Ghidra trace."""

    radix = util.get_convenience_variable('output-radix')
    trace, tx = commands.STATE.require_tx()
    with trace.client.batch() as b:
        put_threads_exdi(trace, pid, radix)


@util.dbg.eng_thread
def ghidra_trace_put_all_exdi() -> None:
    """Put everything currently selected into the Ghidra trace."""

    radix = util.get_convenience_variable('output-radix')
    trace, tx = commands.STATE.require_tx()
    with trace.client.batch() as b:
        if util.dbg.use_generics == False:
            put_processes_exdi(trace, radix)
        put_regions_exdi(trace)
        put_kmodules_exdi(trace)


@util.dbg.eng_thread
def put_processes_exdi(trace: Trace, radix: int) -> None:
    radix = util.get_convenience_variable('output-radix')
    keys = []
    result = util.dbg._base.cmd("!process 0 0")
    lines = list(x for x in result.splitlines() if "DeepFreeze" not in x)
    count = int((len(lines)-2)/5)
    for i in range(0, count):
        l1 = lines[i*5+1].strip().split()  # PROCESS
        l2 = lines[i*5+2].strip().split()  # SessionId, Cid, Peb: ParentId
        l3 = lines[i*5+3].strip().split()  # DirBase, ObjectTable, HandleCount
        l4 = lines[i*5+4].strip().split()  # Image
        id = int(l2[3], 16)
        name = l4[1]
        ppath = PROCESS_PATTERN.format(pid=id)
        procobj = trace.create_object(ppath)
        keys.append(PROCESS_KEY_PATTERN.format(pid=id))
        pidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(id)
        procobj.set_value('PID', id)
        procobj.set_value('Name', name)
        procobj.set_value('_display', '[{}] {}'.format(pidstr, name))
        (base, addr) = commands.map_address(int(l1[1], 16))
        procobj.set_value('EPROCESS', addr, schema=sch.ADDRESS)
        (base, addr) = commands.map_address(int(l2[5], 16))
        procobj.set_value('PEB', addr, schema=sch.ADDRESS)
        (base, addr) = commands.map_address(int(l3[1], 16))
        procobj.set_value('DirBase', addr, schema=sch.ADDRESS)
        (base, addr) = commands.map_address(int(l3[3], 16))
        procobj.set_value('ObjectTable', addr, schema=sch.ADDRESS)
        # procobj.set_value('ObjectTable', l3[3])
        tcobj = trace.create_object(ppath+".Threads")
        procobj.insert()
        tcobj.insert()
    trace.proxy_object_path(PROCESSES_PATH).retain_values(keys)


@util.dbg.eng_thread
def put_regions_exdi(trace: Trace) -> None:
    radix = util.get_convenience_variable('output-radix')
    keys = []
    result = util.dbg._base.cmd("!address")
    lines = result.split("\n")
    init = False
    for l in lines:
        if "-------" in l:
            init = True
            continue
        if init == False:
            continue
        fields = l.strip().replace('`', '').split()  # PROCESS
        if len(fields) < 4:
            continue
        start = fields[0]
        # finish = fields[1]
        length = fields[2]
        type = fields[3]
        (sbase, saddr) = commands.map_address(int(start, 16))
        # (fbase, faddr) = commands.map_address(int(finish,16))
        rng = saddr.extend(int(length, 16))
        rpath = REGION_PATTERN.format(start=start)
        keys.append(REGION_KEY_PATTERN.format(start=start))
        regobj = trace.create_object(rpath)
        regobj.set_value('Range', rng, schema=sch.RANGE)
        regobj.set_value('Size', length)
        regobj.set_value('Type', type)
        regobj.set_value('_readable', True)
        regobj.set_value('_writable', True)
        regobj.set_value('_executable', True)
        regobj.set_value('_display', '[{}] {}'.format(
            start, type))
        regobj.insert()
    trace.proxy_object_path(MEMORY_PATH).retain_values(keys)


@util.dbg.eng_thread
def put_kmodules_exdi(trace: Trace) -> None:
    radix = util.get_convenience_variable('output-radix')
    keys = []
    result = util.dbg._base.cmd("lm")
    lines = result.split("\n")
    init = False
    for l in lines:
        if "start" in l:
            continue
        if "Unloaded" in l:
            continue
        fields = l.strip().replace('`', '').split()
        if len(fields) < 3:
            continue
        start = fields[0]
        finish = fields[1]
        name = fields[2]
        sname = name.replace('.sys', '').replace('.dll', '')
        (sbase, saddr) = commands.map_address(int(start, 16))
        (fbase, faddr) = commands.map_address(int(finish, 16))
        sz = faddr.offset - saddr.offset
        rng = saddr.extend(sz)
        mpath = KMODULE_PATTERN.format(modpath=sname)
        keys.append(KMODULE_KEY_PATTERN.format(modpath=sname))
        modobj = trace.create_object(mpath)
        modobj.set_value('Name', name)
        modobj.set_value('Base', saddr, schema=sch.ADDRESS)
        modobj.set_value('Range', rng, schema=sch.RANGE)
        modobj.set_value('Size', hex(sz))
        modobj.insert()
    trace.proxy_object_path(KMODULES_PATH).retain_values(keys)


@util.dbg.eng_thread
def put_threads_exdi(trace: Trace, pid: int, radix: int) -> None:
    radix = util.get_convenience_variable('output-radix')
    pidstr = ('0x{:x}' if radix == 16 else '0{:o}' if radix ==
              8 else '{}').format(pid)
    keys = []
    result = util.dbg._base.cmd("!process "+hex(pid)+" 4")
    lines = result.split("\n")
    for l in lines:
        l = l.strip()
        if "THREAD" not in l:
            continue
        fields = l.split()
        cid = fields[3]  # pid.tid (decimal)
        tid = int(cid.split('.')[1], 16)
        tidstr = ('0x{:x}' if radix ==
                  16 else '0{:o}' if radix == 8 else '{}').format(tid)
        tpath = THREAD_PATTERN.format(pid=pid, tnum=tid)
        tobj = trace.create_object(tpath)
        keys.append(THREAD_KEY_PATTERN.format(tnum=tidstr))
        tobj = trace.create_object(tpath)
        tobj.set_value('PID', pidstr)
        tobj.set_value('TID', tidstr)
        tobj.set_value('_display', '[{}]'.format(tidstr))
        tobj.set_value('ETHREAD', fields[1])
        tobj.set_value('TEB', fields[5])
        tobj.set_value('Win32Thread', fields[7])
        tobj.set_value('State', fields[8])
        tobj.insert()
    trace.proxy_object_path(THREADS_PATTERN.format(
        pid=pidstr)).retain_values(keys)
