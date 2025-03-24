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
from typing import Dict, List, Optional, Tuple
from ghidratrace.client import Address, RegVal
import lldb

from . import util


# NOTE: This map is derived from the ldefs using a script
language_map: Dict[str, List[str]] = {
    'aarch64': ['AARCH64:BE:64:v8A', 'AARCH64:LE:64:AppleSilicon',
                'AARCH64:LE:64:v8A'],
    'arm': ['ARM:BE:32:v8', 'ARM:BE:32:v8T', 'ARM:LE:32:v8', 'ARM:LE:32:v8T'],
    'armv4': ['ARM:BE:32:v4', 'ARM:LE:32:v4'],
    'armv4t': ['ARM:BE:32:v4t', 'ARM:LE:32:v4t'],
    'armv5': ['ARM:BE:32:v5', 'ARM:LE:32:v5'],
    'armv5e': ['ARM:BE:32:v5t', 'ARM:LE:32:v5t'],
    'armv5t': ['ARM:BE:32:v5t', 'ARM:LE:32:v5t'],
    'armv6': ['ARM:BE:32:v6', 'ARM:LE:32:v6'],
    'armv6m': ['ARM:BE:32:Cortex', 'ARM:LE:32:Cortex'],
    'armv7': ['ARM:BE:32:v7', 'ARM:LE:32:v7'],
    'armv7l': ['ARM:BE:32:v7', 'ARM:LE:32:v7'],
    'armv7f': ['ARM:BE:32:v7', 'ARM:LE:32:v7'],
    'armv7s': ['ARM:BE:32:v7', 'ARM:LE:32:v7'],
    'armv7k': ['ARM:BE:32:v7', 'ARM:LE:32:v7'],
    'armv7m': ['ARM:BE:32:v7', 'ARM:LE:32:v7'],
    'armv7em': ['ARM:BE:32:Cortex', 'ARM:LE:32:Cortex'],
    'xscale': ['ARM:BE:32:v6', 'ARM:LE:32:v6'],
    'thumbv5': ['ARM:BE:32:v5', 'ARM:LE:32:v5'],
    'thumbv5e': ['ARM:BE:32:v5', 'ARM:LE:32:v5'],
    'thumbv6': ['ARM:BE:32:v6', 'ARM:LE:32:v6'],
    'thumbv6m': ['ARM:BE:32:Cortex', 'ARM:LE:32:Cortex'],
    'thumbv7': ['ARM:BE:32:v7', 'ARM:LE:32:v7'],
    'thumbv7f': ['ARM:BE:32:v7', 'ARM:LE:32:v7'],
    'thumbv7s': ['ARM:BE:32:v7', 'ARM:LE:32:v7'],
    'thumbv7k': ['ARM:BE:32:v7', 'ARM:LE:32:v7'],
    'thumbv7m': ['ARM:BE:32:v7', 'ARM:LE:32:v7'],
    'thumbv7em': ['ARM:BE:32:Cortex', 'ARM:LE:32:Cortex'],
    'armv8': ['ARM:BE:32:v8', 'ARM:LE:32:v8'],
    'armv8l': ['ARM:BE:32:v8', 'ARM:LE:32:v8'],
    'arm64': ['AARCH64:BE:64:v8A', 'AARCH64:LE:64:AppleSilicon',
              'AARCH64:LE:64:v8A'],
    'arm64e': ['AARCH64:BE:64:v8A', 'AARCH64:LE:64:AppleSilicon',
               'AARCH64:LE:64:v8A'],
    'arm64_32': ['ARM:BE:32:v8', 'ARM:LE:32:v8'],
    'mips': ['MIPS:BE:32:default', 'MIPS:LE:32:default'],
    'mipsr2': ['MIPS:BE:32:default', 'MIPS:LE:32:default'],
    'mipsr3': ['MIPS:BE:32:default', 'MIPS:LE:32:default'],
    'mipsr5': ['MIPS:BE:32:default', 'MIPS:LE:32:default'],
    'mipsr6': ['MIPS:BE:32:default', 'MIPS:LE:32:default'],
    'mipsel': ['MIPS:BE:32:default', 'MIPS:LE:32:default'],
    'mipsr2el': ['MIPS:BE:32:default', 'MIPS:LE:32:default'],
    'mipsr3el': ['MIPS:BE:32:default', 'MIPS:LE:32:default'],
    'mipsr5el': ['MIPS:BE:32:default', 'MIPS:LE:32:default'],
    'mipsr6el': ['MIPS:BE:32:default', 'MIPS:LE:32:default'],
    'mips64': ['MIPS:BE:3264:default', 'MIPS:LE:64:default'],
    'mips64r2': ['MIPS:BE:64:default', 'MIPS:LE:64:default'],
    'mips64r3': ['MIPS:BE:64:default', 'MIPS:LE:64:default'],
    'mips64r5': ['MIPS:BE:64:default', 'MIPS:LE:64:default'],
    'mips64r6': ['MIPS:BE:64:default', 'MIPS:LE:64:default'],
    'mips64el': ['MIPS:BE:64:default', 'MIPS:LE:64:default'],
    'mips64r2el': ['MIPS:BE:64:default', 'MIPS:LE:64:default'],
    'mips64r3el': ['MIPS:BE:64:default', 'MIPS:LE:64:default'],
    'mips64r5el': ['MIPS:BE:64:default', 'MIPS:LE:64:default'],
    'mips64r6el': ['MIPS:BE:64:default', 'MIPS:LE:64:default'],
    'msp:430X': ['TI_MSP430:LE:16:default'],
    'powerpc': ['PowerPC:BE:32:4xx', 'PowerPC:LE:32:4xx'],
    'ppc601': ['PowerPC:BE:32:4xx', 'PowerPC:LE:32:4xx'],
    'ppc602': ['PowerPC:BE:32:4xx', 'PowerPC:LE:32:4xx'],
    'ppc603': ['PowerPC:BE:32:4xx', 'PowerPC:LE:32:4xx'],
    'ppc603e': ['PowerPC:BE:32:4xx', 'PowerPC:LE:32:4xx'],
    'ppc603ev': ['PowerPC:BE:32:4xx', 'PowerPC:LE:32:4xx'],
    'ppc604': ['PowerPC:BE:32:4xx', 'PowerPC:LE:32:4xx'],
    'ppc604e': ['PowerPC:BE:32:4xx', 'PowerPC:LE:32:4xx'],
    'ppc620': ['PowerPC:BE:32:4xx', 'PowerPC:LE:32:4xx'],
    'ppc750': ['PowerPC:BE:32:4xx', 'PowerPC:LE:32:4xx'],
    'ppc7400': ['PowerPC:BE:32:4xx', 'PowerPC:LE:32:4xx'],
    'ppc7450': ['PowerPC:BE:32:4xx', 'PowerPC:LE:32:4xx'],
    'ppc970': ['PowerPC:BE:32:4xx', 'PowerPC:LE:32:4xx'],
    'powerpc64': ['PowerPC:BE:64:4xx', 'PowerPC:LE:64:4xx'],
    'powerpc64le': ['PowerPC:BE:64:4xx', 'PowerPC:LE:64:4xx'],
    'ppc970-64': ['PowerPC:BE:64:4xx', 'PowerPC:LE:64:4xx'],
    's390x': [],
    'sparc': ['sparc:BE:32:default', 'sparc:BE:64:default'],
    'sparcv9': ['sparc:BE:32:default', 'sparc:BE:64:default'],
    'i386': ['x86:LE:32:default'],
    'i486': ['x86:LE:32:default'],
    'i486sx': ['x86:LE:32:default'],
    'i686': ['x86:LE:64:default'],
    'x86_64': ['x86:LE:64:default'],
    'x86_64h': ['x86:LE:64:default'],
    'hexagon': [],
    'hexagonv4': [],
    'hexagonv5': [],
    'riscv32': ['RISCV:LE:32:RV32G', 'RISCV:LE:32:RV32GC', 'RISCV:LE:32:RV32I',
                'RISCV:LE:32:RV32IC', 'RISCV:LE:32:RV32IMC',
                'RISCV:LE:32:default'],
    'riscv64': ['RISCV:LE:64:RV64G', 'RISCV:LE:64:RV64GC', 'RISCV:LE:64:RV64I',
                'RISCV:LE:64:RV64IC', 'RISCV:LE:64:default'],
    'unknown-mach-32': ['DATA:LE:32:default', 'DATA:LE:32:default'],
    'unknown-mach-64': ['DATA:LE:64:default', 'DATA:LE:64:default'],
    'arc': [],
    'avr': ['avr8:LE:24:xmega'],
    'wasm32': ['x86:LE:32:default'],
}

data64_compiler_map: Dict[Optional[str], str] = {
    None: 'pointer64',
}

x86_compiler_map: Dict[Optional[str], str] = {
    'windows': 'windows',
    'Cygwin': 'windows',
    'linux': 'gcc',
    'default': 'gcc',
    'unknown': 'gcc',
    None: 'gcc',
}

default_compiler_map: Dict[Optional[str], str] = {
    'freebsd': 'gcc',
    'linux': 'gcc',
    'netbsd': 'gcc',
    'ps4': 'gcc',
    'ios': 'gcc',
    'macosx': 'gcc',
    'tvos': 'gcc',
    'watchos': 'gcc',
    'windows': 'windows',
    'Cygwin': 'windows',
    'default': 'default',
    'unknown': 'default',
}

compiler_map: Dict[str, Dict[Optional[str], str]] = {
    'DATA:BE:64:': data64_compiler_map,
    'DATA:LE:64:': data64_compiler_map,
    'x86:LE:32:': x86_compiler_map,
    'x86:LE:64:': x86_compiler_map,
    'ARM:LE:32:': default_compiler_map,
    'ARM:LE:64:': default_compiler_map,
}


def find_host_triple() -> str:
    dbg = util.get_debugger()
    for i in range(dbg.GetNumPlatforms()):
        platform = dbg.GetPlatformAtIndex(i)
        if platform.GetName() == 'host':
            return platform.GetTriple()
    return 'unrecognized'


def find_triple() -> str:
    triple = util.get_target().triple
    if triple is not None:
        return triple
    return find_host_triple()


def get_arch() -> str:
    triple = find_triple()
    return triple.split('-')[0]


def get_endian() -> str:
    parm = util.get_convenience_variable('endian')
    if parm != 'auto':
        return parm
    order = util.get_target().GetByteOrder()
    if order is lldb.eByteOrderLittle:
        return 'little'
    if order is lldb.eByteOrderBig:
        return 'big'
    if order is lldb.eByteOrderPDP:
        return 'pdp'
    return 'unrecognized'


def get_osabi() -> str:
    parm = util.get_convenience_variable('osabi')
    if not parm in ['auto', 'default']:
        return parm
    triple = find_triple()
    # this is an unfortunate feature of the tests
    if triple is None or '-' not in triple:
        return "default"
    triple = find_triple()
    return triple.split('-')[2]


def compute_ghidra_language() -> str:
    # First, check if the parameter is set
    lang = util.get_convenience_variable('ghidra-language')
    if lang != 'auto':
        return lang

    # Get the list of possible languages for the arch. We'll need to sift
    # through them by endian and probably prefer default/simpler variants. The
    # heuristic for "simpler" will be 'default' then shortest variant id.
    arch = get_arch()
    osabi = get_osabi()
    if osabi == 'windows' and arch == 'i386':
        arch = 'x86_64'
    endian = get_endian()
    lebe = ':BE:' if endian == 'big' else ':LE:'
    if not arch in language_map:
        return 'DATA' + lebe + '64:default'
    langs = language_map[arch]
    matched_endian = sorted(
        (l for l in langs if lebe in l),
        key=lambda l: 0 if l.endswith(':default') else len(l)
    )
    if len(matched_endian) > 0:
        return matched_endian[0]
    # NOTE: I'm disinclined to fall back to a language match with wrong endian.
    return 'DATA' + lebe + '64:default'


def compute_ghidra_compiler(lang: str) -> str:
    # First, check if the parameter is set
    comp = util.get_convenience_variable('ghidra-compiler')
    if comp != 'auto':
        return comp

    # Check if the selected lang has specific compiler recommendations
    # NOTE: Unlike other agents, we put prefixes in map keys
    matches = [l for l in compiler_map if lang.startswith(l)]
    if len(matches) == 0:
        print(f"{lang} not found in compiler map - using default compiler")
        return 'default'
    comp_map = compiler_map[matches[0]]
    if comp_map == data64_compiler_map:
        print(f"Using the DATA64 compiler map")
    osabi = get_osabi()
    if osabi in comp_map:
        return comp_map[osabi]
    if None in comp_map:
        def_comp = comp_map[None]
        print(f"{osabi} not found in compiler map - using {def_comp} compiler")
        return def_comp
    print(f"{osabi} not found in compiler map - using default compiler")
    return 'default'


def compute_ghidra_lcsp() -> Tuple[str, str]:
    lang = compute_ghidra_language()
    comp = compute_ghidra_compiler(lang)
    return lang, comp


class DefaultMemoryMapper(object):

    def __init__(self, defaultSpace: str) -> None:
        self.defaultSpace = defaultSpace

    def map(self, proc: lldb.SBProcess, offset: int) -> Tuple[str, Address]:
        space = self.defaultSpace
        return self.defaultSpace, Address(space, offset)

    def map_back(self, proc: lldb.SBProcess, address: Address) -> int:
        if address.space == self.defaultSpace:
            return address.offset
        raise ValueError(
            f"Address {address} is not in process {proc.GetProcessID()}")


DEFAULT_MEMORY_MAPPER = DefaultMemoryMapper('ram')

memory_mappers: Dict[str, DefaultMemoryMapper] = {}


def compute_memory_mapper(lang: str) -> DefaultMemoryMapper:
    if not lang in memory_mappers:
        return DEFAULT_MEMORY_MAPPER
    return memory_mappers[lang]


class DefaultRegisterMapper(object):

    def __init__(self, byte_order: str) -> None:
        if not byte_order in ['big', 'little']:
            raise ValueError("Invalid byte_order: {}".format(byte_order))
        self.byte_order = byte_order

    def map_name(self, proc: lldb.SBProcess, name: str) -> str:
        return name

    def map_value(self, proc: lldb.SBProcess, name: str, value: bytes) -> RegVal:
        return RegVal(self.map_name(proc, name), value)

    def map_name_back(self, proc: lldb.SBProcess, name: str) -> str:
        return name

    def map_value_back(self, proc: lldb.SBProcess, name: str,
                       value: bytes) -> RegVal:
        return RegVal(self.map_name_back(proc, name), value)


class Intel_x86_64_RegisterMapper(DefaultRegisterMapper):

    def __init__(self) -> None:
        super().__init__('little')

    def map_name(self, proc: lldb.SBProcess, name: str) -> str:
        if name is None:
            return 'UNKNOWN'
        if name == 'eflags':
            return 'rflags'
        if name.startswith('zmm'):
            # Ghidra only goes up to ymm, right now
            return 'ymm' + name[3:]
        return super().map_name(proc, name)

    def map_value(self, proc: lldb.SBProcess, name: str, value: bytes) -> RegVal:
        rv = super().map_value(proc, name, value)
        if rv.name.startswith('ymm') and len(rv.value) > 32:
            return RegVal(rv.name, rv.value[-32:])
        return rv

    def map_name_back(self, proc: lldb.SBProcess, name: str) -> str:
        if name == 'rflags':
            return 'eflags'
        return super().map_name_back(proc, name)


DEFAULT_BE_REGISTER_MAPPER = DefaultRegisterMapper('big')
DEFAULT_LE_REGISTER_MAPPER = DefaultRegisterMapper('little')

register_mappers: Dict[str, DefaultRegisterMapper] = {
    'x86:LE:64:default': Intel_x86_64_RegisterMapper()
}


def compute_register_mapper(lang: str) -> DefaultRegisterMapper:
    if not lang in register_mappers:
        if ':BE:' in lang:
            return DEFAULT_BE_REGISTER_MAPPER
        if ':LE:' in lang:
            return DEFAULT_LE_REGISTER_MAPPER
    return register_mappers[lang]
