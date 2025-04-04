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
from pybag import pydbg # type: ignore

from . import util


language_map: Dict[str, List[str]] = {
    'AARCH64': ['AARCH64:LE:64:AppleSilicon'],
    'ARM': ['ARM:LE:32:v8'],
    'Itanium': [],
    'x86': ['x86:LE:32:default'],
    'x86_64': ['x86:LE:64:default'],
    'EFI': ['x86:LE:64:default'],
    'MIPS': ['MIPS:LE:64:default'],
    'MIPS-BE': ['MIPS:BE:64:default'],
    'SH4': ['SuperH4:LE:32:default'],
}

data64_compiler_map: Dict[Optional[str], str] = {
    None: 'pointer64',
}

x86_compiler_map: Dict[Optional[str], str] = {
    'windows': 'windows',
    'Cygwin': 'windows',
    'default': 'windows',
}

default_compiler_map: Dict[Optional[str], str] = {
    'windows': 'default',
}

windows_compiler_map: Dict[Optional[str], str] = {
    'windows': 'windows',
}

compiler_map : Dict[str, Dict[Optional[str], str]]= {
    'DATA:BE:64:default': data64_compiler_map,
    'DATA:LE:64:default': data64_compiler_map,
    'x86:LE:32:default': x86_compiler_map,
    'x86:LE:64:default': x86_compiler_map,
    'AARCH64:LE:64:AppleSilicon': default_compiler_map,
    'ARM:LE:32:v8': windows_compiler_map,
    'MIPS:BE:64:default': default_compiler_map,
    'MIPS:LE:64:default': windows_compiler_map,
    'SuperH4:LE:32:default': windows_compiler_map,
}


def get_arch() -> str:
    try:
        type = util.dbg.get_actual_processor_type()
    except Exception as e:
        print(f"Error getting actual processor type: {e}")
        return "Unknown"
    if type is None:
        return "x86_64"
    if type == 0x8664:
        return "x86_64"
    if type == 0xAA64:
        return "AARCH64"
    if type == 0x014c:
        return "x86"
    if type == 0x0160:  # R3000 BE
        return "MIPS-BE"
    if type == 0x0162:  # R3000 LE
        return "MIPS"
    if type == 0x0166:  # R4000 LE
        return "MIPS"
    if type == 0x0168:  # R10000 LE
        return "MIPS"
    if type == 0x0169:  # WCE v2 LE
        return "MIPS"
    if type == 0x0266:  # MIPS 16
        return "MIPS"
    if type == 0x0366:  # MIPS FPU
        return "MIPS"
    if type == 0x0466:  # MIPS FPU16
        return "MIPS"
    if type == 0x0184:  # Alpha AXP
        return "Alpha"
    if type == 0x0284:  # Aplha 64
        return "Alpha"
    if type >= 0x01a2 and type < 0x01a6:
        return "SH"
    if type == 0x01a6:
        return "SH4"
    if type == 0x01a6:
        return "SH5"
    if type == 0x01c0:  # ARM LE
        return "ARM"
    if type == 0x01c2:  # ARM Thumb/Thumb-2 LE
        return "ARM"
    if type == 0x01c4:  # ARM Thumb-2 LE
        return "ARM"
    if type == 0x01d3:  # AM33
        return "ARM"
    if type == 0x01f0 or type == 0x1f1:  # PPC
        return "PPC"
    if type == 0x0200:
        return "Itanium"
    if type == 0x0520:
        return "Infineon"
    if type == 0x0CEF:
        return "CEF"
    if type == 0x0EBC:
        return "EFI"
    if type == 0x8664:  # AMD64 (K8)
        return "x86_64"
    if type == 0x9041:  # M32R
        return "M32R"
    if type == 0xC0EE:
        return "CEE"
    return "Unknown"


def get_endian() -> str:
    parm = util.get_convenience_variable('endian')
    if parm != 'auto':
        return parm
    return 'little'


def get_osabi() -> str:
    parm = util.get_convenience_variable('osabi')
    if not parm in ['auto', 'default']:
        return parm
    try:
        os = util.dbg.cmd("vertarget")
        if "Windows" not in os:
            return "default"
    except Exception:
        print("Error getting target OS/ABI")
        pass
    return "windows"


def compute_ghidra_language() -> str:
    # First, check if the parameter is set
    lang = util.get_convenience_variable('ghidra-language')
    if lang != 'auto':
        return lang

    # Get the list of possible languages for the arch. We'll need to sift
    # through them by endian and probably prefer default/simpler variants. The
    # heuristic for "simpler" will be 'default' then shortest variant id.
    arch = get_arch()
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
    if not lang in compiler_map:
        print(f"{lang} not found in compiler map")
        return 'default'
    comp_map = compiler_map[lang]
    if comp_map == data64_compiler_map:
        print(f"Using the DATA64 compiler map")
    osabi = get_osabi()
    if osabi in comp_map:
        return comp_map[osabi]
    if None in comp_map:
        return comp_map[None]
    print(f"{osabi} not found in compiler map")
    return 'default'


def compute_ghidra_lcsp() -> Tuple[str, str]:
    lang = compute_ghidra_language()
    comp = compute_ghidra_compiler(lang)
    return lang, comp


class DefaultMemoryMapper(object):

    def __init__(self, defaultSpace: str) -> None:
        self.defaultSpace = defaultSpace

    def map(self, proc: int, offset: int) -> Tuple[str, Address]:
        space = self.defaultSpace
        return self.defaultSpace, Address(space, offset)

    def map_back(self, proc: int, address: Address) -> int:
        if address.space == self.defaultSpace:
            return address.offset
        raise ValueError(f"Address {address} is not in process {proc}")


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

    def map_name(self, proc: int, name: str):
        return name

    def map_value(self, proc: int, name: str, value: int):
        try:
            # TODO: this seems half-baked
            av = value.to_bytes(8, "big")
        except Exception:
            raise ValueError("Cannot convert {}'s value: '{}', type: '{}'"
                             .format(name, value, type(value)))
        return RegVal(self.map_name(proc, name), av)

    def map_name_back(self, proc: int, name: str) -> str:
        return name

    def map_value_back(self, proc: int, name: str, value: bytes):
        return RegVal(self.map_name_back(proc, name), value)


class Intel_x86_64_RegisterMapper(DefaultRegisterMapper):

    def __init__(self):
        super().__init__('little')

    def map_name(self, proc, name):
        if name is None:
            return 'UNKNOWN'
        if name == 'efl':
            return 'rflags'
        if name.startswith('zmm'):
            # Ghidra only goes up to ymm, right now
            return 'ymm' + name[3:]
        return super().map_name(proc, name)

    def map_value(self, proc, name, value):
        rv = super().map_value(proc, name, value)
        if rv.name.startswith('ymm') and len(rv.value) > 32:
            return RegVal(rv.name, rv.value[-32:])
        return rv

    def map_name_back(self, proc, name):
        if name == 'rflags':
            return 'eflags'


DEFAULT_BE_REGISTER_MAPPER = DefaultRegisterMapper('big')
DEFAULT_LE_REGISTER_MAPPER = DefaultRegisterMapper('little')

register_mappers = {
    'x86:LE:64:default': Intel_x86_64_RegisterMapper()
}


def compute_register_mapper(lang: str)-> DefaultRegisterMapper:
    if not lang in register_mappers:
        if ':BE:' in lang:
            return DEFAULT_BE_REGISTER_MAPPER
        if ':LE:' in lang:
            return DEFAULT_LE_REGISTER_MAPPER
    return register_mappers[lang]
