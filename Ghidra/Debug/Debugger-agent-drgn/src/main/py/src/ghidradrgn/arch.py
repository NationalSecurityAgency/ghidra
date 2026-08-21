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
from typing import Dict, List, Literal, Optional, Tuple

from ghidratrace.client import Address, RegVal
import drgn

from . import util


# NOTE: This map is derived from the ldefs using a script
language_map: Dict[str, List[str]] = {
    'AARCH64': ['AARCH64:BE:64:v8A', 'AARCH64:LE:64:AppleSilicon', 'AARCH64:LE:64:v8A'],
    'ARM': ['ARM:BE:32:v8', 'ARM:BE:32:v8T', 'ARM:LE:32:v8', 'ARM:LE:32:v8T'],
    'PPC64': ['PowerPC:BE:64:4xx', 'PowerPC:LE:64:4xx'],
    'S390': [],
    'S390X': [],
    'I386': ['x86:LE:32:default'],
    'X86_64': ['x86:LE:64:default'],
    'UNKNOWN': ['DATA:LE:64:default', 'DATA:LE:64:default'],
}

data64_compiler_map: Dict[Optional[str], str] = {
    None: 'pointer64',
}

default_compiler_map: Dict[Optional[str], str] = {
    'Language.C': 'default',
}

x86_compiler_map: Dict[Optional[str], str] = {
    'Language.C': 'gcc',
}

compiler_map: Dict[str, Dict[Optional[str], str]] = {
    'DATA:BE:64:': data64_compiler_map,
    'DATA:LE:64:': data64_compiler_map,
    'x86:LE:32:': x86_compiler_map,
    'x86:LE:64:': x86_compiler_map,
    'AARCH64:LE:64:': default_compiler_map,
    'ARM:BE:32:': default_compiler_map,
    'ARM:LE:32:': default_compiler_map,
    'PowerPC:BE:64:': default_compiler_map,
    'PowerPC:LE:64:': default_compiler_map,
}


def get_arch() -> str:
    platform = drgn.host_platform
    return platform.arch.name


def get_endian() -> Literal['little', 'big']:
    parm = util.get_convenience_variable('endian')
    if parm != 'auto':
        return parm
    platform = drgn.host_platform
    order = platform.flags.IS_LITTLE_ENDIAN
    if order.value > 0:
        return 'little'
    else:
        return 'big'


def get_size() -> str:
    parm = util.get_convenience_variable('size')
    if parm != 'auto':
        return parm
    platform = drgn.host_platform
    order = platform.flags.IS_64_BIT
    if order.value > 0:
        return '64'
    else:
        return '32'


def get_osabi() -> str:
    return "Language.C"


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
    sz = get_size()
    lebe = ':BE:' if endian == 'big' else ':LE:'
    if not arch in language_map:
        return 'DATA' + lebe + sz + ':default'
    langs = language_map[arch]
    matched_endian = sorted(
        (l for l in langs if lebe in l),
        key=lambda l: 0 if l.endswith(':default') else len(l)
    )
    if len(matched_endian) > 0:
        return matched_endian[0]
    # NOTE: I'm disinclined to fall back to a language match with wrong endian.
    return 'DATA' + lebe + sz + ':default'


def compute_ghidra_compiler(lang: str) -> str:
    # First, check if the parameter is set
    comp = util.get_convenience_variable('ghidra-compiler')
    if comp != 'auto':
        return comp

    # Check if the selected lang has specific compiler recommendations
    matched_lang = sorted(
        (l for l in compiler_map if l in lang),
        #        key=lambda l: compiler_map[l]
    )
    if len(matched_lang) == 0:
        print(f"{lang} not found in compiler map - using default compiler")
        return 'default'

    comp_map = compiler_map[matched_lang[0]]
    if comp_map == data64_compiler_map:
        print(f"Using the DATA64 compiler map")
    osabi = get_osabi()
    if osabi in comp_map:
        return comp_map[osabi]
    if lang.startswith("X86:"):
        print(f"{osabi} not found in compiler map - using gcc")
        return 'gcc'
    if None in comp_map:
        return comp_map[None]
    print(f"{osabi} not found in compiler map - using default compiler")
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
        raise ValueError(
            f"Address {address} is not in process {proc}")


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

    def map_name(self, proc: int, name: str) -> str:
        return name

    def map_value(self, proc: int, name: str, value: bytes):
        return RegVal(self.map_name(proc, name), value)

    def map_name_back(self, proc: int, name: str):
        return name

    def map_value_back(self, proc: int, name: str, value: bytes):
        return RegVal(self.map_name_back(proc, name), value)


DEFAULT_BE_REGISTER_MAPPER = DefaultRegisterMapper('big')
DEFAULT_LE_REGISTER_MAPPER = DefaultRegisterMapper('little')


def compute_register_mapper(lang: str) -> DefaultRegisterMapper:
    if ':BE:' in lang:
        return DEFAULT_BE_REGISTER_MAPPER
    else:
        return DEFAULT_LE_REGISTER_MAPPER
