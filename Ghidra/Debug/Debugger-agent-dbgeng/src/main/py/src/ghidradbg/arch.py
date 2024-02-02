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
from ghidratrace.client import Address, RegVal

from pybag import pydbg

from . import util

language_map = {
    'ARM': ['AARCH64:BE:64:v8A', 'AARCH64:LE:64:AppleSilicon', 'AARCH64:LE:64:v8A', 'ARM:BE:64:v8', 'ARM:LE:64:v8'],
    'Itanium': [],
    'x86': ['x86:LE:32:default'],
    'x86_64': ['x86:LE:64:default'],
    'EFI': ['x86:LE:64:default'],
}

data64_compiler_map = {
    None: 'pointer64',
}

x86_compiler_map = {
    'windows': 'windows',
    'Cygwin': 'windows',
}

arm_compiler_map = {
    'windows': 'windows',
}

compiler_map = {
    'DATA:BE:64:default': data64_compiler_map,
    'DATA:LE:64:default': data64_compiler_map,
    'x86:LE:32:default': x86_compiler_map,
    'x86:LE:64:default': x86_compiler_map,
    'AARCH64:BE:64:v8A': arm_compiler_map,
    'AARCH64:LE:64:AppleSilicon': arm_compiler_map,
    'AARCH64:LE:64:v8A': arm_compiler_map,
    'ARM:BE:64:v8': arm_compiler_map,
    'ARM:LE:64:v8': arm_compiler_map,
}


def get_arch():
    try:
        type = util.dbg.get_actual_processor_type()
    except Exception:
        print("Error getting actual processor type.")
        return "Unknown"
    if type is None:
        return "x86_64"
    if type == 0x8664:
        return "x86_64"
    if type == 0x014c:
        return "x86"
    if type == 0x01c0:
        return "ARM"
    if type == 0x0200:
        return "Itanium"
    if type == 0x0EBC:
        return "EFI"
    return "Unknown"


def get_endian():
    parm = util.get_convenience_variable('endian')
    if parm != 'auto':
        return parm
    return 'little'


def get_osabi():
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


def compute_ghidra_language():
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


def compute_ghidra_compiler(lang):
    # First, check if the parameter is set
    comp = util.get_convenience_variable('ghidra-compiler')
    if comp != 'auto':
        return comp

    # Check if the selected lang has specific compiler recommendations
    if not lang in compiler_map:
        return 'default'
    comp_map = compiler_map[lang]
    osabi = get_osabi()
    if osabi in comp_map:
        return comp_map[osabi]
    if None in comp_map:
        return comp_map[None]
    return 'default'


def compute_ghidra_lcsp():
    lang = compute_ghidra_language()
    comp = compute_ghidra_compiler(lang)
    return lang, comp


class DefaultMemoryMapper(object):

    def __init__(self, defaultSpace):
        self.defaultSpace = defaultSpace

    def map(self, proc: int, offset: int):
        space = self.defaultSpace
        return self.defaultSpace, Address(space, offset)

    def map_back(self, proc: int, address: Address) -> int:
        if address.space == self.defaultSpace:
            return address.offset
        raise ValueError(
            f"Address {address} is not in process {proc.GetProcessID()}")


DEFAULT_MEMORY_MAPPER = DefaultMemoryMapper('ram')

memory_mappers = {}


def compute_memory_mapper(lang):
    if not lang in memory_mappers:
        return DEFAULT_MEMORY_MAPPER
    return memory_mappers[lang]


class DefaultRegisterMapper(object):

    def __init__(self, byte_order):
        if not byte_order in ['big', 'little']:
            raise ValueError("Invalid byte_order: {}".format(byte_order))
        self.byte_order = byte_order
        self.union_winners = {}

    def map_name(self, proc, name):
        return name

    def map_value(self, proc, name, value):
        try:
            # TODO: this seems half-baked
            av = value.to_bytes(8, "big")
        except Exception:
            raise ValueError("Cannot convert {}'s value: '{}', type: '{}'"
                             .format(name, value, type(value)))
        return RegVal(self.map_name(proc, name), av)

    def map_name_back(self, proc, name):
        return name

    def map_value_back(self, proc, name, value):
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


def compute_register_mapper(lang):
    if not lang in register_mappers:
        if ':BE:' in lang:
            return DEFAULT_BE_REGISTER_MAPPER
        if ':LE:' in lang:
            return DEFAULT_LE_REGISTER_MAPPER
    return register_mappers[lang]
