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

import lldb

from . import util

# NOTE: This map is derived from the ldefs using a script
language_map = {
    'aarch64': ['AARCH64:BE:64:v8A', 'AARCH64:LE:64:AppleSilicon', 'AARCH64:LE:64:v8A'],
    'armv7': ['ARM:BE:32:v7', 'ARM:LE:32:v7'],
    'armv7k': ['ARM:BE:32:v7', 'ARM:LE:32:v7'],
    'armv7s': ['ARM:BE:32:v7', 'ARM:LE:32:v7'],
    'arm64': ['ARM:BE:64:v8', 'ARM:LE:64:v8'],
    'arm64_32': ['ARM:BE:32:v8', 'ARM:LE:32:v8'],
    'arm64e': ['ARM:BE:64:v8', 'ARM:LE:64:v8'],
    'i386': ['x86:LE:32:default'],
    'thumbv7': ['ARM:BE:32:v7', 'ARM:LE:32:v7'],
    'thumbv7k': ['ARM:BE:32:v7', 'ARM:LE:32:v7'],
    'thumbv7s': ['ARM:BE:32:v7', 'ARM:LE:32:v7'],
    'x86_64': ['x86:LE:64:default'],
    'wasm32': ['x86:LE:64:default'],
}

data64_compiler_map = {
    None: 'pointer64',
}

x86_compiler_map = {
    'freebsd': 'gcc',
    'linux': 'gcc',
    'netbsd': 'gcc',
    'ps4': 'gcc',
    'ios': 'clang',
    'macosx': 'clang',
    'tvos': 'clang',
    'watchos': 'clang',
    'windows': 'Visual Studio',
    # This may seem wrong, but Ghidra cspecs really describe the ABI
    'Cygwin': 'Visual Studio',
}

compiler_map = {
    'DATA:BE:64:default': data64_compiler_map,
    'DATA:LE:64:default': data64_compiler_map,
    'x86:LE:32:default': x86_compiler_map,
    'x86:LE:64:default': x86_compiler_map,
}


def get_arch():
    triple = util.get_target().triple
    if triple is None:
        return "x86_64"
    return triple.split('-')[0]


def get_endian():
    parm = util.get_convenience_variable('endian')
    if parm != 'auto':
        return parm
    # Once again, we have to hack using the human-readable 'show'
    order = util.get_target().GetByteOrder()
    if order is lldb.eByteOrderLittle:
        return 'little'
    if order is lldb.eByteOrderBig:
        return 'big'
    if order is lldb.eByteOrderPDP:
        return 'pdp'
    return 'unrecognized'


def get_osabi():
    parm = util.get_convenience_variable('osabi')
    if not parm in ['auto', 'default']:
        return parm
    # We have to hack around the fact the LLDB won't give us the current OS ABI
    # via the API if it is "auto" or "default". Using "show", we can get it, but
    # we have to parse output meant for a human. The current value will be on
    # the top line, delimited by double quotes. It will be the last delimited
    # thing on that line. ("auto" may appear earlier on the line.)
    triple = util.get_target().triple
    # this is an unfortunate feature of the tests
    if triple is None:
        return "linux"
    return triple.split('-')[2]


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

    def map(self, proc: lldb.SBProcess, offset: int):
        space = self.defaultSpace
        return self.defaultSpace, Address(space, offset)

    def map_back(self, proc: lldb.SBProcess, address: Address) -> int:
        if address.space == self.defaultSpace:
            return address.offset
        raise ValueError(f"Address {address} is not in process {proc.GetProcessID()}")


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

    """
    def convert_value(self, value, type=None):
        if type is None:
            type = value.dynamic_type.strip_typedefs()
        l = type.sizeof
        # l - 1 because array() takes the max index, inclusive
        # NOTE: Might like to pre-lookup 'unsigned char', but it depends on the
        # architecture *at the time of lookup*.
        cv = value.cast(lldb.lookup_type('unsigned char').array(l - 1))
        rng = range(l)
        if self.byte_order == 'little':
            rng = reversed(rng)
        return bytes(cv[i] for i in rng)
    """

    def map_value(self, proc, name, value):
        try:
            ### TODO: this seems half-baked
            av = value.to_bytes(8, "big")
        except e:
            raise ValueError("Cannot convert {}'s value: '{}', type: '{}'"
                               .format(name, value, value.type))
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
        if name == 'eflags':
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
    
