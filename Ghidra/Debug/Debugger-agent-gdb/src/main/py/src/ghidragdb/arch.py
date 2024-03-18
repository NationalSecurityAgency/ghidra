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

import gdb

# NOTE: This map is derived from the ldefs using a script
# i386 is hand-patched
language_map = {
    'aarch64': ['AARCH64:BE:64:v8A', 'AARCH64:LE:64:AppleSilicon', 'AARCH64:LE:64:v8A'],
    'aarch64:ilp32': ['AARCH64:BE:32:ilp32', 'AARCH64:LE:32:ilp32', 'AARCH64:LE:64:AppleSilicon'],
    'arm_any': ['ARM:BE:32:v8', 'ARM:BE:32:v8T', 'ARM:LE:32:v8', 'ARM:LE:32:v8T'],
    'armv2': ['ARM:BE:32:v4', 'ARM:LE:32:v4'],
    'armv2a': ['ARM:BE:32:v4', 'ARM:LE:32:v4'],
    'armv3': ['ARM:BE:32:v4', 'ARM:LE:32:v4'],
    'armv3m': ['ARM:BE:32:v4', 'ARM:LE:32:v4'],
    'armv4': ['ARM:BE:32:v4', 'ARM:LE:32:v4'],
    'armv4t': ['ARM:BE:32:v4t', 'ARM:LE:32:v4t'],
    'armv5': ['ARM:BE:32:v5', 'ARM:LE:32:v5'],
    'armv5t': ['ARM:BE:32:v5t', 'ARM:LE:32:v5t'],
    'armv5tej': ['ARM:BE:32:v5t', 'ARM:LE:32:v5t'],
    'armv6': ['ARM:BE:32:v6', 'ARM:LE:32:v6'],
    'armv6-m': ['ARM:BE:32:Cortex', 'ARM:LE:32:Cortex'],
    'armv6k': ['ARM:BE:32:Cortex', 'ARM:LE:32:Cortex'],
    'armv6kz': ['ARM:BE:32:Cortex', 'ARM:LE:32:Cortex'],
    'armv6s-m': ['ARM:BE:32:Cortex', 'ARM:LE:32:Cortex'],
    'armv7': ['ARM:BE:32:v7', 'ARM:LE:32:v7'],
    'armv7e-m': ['ARM:LE:32:Cortex'],
    'armv8-a': ['ARM:BE:32:v8', 'ARM:LE:32:v8'],
    'armv8-m.base': ['ARM:BE:32:v8', 'ARM:LE:32:v8'],
    'armv8-m.main': ['ARM:BE:32:v8', 'ARM:LE:32:v8'],
    'armv8-r': ['ARM:BE:32:v8', 'ARM:LE:32:v8'],
    'armv8.1-m.main': ['ARM:BE:32:v8', 'ARM:LE:32:v8'],
    'avr:107': ['avr8:LE:24:xmega'],
    'avr:31': ['avr8:LE:16:default'],
    'avr:51': ['avr8:LE:16:atmega256'],
    'avr:6': ['avr8:LE:16:atmega256'],
    'hppa2.0w': ['pa-risc:BE:32:default'],
    'i386': ['x86:LE:32:default'],
    'i386:intel': ['x86:LE:32:default'],
    'i386:x86-64': ['x86:LE:64:default'],
    'i386:x86-64:intel': ['x86:LE:64:default'],
    'i8086': ['x86:LE:16:Protected Mode', 'x86:LE:16:Real Mode'],
    'iwmmxt': ['ARM:BE:32:v7', 'ARM:BE:32:v8', 'ARM:BE:32:v8T', 'ARM:LE:32:v7', 'ARM:LE:32:v8', 'ARM:LE:32:v8T'],
    'm68hc12': ['HC-12:BE:16:default'],
    'm68k': ['68000:BE:32:default'],
    'm68k:68020': ['68000:BE:32:MC68020'],
    'm68k:68030': ['68000:BE:32:MC68030'],
    'm9s12x': ['HCS-12:BE:24:default', 'HCS-12X:BE:24:default'],
    'mips:4000': ['MIPS:BE:32:default', 'MIPS:LE:32:default'],
    'mips:5000': ['MIPS:BE:64:64-32addr', 'MIPS:BE:64:default', 'MIPS:LE:64:64-32addr', 'MIPS:LE:64:default'],
    'mips:micromips': ['MIPS:BE:32:micro'],
    'msp:430X': ['TI_MSP430:LE:16:default'],
    'powerpc:403': ['PowerPC:BE:32:4xx', 'PowerPC:LE:32:4xx'],
    'powerpc:MPC8XX': ['PowerPC:BE:32:MPC8270', 'PowerPC:BE:32:QUICC', 'PowerPC:LE:32:QUICC'],
    'powerpc:common': ['PowerPC:BE:32:default', 'PowerPC:LE:32:default'],
    'powerpc:common64': ['PowerPC:BE:64:64-32addr', 'PowerPC:BE:64:default', 'PowerPC:LE:64:64-32addr', 'PowerPC:LE:64:default'],
    'powerpc:e500': ['PowerPC:BE:32:e500', 'PowerPC:LE:32:e500'],
    'powerpc:e500mc': ['PowerPC:BE:64:A2ALT', 'PowerPC:LE:64:A2ALT'],
    'powerpc:e500mc64': ['PowerPC:BE:64:A2-32addr', 'PowerPC:BE:64:A2ALT-32addr', 'PowerPC:LE:64:A2-32addr', 'PowerPC:LE:64:A2ALT-32addr'],
    'riscv:rv32': ['RISCV:LE:32:RV32G', 'RISCV:LE:32:RV32GC', 'RISCV:LE:32:RV32I', 'RISCV:LE:32:RV32IC', 'RISCV:LE:32:RV32IMC', 'RISCV:LE:32:default'],
    'riscv:rv64': ['RISCV:LE:64:RV64G', 'RISCV:LE:64:RV64GC', 'RISCV:LE:64:RV64I', 'RISCV:LE:64:RV64IC', 'RISCV:LE:64:default'],
    'sh4': ['SuperH4:BE:32:default', 'SuperH4:LE:32:default'],
    'sparc:v9b': ['sparc:BE:32:default', 'sparc:BE:64:default'],
    'xscale': ['ARM:BE:32:v6', 'ARM:LE:32:v6'],
    'z80': ['z80:LE:16:default', 'z8401x:LE:16:default']
}

data64_compiler_map = {
    None: 'pointer64',
}

x86_compiler_map = {
    'GNU/Linux': 'gcc',
    'Windows': 'Visual Studio',
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
    return gdb.selected_inferior().architecture().name()


def get_endian():
    parm = gdb.parameter('endian')
    if parm != 'auto':
        return parm
    # Once again, we have to hack using the human-readable 'show'
    show = gdb.execute('show endian', to_string=True)
    if 'little' in show:
        return 'little'
    if 'big' in show:
        return 'big'
    return 'unrecognized'


def get_osabi():
    parm = gdb.parameter('osabi')
    if not parm in ['', 'auto', 'default']:
        return parm
    # We have to hack around the fact the GDB won't give us the current OS ABI
    # via the API if it is "auto" or "default". Using "show", we can get it, but
    # we have to parse output meant for a human. The current value will be on
    # the top line, delimited by double quotes. It will be the last delimited
    # thing on that line. ("auto" may appear earlier on the line.)
    show = gdb.execute('show osabi', to_string=True)
    line = show.split('\n')[0]
    return line.split('"')[-2]


def compute_ghidra_language():
    # First, check if the parameter is set
    lang = gdb.parameter('ghidra-language')
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
    comp = gdb.parameter('ghidra-compiler')
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

    def map(self, inf: gdb.Inferior, offset: int):
        if inf.num == 1:
            space = self.defaultSpace
        else:
            space = f'{self.defaultSpace}{inf.num}'
        return self.defaultSpace, Address(space, offset)

    def map_back(self, inf: gdb.Inferior, address: Address) -> int:
        if address.space == self.defaultSpace and inf.num == 1:
            return address.offset
        if address.space == f'{self.defaultSpace}{inf.num}':
            return address.offset
        raise ValueError(f"Address {address} is not in inferior {inf.num}")


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

    def map_name(self, inf, name):
        return name

    def convert_value(self, value, type=None):
        if type is None:
            type = value.dynamic_type.strip_typedefs()
        l = type.sizeof
        # l - 1 because array() takes the max index, inclusive
        # NOTE: Might like to pre-lookup 'unsigned char', but it depends on the
        # architecture *at the time of lookup*.
        cv = value.cast(gdb.lookup_type('unsigned char').array(l - 1))
        rng = range(l)
        if self.byte_order == 'little':
            rng = reversed(rng)
        return bytes(cv[i] for i in rng)

    def map_value(self, inf, name, value):
        try:
            av = self.convert_value(value)
        except gdb.error as e:
            raise gdb.GdbError("Cannot convert {}'s value: '{}', type: '{}'"
                               .format(name, value, value.type))
        return RegVal(self.map_name(inf, name), av)

    def convert_value_back(self, value, size=None):
        if size is not None:
            value = value[-size:].rjust(size, b'\0')
        if self.byte_order == 'little':
            value = bytes(reversed(value))
        return value

    def map_name_back(self, inf, name):
        return name

    def map_value_back(self, inf, name, value):
        return RegVal(self.map_name_back(inf, name), self.convert_value_back(value))


class Intel_x86_64_RegisterMapper(DefaultRegisterMapper):

    def __init__(self):
        super().__init__('little')

    def map_name(self, inf, name):
        if name == 'eflags':
            return 'rflags'
        if name.startswith('zmm'):
            # Ghidra only goes up to ymm, right now
            return 'ymm' + name[3:]
        return super().map_name(inf, name)

    def map_value(self, inf, name, value):
        rv = super().map_value(inf, name, value)
        if rv.name.startswith('ymm') and len(rv.value) > 32:
            return RegVal(rv.name, rv.value[-32:])
        return rv

    def map_name_back(self, inf, name):
        if name == 'rflags':
            return 'eflags'
        return name


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
