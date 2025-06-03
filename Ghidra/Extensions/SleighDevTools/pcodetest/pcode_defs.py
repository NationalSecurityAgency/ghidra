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
# The available pcode tests are recorded here as instances of the 'name'
# python class.
from pcodetest import PCodeTest

PCodeTest({
    'name': 'ARM',
    'build_all': 1,
    'build_exe': 1,
    'qemu_command': 'qemu-arm',
    'toolchain': 'ARM/arm-eabi',
    'language_id': 'ARM:LE:32:v7',
    'cclibs': '-lgcc',
    'proc_test': 'arm',
})

PCodeTest({
    'name': 'ARM_BE',
    'build_all': 1,
    'build_exe': 1,
    'qemu_command': 'qemu-armbe',
    'toolchain': 'ARM/armbe-eabi',
    'language_id': 'ARM:BE:32:v7',
    'ccflags': '-mbig-endian',
    'cclibs': '-lgcc',
    'proc_test': 'arm',
    'has_float': 0,
    'has_double': 0,
    'has_longlong': 0,
})


PCodeTest({
    'name': 'ARM2',
    'toolchain': 'ARM/arm-eabi',
    'ccflags': '-mcpu=arm2',
    'cclibs': '-lgcc',
    'language_id': 'ARM:LE:32:v7',
    'proc_test': 'arm',
})

PCodeTest({
    'name': 'ARMv5',
    'build_all': 1,
    'build_exe': 1,
    'qemu_command': 'qemu-arm',
    'toolchain': 'ARM/arm-eabi',
    'language_id': 'ARM:LE:32:v5',
    'gcc_version': '7.3.0',
    'ccflags': '-march=armv5',
    'cclibs': '-lgcc',
})

PCodeTest({
    'name': 'ARMv6',
    'build_all': 1,
    'build_exe': 1,
    'qemu_command': 'qemu-arm',
    'toolchain': 'ARM/arm-eabi',
    'language_id': 'ARM:LE:32:v6',
    'ccflags': '-march=armv6+fp',
    'cclibs': '-lgcc',
})

PCodeTest({
    'name': 'ARM7',
    'toolchain': 'ARM/arm-eabi',
    'ccflags': '-march=armv7-a+simd',
    'cclibs': '-lgcc',
    'language_id': 'ARM:LE:32:v7',
    'proc_test': 'arm',
})

PCodeTest({
    'name': 'ARM8',
    'toolchain': 'ARM/arm-eabi',
    'ccflags': '-mcpu=arm8',
    'cclibs': '-lgcc',
    'language_id': 'ARM:LE:32:v7',
    'proc_test': 'arm',
})

PCodeTest({
    'name': 'ARM9',
    'toolchain': 'ARM/arm-eabi',
    'ccflags': '-mcpu=arm9',
    'cclibs': '-lgcc',
    'language_id': 'ARM:LE:32:v7',
    'proc_test': 'arm',
})

PCodeTest({
    'name': 'ARM10e',
    'build_all': 1,
    'build_exe': 1,
    'qemu_command': 'qemu-arm',
    'toolchain': 'ARM/arm-eabi',
    'ccflags': '-mcpu=arm10e',
    'cclibs': '-lgcc',
    'language_id': 'ARM:LE:32:v7',
    'proc_test': 'arm',
})

PCodeTest({
    'name': 'ARM_thumb',
    'build_all': 1,
    'build_exe': 1,
    'qemu_command': 'qemu-arm -cpu cortex-a8',
    'toolchain': 'ARM/arm-eabi',
    'ccflags': '-mthumb -DTHUMB -march=armv7-a+simd',
    'gcc_libdir': '%(toolchain_dir)s/lib/gcc/arm-eabi/%(gcc_version)s/thumb',
    'cclibs': '-lgcc',
    'language_id': 'ARM:LE:32:v7',
    'proc_test': 'arm',
})

PCodeTest({
    'name': 'ARM_BE_thumb',
    'build_all': 1,
    'toolchain': 'ARM/armbe-eabi',
    'ccflags': '-mthumb -DTHUMB -mbig-endian',
    'gcc_libdir': '%(toolchain_dir)s/lib/gcc/arm-eabi/%(gcc_version)s/thumb',
    'cclibs': '-lgcc',
    'language_id': 'ARM:BE:32:v7',
    'proc_test': 'arm',
    'has_float': 0,
    'has_double': 0,
    'has_longlong': 0,
})

PCodeTest({
    'name': 'ARM_cortex',
    'build_all': 1,
    'build_exe': 1,
    'qemu_command': 'qemu-arm -cpu cortex-a8',
    'toolchain': 'ARM/arm-eabi',
    'ccflags': '-mthumb -DTHUMB -mcpu=cortex-a8 -mfloat-abi=softfp',
    'gcc_libdir': '%(toolchain_dir)s/lib/gcc/arm-eabi/%(gcc_version)s/thumb',
    'cclibs': '-lgcc',
    'language_id': 'ARM:LE:32:v7',
    'proc_test': 'arm',
})

PCodeTest({
    'name': 'ARM_v8m',
    'build_all': 1,
    'build_exe': 1,
    'qemu_command': 'qemu-arm -cpu cortex-m33',
    'toolchain': 'ARM/arm-eabi',
    'ccflags': '-mthumb -DTHUMB -march=armv8-m.main -mfloat-abi=softfp',
    'gcc_libdir': '%(toolchain_dir)s/lib/gcc/arm-eabi/%(gcc_version)s/thumb',
    'cclibs': '-lgcc',
    'language_id': 'ARM:LE:32:Cortexv8m',
})

PCodeTest({
    'name': 'AARCH64',
    'build_all': 1,
    'build_exe': 1,
    'qemu_command': 'qemu-aarch64',
    'toolchain': 'ARM/aarch64-elf',
    'language_id': 'AARCH64:LE:64:v8A',
})

PCodeTest({
    'name': 'AARCH64_ILP32',
    'toolchain': 'ARM/aarch64-elf',
    'ccflags': '-mabi=ilp32',
    'language_id': 'AARCH64:LE:64:v8A',
})

PCodeTest({
    'name': 'AARCH64_BE',
    'build_all': 1,
    'toolchain': 'ARM/aarch64_be-elf',
    'language_id': 'AARCH64:BE:64:v8A',
})

PCodeTest({
    'name': 'AARCH64_BE_ILP32',
    'toolchain': 'ARM/aarch64_be-elf',
    'ccflags': '-mabi=ilp32',
    'language_id': 'AARCH64:BE:64:v8A',
})

PCodeTest({
    'name': 'AVR',
    'build_all': 1,
    'toolchain': 'AVR/avr-elf',
    'ccflags': '-mmcu=avr6 -lgcc',
    'cclibs': '-lgcc',
    'language_id': 'avr32:BE:32:default',
    'processor': 'Atmel',
    'has_float': 0,
    'has_double': 0,
})

PCodeTest({
    'name': 'AVR8_31',
    'toolchain': 'AVR/avr-elf',
    'ccflags': '-mmcu=avr31 -lgcc',
    'cclibs': '-lgcc',
    'language_id': 'avr8:LE:16:default',
    'has_float': 0,
    'has_double': 0,
    'has_longlong': 0,
    'small_build': 1,
})

PCodeTest({
    'name': 'AVR8_51',
    'toolchain': 'AVR/avr-elf',
    'ccflags': '-mmcu=avr51 -lgcc',
    'language_id': 'avr8:LE:16:extended',
    'has_float': 0,
    'has_double': 0,
    'has_longlong': 0,
    'small_build': 1,
})

PCodeTest({
    'name': 'AVR8_6',
    'toolchain': 'AVR/avr-elf',
    'ccflags': '-mmcu=avr6 -lgcc',
    'cclibs': '-lgcc',
    'language_id': 'avr8:LE:16:atmega256',
    'has_float': 0,
    'has_double': 0,
    'has_longlong': 0,
    'small_build': 1,
})

PCodeTest({
    'name': 'HCS12',
    'toolchain': 'HCS12/m6812',
    'language_id': 'HCS12:BE:16:default',
})

PCodeTest({
    'name': 'HPPA1.1',
    'build_all': 1,
    'toolchain': 'HPPA/hppa-linux',
    'ccflags': '-march=1.1 -static -mlong-calls',
    'cclibs': '-lgcc',
    'language_id': 'pa-risc:BE:32:default',
    'processor': 'PA-RISC',
    'architecture_test': 'PARISC',
})

PCodeTest({
    'name': 'HPPA2.0',
    'build_all': 1,
    'toolchain': 'HPPA/hppa-linux',
    'ccflags': '-march=2.0 -static -mlong-calls',
    'cclibs': '-lgcc',
    'language_id': 'pa-risc:BE:32:default',
    'processor': 'PA-RISC',
    'architecture_test': 'PARISC',
})

PCodeTest({
    'name': 'Loongarch64',
    'build_all': 1,
    'build_exe': 0,
    'qemu_command': 'qemu-loongarch64',
    'toolchain': 'LoongArch/loongarch64-linux-gnu',
    'ccflags': '-march=loongarch64 -mabi=lp64d',
    'language_id': 'Loongarch:LE:64:default',
    #'has_longlong': 0,
})

PCodeTest({
    'name': 'Loongarch64f',
    'build_all': 1,
    'build_exe': 0,
    'gcc_version': '12.3.0',
    'qemu_command': 'qemu-loongarch64',
    'target': 'loongson-linux',
    'toolchain': 'LoongArch/loongarch64-linux-gnu',
    'ccflags': '-march=loongarch64 -mabi=lp64f',
    #'cclibs': '-lgcc',
    'language_id': 'Loongarch:LE:64:lp64f',
    'has_double': 0,
})


# Note that libgcc.a was built for m68020 which has a different function calling convention from pre-68020

PCodeTest({
    'name': 'm68000',
    'build_all': 1,
    'build_exe': 0,
    'qemu_command': 'qemu-m68k',            # qemu: fatal: Illegal instruction
    'toolchain': 'm68k/m68k-elf',
    'ccflags': '-mcpu=68020 -m68020',
    'cclibs': '-lgcc',
    'language_id': '68000:BE:32:default',
})

PCodeTest({
    'name': 'MIPS',
    'build_all': 1,
    'build_exe': 1,
    'qemu_command': 'qemu-mips',
    'toolchain': 'MIPS/mips-elf',
    'ccflags': '-mno-gpopt',
    'gcc_libdir': '%(toolchain_dir)s/lib/gcc/mips-mti-elf/%(gcc_actual_version)s',
    'cclibs': '-lgcc',
    'language_id': 'MIPS:BE:32:default',
})

PCodeTest({
    'name': 'MIPSEL',
    'build_all': 1,
    'build_exe': 1,
    'toolchain': 'MIPS/mips-elf',
    'ccflags': '-mno-gpopt -mel',
    'gcc_libdir': '%(toolchain_dir)s/lib/gcc/mips-mti-elf/%(gcc_actual_version)s/el',
    'cclibs': '-lgcc',
    'language_id': 'MIPS:LE:32:default',
})

PCodeTest({
    'name': 'MIPS16',
    'build_all': 1,
    'build_exe': 1,
    'qemu_command': 'qemu-mips',
    'toolchain': 'MIPS/mips-elf',
    'ccflags': '-mno-gpopt',
    'language_id': 'MIPS:BE:32:default',
    'has_float': 0,
    'has_double': 0,
    'has_longlong': 0,
})

PCodeTest({
    'name': 'MIPS16MIX',
    'build_all': 1,
    'build_exe': 1,
    'qemu_command': 'qemu-mips',
    'toolchain': 'MIPS/mips-elf',
    'ccflags': '-mno-gpopt',
    'language_id': 'MIPS:BE:32:default',
    'has_float': 0,
    'has_double': 0,
    'has_longlong': 0,
})

PCodeTest({
    'name': 'MIPSMIC',
    'build_all': 1,
    'toolchain': 'MIPS/mips-elf',
    'ccflags': '-mmicromips',
    'gcc_libdir': '%(toolchain_dir)s/lib/gcc/mips-mti-elf/%(gcc_actual_version)s/micromips',
    'cclibs': '-lgcc',
    'language_id': 'MIPS:BE:32:micro',
    'architecture_test': 'MIPSMICRO',
})

PCodeTest({
    'name': 'MIPSMICMIX',
    'build_all': 1,
    'toolchain': 'MIPS/mips-elf',
    'ccflags': '-minterlink-compressed -D BODYNEW=micromips',
    'gcc_libdir': '%(toolchain_dir)s/lib/gcc/mips-mti-elf/%(gcc_actual_version)s/micromips',
    'cclibs': '-lgcc',
    'language_id': 'MIPS:BE:32:micro',
    'architecture_test': 'MIPSMICROMIX',
})

PCodeTest({
    'name': 'MIPSMIC64',
    'build_all': 1,
    'toolchain': 'MIPS/mipsr6-elf',
    'ccflags': '-mips64r5 -mmicromips -minterlink-compressed',
    'language_id': 'MIPS:BE:64:micro',
})

PCodeTest({
    'name': 'MIPS64_32addr',
    'build_all': 1,
    'toolchain': 'MIPS/mipsr6-elf',
    'ccflags': '-mips64r2',
    'language_id': 'MIPS:BE:64:64-32addr',
})

PCodeTest({
    'name': 'MIPS64_64addr',
    'build_all': 1,
    'toolchain': 'MIPS/mipsr6-elf',
    'ccflags': '-mips64r2 -mabi=64',
    'language_id': 'MIPS:BE:64:64-64addr',
})

PCodeTest({
    'name': 'MIPS64_64addrLE',
    'build_all': 1,
    'toolchain': 'MIPS/mipsr6-elf',
    'ccflags': '-mips64r2 -mabi=64 -EL',
    'language_id': 'MIPS:LE:64:64-64addr',
})

PCodeTest({
    'name': 'MIPSR6',
    'build_all': 1,
    'toolchain': 'MIPS/mipsr6-elf',
    'ccflags': '-mips32r6',
    'gcc_libdir': '-L %(toolchain_dir)s/lib/gcc/mips-img-elf/%(gcc_actual_version)s',
    'cclibs': '-lgcc',
    'language_id': 'MIPS:BE:32:R6',
})

PCodeTest({
    'name': 'MIPS64R6',
    'build_all': 1,
    'toolchain': 'MIPS/mipsr6-elf',
    'ccflags': '-mips64r6 -mabi=64',
    'language_id': 'MIPS:BE:64:R6',
})

PCodeTest({
    'name': 'NDS32BE',
    'build_all': 1,
    'toolchain': 'NDS32/nds32be-elf',
    'ccflags': '',
    'cclibs': '-lgcc',
    'language_id': 'NDS32:BE:32:default',
})

PCodeTest({
    'name': 'NDS32LE',
    'build_all': 1,
    'toolchain': 'NDS32/nds32le-elf',
    'ccflags': '',
    'cclibs': '-lgcc',
    'language_id': 'NDS32:LE:32:default',
})

PCodeTest({
    'name': 'power6',
    'toolchain': 'PPC/powerpc-elf',
    'ccflags': '-mcpu=G5 -m32 -mno-relocatable',
    'cclibs': '-lgcc',
    'language_id': 'PowerPC:BE:32:default',
})

PCodeTest({
    'name': 'powerpc32',
    'build_all': 1,
    'build_exe': 1,
    'qemu_command': 'qemu-ppc64abi32',
    'toolchain': 'PPC/powerpc-elf',
    'ccflags': '-mcpu=powerpc -m32 -maltivec -mno-relocatable',
    'cclibs': '-lgcc',
    'language_id': 'PowerPC:BE:32:default',
    'architecture_test': 'PPC',
})

PCodeTest({
    'name': 'powerpc64',
    'build_all': 1,
    'build_exe': 1,
    'qemu_command': 'qemu-ppc64',
    'toolchain': 'PPC/powerpc64-linux',
    'ccflags': '-mabi=elfv1 -maltivec -mno-relocatable',
    'cclibs': '-lgcc',
    'language_id': 'PowerPC:BE:64:default',
    'architecture_test': 'PPC64',
})

PCodeTest({
    'name': 'powerpc64v2',
    'toolchain': 'PPC/powerpc64-linux',
    'ccflags': '-mabi=elfv2 -maltivec -mno-relocatable',
    'cclibs': '-lgcc',
    'language_id': 'PowerPC:BE:64:default',
})

PCodeTest({
    'name': 'ppcA2',
    'build_all': 1,
    'toolchain': 'PPC/powerpc-elf',
    'ccflags': '-mcpu=a2',
    'cclibs': '-lgcc',
    'language_id': 'PowerPC:BE:32:A2',
    'architecture_test': 'PPCA2',
})

PCodeTest({
    'name': 'ppcA2Alt',
    'build_all': 1,
    'toolchain': 'PPC/powerpc-elf',
    'ccflags': '-mcpu=a2 -maltivec',
    'cclibs': '-lgcc',
    'language_id': 'PowerPC:BE:32:A2ALT',
    'architecture_test': 'PPCA2Alt',
})

PCodeTest({
    'name': 'ppcP8Alt',
    'build_all': 1,
    'toolchain': 'PPC/powerpc-elf',
    'ccflags': '-mcpu=power8 -mvsx -maltivec',
    'cclibs': '-lgcc',
    'language_id': 'PowerPC:BE:32:A2ALT',
    'architecture_test': 'PPCP8Alt',
})

PCodeTest({
    'name': 'ppcP9Alt',
    'build_all': 1,
    'toolchain': 'PPC/powerpc-elf',
    'ccflags': '-mcpu=power9 -mvsx -maltivec',
    'cclibs': '-lgcc',
    'language_id': 'PowerPC:BE:32:A2ALT',
    'architecture_test': 'PPCP9Alt',
})

PCodeTest({
    'name': 'msp430x',
    'build_all': 1,
    'toolchain': 'TI/msp430-elf',
    'ccflags': '-g -mcpu=msp430x -mlarge -mhwmult=none -fno-builtin -Wl,-T,msp430x.ld',
    'cclibs': '-lgcc -lmul_none',
    'language_id': 'TI_MSP430X:LE:32:default',
    'processor': 'TI',
    'architecture_test': 'MSP430X',
    'has_float': 1,
    'has_double': 1,
    'has_longlong': 0,
    'small_build': 1,
    'skip_files': ['PointerManipulation.test', 'misc.out'],
})

PCodeTest({
    'name': 'msp430',
    'build_all': 1,
    'toolchain': 'TI/msp430-elf',
    'ccflags': '-g -mcpu=msp430 -fno-builtin -mhwmult=none',
    'cclibs': '-lgcc -lmul_none',
    'language_id': 'TI_MSP430:LE:16:default',
    'processor': 'TI',
    'architecture_test': 'MSP430',
    'has_float': 1,
    'has_double': 1,
    'has_longlong': 0,
    'small_build': 1,
})

PCodeTest({
    'name': 'SH4',
    'build_all': 1,
    'build_exe': 0,
    'qemu_command': 'qemu-sh4eb',            # qemu gets "Invalid argument" error
    'toolchain': 'SuperH4/sh4-elf',
    'ccflags': '-mb -mrenesas -m4',
    'cclibs': '-lgcc',
    'language_id': 'SuperH4:BE:32:default',
    'architecture_test': 'SuperH4_BE',
})

PCodeTest({
    'name': 'SH4_LE',
    'build_all': 1,
    'toolchain': 'SuperH4/sh4le-elf',
    'ccflags': '-ml -mrenesas -m4',
    'cclibs': '-lgcc',
    'language_id': 'SuperH4:LE:32:default',
    'architecture_test': 'SuperH4',
})

PCodeTest({
    'name': 'sparcV9_32',
    'build_all': 1,
    'build_exe': 1,
    'can_run': 0,                    # instruction error causes infinite loop
    'qemu_command': 'qemu-sparc32plus',
    'toolchain': 'SparcV9/sparc-elf',
    'ccflags': '-mcpu=v9 -m32',
    'language_id': 'sparc:BE:32:default',
    'processor': 'Sparc',
    'architecture_test': 'SparcV9_m32',
    'has_float': 0,
    'has_double': 0,
    'has_longlong': 0,
})

# to suppress usage of application registers g2 and g3, add -mno-app-regs here

PCodeTest({
    'name': 'sparcV9_64',
    'build_all': 1,
    'toolchain': 'SparcV9/sparc64-elf',
    'ccflags': '-mcpu=v9 -m64',
    'language_id': 'sparc:BE:64:default',
})

PCodeTest({
    'name': 'pentium',
    'build_all': 1,
    'build_exe': 1,
    'qemu_command': 'qemu-i386',
    'toolchain': 'x86/i386-elf-linux',
    'ccflags': '-march=pentium -m32',
    'cclibs': '-lgcc',
    'objdump_option': '-M intel',
    'language_id': 'x86:LE:32:default',
    'architecture_test': 'X86m32',
    'has_vector': 1,
})

PCodeTest({
    'name': 'i386_CLANG',
    'toolchain': 'LLVM/llvm',
    'toolchain_type': 'llvm',
    'ccflags': '--target=i386 -DU4="unsigned __INT32_TYPE__" -DI4="signed __INT32_TYPE__',
    'objdump_option': '-M intel',
    'language_id': 'x86:LE:32:default',
})

PCodeTest({
    'name': 'i686_CLANG',
    'toolchain': 'LLVM/llvm',
    'toolchain_type': 'llvm',
    'ccflags': '--target=i686 -DU4="unsigned __INT32_TYPE__" -DI4="signed __INT32_TYPE__',
    'objdump_option': '-M intel',
    'language_id': 'x86:LE:32:default',
})

PCodeTest({
    'name': 'AVX2',
    'build_all': 1,
    'toolchain': 'x86/x86_64-elf',
    'ccflags': '-march=core-avx2',
    'objdump_option': '-M intel',
    'language_id': 'x86:LE:64:default',
    'has_vector': 1,
})

PCodeTest({
    'name': 'AVXi',
    'toolchain': 'x86/x86_64-elf',
    'ccflags': '-march=core-avx-i',
    'objdump_option': '-M intel',
    'language_id': 'x86:LE:64:default',
})

PCodeTest({
    'name': 'bdver2',
    'toolchain': 'x86/x86_64-elf',
    'ccflags': '-march=bdver2',
    'objdump_option': '-M intel',
    'language_id': 'x86:LE:64:default',
})

PCodeTest({
    'name': 'core2',
    'toolchain': 'x86/x86_64-elf',
    'ccflags': '-march=bdver2',
    'objdump_option': '-M intel',
    'language_id': 'x86:LE:64:default',
})

PCodeTest({
    'name': 'x86_m64',
    'build_all': 1,
    'build_exe': 1,
    'qemu_command': 'qemu-x86_64',
    'toolchain': 'x86/x86_64-elf',
    'ccflags': '-static -m64',
    'objdump_option': '-M intel',
    'language_id': 'x86:LE:64:default',
    'architecture_test': 'X86m64',
})

PCodeTest({
    'name': 'x86_fma4',
    'toolchain': 'x86/x86_64-elf',
    'ccflags': '-mfma',
    'objdump_option': '-M intel',
    'language_id': 'x86:LE:64:default',
})

# the PIC30 toolchain is distributed by mchp. So when making the
# toolchain, specify toolchain_type to be mchp. But it is based on
# gcc, and after it's installed, it behaves exactly like gcc. So, when
# making a pcode test, specify toolchain_type to be gcc.

PCodeTest({
    'name': 'PIC30',
    'build_all': 1,
    'toolchain': 'PIC/xc16',
    'compile_exe': 'bin/xc16-gcc',
    'objdump_exe': 'bin/xc16-objdump',
    'readelf_exe': 'bin/xc16-readelf',
    'nm_exe': 'bin/xc16-nm',
    'ccflags': '-mcpu=30F2011 -DI4="signed long" -DU4="unsigned long" -DF8="long double" -Xlinker --defsym -Xlinker _main=0x0',
    'gcc_libdir': '%(toolchain_dir)s/lib',
    'cclibs': '-lpic30 -lc -lm',
    'language_id': 'dsPIC30F:LE:24:default',
    'skip_files': ['misc.test'],
    'variants': {'O0': '-O0'},
    'small_build': 1,
})

PCodeTest({
    'name': 'PIC16',
    'toolchain': 'PIC/xc8',
    'compile_exe': 'bin/xc8',
    'objdump_exe': 'bin/dump',
    'ccflags': '-chip=16C57 -DI4="signed long" -DU4="unsigned long" -DSTATIC_MAIN',
    'gcc_libdir': '%(toolchain_dir)s/lib',
    'cclibs': '-lpic30 -lc -lm',
    'language_id': 'dsPIC16F:LE:24:default',
    'small_build': 1,
})

PCodeTest({
    'name': 'HCS08',
    'toolchain': 'SDCC/s08',
    'toolchain_type': 'sdcc',
    'compile_exe': 'bin/sdcc',
    'ccflags': '--out-fmt-elf --std-sdcc11',
    'language_id': 'HCS08:BE:16:MC9S08GB60',
    'variants': {'OX': ''},
    'has_double': 0,
    'has_longlong': 0,
})

PCodeTest({
    'name': 'Z80',
    'toolchain': 'SDCC/z80',
    'toolchain_type': 'sdcc',
    'compile_exe': 'bin/sdcc',
    'ccflags': '-mz80 -V --verbose --std-sdcc11 -DI4="signed long" -DU4="unsigned long"',
    'language_id': 'z80:LE:16:default',
    'variants': {'OX':''},
    'has_float': 0,
    'has_double': 0,
    'has_longlong': 0,
    'small_build': 1,
    # Currently the 'omitted' option is only supported by the SDCC toolchain!
    # Causes a bit of funk with tpp.py still including references to these
    # tests in cunit_main.c but the compiler accepts it with a warning. 
    'skip_files': ['PointerManipulation.test', 'StructUnionManipulation.test'],
    # These tests are omitted because the SDCC compiler doesn't properly handle
    # structs in functions and requires a more strict format than ANSI C requires.
})

PCodeTest({
    'name': 'CR16C',
    'build_all': 1,
    'toolchain': 'NS/cr16-elf',
    'language_id': 'CR16C:LE:16:default',
    'processor': 'CR16',
    'architecture_test': 'CRC16C',
    'ccflags': '-lgcc',
    'has_float': 0,
    'has_double': 0,
    'has_longlong': 0,
})

PCodeTest({
    'name': 'RISCV',
    'build_all': 1,
    'toolchain': 'RISCV/riscv32-elf',
    'language_id': 'RISCV:BE:32:default',
    'architecture_test': 'RISCV',
    'ccflags': '-lgcc',
    'has_float': 0,
    'has_double': 0,
    'has_longlong': 0,
})

PCodeTest({
    'name': 'V850',
    'build_all': 1,
    'build_exe': 1,
    'toolchain': 'V850/v850-elf',
    'language_id': 'V850:LE:32:default',
    'ccflags': '-mv850e2v3 -lgcc',
})

PCodeTest({
    'name': 'RH850',
    'build_all': 1,
    'build_exe': 1,
    'toolchain': 'V850/v850-elf',
    'language_id': 'V850:LE:32:v850e3v5',
    'ccflags': '-mv850e3v5 -mloop -mrh850-abi -lgcc',
})

PCodeTest({
    'name': 'Xtensa',
    'build_all': 1,
    'build_exe': 1,
    'toolchain': 'Xtensa/xtensa-elf',
    'language_id': 'Xtensa:LE:32:default',
    'ccflags': '-lgcc',
})

PCodeTest({
    'name': 'Xtensa_LE',
    'build_all': 1,
    'build_exe': 1,
    'toolchain': 'Xtensa/xtensa-esp32-elf',
    'language_id': 'Xtensa:LE:32:default',
    'gcc_version' : '8.4.0',
    'ccflags': '-L %(toolchain_dir)s/lib/gcc/xtensa-esp32-elf/%(gcc_version)s',
})

PCodeTest({
    'name': 'Xtensa_BE',
    'build_all': 1,
    'build_exe': 1,
    'toolchain': 'Xtensa/xtensa-elf',
    'language_id': 'Xtensa:BE:32:default',
    'ccflags': '-L %(toolchain_dir)s/lib/gcc/xtensa-elf/%(gcc_version)s',
})
