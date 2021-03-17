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
# Default values can be modified here, or (in
# some cases) on the build command line (see ./build --help)

# PCodeTest.defaults that can be overridden on command line

PCodeTest.defaults.toolchain_root = '/local/ToolChains'
PCodeTest.defaults.build_root = '/local/build-pcodetest'
PCodeTest.defaults.gcc_version = '7.3.0'
PCodeTest.defaults.skip_files = []
PCodeTest.defaults.export_root = os.getcwd() + '/../../../../../ghidra.bin/Ghidra/Test/TestResources/data/pcodetests/'
PCodeTest.defaults.pcodetest_src = os.getcwd() + '/c_src'

# PCodeTest.defaults that cannot be overridden on the command line

PCodeTest.defaults.build_all = 0
PCodeTest.defaults.ccflags = ''
PCodeTest.defaults.has_decimal128 = 0
PCodeTest.defaults.has_decimal32 = 0


PCodeTest.defaults.has_decimal64 = 0
PCodeTest.defaults.has_double = 1
PCodeTest.defaults.has_float = 1
PCodeTest.defaults.has_longlong = 1
PCodeTest.defaults.has_shortfloat = 0
PCodeTest.defaults.has_vector = 0
PCodeTest.defaults.small_build = 0
PCodeTest.defaults.ld_library_path = ''
PCodeTest.defaults.toolchain_type = 'gcc'
PCodeTest.defaults.compile_exe = 'bin/gcc'
PCodeTest.defaults.objdump_exe = 'bin/objdump'
PCodeTest.defaults.objdump_option = ''
PCodeTest.defaults.readelf_exe = 'bin/readelf'
PCodeTest.defaults.nm_exe = 'bin/nm'
PCodeTest.defaults.strip_exe = 'bin/strip'
PCodeTest.defaults.variants = {'O0': '-O0', 'O3': '-O3'}

