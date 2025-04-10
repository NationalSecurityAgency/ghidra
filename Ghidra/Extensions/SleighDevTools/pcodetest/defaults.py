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
# Default values can be modified here, or (in
# some cases) on the build command line (see ./build --help)

# defaults that can be overridden on command line

from types import SimpleNamespace
import os

filePath = os.path.abspath(os.path.dirname(__file__))
pcodeTestDefaults = SimpleNamespace()

pcodeTestDefaults.toolchain_root = '/data/ToolChains'
pcodeTestDefaults.build_root = '/data/build'
pcodeTestDefaults.gcc_version = 'latest'
pcodeTestDefaults.gcc_config = pcodeTestDefaults.gcc_version
pcodeTestDefaults.skip_files = []
pcodeTestDefaults.export_root = os.path.join(filePath, '../../../../../ghidra.bin/Ghidra/Test/TestResources/data/pcodetests/')
pcodeTestDefaults.pcodetest_src = os.path.join(filePath, 'c_src')
# defaults that cannot be overridden on the command line
# These are set by processor test definitions in the pcode_defs.py file
pcodeTestDefaults.build_all = 0
pcodeTestDefaults.ccflags = ''
pcodeTestDefaults.cclibs = ''
pcodeTestDefaults.has_decimal128 = 0
pcodeTestDefaults.has_decimal32 = 0
pcodeTestDefaults.has_decimal64 = 0
pcodeTestDefaults.has_double = 1
pcodeTestDefaults.has_float = 1
pcodeTestDefaults.has_longlong = 1
pcodeTestDefaults.has_shortfloat = 0
pcodeTestDefaults.has_vector = 0
pcodeTestDefaults.small_build = 0
pcodeTestDefaults.ld_library_path = ''
pcodeTestDefaults.toolchain_type = 'gcc'
pcodeTestDefaults.compile_exe = 'bin/gcc'
pcodeTestDefaults.objdump_exe = 'bin/objdump'
pcodeTestDefaults.objdump_option = ''
pcodeTestDefaults.readelf_exe = 'bin/readelf'
pcodeTestDefaults.nm_exe = 'bin/nm'
pcodeTestDefaults.strip_exe = 'bin/strip'
pcodeTestDefaults.variants = {'O0': '-O0', 'O3': '-O3'}
pcodeTestDefaults.proc_test = ''
pcodeTestDefaults.force = False
