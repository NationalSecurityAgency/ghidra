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
import gdb

# TODO: I don't know how to register a custom parameter prefix. I would rather
# these were 'ghidra language' and 'ghidra compiler'


class GhidraLanguageParameter(gdb.Parameter):
    """
    The language id for Ghidra traces. Set this to 'auto' to try to derive it
    from 'show arch' and 'show endian'. Otherwise, set it to a Ghidra
    LanguageID.
    """

    def __init__(self) -> None:
        super().__init__('ghidra-language', gdb.COMMAND_DATA, gdb.PARAM_STRING)
        self.value = 'auto'


GhidraLanguageParameter()


class GhidraCompilerParameter(gdb.Parameter):
    """
    The compiler spec id for Ghidra traces. Set this to 'auto' to try to derive
    it from 'show osabi'. Otherwise, set it to a Ghidra CompilerSpecID. Note
    that valid compiler spec ids depend on the language id.
    """

    def __init__(self) -> None:
        super().__init__('ghidra-compiler', gdb.COMMAND_DATA, gdb.PARAM_STRING)
        self.value = 'auto'


GhidraCompilerParameter()
