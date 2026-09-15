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
from dataclasses import dataclass


@dataclass(frozen=True)
class Schema:
    name: str

    def __str__(self):
        return self.name


UNSPECIFIED = Schema('')
ANY = Schema('ANY')
OBJECT = Schema('OBJECT')
VOID = Schema('VOID')
BOOL = Schema('BOOL')
BYTE = Schema('BYTE')
CHAR = Schema('CHAR')
SHORT = Schema('SHORT')
INT = Schema('INT')
LONG = Schema('LONG')
STRING = Schema('STRING')
ADDRESS = Schema('ADDRESS')
RANGE = Schema('RANGE')

BOOL_ARR = Schema('BOOL_ARR')
BYTE_ARR = Schema('BYTE_ARR')
CHAR_ARR = Schema('CHAR_ARR')
SHORT_ARR = Schema('SHORT_ARR')
INT_ARR = Schema('INT_ARR')
LONG_ARR = Schema('LONG_ARR')
STRING_ARR = Schema('STRING_ARR')
