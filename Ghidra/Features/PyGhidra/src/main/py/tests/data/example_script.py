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
import sys


def import_test_function():
    print("imported successfully")


if __name__ == '__main__':
    print(" ".join(sys.argv))
    print(" ".join(getScriptArgs()))
    print(currentProgram)
    assert currentProgram.name == "strings.exe"
    assert currentProgram.listing
    assert currentProgram.changeable
    assert toAddr(0).offset == 0
    assert monitor is not None
    assert hasattr(__this__, "currentAddress")
    assert currentSelection is None
    assert currentHighlight is None
