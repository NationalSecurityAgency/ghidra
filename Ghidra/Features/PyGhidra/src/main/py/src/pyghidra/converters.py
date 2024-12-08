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
from pathlib import Path

from jpype import JConversion, JClass


@JConversion("java.lang.String", instanceof=Path)
def pathToString(cls: JClass, path: Path):
    return cls(path.resolve().__str__())


@JConversion("java.io.File", instanceof=Path)
def pathToFile(cls: JClass, path: Path):
    return cls(path)
