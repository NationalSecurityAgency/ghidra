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

from pyghidra.version import ExtensionDetails


def test_extension_details_round_trip(tmp_path: Path):
    details = ExtensionDetails(
        name="Demo",
        description="A normal description",
        author="tester"
    )
    path = tmp_path / "extension.properties"
    path.write_text(str(details))
    parsed = ExtensionDetails.from_file(path)
    assert parsed.name == details.name
    assert parsed.description == details.description
    assert parsed.author == details.author


def test_extension_details_value_containing_equals(tmp_path: Path):
    # _install_plugin writes the properties file with str(details) and
    # _uninstall_old_plugin reads it back, so a value containing '=' must survive
    details = ExtensionDetails(
        name="Demo",
        description="Parses key=value pairs",
        author="tester"
    )
    path = tmp_path / "extension.properties"
    path.write_text(str(details))
    assert ExtensionDetails.from_file(path).description == "Parses key=value pairs"


def test_extension_details_ignores_comments_and_blank_lines(tmp_path: Path):
    path = tmp_path / "extension.properties"
    path.write_text(
        "# a comment\n"
        "\n"
        "name=Demo\n"
        "description=A normal description\n"
        "author=tester\n"
    )
    assert ExtensionDetails.from_file(path).name == "Demo"
