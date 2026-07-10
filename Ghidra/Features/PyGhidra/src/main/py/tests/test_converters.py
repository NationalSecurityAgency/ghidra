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
"""Unit tests for :mod:`pyghidra.converters`.

The JPype :func:`JConversion` decorator stores the user-supplied
function unchanged (see ``jpype._jcustomizer.JConversion``) and only
attaches the conversion metadata to JPype's internal registry. As a
result, the conversion bodies can be exercised directly with a mock
target class, no live JVM is required.
"""
from pathlib import Path

from pyghidra.converters import pathToFile, pathToString


class _MockJClass:
    """Stand-in for a Java class. Records the constructor argument."""

    def __init__(self, value):
        self.value = value

    def __eq__(self, other):
        return isinstance(other, _MockJClass) and self.value == other.value

    def __hash__(self):
        return hash(self.value)


def test_module_exposes_public_helpers():
    """Both conversion helpers are part of the public API."""
    import pyghidra.converters as converters

    assert converters.__all__ == ["pathToString", "pathToFile"]
    assert converters.pathToString is pathToString
    assert converters.pathToFile is pathToFile


def test_pathToString_invokes_resolve(tmp_path: Path):
    """``pathToString`` should call ``Path.resolve()`` before constructing the target."""
    nested = tmp_path / "missing" / "child.txt"

    result = pathToString(_MockJClass, nested)

    assert isinstance(result, _MockJClass)
    assert result.value == str(nested.resolve())


def test_pathToFile_preserves_input_path(tmp_path: Path):
    """``pathToFile`` should pass the path through unchanged (no ``resolve()``)."""
    nested = tmp_path / "missing" / "child.txt"

    result = pathToFile(_MockJClass, nested)

    assert isinstance(result, _MockJClass)
    assert result.value == str(nested)


def test_helpers_diverge_on_path_with_dotdot(tmp_path: Path):
    """The two helpers must produce different output for an un-resolved path.

    ``tmp_path`` is absolute, so a plain ``tmp_path / "x"`` is already
    canonical. To exercise the ``Path.resolve()`` branch in
    :func:`pathToString`, the input has to contain ``..`` segments.
    """
    nested = tmp_path / "missing" / ".." / "child.txt"

    as_string = pathToString(_MockJClass, nested)
    as_file = pathToFile(_MockJClass, nested)

    assert as_string.value != as_file.value
    assert as_file.value == str(nested)
    assert as_string.value == str(nested.resolve())
