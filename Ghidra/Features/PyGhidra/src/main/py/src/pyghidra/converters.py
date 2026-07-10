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
"""JPype type conversions for transparent Python-to-Java interop.

This module registers JPype conversion handlers so that Python
:class:`pathlib.Path` instances can be passed directly to Java APIs
that expect ``java.lang.String`` or ``java.io.File`` parameters. The
:func:`jpype.JConversion` decorator installs each handler the first
time this module is imported, so importing :mod:`pyghidra` is
sufficient to enable the conversions globally.
"""
from pathlib import Path

from jpype import JConversion, JClass

__all__ = ["pathToString", "pathToFile"]


@JConversion("java.lang.String", instanceof=Path)
def pathToString(cls: JClass, path: Path):
    """Convert a :class:`Path` to a ``java.lang.String`` via JPype.

    The path is first resolved to an absolute, canonical form via
    :meth:`Path.resolve` before being passed to ``cls`` (the target
    Java class constructor).

    :param cls: The target ``java.lang.String`` class supplied by JPype.
    :param path: The Python :class:`Path` to convert.
    :return: A ``java.lang.String`` representing the absolute path.
    """
    return cls(path.resolve().__str__())


@JConversion("java.io.File", instanceof=Path)
def pathToFile(cls: JClass, path: Path):
    """Convert a :class:`Path` to a ``java.io.File`` via JPype.

    Unlike :func:`pathToString`, the path is passed through unchanged
    (no ``resolve()`` call) so that Java receives the path exactly as
    the Python caller provided it.

    :param cls: The target ``java.io.File`` class supplied by JPype.
    :param path: The Python :class:`Path` to convert.
    :return: A ``java.io.File`` pointing at the same location.
    """
    return cls(path)
