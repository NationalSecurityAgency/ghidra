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
import builtins
from keyword import iskeyword
from typing import Mapping, Sequence
from rlcompleter import Completer
from types import CodeType, FunctionType, MappingProxyType, MethodType, ModuleType

from docking.widgets.label import GLabel
from generic.theme import GColor
from ghidra.app.plugin.core.console import CodeCompletion
from java.util import Arrays, Collections  # type:ignore @UnresolvedImport
from jpype import JPackage
from jpype.types import JDouble, JFloat, JInt, JLong, JShort


NoneType = type(None)

CLASS_COLOR = GColor("color.fg.plugin.python.syntax.class")
CODE_COLOR = GColor("color.fg.plugin.python.syntax.code")
FUNCTION_COLOR = GColor("color.fg.plugin.python.syntax.function")
INSTANCE_COLOR = GColor("color.fg.plugin.python.syntax.instance")
MAP_COLOR = GColor("color.fg.plugin.python.syntax.map")
METHOD_COLOR = GColor("color.fg.plugin.python.syntax.method")
NULL_COLOR = GColor("color.fg.plugin.python.syntax.null")
NUMBER_COLOR = GColor("color.fg.plugin.python.syntax.number")
PACKAGE_COLOR = GColor("color.fg.plugin.python.syntax.package")
SEQUENCE_COLOR = GColor("color.fg.plugin.python.syntax.sequence")

_TYPE_COLORS = {
    type: CLASS_COLOR,
    CodeType: CODE_COLOR,
    FunctionType: FUNCTION_COLOR,
    dict: MAP_COLOR,
    MappingProxyType: MAP_COLOR,
    MethodType: METHOD_COLOR,
    NoneType: NULL_COLOR,
    int: NUMBER_COLOR,
    float: NUMBER_COLOR,
    complex: NUMBER_COLOR,
    JShort: NUMBER_COLOR,
    JInt: NUMBER_COLOR,
    JLong: NUMBER_COLOR,
    JFloat: NUMBER_COLOR,
    JDouble: NUMBER_COLOR,
    ModuleType: PACKAGE_COLOR,
    JPackage: PACKAGE_COLOR
}


class PythonCodeCompleter(Completer):
    """
    Code Completer for Ghidra's Python interpreter window
    """

    _BUILTIN_ATTRIBUTE = object()
    __slots__ = ('cmd',)

    def __init__(self, py_console):
        super().__init__(py_console.locals.get_static_view())
        self.cmd: str

    def _get_label(self, i: int) -> GLabel:
        match = self.matches[i].rstrip("()")
        label = GLabel(match)
        attr = self.namespace.get(match, PythonCodeCompleter._BUILTIN_ATTRIBUTE)
        if attr is PythonCodeCompleter._BUILTIN_ATTRIBUTE:
            if iskeyword(match.rstrip()):
                return label
            builtins_dict = builtins.__dict__      
            attr = builtins_dict.get(match, PythonCodeCompleter._BUILTIN_ATTRIBUTE)
            if attr is not PythonCodeCompleter._BUILTIN_ATTRIBUTE and not match.startswith("__"):
                attr = builtins_dict[match]
            else:
                return label
        color = _TYPE_COLORS.get(type(attr), PythonCodeCompleter._BUILTIN_ATTRIBUTE)
        if color is PythonCodeCompleter._BUILTIN_ATTRIBUTE:
            t = type(attr)
            if isinstance(t, Sequence):
                color = SEQUENCE_COLOR
            elif isinstance(t, Mapping):
                color = MAP_COLOR
            else:
                color = INSTANCE_COLOR
        label.setForeground(color)
        return label

    def _supplier(self, i: int) -> CodeCompletion:
        insertion = self.matches[i][len(self.cmd):]
        return CodeCompletion(self.matches[i], insertion, self._get_label(i))

    def get_completions(self, cmd: str):
        """
        Gets all the possible CodeCompletion(s) for the provided cmd

        :param cmd: The code to complete
        :return: A Java List of all possible CodeCompletion(s)
        """
        try:
            self.cmd = cmd
            if self.complete(cmd, 0) is None:
                return Collections.emptyList()
            res = CodeCompletion[len(self.matches)]
            Arrays.setAll(res, self._supplier)
            return Arrays.asList(res)
        except:  # pylint: disable=bare-except
            return Collections.emptyList()
