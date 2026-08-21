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
from ctypes import *

from comtypes import BSTR, COMError
from comtypes.gen import DbgMod
from comtypes.hresult import S_OK, S_FALSE
from pybag.dbgeng import exception


class StringDisplayableConcept(object):
    def __init__(self, concept):
        self._concept = concept
        concept.AddRef()

    # StringDisplayableConcept

    def ToDisplayString(self, context):
        try:
            val = BSTR()
            self._concept.ToDisplayString(context._obj, None, byref(val))
        except COMError as ce:
            return None
        return val.value
