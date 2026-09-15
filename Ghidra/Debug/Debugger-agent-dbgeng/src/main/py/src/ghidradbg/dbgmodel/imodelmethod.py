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

from comtypes import COMError
from comtypes.gen import DbgMod
from comtypes.hresult import S_OK, S_FALSE
from pybag.dbgeng import exception

from . import imodelobject as mo


class ModelMethod(object):
    def __init__(self, method):
        self._method = method
        method.AddRef()

    # ModelMethod

    def Call(self, object, argcount=0, arguments=None):
        if argcount == 0:
            arguments = POINTER(DbgMod.IModelObject)()
        result = POINTER(DbgMod.IModelObject)()
        metadata = POINTER(DbgMod.IKeyStore)()
        try:
            self._method.Call(byref(object), argcount, byref(arguments),
                              byref(result), byref(metadata))
        except COMError as ce:
            return None

        return mo.ModelObject(result)
