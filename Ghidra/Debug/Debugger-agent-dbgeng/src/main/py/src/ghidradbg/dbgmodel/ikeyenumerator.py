## ###
#  IP: GHIDRA
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#       http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##
from ctypes import *

from comtypes import BSTR
from comtypes.gen import DbgMod
from comtypes.hresult import S_OK, S_FALSE
from pybag.dbgeng import exception

from . import imodelobject as mo


class KeyEnumerator(object):
    def __init__(self, keys):
        self._keys = keys
        exception.wrap_comclass(self._keys)

    def Release(self):
        cnt = self._keys.Release()
        if cnt == 0:
            self._keys = None
        return cnt

    # KeyEnumerator

    def GetNext(self):
        key = BSTR()
        value = POINTER(DbgMod.IModelObject)()
        store = POINTER(DbgMod.IKeyStore)()
        hr = self._keys.GetNext(byref(key), byref(value), byref(store))
        if hr != S_OK:
            return (None, None)
        return (key, mo.ModelObject(value))

    def Reset(self):
        hr = self._keys.Reset()
        exception.check_err(hr)
