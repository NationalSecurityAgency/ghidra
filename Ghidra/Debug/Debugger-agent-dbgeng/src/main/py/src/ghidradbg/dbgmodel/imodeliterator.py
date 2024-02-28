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

from comtypes import COMError
from comtypes.gen import DbgMod
from comtypes.hresult import S_OK, S_FALSE
from pybag.dbgeng import exception

from . import imodelobject as mo


class ModelIterator(object):
    def __init__(self, iter):
        self._iter = iter
        iter.AddRef()

    # ModelIterator

    def GetNext(self, dimensions):
        object = POINTER(DbgMod.IModelObject)()
        indexer = POINTER(DbgMod.IModelObject)()
        metadata = POINTER(DbgMod.IKeyStore)()
        try:
            self._iter.GetNext(byref(object), dimensions,
                               byref(indexer), byref(metadata))
        except COMError as ce:
            return None
        index = mo.ModelObject(indexer)
        id = index.GetIntrinsicValue().value
        return (id, mo.ModelObject(object))

    def Reset(self):
        hr = self._keys.Reset()
        exception.check_err(hr)
