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

from comtypes.gen import DbgMod
from comtypes.hresult import S_OK, S_FALSE
from pybag.dbgeng import exception

from .idatamodelmanager import DataModelManager
from .idebughost import DebugHost


class HostDataModelAccess(object):
    def __init__(self, hdma):
        self._hdma = hdma
        exception.wrap_comclass(self._hdma)

    def Release(self):
        cnt = self._hdma.Release()
        if cnt == 0:
            self._hdma = None
        return cnt

    # HostDataModelAccess

    def GetDataModel(self):
        manager = POINTER(DbgMod.IDataModelManager)()
        host = POINTER(DbgMod.IDebugHost)()
        hr = self._hdma.GetDataModel(byref(manager), byref(host))
        exception.check_err(hr)
        return (DataModelManager(manager), DebugHost(host))
