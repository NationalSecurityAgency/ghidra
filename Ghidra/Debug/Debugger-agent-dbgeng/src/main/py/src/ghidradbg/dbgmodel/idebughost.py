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

from comtypes.gen import DbgMod
from comtypes.hresult import S_OK, S_FALSE
from pybag.dbgeng import exception
from pybag.dbgeng import win32


class DebugHost(object):
    def __init__(self, host):
        self._host = host
        exception.wrap_comclass(self._host)

    def Release(self):
        cnt = self._host.Release()
        if cnt == 0:
            self._host = None
        return cnt

    # DebugHost

    def GetCurrentContext(self, context):
        raise exception.E_NOTIMPL_Error

    def GetDefaultMetadata(self, metadata):
        raise exception.E_NOTIMPL_Error

    def GetHostDefinedInterface(self, hostUnk):
        raise exception.E_NOTIMPL_Error
