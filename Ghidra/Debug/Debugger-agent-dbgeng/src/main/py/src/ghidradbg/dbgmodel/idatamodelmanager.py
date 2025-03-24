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

from . import imodelobject as mo


class DataModelManager(object):
    def __init__(self, mgr):
        self._mgr = mgr
        exception.wrap_comclass(self._mgr)

    def Release(self):
        cnt = self._mgr.Release()
        if cnt == 0:
            self._mgr = None
        return cnt

    # DataModelManager

    def GetRootNamespace(self):
        root = POINTER(DbgMod.IModelObject)()
        hr = self._mgr.GetRootNamespace(byref(root))
        exception.check_err(hr)
        return mo.ModelObject(root)

    def AcquireNamedModel(self, modelName, modelObject):
        raise exception.E_NOTIMPL_Error

    def Close(self):
        raise exception.E_NOTIMPL_Error

    def CreateNoValue(self, object):
        raise exception.E_NOTIMPL_Error

    def CreateErrorObject(self, error, message, object):
        raise exception.E_NOTIMPL_Error

    def CreateTypedObject(self, context, objectLocation, objectType, object):
        raise exception.E_NOTIMPL_Error

    def CreateTypedObjectByReference(self, context, objectLocation, objectType, object):
        raise exception.E_NOTIMPL_Error

    def CreateSyntheticObject(self, context, object):
        raise exception.E_NOTIMPL_Error

    def CreateDataModelObject(self, dataModel, object):
        raise exception.E_NOTIMPL_Error

    def CreateTypedIntrinsicObject(self, intrinsicData, type, object):
        raise exception.E_NOTIMPL_Error

    def CreateIntrinsicObject(self, objectKind, intrinsicData, object):
        raise exception.E_NOTIMPL_Error

    def GetModelForTypeSignature(self, typeSignature, dataModel):
        raise exception.E_NOTIMPL_Error

    def GetModelForType(self, type, dataModel, typeSignature, wildcardMatches):
        raise exception.E_NOTIMPL_Error

    def RegisterExtensionForTypeSignature(self, typeSignature, dataModel):
        raise exception.E_NOTIMPL_Error

    def RegisterModelForTypeSignature(self, typeSignature, dataModel):
        raise exception.E_NOTIMPL_Error

    def RegisterNamedModel(self, modelName, modelObject):
        raise exception.E_NOTIMPL_Error

    def UnregisterExtensionForTypeSignature(self, dataModel, typeSignature):
        raise exception.E_NOTIMPL_Error

    def UnregisterModelForTypeSignature(self, dataModel, typeSignature):
        raise exception.E_NOTIMPL_Error

    def UnregisterNamedModel(self, modelName):
        raise exception.E_NOTIMPL_Error
