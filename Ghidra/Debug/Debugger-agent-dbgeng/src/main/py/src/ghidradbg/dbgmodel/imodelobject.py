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
from enum import Enum

from comtypes import IUnknown, COMError
from comtypes.automation import IID, VARIANT
from comtypes.gen import DbgMod
from comtypes.hresult import S_OK, S_FALSE
from pybag.dbgeng import exception

from comtypes.gen.DbgMod import *

from .iiterableconcept import IterableConcept
from .ikeyenumerator import KeyEnumerator


class ModelObjectKind(Enum):
    PROPERTY_ACCESSOR = 0
    CONTEXT = 1
    TARGET_OBJECT = 2
    TARGET_OBJECT_REFERENCE = 3
    SYNTHETIC = 4
    NO_VALUE = 5
    ERROR = 6
    INTRINSIC = 7
    METHOD = 8
    KEY_REFERENCE = 9


class ModelObject(object):
    def __init__(self, obj):
        self._obj = obj
        self.concept = None
        exception.wrap_comclass(self._obj)

    def Release(self):
        print("RELEASE ModelObject")
        breakpoint()
        cnt = self._obj.Release()
        if cnt == 0:
            self._obj = None
        return cnt

    # ModelObject

    def AddParentModel(self, model, contextObject, override):
        raise exception.E_NOTIMPL_Error

    def ClearConcepts(self):
        raise exception.E_NOTIMPL_Error

    def ClearKeys(self):
        raise exception.E_NOTIMPL_Error

    def Compare(self, other, equal):
        raise exception.E_NOTIMPL_Error

    def Dereference(self, object):
        raise exception.E_NOTIMPL_Error

    def EnumerateKeyReferences(self):
        raise exception.E_NOTIMPL_Error

    def EnumerateKeys(self):
        keys = POINTER(DbgMod.IKeyEnumerator)()
        hr = self._obj.EnumerateKeys(byref(keys))
        if hr != S_OK:
            return None
        return KeyEnumerator(keys)

    def EnumerateKeyValues(self):
        raise exception.E_NOTIMPL_Error

    def EnumerateRawReferences(self, kind, searchFlags):
        raise exception.E_NOTIMPL_Error

    def EnumerateRawValues(self, kind, searchFlag):
        keys = POINTER(DbgMod.IRawEnumerator)()
        hr = self._obj.EnumerateRawValues(kind, searchFlag, byref(keys))
        if hr != S_OK:
            return None
        return RawEnumerator(keys, kind)

    def GetConcept(self, ref):
        ifc = POINTER(IUnknown)()
        metadata = POINTER(DbgMod.IKeyStore)()
        hr = self._obj.GetConcept(ref._iid_, byref(ifc), byref(metadata))
        if hr != S_OK:
            return None
        return cast(ifc, POINTER(ref))

    def GetContext(self, context):
        raise exception.E_NOTIMPL_Error

    def GetContextForDataModel(self, dataModelObject, context):
        raise exception.E_NOTIMPL_Error

    def GetIntrinsicValue(self):
        var = VARIANT()
        hr = self._obj.GetIntrinsicValue(var)
        if hr != S_OK:
            return None
        return var

    def GetIntrinsicValueAs(self, vt):
        raise exception.E_NOTIMPL_Error

    def GetKey(self, key, object, metadata):
        raise exception.E_NOTIMPL_Error

    def GetKeyReference(self, key, objectReference, metadata):
        raise exception.E_NOTIMPL_Error

    def GetKeyValue(self, key):
        kbuf = cast(c_wchar_p(key), POINTER(c_ushort))
        value = POINTER(DbgMod.IModelObject)()
        store = POINTER(DbgMod.IKeyStore)()
        hr = self._obj.GetKeyValue(kbuf, byref(value), byref(store))
        if hr != S_OK:
            return None
        return ModelObject(value)

    def GetKind(self):
        kind = c_long()
        hr = self._obj.GetKind(kind)
        exception.check_err(hr)
        return kind

    def GetLocation(self, location):
        raise exception.E_NOTIMPL_Error

    def GetNumberOfParentModels(self, numModels):
        raise exception.E_NOTIMPL_Error

    def GetParentModel(self, i, model, context):
        raise exception.E_NOTIMPL_Error

    def GetRawReference(self, kind, name, searchFlags, object):
        raise exception.E_NOTIMPL_Error

    def GetRawValue(self, kind, name, searchFlags, object):
        raise exception.E_NOTIMPL_Error

    def GetTargetInfo(self):
        location = POINTER(DbgMod._Location)()
        type = POINTER(DbgMod.IDebugHostType)()
        hr = self._obj.GetTargetInfo(location, byref(type))
        exception.check_err(hr)
        return type

    def GetTypeInfo(self, type):
        raise exception.E_NOTIMPL_Error

    def IsEqualTo(self, other, equal):
        raise exception.E_NOTIMPL_Error

    def RemoveParentModel(self, model):
        raise exception.E_NOTIMPL_Error

    def SetConcept(self, ref, interface, metadata):
        raise exception.E_NOTIMPL_Error

    def SetContextForDataModel(self, modelObject, context):
        raise exception.E_NOTIMPL_Error

    def SetKey(self, key, object, metadata):
        raise exception.E_NOTIMPL_Error

    def SetKeyValue(self, key, object):
        raise exception.E_NOTIMPL_Error

    def TryCastToRuntimeType(self, runtimeTypedObject):
        raise exception.E_NOTIMPL_Error

    # Auxiliary

    def GetKeyValueMap(self):
        map = {}
        keys = self.EnumerateKeys()
        (k, v) = keys.GetNext()
        while k is not None:
            map[k.value] = self.GetKeyValue(k.value)
            (k, v) = keys.GetNext()
        return map

    def GetRawValueMap(self):
        map = {}
        kind = self.GetKind()
        keys = self.EnumerateRawValues(kind, c_long(0))
        (k, v) = keys.GetNext()
        while k is not None:
            map[k.value] = v
            (k, v) = keys.GetNext()
        return map

    def GetAttributes(self):
        map = {}
        kind = self.GetKind()
        if kind == ModelObjectKind.ERROR:
            return map
        if kind == ModelObjectKind.INTRINSIC or \
                kind == ModelObjectKind.TARGET_OBJECT or \
                kind == ModelObjectKind.TARGET_OBJECT_REFERENCE:
            return self.GetRawValueMap()
        return self.GetKeyValueMap()

    def GetElements(self):
        list = []
        if self.concept is None:
            iconcept = self.GetConcept(DbgMod.IIterableConcept)
            if iconcept is None:
                return list
            self.concept = IterableConcept(iconcept)
        iter = self.concept.GetIterator(self)
        if iter is None:
            print("WARNING: iter is None")
            return list
        next = iter.GetNext(1)
        while next is not None:
            list.append(next)
            next = iter.GetNext(1)
        return list

    def GetElement(self, key):
        list = self.GetElements()
        for k, v in list:
            if k == key:
                return v
        return None

    def GetOffspring(self, path):
        next = self
        for element in path:
            if element.startswith("["):
                idx = element[1:len(element)-1]
                if "x" not in idx:
                    idx = int(idx)
                else:
                    idx = int(idx, 16)
                next = next.GetElement(idx)
            else:
                next = next.GetKeyValue(element)
            if next is None:
                print(f"{element} not found")
        return next

    def GetValue(self):
        value = self.GetIntrinsicValue()
        if value is None:
            return None
        if value.vt == 0xd:
            return None
        return value.value

    def GetTypeKind(self):
        kind = self.GetKind()
        if kind == ModelObjectKind.TARGET_OBJECT or \
           kind == ModelObjectKind.INTRINSIC:
            return self.GetTargetInfo()
        return None
