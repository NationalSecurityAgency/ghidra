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
from enum import Enum

from comtypes import IUnknown, COMError
from comtypes.automation import IID, VARIANT
from comtypes.gen import DbgMod
from comtypes.hresult import S_OK, S_FALSE
from pybag.dbgeng import exception

from comtypes import BSTR
from comtypes.gen.DbgMod import *

from .iiterableconcept import IterableConcept
from .istringdisplayableconcept import StringDisplayableConcept
from .ikeyenumerator import KeyEnumerator
from .irawenumerator import RawEnumerator


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
        self.dconcept = None
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
        try:
            ifc = POINTER(IUnknown)()
            metadata = POINTER(DbgMod.IKeyStore)()
            hr = self._obj.GetConcept(ref._iid_, byref(ifc), byref(metadata))
            if hr != S_OK:
                return None
            return cast(ifc, POINTER(ref))
        except Exception as e:
            print(f"GetConcept exception: {e}")
            return None

    def GetContext(self, context):
        raise exception.E_NOTIMPL_Error

    def GetContextForDataModel(self, dataModelObject, context):
        raise exception.E_NOTIMPL_Error

    def GetIntrinsicValue(self):
        var = VARIANT()
        try:
            hr = self._obj.GetIntrinsicValue(var)
            if hr != S_OK:
                return None
            return var
        except Exception as e:
            print(f"GetIntrinsicValue exception: {e}")
            return None

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

    # DOESN"T WORK YET
    # def GetTypeKind(self):
    #     typeKind = None
    #     modelKind = self.GetKind()
    #     if modelKind.value == ModelObjectKind.TARGET_OBJECT.value:
    #         targetInfo = self.GetTargetInfo()
    #         if targetInfo is not None:
    #             typeKind = DbgMod.tagTYPEKIND()
    #             hr = targetInfo._obj.GetTypeKind(byref(typeKind))
    #             if hr != S_OK:
    #                 return None
    #     if modelKind.value == ModelObjectKind.INTRINSIC.value:
    #         typeInfo = self.GetTypeInfo()
    #         if typeInfo is not None:
    #             typeKind = DbgMod.tagTYPEKIND()
    #             hr = typeInfo._obj.GetTypeKind(byref(typeKind))
    #             if hr != S_OK:
    #                 return None
    #     return typeKind

    def GetLocation(self):
        loc = DbgMod._Location()
        hr = self._obj.GetLocation(loc)
        exception.check_err(hr)
        return loc

    def GetNumberOfParentModels(self, numModels):
        raise exception.E_NOTIMPL_Error

    def GetParentModel(self, i, model, context):
        raise exception.E_NOTIMPL_Error

    def GetRawReference(self, kind, name, searchFlags, object):
        raise exception.E_NOTIMPL_Error

    def GetRawValue(self, kind, name, searchFlags):
        kbuf = cast(c_wchar_p(name), POINTER(c_ushort))
        value = POINTER(DbgMod.IModelObject)()
        hr = self._obj.GetRawValue(kind, kbuf, searchFlags, byref(value))
        if hr != S_OK:
            return None
        return ModelObject(value)

    def GetTargetInfo(self):
        location = DbgMod._Location()
        type = POINTER(DbgMod.IDebugHostType)()
        hr = self._obj.GetTargetInfo(location, byref(type))
        exception.check_err(hr)
        return ModelObject(type)

    def GetTypeInfo(self):
        type = POINTER(DbgMod.IDebugHostType)()
        hr = self._obj.GetTypeInfo(byref(type))
        exception.check_err(hr)
        return ModelObject(type)

    def GetName(self):
        name = BSTR()
        hr = self._obj.GetName(name)
        exception.check_err(hr)
        return name

    def ToDisplayString(self):
        if self.dconcept is None:
            dconcept = self.GetConcept(DbgMod.IStringDisplayableConcept)
            if dconcept is None:
                return None
            self.dconcept = StringDisplayableConcept(dconcept)
        return self.dconcept.ToDisplayString(self)

    # This does NOT work - returns a null pointer for value.  Why?
    # One possibility: casting is not a valid way to obtain an IModelMethod
    #
    # def ToDisplayString0(self):
    #     map = self.GetAttributes()
    #     method = map["ToDisplayString"]
    #     mm = cast(method._obj, POINTER(DbgMod.IModelMethod))
    #     context = self._obj
    #     args = POINTER(DbgMod.IModelObject)()
    #     value = POINTER(DbgMod.IModelObject)()
    #     meta = POINTER(DbgMod.IKeyStore)()
    #     hr = mm.Call(context, c_ulonglong(0), args, byref(value), byref(meta))
    #     exception.check_err(hr)
    #     return ModelObject(value)

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
        # print(f"GetRawValueMap: {self}")
        map = {}
        kind = self.GetKind()
        # TODO: forcing kind to 0 because we can't GetTypeKind
        keys = self.EnumerateRawValues(c_long(0), 0)
        (k, v) = keys.GetNext()
        while k is not None:
            map[k.value] = v
            (k, v) = keys.GetNext()
            # print(f"{k}:{v}")
        return map

    def GetAttributes(self):
        map = {}
        kind = self.GetKind()
        # print(f"GetAttributes: {kind}")
        if kind is not None and kind.value == ModelObjectKind.ERROR.value:
            print(f"ERROR from GetAttributes")
            return map
        if kind.value == ModelObjectKind.INTRINSIC.value or \
                kind.value == ModelObjectKind.TARGET_OBJECT.value or \
                kind.value == ModelObjectKind.TARGET_OBJECT_REFERENCE.value:
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
            if next is None:
                return None
            kind = next.GetKind()
            if element.startswith("["):
                idx = element[1:len(element)-1]
                if "x" not in idx:
                    idx = int(idx)
                else:
                    idx = int(idx, 16)
                next = next.GetElement(idx)
            # THIS IS RELATIVELY HORRIBLE - replace with GetRawValue?
            elif kind is not None and kind.value == ModelObjectKind.TARGET_OBJECT.value:
                map = next.GetAttributes()
                next = map[element]
            else:
                next = next.GetKeyValue(element)
            # if next is None:
            #    print(f"{element} not found")
        return next

    def GetValue(self):
        value = self.GetIntrinsicValue()
        if value is None:
            return None
        if value.vt == 0xd:
            return None
        return value.value
