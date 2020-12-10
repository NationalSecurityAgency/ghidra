/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package agent.dbgmodel.jna.dbgmodel.main;

import com.sun.jna.*;
import com.sun.jna.platform.win32.Guid.REFIID;
import com.sun.jna.platform.win32.Variant.VARIANT;
import com.sun.jna.platform.win32.WTypes.VARTYPE;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;

public class WrapIModelObject extends UnknownWithUtils implements IModelObject {
	public static class ByReference extends WrapIModelObject implements Structure.ByReference {
	}

	public WrapIModelObject() {
	}

	public WrapIModelObject(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetContext(PointerByReference context) {
		return _invokeHR(VTIndices.GET_CONTEXT, getPointer(), context);
	}

	@Override
	public HRESULT GetKind(ULONGByReference kind) {
		return _invokeHR(VTIndices.GET_KIND, getPointer(), kind);
	}

	@Override
	public HRESULT GetIntrinsicValue(VARIANT.ByReference intrinsicData) {
		return _invokeHR(VTIndices.GET_INTRINSIC_VALUE, getPointer(), intrinsicData);
	}

	@Override
	public HRESULT GetIntrinsicValueAs(VARTYPE vt, VARIANT.ByReference intrinsicData) {
		return _invokeHR(VTIndices.GET_INTRINSIC_VALUE, getPointer(), vt, intrinsicData);
	}

	@Override
	public HRESULT GetKeyValue(WString key, PointerByReference object,
			PointerByReference metadata) {
		return _invokeHR(VTIndices.GET_KEY_VALUE, getPointer(), key, object, metadata);
	}

	@Override
	public HRESULT SetKeyValue(WString key, Pointer object) {
		return _invokeHR(VTIndices.SET_KEY_VALUE, getPointer(), key, object);
	}

	@Override
	public HRESULT EnumerateKeyValues(PointerByReference enumerator) {
		return _invokeHR(VTIndices.ENUMERATE_KEY_VALUES, getPointer(), enumerator);
	}

	@Override
	public HRESULT GetRawValue(ULONG kind, WString name, ULONG searchFlags,
			PointerByReference object) {
		return _invokeHR(VTIndices.GET_RAW_VALUE, getPointer(), kind, name, searchFlags, object);
	}

	@Override
	public HRESULT EnumerateRawValues(ULONG kind, ULONG searchFlags,
			PointerByReference enumerator) {
		return _invokeHR(VTIndices.ENUMERATE_RAW_VALUES, getPointer(), kind, searchFlags,
			enumerator);
	}

	@Override
	public HRESULT Dereference(PointerByReference object) {
		return _invokeHR(VTIndices.DEREFERENCE, getPointer(), object);
	}

	@Override
	public HRESULT TryCastToRuntimeType(PointerByReference runtimeTypedObject) {
		return _invokeHR(VTIndices.TRY_CAST_TO_RUNTIME_TYPE, getPointer(), runtimeTypedObject);
	}

	@Override
	public HRESULT GetConcept(REFIID conceptId, PointerByReference conceptInterface,
			PointerByReference conceptMetadata) {
		return _invokeHR(VTIndices.GET_CONCEPT, getPointer(), conceptId, conceptInterface,
			conceptMetadata);
	}

	@Override
	public HRESULT GetLocation(LOCATION.ByReference location) {
		return _invokeHR(VTIndices.GET_LOCATION, getPointer(), location);
	}

	@Override
	public HRESULT GetTypeInfo(PointerByReference type) {
		return _invokeHR(VTIndices.GET_TYPE_INFO, getPointer(), type);
	}

	@Override
	public HRESULT GetTargetInfo(LOCATION.ByReference location, PointerByReference type) {
		return _invokeHR(VTIndices.GET_TARGET_INFO, getPointer(), location, type);
	}

	@Override
	public HRESULT GetNumberOfParentModels(ULONGLONGByReference numModels) {
		return _invokeHR(VTIndices.GET_NUMBER_OF_PARENT_MODELS, getPointer(), numModels);
	}

	@Override
	public HRESULT GetParentModel(ULONG i, PointerByReference model,
			PointerByReference contextObject) {
		return _invokeHR(VTIndices.GET_PARENT_MODEL, getPointer(), i, model, contextObject);
	}

	@Override
	public HRESULT AddParentModel(Pointer model, Pointer contextObject, BOOL override) {
		return _invokeHR(VTIndices.ADD_PARENT_MODEL, getPointer(), model, contextObject, override);
	}

	@Override
	public HRESULT RemoveParentModel(Pointer model) {
		return _invokeHR(VTIndices.REMOVE_PARENT_MODEL, getPointer(), model);
	}

	@Override
	public HRESULT GetKey(WString key, PointerByReference object, PointerByReference metadata) {
		return _invokeHR(VTIndices.GET_KEY, getPointer(), key, object, metadata);
	}

	@Override
	public HRESULT GetKeyReference(WString key, PointerByReference objectReference,
			PointerByReference metadata) {
		return _invokeHR(VTIndices.GET_KEY_REFERENCE, getPointer(), key, objectReference, metadata);
	}

	@Override
	public HRESULT SetKey(WString key, Pointer object, Pointer metadata) {
		return _invokeHR(VTIndices.SET_KEY, getPointer(), key, object, metadata);
	}

	@Override
	public HRESULT ClearKeys() {
		return _invokeHR(VTIndices.CLEAR_KEYS, getPointer());
	}

	@Override
	public HRESULT EnumerateKeys(PointerByReference enumerator) {
		return _invokeHR(VTIndices.ENUMERATE_KEYS, getPointer(), enumerator);
	}

	@Override
	public HRESULT EnumerateKeyReferences(PointerByReference enumerator) {
		return _invokeHR(VTIndices.ENUMERATE_KEY_REFERENCES, getPointer(), enumerator);
	}

	@Override
	public HRESULT SetConcept(REFIID conceptId, Pointer conceptInterface, Pointer conceptMetadata) {
		return _invokeHR(VTIndices.SET_CONCEPT, getPointer(), conceptId, conceptInterface,
			conceptMetadata);
	}

	@Override
	public HRESULT ClearConcepts() {
		return _invokeHR(VTIndices.CLEAR_CONCEPTS, getPointer());
	}

	@Override
	public HRESULT GetRawReference(ULONG kind, WString name, ULONG searchFlags,
			PointerByReference object) {
		return _invokeHR(VTIndices.GET_RAW_REFERENCE, getPointer(), kind, name, searchFlags,
			object);
	}

	@Override
	public HRESULT EnumerateRawReferences(ULONGByReference kind, ULONG searchFlags,
			PointerByReference enumerator) {
		return _invokeHR(VTIndices.ENUMERATE_RAW_REFERENCES, getPointer(), kind, searchFlags,
			enumerator);
	}

	@Override
	public HRESULT SetContextForDataModel(Pointer dataModelObject, Pointer context) {
		return _invokeHR(VTIndices.SET_CONTEXT_FOR_DATA_MODEL, getPointer(), dataModelObject,
			context);
	}

	@Override
	public HRESULT GetContextForDataModel(Pointer dataModelObject, PointerByReference context) {
		return _invokeHR(VTIndices.GET_CONTEXT_FOR_DATA_MODEL, getPointer(), dataModelObject,
			context);
	}

	@Override
	public HRESULT Compare(Pointer other, BOOLByReference ppResult) {
		return _invokeHR(VTIndices.COMPARE, getPointer(), other, ppResult);
	}

	@Override
	public HRESULT IsEqualTo(Pointer other, BOOLByReference equal) {
		return _invokeHR(VTIndices.IS_EQUAL_TO, getPointer(), other, equal);
	}

}
