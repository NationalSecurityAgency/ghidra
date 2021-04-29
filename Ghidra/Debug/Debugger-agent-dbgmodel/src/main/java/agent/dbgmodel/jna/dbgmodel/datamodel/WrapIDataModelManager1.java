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
package agent.dbgmodel.jna.dbgmodel.datamodel;

import com.sun.jna.*;
import com.sun.jna.platform.win32.Variant.VARIANT;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.ModelObjectKind;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;

public class WrapIDataModelManager1 extends UnknownWithUtils implements IDataModelManager1 {
	public static class ByReference extends WrapIDataModelManager1
			implements Structure.ByReference {
	}

	public WrapIDataModelManager1() {
	}

	public WrapIDataModelManager1(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT Close() {
		return _invokeHR(VTIndices1.CLOSE, getPointer());
	}

	@Override
	public HRESULT CreateNoValue(PointerByReference object) {
		return _invokeHR(VTIndices1.CREATE_NO_VALUE, getPointer(), object);
	}

	@Override
	public HRESULT CreateErrorObject(HRESULT hrError, WString pwszMessage,
			PointerByReference object) {
		return _invokeHR(VTIndices1.CREATE_ERROR_OBJECT, getPointer(), hrError, pwszMessage,
			object);
	}

	@Override
	public HRESULT CreateTypedObject(Pointer context, LOCATION objectLocation, Pointer objectTye,
			PointerByReference object) {
		return _invokeHR(VTIndices1.CREATE_TYPED_OBJECT, getPointer(), context, objectLocation,
			objectTye, object);
	}

	@Override
	public HRESULT CreateTypedObjectReference(Pointer context, LOCATION objectLocation,
			Pointer objectTye,
			PointerByReference object) {
		return _invokeHR(VTIndices1.CREATE_TYPED_OBJECT_REFERENCE, getPointer(), context,
			objectLocation, objectTye, object);
	}

	@Override
	public HRESULT CreateSyntheticObject(Pointer context, PointerByReference object) {
		return _invokeHR(VTIndices1.CREATE_SYNTHETIC_OBJECT, getPointer(), context, object);
	}

	@Override
	public HRESULT CreateDataModelObject(Pointer dataModel, PointerByReference object) {
		return _invokeHR(VTIndices1.CREATE_DATA_MODEL_OBJECT, getPointer(), dataModel, object);
	}

	@Override
	public HRESULT CreateIntrinsicObject(ModelObjectKind objectKind,
			VARIANT.ByReference intrinsicData,
			PointerByReference object) {
		return _invokeHR(VTIndices1.CREATE_INTRINSIC_OBJECT, getPointer(), objectKind.ordinal(),
			intrinsicData, object);
	}

	@Override
	public HRESULT CreateTypedIntrinsicObject(VARIANT.ByReference intrinsicData, Pointer type,
			PointerByReference object) {
		return _invokeHR(VTIndices1.CREATE_TYPED_INTRINSIC_OBJECT, getPointer(), intrinsicData,
			type, object);
	}

	@Override
	public HRESULT GetModelForTypeSignature(Pointer typeSignature, PointerByReference dataModel) {
		return _invokeHR(VTIndices1.GET_MODEL_FOR_TYPE_SIGNATURE, getPointer(), typeSignature,
			dataModel);
	}

	@Override
	public HRESULT GetModelForType(Pointer type, PointerByReference dataModel,
			PointerByReference typeSignature, PointerByReference wildcardMatches) {
		return _invokeHR(VTIndices1.GET_MODEL_FOR_TYPE, getPointer(), type, dataModel,
			typeSignature, wildcardMatches);
	}

	@Override
	public HRESULT RegisterModelForTypeSignature(Pointer typeSignature, Pointer dataModel) {
		return _invokeHR(VTIndices1.REGISTER_MODEL_FOR_TYPE_SIGNATURE, getPointer(), typeSignature,
			dataModel);
	}

	@Override
	public HRESULT UnregisterModelForTypeSignature(Pointer dataModel, Pointer typeSignature) {
		return _invokeHR(VTIndices1.UNREGISTER_MODEL_FOR_TYPE_SIGNATURE, getPointer(), dataModel,
			typeSignature);
	}

	@Override
	public HRESULT RegisterExtensionForTypeSignature(Pointer typeSignature, Pointer dataModel) {
		return _invokeHR(VTIndices1.REGISTER_EXTENSION_FOR_TYPE_SIGNATURE, getPointer(),
			typeSignature, dataModel);
	}

	@Override
	public HRESULT UnregisterExtensionForTypeSignature(Pointer typeSignature, Pointer dataModel) {
		return _invokeHR(VTIndices1.UNREGISTER_EXTENSION_FOR_TYPE_SIGNATURE, getPointer(),
			typeSignature, dataModel);
	}

	@Override
	public HRESULT CreateMetadataStore(Pointer parentStore, PointerByReference metadataStore) {
		return _invokeHR(VTIndices1.CREATE_METADATA_STORE, getPointer(), parentStore,
			metadataStore);
	}

	@Override
	public HRESULT GetRootNamespace(PointerByReference rootNamespace) {
		return _invokeHR(VTIndices1.GET_ROOT_NAMESPACE, getPointer(), rootNamespace);
	}

	@Override
	public HRESULT RegisterNamedModel(WString modelName, Pointer modelObject) {
		return _invokeHR(VTIndices1.REGISTER_NAMED_MODEL, getPointer(), modelName, modelObject);
	}

	@Override
	public HRESULT UnregisterNamedModel(WString modelName) {
		return _invokeHR(VTIndices1.UNREGISTER_NAMED_MODEL, getPointer(), modelName);
	}

	@Override
	public HRESULT AcquireNamedModel(WString modelName, PointerByReference modelObject) {
		return _invokeHR(VTIndices1.ACQUIRE_NAMED_MODEL, getPointer(), modelName, modelObject);
	}

}
