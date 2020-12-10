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

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.Variant.VARIANT;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.ModelObjectKind;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDataModelManager1 extends IUnknownEx {
	final IID IID_IDATA_MODEL_MANAGER = new IID("73FE19F4-A110-4500-8ED9-3C28896F508C");

	enum VTIndices1 implements VTableIndex {
		CLOSE, //
		CREATE_NO_VALUE, //
		CREATE_ERROR_OBJECT, //
		CREATE_TYPED_OBJECT, //
		CREATE_TYPED_OBJECT_REFERENCE, //
		CREATE_SYNTHETIC_OBJECT, //
		CREATE_DATA_MODEL_OBJECT, //
		CREATE_INTRINSIC_OBJECT, //
		CREATE_TYPED_INTRINSIC_OBJECT, //
		GET_MODEL_FOR_TYPE_SIGNATURE, //
		GET_MODEL_FOR_TYPE, //
		REGISTER_MODEL_FOR_TYPE_SIGNATURE, //
		UNREGISTER_MODEL_FOR_TYPE_SIGNATURE, //
		REGISTER_EXTENSION_FOR_TYPE_SIGNATURE, //
		UNREGISTER_EXTENSION_FOR_TYPE_SIGNATURE, //
		CREATE_METADATA_STORE, //
		GET_ROOT_NAMESPACE, //
		REGISTER_NAMED_MODEL, //
		UNREGISTER_NAMED_MODEL, //
		ACQUIRE_NAMED_MODEL, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT Close();

	HRESULT CreateNoValue(PointerByReference object);

	HRESULT CreateErrorObject(HRESULT hrError, WString pwszMessage, PointerByReference object);

	HRESULT CreateTypedObject(Pointer context, LOCATION objectLocation, Pointer objectType,
			PointerByReference object);

	HRESULT CreateTypedObjectReference(Pointer context, LOCATION objectLocation, Pointer objectTye,
			PointerByReference object);

	HRESULT CreateSyntheticObject(Pointer context, PointerByReference object);

	HRESULT CreateDataModelObject(Pointer dataModel, PointerByReference object);

	HRESULT CreateIntrinsicObject(ModelObjectKind objectKind, VARIANT.ByReference intrinsicData,
			PointerByReference object);

	HRESULT CreateTypedIntrinsicObject(VARIANT.ByReference intrinsicData, Pointer type,
			PointerByReference object);

	HRESULT GetModelForTypeSignature(Pointer typeSignature, PointerByReference dataModel);

	HRESULT GetModelForType(Pointer type, PointerByReference dataModel,
			PointerByReference typeSignature, PointerByReference wildcardMatches);

	HRESULT RegisterModelForTypeSignature(Pointer typeSignature, Pointer dataModel);

	HRESULT UnregisterModelForTypeSignature(Pointer dataModel, Pointer typeSignature);

	HRESULT RegisterExtensionForTypeSignature(Pointer typeSignature, Pointer dataModel);

	HRESULT UnregisterExtensionForTypeSignature(Pointer dataModel, Pointer typeSignature);

	HRESULT CreateMetadataStore(Pointer parentStore, PointerByReference metadataStore);

	HRESULT GetRootNamespace(PointerByReference rootNamespace);

	HRESULT RegisterNamedModel(WString modelName, Pointer modelObject);

	HRESULT UnregisterNamedModel(WString modelName);

	HRESULT AcquireNamedModel(WString modelName, PointerByReference modelObject);

}
