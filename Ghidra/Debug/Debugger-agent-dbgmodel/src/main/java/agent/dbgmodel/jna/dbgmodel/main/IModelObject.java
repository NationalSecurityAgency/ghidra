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

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.Guid.REFIID;
import com.sun.jna.platform.win32.Variant.VARIANT;
import com.sun.jna.platform.win32.WTypes.VARTYPE;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION.ByReference;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IModelObject extends IUnknownEx {
	final IID IID_IMODEL_OBJECT = new IID("E28C7893-3F4B-4b96-BACA-293CDC55F45D");

	enum VTIndices implements VTableIndex {
		GET_CONTEXT, //
		GET_KIND, //
		GET_INTRINSIC_VALUE, //
		GET_INTRINSIC_VALUE_AS, //
		GET_KEY_VALUE, //
		SET_KEY_VALUE, //
		ENUMERATE_KEY_VALUES, //
		GET_RAW_VALUE, //
		ENUMERATE_RAW_VALUES, //
		DEREFERENCE, //
		TRY_CAST_TO_RUNTIME_TYPE, //
		GET_CONCEPT, //
		GET_LOCATION, //
		GET_TYPE_INFO, //
		GET_TARGET_INFO, //
		GET_NUMBER_OF_PARENT_MODELS, //
		GET_PARENT_MODEL, //
		ADD_PARENT_MODEL, //
		REMOVE_PARENT_MODEL, //
		GET_KEY, //
		GET_KEY_REFERENCE, //
		SET_KEY, //
		CLEAR_KEYS, //
		ENUMERATE_KEYS, //
		ENUMERATE_KEY_REFERENCES, //
		SET_CONCEPT, //
		CLEAR_CONCEPTS, //
		GET_RAW_REFERENCE, //
		ENUMERATE_RAW_REFERENCES, //
		SET_CONTEXT_FOR_DATA_MODEL, //
		GET_CONTEXT_FOR_DATA_MODEL, //
		COMPARE, //
		IS_EQUAL_TO, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetContext(PointerByReference context);

	HRESULT GetKind(ULONGByReference kind);

	HRESULT GetIntrinsicValue(VARIANT.ByReference intrinsicData);

	HRESULT GetIntrinsicValueAs(VARTYPE vt, VARIANT.ByReference intrinsicData);

	HRESULT GetKeyValue(WString key, PointerByReference object, PointerByReference metadata);

	HRESULT SetKeyValue(WString key, Pointer object);

	HRESULT EnumerateKeyValues(PointerByReference enumerator);

	HRESULT GetRawValue(ULONG kind, WString name, ULONG searchFlags, PointerByReference object);  // SymbolKind

	HRESULT EnumerateRawValues(ULONG kind, ULONG searchFlags, PointerByReference enumerator); // SymbolKind

	HRESULT Dereference(PointerByReference object);

	HRESULT TryCastToRuntimeType(PointerByReference runtimeTypedObject);

	HRESULT GetConcept(REFIID conceptId, PointerByReference conceptInterface,
			PointerByReference conceptMetadata);

	HRESULT GetLocation(ByReference pLocation);

	HRESULT GetTypeInfo(PointerByReference type);

	HRESULT GetTargetInfo(LOCATION.ByReference location, PointerByReference type);

	HRESULT GetNumberOfParentModels(ULONGLONGByReference pulNumModels);

	HRESULT GetParentModel(ULONG i, PointerByReference model, PointerByReference contextObject);

	HRESULT AddParentModel(Pointer model, Pointer contextObject, BOOL override);

	HRESULT RemoveParentModel(Pointer model);

	HRESULT GetKey(WString key, PointerByReference object, PointerByReference metadata);

	HRESULT GetKeyReference(WString key, PointerByReference objectReference,
			PointerByReference metadata);

	HRESULT SetKey(WString key, Pointer object, Pointer metadata);

	HRESULT ClearKeys();

	HRESULT EnumerateKeys(PointerByReference enumerator);

	HRESULT EnumerateKeyReferences(PointerByReference enumerator);

	HRESULT SetConcept(REFIID conceptId, Pointer conceptInterface, Pointer conceptMetadata);

	HRESULT ClearConcepts();

	HRESULT GetRawReference(ULONG kind, WString name, ULONG searchFlags,
			PointerByReference object); // SymbolKind

	HRESULT EnumerateRawReferences(ULONGByReference kind, ULONG searchFlags,
			PointerByReference enumerator);

	HRESULT SetContextForDataModel(Pointer dataModelObject, Pointer pContext);

	HRESULT GetContextForDataModel(Pointer dataModelObject, PointerByReference context);

	HRESULT Compare(Pointer other, BOOLByReference bEqual);

	HRESULT IsEqualTo(Pointer other, BOOLByReference equal);

}
