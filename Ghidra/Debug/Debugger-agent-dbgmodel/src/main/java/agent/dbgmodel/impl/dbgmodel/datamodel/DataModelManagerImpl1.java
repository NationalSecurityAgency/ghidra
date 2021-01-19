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
package agent.dbgmodel.impl.dbgmodel.datamodel;

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Variant.VARIANT;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.concept.DataModelConcept;
import agent.dbgmodel.dbgmodel.datamodel.script.DataModelScriptManager;
import agent.dbgmodel.dbgmodel.debughost.*;
import agent.dbgmodel.dbgmodel.main.KeyStore;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.impl.dbgmodel.datamodel.script.DataModelScriptManagerInternal;
import agent.dbgmodel.impl.dbgmodel.debughost.DebugHostSymbolEnumeratorInternal;
import agent.dbgmodel.impl.dbgmodel.debughost.DebugHostTypeSignatureInternal;
import agent.dbgmodel.impl.dbgmodel.main.KeyStoreInternal;
import agent.dbgmodel.impl.dbgmodel.main.ModelObjectInternal;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.ModelObjectKind;
import agent.dbgmodel.jna.dbgmodel.datamodel.IDataModelManager1;
import agent.dbgmodel.jna.dbgmodel.main.WrapIKeyStore;
import agent.dbgmodel.jna.dbgmodel.main.WrapIModelObject;

public class DataModelManagerImpl1 implements DataModelManagerInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDataModelManager1 jnaData;
	private DebugHostTypeSignatureInternal typeSignature;
	private DebugHostSymbolEnumeratorInternal wildcardMatches;

	public DataModelManagerImpl1(IDataModelManager1 jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public void close() {
		COMUtils.checkRC(jnaData.Close());
	}

	@Override
	public ModelObject createNoValue() {
		PointerByReference ppContextObject = new PointerByReference();
		COMUtils.checkRC(jnaData.CreateNoValue(ppContextObject));

		WrapIModelObject wrap = new WrapIModelObject(ppContextObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public ModelObject createErrorObject(HRESULT hrError, WString pwszMessage) {
		PointerByReference ppContextObject = new PointerByReference();
		COMUtils.checkRC(jnaData.CreateErrorObject(hrError, pwszMessage, ppContextObject));

		WrapIModelObject wrap = new WrapIModelObject(ppContextObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public ModelObject createTypedObject(DebugHostContext context, LOCATION objectLocation,
			DebugHostType1 objectType) {
		Pointer pContext = context.getPointer();
		Pointer pObjectType = objectType.getPointer();
		PointerByReference ppObject = new PointerByReference();
		COMUtils.checkRC(
			jnaData.CreateTypedObject(pContext, objectLocation, pObjectType, ppObject));

		WrapIModelObject wrap = new WrapIModelObject(ppObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public ModelObject createTypedObjectReference(DebugHostContext context, LOCATION objectLocation,
			DebugHostType1 objectType) {
		Pointer pContext = context.getPointer();
		Pointer pObjectType = context.getPointer();
		PointerByReference ppObject = new PointerByReference();
		COMUtils.checkRC(
			jnaData.CreateTypedObjectReference(pContext, objectLocation, pObjectType, ppObject));

		WrapIModelObject wrap = new WrapIModelObject(ppObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public ModelObject createSyntheticObject(DebugHostContext context) {
		Pointer pContext = context.getPointer();
		PointerByReference ppObject = new PointerByReference();
		COMUtils.checkRC(jnaData.CreateSyntheticObject(pContext, ppObject));

		WrapIModelObject wrap = new WrapIModelObject(ppObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public ModelObject createDataModelObject(DataModelConcept dataModel) {
		Pointer pDataModel = dataModel.getPointer();
		PointerByReference ppObject = new PointerByReference();
		COMUtils.checkRC(jnaData.CreateDataModelObject(pDataModel, ppObject));

		WrapIModelObject wrap = new WrapIModelObject(ppObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public ModelObject createIntrinsicObject(ModelObjectKind objectKind,
			VARIANT.ByReference intrinsicData) {
		PointerByReference ppObject = new PointerByReference();
		COMUtils.checkRC(jnaData.CreateIntrinsicObject(objectKind, intrinsicData, ppObject));

		WrapIModelObject wrap = new WrapIModelObject(ppObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public ModelObject createTypedIntrinsicObject(VARIANT.ByReference intrinsicData,
			DebugHostType1 type) {
		Pointer pType = type.getPointer();
		PointerByReference ppObject = new PointerByReference();
		COMUtils.checkRC(jnaData.CreateTypedIntrinsicObject(intrinsicData, pType, ppObject));

		WrapIModelObject wrap = new WrapIModelObject(ppObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public ModelObject getModelForTypeSignature(DebugHostTypeSignature typeSignature) {
		Pointer pTypeSignature = typeSignature.getPointer();
		PointerByReference ppObject = new PointerByReference();
		COMUtils.checkRC(jnaData.GetModelForTypeSignature(pTypeSignature, ppObject));

		WrapIModelObject wrap = new WrapIModelObject(ppObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public ModelObject getModelForType(DebugHostType1 type) {
		Pointer pType = type.getPointer();
		PointerByReference ppObject = new PointerByReference();
		PointerByReference ppTypeSignature = new PointerByReference();
		PointerByReference ppWildcardMatches = new PointerByReference();
		COMUtils.checkRC(
			jnaData.GetModelForType(pType, ppObject, ppTypeSignature, ppWildcardMatches));

		WrapIModelObject wrap0 = new WrapIModelObject(ppTypeSignature.getValue());
		try {
			typeSignature =
				DebugHostTypeSignatureInternal.tryPreferredInterfaces(wrap0::QueryInterface);
		}
		finally {
			wrap0.Release();
		}
		WrapIModelObject wrap1 = new WrapIModelObject(ppWildcardMatches.getValue());
		try {
			wildcardMatches =
				DebugHostSymbolEnumeratorInternal.tryPreferredInterfaces(wrap1::QueryInterface);
		}
		finally {
			wrap1.Release();
		}
		WrapIModelObject wrap = new WrapIModelObject(ppObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public void registerModelForTypeSignature(DebugHostTypeSignature typeSignature,
			ModelObject dataModel) {
		Pointer pTypeSignature = typeSignature.getPointer();
		Pointer pDataModel = dataModel.getPointer();
		COMUtils.checkRC(jnaData.RegisterModelForTypeSignature(pTypeSignature, pDataModel));
	}

	@Override
	public void unregisterModelForTypeSignature(ModelObject dataModel,
			DebugHostTypeSignature typeSignature) {
		Pointer pDataModel = dataModel.getPointer();
		Pointer pTypeSignature = typeSignature.getPointer();
		COMUtils.checkRC(jnaData.UnregisterModelForTypeSignature(pDataModel, pTypeSignature));
	}

	@Override
	public void registerExtensionForTypeSignature(DebugHostTypeSignature typeSignature,
			ModelObject dataModel) {
		Pointer pTypeSignature = typeSignature.getPointer();
		Pointer pDataModel = dataModel.getPointer();
		COMUtils.checkRC(jnaData.RegisterExtensionForTypeSignature(pTypeSignature, pDataModel));
	}

	@Override
	public void unregisterExtensionForTypeSignature(ModelObject dataModel,
			DebugHostTypeSignature typeSignature) {
		Pointer pDataModel = dataModel.getPointer();
		Pointer pTypeSignature = typeSignature.getPointer();
		COMUtils.checkRC(jnaData.UnregisterExtensionForTypeSignature(pDataModel, pTypeSignature));
	}

	@Override
	public KeyStore createMetadataStore(KeyStore parentStore) {
		Pointer pParentStore = parentStore.getPointer();
		PointerByReference ppMetadataStore = new PointerByReference();
		COMUtils.checkRC(jnaData.CreateMetadataStore(pParentStore, ppMetadataStore));

		WrapIKeyStore wrap = new WrapIKeyStore(ppMetadataStore.getValue());
		try {
			return KeyStoreInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public ModelObject getRootNamespace() {
		PointerByReference ppObject = new PointerByReference();
		COMUtils.checkRC(jnaData.GetRootNamespace(ppObject));

		Pointer value = ppObject.getValue();
		if (value == null) {
			return null;
		}
		WrapIModelObject wrap = new WrapIModelObject(value);
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public void registerNamedModel(WString modelName, ModelObject modelObject) {
		Pointer pModelObject = modelObject.getPointer();
		COMUtils.checkRC(jnaData.RegisterNamedModel(modelName, pModelObject));
	}

	@Override
	public void unregisterNamedModel(WString modelName) {
		COMUtils.checkRC(jnaData.UnregisterNamedModel(modelName));
	}

	@Override
	public ModelObject acquireNamedModel(WString modelName) {
		PointerByReference ppModelObject = new PointerByReference();
		COMUtils.checkRC(jnaData.AcquireNamedModel(modelName, ppModelObject));

		WrapIModelObject wrap = new WrapIModelObject(ppModelObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	public DebugHostTypeSignatureInternal getTypeSignature() {
		return typeSignature;
	}

	public DebugHostSymbolEnumeratorInternal getWildcardMatches() {
		return wildcardMatches;
	}

	@Override
	public DataModelScriptManager asScriptManager() {
		return DataModelScriptManagerInternal.tryPreferredInterfaces(jnaData::QueryInterface);
	}
}
