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
package agent.dbgmodel.impl.dbgmodel.main;

import java.util.*;

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.REFIID;
import com.sun.jna.platform.win32.Variant.VARIANT;
import com.sun.jna.platform.win32.WTypes.VARTYPE;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.platform.win32.COM.Unknown;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.*;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.concept.*;
import agent.dbgmodel.dbgmodel.datamodel.DataModelManager1;
import agent.dbgmodel.dbgmodel.debughost.DebugHostContext;
import agent.dbgmodel.dbgmodel.debughost.DebugHostType1;
import agent.dbgmodel.dbgmodel.main.*;
import agent.dbgmodel.impl.dbgmodel.UnknownExImpl;
import agent.dbgmodel.impl.dbgmodel.UnknownExInternal;
import agent.dbgmodel.impl.dbgmodel.concept.*;
import agent.dbgmodel.impl.dbgmodel.debughost.DebugHostContextInternal;
import agent.dbgmodel.impl.dbgmodel.debughost.DebugHostTypeInternal;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.*;
import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.WrapIUnknownEx;
import agent.dbgmodel.jna.dbgmodel.concept.*;
import agent.dbgmodel.jna.dbgmodel.debughost.WrapIDebugHostContext;
import agent.dbgmodel.jna.dbgmodel.debughost.WrapIDebugHostType1;
import agent.dbgmodel.jna.dbgmodel.main.*;
import ghidra.util.Msg;

public class ModelObjectImpl implements ModelObjectInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IModelObject jnaData;

	private KeyStore metadata;
	private ModelObject contextObject;

	private LOCATION targetLocation;
	private ModelObject indexer;
	private String key;

	public ModelObjectImpl(IModelObject jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public IModelObject getJnaData() {
		return jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public DebugHostContext getContext() {
		PointerByReference ppContext = new PointerByReference();
		COMUtils.checkRC(jnaData.GetContext(ppContext));

		Pointer value = ppContext.getValue();
		if (value == null) {
			return null;
		}

		WrapIDebugHostContext wrap = new WrapIDebugHostContext(value);
		try {
			return DebugHostContextInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public ModelObjectKind getKind() {
		try {
			ULONGByReference pulKind = new ULONGByReference();
			COMUtils.checkRC(jnaData.GetKind(pulKind));
			int i = pulKind.getValue().intValue();
			return ModelObjectKind.values()[i];
		}
		catch (Exception e) {
			System.err.println("GetKind error " + getSearchKey() + ":" + e);
		}
		return ModelObjectKind.OBJECT_ERROR;
	}

	@Override
	public Object getIntrinsicValue() {
		VARIANT.ByReference pIntrinsicData = new VARIANT.ByReference();
		HRESULT hr = jnaData.GetIntrinsicValue(pIntrinsicData);
		if (hr.equals(COMUtilsExtra.E_FAIL)) {
			return null;
		}
		COMUtils.checkRC(hr);
		return pIntrinsicData.getValue();
	}

	@Override
	public VARIANT getIntrinsicValueAs(VARTYPE vt) {
		VARIANT.ByReference pIntrinsicData = new VARIANT.ByReference();
		COMUtils.checkRC(jnaData.GetIntrinsicValueAs(vt, pIntrinsicData));
		return (VARIANT) pIntrinsicData.getValue();
	}

	@Override
	public ModelObject getKeyValue(String searchKey) {
		PointerByReference ppObject = new PointerByReference();
		PointerByReference ppMetadata = new PointerByReference();
		HRESULT hr = jnaData.GetKeyValue(new WString(searchKey), ppObject, ppMetadata);
		if (!hr.equals(new HRESULT(0)) &&
			(searchKey.equals("Parameters") || searchKey.equals("LocalVariables"))) {
			return null;
		}
		if (hr.equals(COMUtilsExtra.E_FAIL)) {
			System.err.println(searchKey + " failed");
			return null;
		}
		if (hr.equals(COMUtilsExtra.E_BOUNDS)) {
			System.err.println(searchKey + " out of bounds");
			return null;
		}
		if (hr.equals(COMUtilsExtra.E_INVALID_PARAM)) {
			Msg.debug(this, searchKey + " invalid param");
			return null;
		}
		if (hr.equals(COMUtilsExtra.E_SCOPE_NOT_FOUND)) {
			Msg.debug(this, searchKey + " scope not found");
			return null;
		}
		COMUtils.checkRC(hr);

		ModelObject retval = getObjectWithMetadata(ppObject, ppMetadata);
		retval.setSearchKey(searchKey);
		return retval;
	}

	@Override
	public void setKeyValue(WString key, ModelObject object) {
		Pointer pObject = object.getPointer();
		COMUtils.checkRC(jnaData.SetKeyValue(key, pObject));
	}

	@Override
	public KeyEnumerator enumerateKeyValues() {
		PointerByReference ppEnumerator = new PointerByReference();
		COMUtils.checkRC(jnaData.EnumerateKeyValues(ppEnumerator));

		WrapIKeyEnumerator wrap = new WrapIKeyEnumerator(ppEnumerator.getValue());
		try {
			return KeyEnumeratorInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public ModelObject getRawValue(int kind, WString name, int searchFlags) {
		ULONG ulKind = new ULONG(kind);
		ULONG ulSearchFlags = new ULONG(searchFlags);
		PointerByReference ppObject = new PointerByReference();
		COMUtils.checkRC(jnaData.GetRawValue(ulKind, name, ulSearchFlags, ppObject));

		WrapIModelObject wrap = new WrapIModelObject(ppObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public RawEnumerator enumerateRawValues(int kind, int searchFlags) {
		ULONG ulKind = new ULONG(kind);
		ULONG ulSearchFlags = new ULONG(searchFlags);
		PointerByReference ppEnumerator = new PointerByReference();
		COMUtils.checkRC(jnaData.EnumerateRawValues(ulKind, ulSearchFlags, ppEnumerator));

		WrapIRawEnumerator wrap = new WrapIRawEnumerator(ppEnumerator.getValue());
		try {
			return RawEnumeratorInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public ModelObject dereference() {
		PointerByReference ppObject = new PointerByReference();
		COMUtils.checkRC(jnaData.Dereference(ppObject));

		WrapIModelObject wrap = new WrapIModelObject(ppObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public ModelObject tryCastToRuntimeType() {
		PointerByReference ppRuntimeTypedObject = new PointerByReference();
		COMUtils.checkRC(jnaData.TryCastToRuntimeType(ppRuntimeTypedObject));

		WrapIModelObject wrap = new WrapIModelObject(ppRuntimeTypedObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public Concept getConcept(REFIID conceptId) {
		PointerByReference ppConceptInterface = new PointerByReference();
		PointerByReference ppConceptMetadata = new PointerByReference();
		HRESULT hr = jnaData.GetConcept(conceptId, ppConceptInterface, ppConceptMetadata);
		if (hr.equals(COMUtilsExtra.E_NOINTERFACE)) {
			//System.err.println("No such interface " + conceptId);
			return null;
		}
		COMUtils.checkRC(hr);

		Concept object = null;
		KeyStore mdata = null;

		Pointer value = ppConceptMetadata.getValue();
		if (value != null) {
			WrapIKeyStore wrap1 = new WrapIKeyStore(value);
			try {
				mdata = KeyStoreInternal.tryPreferredInterfaces(wrap1::QueryInterface);
			}
			finally {
				wrap1.Release();
			}
		}

		if (conceptId.getValue()
				.equals(IStringDisplayableConcept.IID_ISTRING_DISPLAYABLE_CONCEPT)) {
			WrapIStringDisplayableConcept wrap =
				new WrapIStringDisplayableConcept(ppConceptInterface.getValue());
			try {
				object =
					StringDisplayableConceptInternal.tryPreferredInterfaces(wrap::QueryInterface);
			}
			finally {
				wrap.Release();
			}
		}

		if (conceptId.getValue()
				.equals(IPreferredRuntimeTypeConcept.IID_IPREFERRED_RUNTIME_TYPE_CONCEPT)) {
			WrapIPreferredRuntimeTypeConcept wrap =
				new WrapIPreferredRuntimeTypeConcept(ppConceptInterface.getValue());
			try {
				object = PreferredRuntimeTypeConceptInternal
						.tryPreferredInterfaces(wrap::QueryInterface);
			}
			finally {
				wrap.Release();
			}
		}

		if (conceptId.getValue().equals(IIterableConcept.IID_IITERABLE_CONCEPT)) {
			WrapIIterableConcept wrap = new WrapIIterableConcept(ppConceptInterface.getValue());
			try {
				object = IterableConceptInternal.tryPreferredInterfaces(wrap::QueryInterface);
			}
			finally {
				wrap.Release();
			}
		}

		if (conceptId.getValue().equals(IIndexableConcept.IID_IINDEXABLE_CONCEPT)) {
			WrapIIndexableConcept wrap = new WrapIIndexableConcept(ppConceptInterface.getValue());
			try {
				object = IndexableConceptInternal.tryPreferredInterfaces(wrap::QueryInterface);
			}
			finally {
				wrap.Release();
			}
		}

		if (conceptId.getValue().equals(IEquatableConcept.IID_IEQUATABLE_CONCEPT)) {
			WrapIEquatableConcept wrap = new WrapIEquatableConcept(ppConceptInterface.getValue());
			try {
				object = EquatableConceptInternal.tryPreferredInterfaces(wrap::QueryInterface);
			}
			finally {
				wrap.Release();
			}
		}

		if (conceptId.getValue()
				.equals(IDynamicKeyProviderConcept.IID_IDYNAMIC_KEY_PROVIDER_CONCEPT)) {
			WrapIDynamicKeyProviderConcept wrap =
				new WrapIDynamicKeyProviderConcept(ppConceptInterface.getValue());
			try {
				object =
					DynamicKeyProviderConceptInternal.tryPreferredInterfaces(wrap::QueryInterface);
			}
			finally {
				wrap.Release();
			}
		}

		if (conceptId.getValue()
				.equals(IDynamicConceptProviderConcept.IID_IDYNAMIC_CONCEPT_PROVIDER_CONCEPT)) {
			WrapIDynamicConceptProviderConcept wrap =
				new WrapIDynamicConceptProviderConcept(ppConceptInterface.getValue());
			try {
				object = DynamicConceptProviderConceptInternal
						.tryPreferredInterfaces(wrap::QueryInterface);
			}
			finally {
				wrap.Release();
			}
		}

		if (conceptId.getValue().equals(IDataModelConcept.IID_IDATA_MODEL_CONCEPT)) {
			WrapIDataModelConcept wrap = new WrapIDataModelConcept(ppConceptInterface.getValue());
			try {
				object = DataModelConceptInternal.tryPreferredInterfaces(wrap::QueryInterface);
			}
			finally {
				wrap.Release();
			}
		}

		if (conceptId.getValue().equals(IComparableConcept.IID_ICOMPARABLE_CONCEPT)) {
			WrapIComparableConcept wrap = new WrapIComparableConcept(ppConceptInterface.getValue());
			try {
				object = ComparableConceptInternal.tryPreferredInterfaces(wrap::QueryInterface);
			}
			finally {
				wrap.Release();
			}
		}

		if (object != null && mdata != null) {
			object.setMetadata(mdata);
		}
		return object;
	}

	@Override
	public LOCATION getLocation() {
		LOCATION.ByReference pLocation = new LOCATION.ByReference();
		COMUtils.checkRC(jnaData.GetLocation(pLocation));
		return new LOCATION(pLocation);
	}

	@Override
	public DebugHostType1 getTypeInfo() {
		PointerByReference ppType = new PointerByReference();
		COMUtils.checkRC(jnaData.GetTypeInfo(ppType));

		Pointer value = ppType.getValue();
		if (value == null) {
			return null;
		}

		WrapIDebugHostType1 wrap = new WrapIDebugHostType1(value);
		try {
			return DebugHostTypeInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DebugHostType1 getTargetInfo() {
		LOCATION.ByReference pLocation = new LOCATION.ByReference();
		PointerByReference ppType = new PointerByReference();
		COMUtils.checkRC(jnaData.GetTargetInfo(pLocation, ppType));

		targetLocation = new LOCATION(pLocation);

		Pointer value = ppType.getValue();
		if (value == null) {
			return null;
		}

		WrapIDebugHostType1 wrap = new WrapIDebugHostType1(value);
		try {
			return DebugHostTypeInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public long getNumberOfParentModels() {
		ULONGLONGByReference pulNumModels = new ULONGLONGByReference();
		COMUtils.checkRC(jnaData.GetNumberOfParentModels(pulNumModels));
		return pulNumModels.getValue().longValue();
	}

	@Override
	public ModelObject getParentModel(int i) {
		ULONG ulI = new ULONG(i);
		PointerByReference ppModel = new PointerByReference();
		PointerByReference ppContextObject = new PointerByReference();
		COMUtils.checkRC(jnaData.GetParentModel(ulI, ppModel, ppContextObject));

		return getObjectWithContext(ppModel, ppContextObject);
	}

	@Override
	public void addParentModel(ModelObject model, ModelObject contextObject, boolean override) {
		Pointer pModel = model.getPointer();
		Pointer pContextObject = contextObject.getPointer();
		BOOL bOverride = new BOOL(override);
		COMUtils.checkRC(jnaData.AddParentModel(pModel, pContextObject, bOverride));
	}

	@Override
	public void removeParentModel(ModelObject model) {
		Pointer pModel = model.getPointer();
		COMUtils.checkRC(jnaData.RemoveParentModel(pModel));
	}

	@Override
	public ModelObject getKey(String searchKey) {
		WString kstr = new WString(searchKey);
		PointerByReference ppObject = new PointerByReference();
		PointerByReference ppMetadata = new PointerByReference();
		COMUtils.checkRC(jnaData.GetKey(kstr, ppObject, ppMetadata));

		ModelObject retval = getObjectWithMetadata(ppObject, ppMetadata);
		retval.setSearchKey(key);
		return retval;
	}

	@Override
	public ModelObject getKeyReference(String searchKey) {
		WString kstr = new WString(searchKey);
		PointerByReference ppObjectReference = new PointerByReference();
		PointerByReference ppMetadata = new PointerByReference();
		COMUtils.checkRC(jnaData.GetKeyReference(kstr, ppObjectReference, ppMetadata));

		ModelObject retval = getObjectWithMetadata(ppObjectReference, ppMetadata);
		retval.setSearchKey(key);
		return retval;
	}

	@Override
	public void setKey(WString key, ModelObject object, KeyStore conceptMetadata) {
		Pointer pObject = object.getPointer();
		Pointer pMetadata = conceptMetadata.getPointer();
		COMUtils.checkRC(jnaData.SetKey(key, pObject, pMetadata));
	}

	@Override
	public void clearKeys() {
		COMUtils.checkRC(jnaData.ClearKeys());
	}

	@Override
	public KeyEnumerator enumerateKeys() {
		PointerByReference ppEnumerator = new PointerByReference();
		COMUtils.checkRC(jnaData.EnumerateKeys(ppEnumerator));

		WrapIKeyEnumerator wrap = new WrapIKeyEnumerator(ppEnumerator.getValue());
		try {
			return KeyEnumeratorInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public KeyEnumerator enumerateKeyReferences() {
		PointerByReference ppEnumerator = new PointerByReference();
		COMUtils.checkRC(jnaData.EnumerateKeyReferences(ppEnumerator));

		WrapIKeyEnumerator wrap = new WrapIKeyEnumerator(ppEnumerator.getValue());
		try {
			return KeyEnumeratorInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public void setConcept(REFIID conceptId, ModelObject conceptInterface,
			ModelObject conceptMetadata) {
		Pointer pConceptInterface = conceptInterface.getPointer();
		Pointer pConceptMetadata = conceptMetadata.getPointer();
		COMUtils.checkRC(jnaData.SetConcept(conceptId, pConceptInterface, pConceptMetadata));

	}

	@Override
	public void clearConcepts() {
		COMUtils.checkRC(jnaData.ClearConcepts());
	}

	@Override
	public ModelObject getRawReference(int kind, WString name, int searchFlags) {
		ULONG ulKind = new ULONG(kind);
		ULONG ulSearchFlags = new ULONG(searchFlags);
		PointerByReference ppObject = new PointerByReference();
		COMUtils.checkRC(jnaData.GetRawValue(ulKind, name, ulSearchFlags, ppObject));

		WrapIModelObject wrap = new WrapIModelObject(ppObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public RawEnumerator enumerateRawReferences(int kind, int searchFlags) {
		ULONG ulKind = new ULONG(kind);
		ULONG ulSearchFlags = new ULONG(searchFlags);
		PointerByReference ppEnumerator = new PointerByReference();
		COMUtils.checkRC(jnaData.EnumerateRawValues(ulKind, ulSearchFlags, ppEnumerator));

		WrapIRawEnumerator wrap = new WrapIRawEnumerator(ppEnumerator.getValue());
		try {
			return RawEnumeratorInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public void setContextForDataModel(ModelObject dataModelObject, IUnknownEx context) {
		Pointer pDataModelObject = dataModelObject.getPointer();
		Pointer pContext = context.getPointer();
		COMUtils.checkRC(jnaData.SetContextForDataModel(pDataModelObject, pContext));

	}

	@Override
	public UnknownEx getContextForDataModel(ModelObject dataModelObject) {
		Pointer pDataModelObject = dataModelObject.getPointer();
		PointerByReference ppContext = new PointerByReference();
		COMUtils.checkRC(jnaData.GetContextForDataModel(pDataModelObject, ppContext));

		WrapIUnknownEx wrap = new WrapIUnknownEx(ppContext.getValue());
		try {
			return UnknownExInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public boolean compare(ModelObject contextObject, ModelObject other) {
		Pointer pOther = other.getPointer();
		BOOLByReference bEqual = new BOOLByReference();
		COMUtils.checkRC(jnaData.Compare(pOther, bEqual));
		return bEqual.getValue().booleanValue();
	}

	/***********************/
	/* CONVENIENCE METHODS */
	/***********************/

	@Override
	public KeyStore getMetadata() {
		return metadata;
	}

	@Override
	public void setMetadata(KeyStore metadata) {
		this.metadata = metadata;
	}

	public ModelObject getContextObject() {
		return contextObject;
	}

	@Override
	public void setContextObject(ModelObject context) {
		this.contextObject = context;
	}

	public LOCATION getTargetLocation() {
		return targetLocation;
	}

	public static ModelObject getObjectWithContext(PointerByReference ppObject,
			PointerByReference ppContext) {
		WrapIModelObject wrap0 = new WrapIModelObject(ppObject.getValue());
		try {
			ModelObject object = ModelObjectInternal.tryPreferredInterfaces(wrap0::QueryInterface);
			WrapIModelObject wrap1 = new WrapIModelObject(ppContext.getValue());
			try {
				ModelObject context =
					ModelObjectInternal.tryPreferredInterfaces(wrap1::QueryInterface);
				object.setContextObject(context);
			}
			finally {
				wrap1.Release();
			}
			return object;
		}
		finally {
			wrap0.Release();
		}
	}

	public static ModelObject getObjectWithMetadata(PointerByReference ppObject,
			PointerByReference ppMetadata) {
		WrapIModelObject wrap0 = new WrapIModelObject(ppObject.getValue());
		try {
			ModelObject object = ModelObjectInternal.tryPreferredInterfaces(wrap0::QueryInterface);
			Pointer value = ppMetadata.getValue();
			if (value != null) {
				WrapIKeyStore wrap1 = new WrapIKeyStore(value);
				try {
					KeyStore mdata = KeyStoreInternal.tryPreferredInterfaces(wrap1::QueryInterface);
					object.setMetadata(mdata);
				}
				finally {
					wrap1.Release();
				}
			}
			return object;
		}
		finally {
			wrap0.Release();
		}
	}

	public static UnknownEx getUnknownWithMetadata(PointerByReference ppObject,
			PointerByReference ppMetadata) {
		WrapIUnknownEx wrap0 = new WrapIUnknownEx(ppObject.getValue());
		try {
			UnknownEx object = UnknownExInternal.tryPreferredInterfaces(wrap0::QueryInterface);
			Pointer value = ppMetadata.getValue();
			if (value != null) {
				WrapIKeyStore wrap1 = new WrapIKeyStore(value);
				try {
					KeyStore mdata = KeyStoreInternal.tryPreferredInterfaces(wrap1::QueryInterface);
					((UnknownExImpl) object).setMetadata(mdata);
				}
				finally {
					wrap1.Release();
				}
			}
			return object;
		}
		finally {
			wrap0.Release();
		}
	}

	@Override
	public List<ModelObject> getElements() {
		List<ModelObject> list = new ArrayList<ModelObject>();
		REFIID ref = new REFIID(IIterableConcept.IID_IITERABLE_CONCEPT);
		IterableConcept concept = (IterableConcept) this.getConcept(ref);
		if (concept == null) {
			return list;
		}

		ModelIterator iterator = concept.getIterator(this);
		//long dim = concept.getDefaultIndexDimensionality(this);
		if (iterator != null) {
			ModelObject next;
			int i = 0;
			while ((next = iterator.getNext(1)) != null) {
				ModelObject index = iterator.getIndexers();
				if (index != null) {
					next.setIndexer(index);
				}
				else {
					next.setSearchKey(Integer.toHexString(i));
				}
				list.add(next);
				i++;
			}
		}
		return list;
	}

	@Override
	public ModelObject getChild(DataModelManager1 manager, VARIANT v) {
		REFIID ref = new REFIID(IIndexableConcept.IID_IINDEXABLE_CONCEPT);
		IndexableConcept indexable = (IndexableConcept) this.getConcept(ref);
		if (indexable == null) {
			return null;
		}
		long dimensionality = indexable.getDimensionality(this);
		Pointer[] ppIndexers = new Pointer[(int) dimensionality];
		VARIANT.ByReference vbr = new VARIANT.ByReference(v);
		ModelObject mo = manager.createIntrinsicObject(ModelObjectKind.OBJECT_INTRINSIC, vbr);
		ppIndexers[0] = mo.getPointer();
		return indexable.getAt(this, dimensionality, ppIndexers);
	}

	@Override
	public void switchTo(DataModelManager1 manager, VARIANT v) {
		Pointer[] args = new Pointer[1];
		VARIANT.ByReference vbr = new VARIANT.ByReference(v);
		ModelObject mo = manager.createIntrinsicObject(ModelObjectKind.OBJECT_INTRINSIC, vbr);
		args[0] = mo.getPointer();
		ModelMethod f = getMethod("SwitchTo");
		f.call(this, 1, args);
	}

	@Override
	public Object getValue() {
		Object val = this.getIntrinsicValue();
		if (val instanceof SHORT) {
			return ((SHORT) val).shortValue();
		}
		if (val instanceof USHORT) {
			return ((USHORT) val).shortValue();
		}
		if (val instanceof LONG) {
			return ((LONG) val).intValue();
		}
		if (val instanceof ULONG) {
			return ((ULONG) val).intValue();
		}
		if (val instanceof ULONGLONG) {
			return ((ULONGLONG) val).longValue();
		}
		return val;
	}

	@Override
	public String getValueString() {
		Object val = this.getIntrinsicValue();
		if (val instanceof SHORT) {
			return Integer.toHexString(((SHORT) val).shortValue());
		}
		if (val instanceof USHORT) {
			return Integer.toHexString(((USHORT) val).shortValue());
		}
		if (val instanceof LONG) {
			return Integer.toHexString(((LONG) val).intValue());
		}
		if (val instanceof ULONG) {
			return Integer.toHexString(((ULONG) val).intValue());
		}
		if (val instanceof ULONGLONG) {
			return Long.toHexString(((ULONGLONG) val).longValue());
		}
		return val == null ? "" : val.toString();
	}

	@Override
	public String toString() {
		REFIID ref = new REFIID(IStringDisplayableConcept.IID_ISTRING_DISPLAYABLE_CONCEPT);
		StringDisplayableConcept displayable = (StringDisplayableConcept) this.getConcept(ref);
		if (displayable == null) {
			return super.toString();
		}
		return displayable.toDisplayString(this, null);
	}

	@Override
	public synchronized Map<String, ModelObject> getKeyValueMap() {
		TreeMap<String, ModelObject> map = new TreeMap<String, ModelObject>();
		String kstr;
		KeyEnumerator enumerator = this.enumerateKeys();
		while ((kstr = enumerator.getNext()) != null) {
			ModelObject value = this.getKeyValue(kstr);
			//ModelObject v2 = enumerator.getValue();
			//if (!v2.equals(value)) {
			//	System.err.println("getKVMap: "+kstr+":"+this.getSearchKey());
			//}
			if (value != null) {
				value.setSearchKey(kstr);
				//System.err.println("kv:" + kstr + ":" + value);
				map.put(kstr, value);
			}
		}
		return map;
	}

	@Override
	public synchronized Map<String, ModelObject> getRawValueMap() {
		TreeMap<String, ModelObject> map = new TreeMap<String, ModelObject>();
		TypeKind typeKind = getTypeKind();
		if (typeKind == null) {
			return map;
		}
		SymbolKind kind = null;
		switch (typeKind) {
			case TYPE_UDT:
				kind = SymbolKind.SYMBOL_FIELD;
				break;
			case TYPE_POINTER:
				kind = SymbolKind.SYMBOL_BASE_CLASS;
				try {
					ModelObject dereference = this.dereference();
					return dereference.getRawValueMap();
				}
				catch (Exception e) {
					kind = null;
					break;
				}
			case TYPE_INTRINSIC:
			case TYPE_ARRAY:
				break;
			default:
				System.err.println(this.getSearchKey() + ":" + typeKind);
				break;
		}

		if (kind == null) {
			return map;
		}
		String kstr;
		RawEnumerator enumerator = this.enumerateRawValues(kind.ordinal(), 0);
		while ((kstr = enumerator.getNext()) != null) {
			ModelObject value = enumerator.getValue();
			value.setSearchKey(kstr);
			map.put(kstr, value);
		}
		return map;
	}

	@Override
	public TypeKind getTypeKind() {
		ModelObjectKind modelKind = getKind();
		TypeKind typeKind = null;
		if (modelKind.equals(ModelObjectKind.OBJECT_TARGET_OBJECT)) {
			DebugHostType1 targetInfo = getTargetInfo();
			typeKind = targetInfo.getTypeKind();
		}
		if (modelKind.equals(ModelObjectKind.OBJECT_INTRINSIC)) {
			DebugHostType1 typeInfo = getTypeInfo();
			if (typeInfo != null) {
				typeKind = typeInfo.getTypeKind();
			}
		}
		return typeKind;
	}

	@Override
	public ModelMethod getMethod(String name) {
		ModelObject m = getKeyValue(name);
		if (m == null || !m.getKind().equals(ModelObjectKind.OBJECT_METHOD)) {
			return null;
		}
		Unknown unk = (Unknown) m.getIntrinsicValue();
		return ModelMethodInternal.tryPreferredInterfaces(unk::QueryInterface);
	}

	@Override
	public ModelObject getIndexer() {
		return indexer;
	}

	@Override
	public void setIndexer(ModelObject indexer) {
		this.indexer = indexer;
		String str = "0x" + indexer.getValueString();
		if (!str.equals("")) {
			key = str;
		}
	}

	@Override
	public String getSearchKey() {
		if (key == null) {
			throw new RuntimeException("null key for " + this);
		}
		Map<String, ModelObject> map = getKeyValueMap();
		if (map.containsKey("BaseAddress")) {
			String valueString = map.get("BaseAddress").getValueString();
			return valueString;
		}
		if (map.containsKey("UniqueID") && map.containsKey("Id")) {
			String valueString = map.get("Id").getValueString();
			return valueString;
		}
		return key;
	}

	@Override
	public String getOriginalKey() {
		if (key == null) {
			throw new RuntimeException("null key for " + this);
		}
		return key;
	}

	@Override
	public void setSearchKey(String key) {
		this.key = key;
	}

}
