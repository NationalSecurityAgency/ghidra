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
package agent.dbgmodel.impl.dbgmodel.concept;

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.WinDef.BOOLByReference;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.main.*;
import agent.dbgmodel.impl.dbgmodel.main.KeyEnumeratorInternal;
import agent.dbgmodel.impl.dbgmodel.main.ModelObjectImpl;
import agent.dbgmodel.jna.dbgmodel.concept.IDynamicKeyProviderConcept;
import agent.dbgmodel.jna.dbgmodel.main.WrapIKeyEnumerator;

public class DynamicKeyProviderConceptImpl implements DynamicKeyProviderConceptInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDynamicKeyProviderConcept jnaData;
	private ModelObject keyValue;
	private KeyStore metadata;

	public DynamicKeyProviderConceptImpl(IDynamicKeyProviderConcept jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public boolean getKey(ModelObject contextObject, WString key) {
		Pointer pContextObject = contextObject.getPointer();
		PointerByReference ppKeyValue = new PointerByReference();
		PointerByReference ppMetadata = new PointerByReference();
		BOOLByReference pHasKey = new BOOLByReference();
		COMUtils.checkRC(jnaData.GetKey(pContextObject, key, ppKeyValue, ppMetadata, pHasKey));

		keyValue = ModelObjectImpl.getObjectWithMetadata(ppKeyValue, ppMetadata);

		return pHasKey.getValue().booleanValue();
	}

	@Override
	public void setKey(ModelObject contextObject, WString key, ModelObject keyValue,
			KeyStore conceptMetadata) {
		Pointer pContextObject = contextObject.getPointer();
		Pointer pKeyValue = keyValue.getPointer();
		Pointer pMetadata = conceptMetadata.getPointer();
		COMUtils.checkRC(
			jnaData.SetKey(pContextObject, key, pKeyValue, pMetadata));
	}

	@Override
	public KeyEnumerator EnumerateKeys(ModelObject contextObject) {
		Pointer pContextObject = contextObject.getPointer();
		PointerByReference ppEnumerator = new PointerByReference();
		COMUtils.checkRC(jnaData.EnumerateKeys(pContextObject, ppEnumerator));

		WrapIKeyEnumerator wrap = new WrapIKeyEnumerator(ppEnumerator.getValue());
		try {
			return KeyEnumeratorInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	public ModelObject getKeyValue() {
		return keyValue;
	}

	@Override
	public KeyStore getMetadata() {
		return metadata;
	}

	@Override
	public void setMetadata(KeyStore metdata) {
		this.metadata = metdata;
	}

}
