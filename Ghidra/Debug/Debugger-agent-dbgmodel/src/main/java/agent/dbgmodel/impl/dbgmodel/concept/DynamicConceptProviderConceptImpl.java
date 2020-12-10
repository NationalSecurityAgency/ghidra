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
import com.sun.jna.platform.win32.Guid.REFIID;
import com.sun.jna.platform.win32.WinDef.BOOLByReference;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.UnknownEx;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.main.KeyStore;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.impl.dbgmodel.UnknownExInternal;
import agent.dbgmodel.impl.dbgmodel.main.KeyStoreInternal;
import agent.dbgmodel.jna.dbgmodel.WrapIUnknownEx;
import agent.dbgmodel.jna.dbgmodel.concept.IDynamicConceptProviderConcept;
import agent.dbgmodel.jna.dbgmodel.main.WrapIKeyStore;

public class DynamicConceptProviderConceptImpl implements DynamicConceptProviderConceptInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDynamicConceptProviderConcept jnaData;

	// TODO: creates IUnknown
	//private UnknownInternal conceptInterface;
	private UnknownEx conceptInterface;
	private KeyStore conceptMetadata;
	private KeyStore metadata;

	public DynamicConceptProviderConceptImpl(IDynamicConceptProviderConcept jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public boolean getConcept(ModelObject contextObject, REFIID conceptId) {
		Pointer pContextObject = contextObject.getPointer();
		PointerByReference ppConceptInterface = new PointerByReference();
		PointerByReference ppConceptMetadata = new PointerByReference();
		BOOLByReference pHasConcept = new BOOLByReference();
		COMUtils.checkRC(jnaData.GetConcept(pContextObject, conceptId, ppConceptInterface,
			ppConceptMetadata, pHasConcept));

		WrapIUnknownEx wrap0 = new WrapIUnknownEx(ppConceptInterface.getValue());
		try {
			conceptInterface = UnknownExInternal.tryPreferredInterfaces(wrap0::QueryInterface);
		}
		finally {
			wrap0.Release();
		}
		WrapIKeyStore wrap1 = new WrapIKeyStore(ppConceptInterface.getValue());
		try {
			conceptMetadata = KeyStoreInternal.tryPreferredInterfaces(wrap1::QueryInterface);
		}
		finally {
			wrap1.Release();
		}

		return pHasConcept.getValue().booleanValue();
	}

	@Override
	public void setConcept(ModelObject contextObject, REFIID conceptId, UnknownEx conceptInterface,
			KeyStore conceptMetadata) {
		Pointer pContextObject = contextObject.getPointer();
		Pointer pConceptInterface = conceptInterface.getPointer();
		Pointer pConceptMetadata = conceptMetadata.getPointer();
		COMUtils.checkRC(
			jnaData.SetConcept(pContextObject, conceptId, pConceptInterface, pConceptMetadata));
	}

	@Override
	public void notifyParent(ModelObject parentModel) {
		Pointer pParentModel = parentModel.getPointer();
		COMUtils.checkRC(jnaData.NotifyParent(pParentModel));
	}

	@Override
	public void notifyParentChange(ModelObject parentModel) {
		Pointer pParentModel = parentModel.getPointer();
		COMUtils.checkRC(jnaData.NotifyParent(pParentModel));
	}

	@Override
	public void notifyDestruct() {
		COMUtils.checkRC(jnaData.NotifyDestruct());
	}

	public UnknownEx getConceptInterface() {
		return conceptInterface;
	}

	public KeyStore getConceptMetadata() {
		return conceptMetadata;
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
