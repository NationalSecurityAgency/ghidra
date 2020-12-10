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
import com.sun.jna.platform.win32.OleAuto;
import com.sun.jna.platform.win32.WTypes.BSTR;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.COM.COMUtils;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.debughost.DebugHostSymbolEnumerator;
import agent.dbgmodel.dbgmodel.debughost.DebugHostTypeSignature;
import agent.dbgmodel.dbgmodel.main.KeyStore;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.jna.dbgmodel.concept.IDataModelConcept;

public class DataModelConceptImpl implements DataModelConceptInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDataModelConcept jnaData;
	private KeyStore metadata;

	public DataModelConceptImpl(IDataModelConcept jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public void initializeObject(ModelObject modelObject,
			DebugHostTypeSignature matchingTypeSignature,
			DebugHostSymbolEnumerator wildcardMatches) {
		Pointer pModelObject = modelObject.getPointer();
		Pointer pMatchingTypeSignature = matchingTypeSignature.getPointer();
		Pointer pWildcardMatches = wildcardMatches.getPointer();
		COMUtils.checkRC(
			jnaData.InitializeObject(pModelObject, pMatchingTypeSignature, pWildcardMatches));
	}

	@Override
	public String getName() {
		BSTRByReference bref = new BSTRByReference();
		COMUtils.checkRC(jnaData.GetName(bref));
		BSTR bstr = bref.getValue();
		String modelName = bstr.getValue();
		OleAuto.INSTANCE.SysFreeString(bstr);
		return modelName;
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
