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
import com.sun.jna.platform.win32.WinDef.BOOLByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.main.KeyStore;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.jna.dbgmodel.concept.IEquatableConcept;

import com.sun.jna.platform.win32.COM.COMUtils;

public class EquatableConceptImpl implements EquatableConceptInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IEquatableConcept jnaData;
	private KeyStore metadata;

	public EquatableConceptImpl(IEquatableConcept jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public boolean areObjectsEqual(ModelObject contextObject, ModelObject otherObject) {
		Pointer pContextObject = contextObject.getPointer();
		Pointer pOtherObject = otherObject.getPointer();
		BOOLByReference pIsEqual = new BOOLByReference();
		COMUtils.checkRC(jnaData.AreObjectsEqual(pContextObject, pOtherObject, pIsEqual));
		return pIsEqual.getValue().booleanValue();
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
