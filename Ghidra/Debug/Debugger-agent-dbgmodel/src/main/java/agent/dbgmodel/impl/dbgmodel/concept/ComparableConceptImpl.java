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
import com.sun.jna.platform.win32.WinDef.ULONGByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.main.KeyStore;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.jna.dbgmodel.concept.IComparableConcept;

import com.sun.jna.platform.win32.COM.COMUtils;

public class ComparableConceptImpl implements ComparableConceptInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IComparableConcept jnaData;
	private KeyStore metadata;

	public ComparableConceptImpl(IComparableConcept jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public int compareObjects(ModelObject contextObject, ModelObject otherObject) {
		Pointer pContextObject = contextObject.getPointer();
		Pointer pOtherObject = otherObject.getPointer();
		ULONGByReference pulComparisonResult = new ULONGByReference();
		COMUtils.checkRC(jnaData.CompareObjects(pContextObject, pOtherObject, pulComparisonResult));
		return pulComparisonResult.getValue().intValue();
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
