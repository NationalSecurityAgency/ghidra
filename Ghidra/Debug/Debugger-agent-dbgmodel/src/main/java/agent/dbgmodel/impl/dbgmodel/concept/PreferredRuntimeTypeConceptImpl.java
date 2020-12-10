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
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.main.KeyStore;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.impl.dbgmodel.main.ModelObjectInternal;
import agent.dbgmodel.jna.dbgmodel.concept.IPreferredRuntimeTypeConcept;
import agent.dbgmodel.jna.dbgmodel.main.WrapIModelObject;

public class PreferredRuntimeTypeConceptImpl implements PreferredRuntimeTypeConceptInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IPreferredRuntimeTypeConcept jnaData;
	private KeyStore metadata;

	public PreferredRuntimeTypeConceptImpl(IPreferredRuntimeTypeConcept jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public ModelObject CastToPreferredRuntimeType(ModelObject contextObject) {
		Pointer pContextObject = contextObject.getPointer();
		PointerByReference ppObject = new PointerByReference();
		COMUtils.checkRC(jnaData.CastToPreferredRuntimeType(pContextObject, ppObject));

		WrapIModelObject wrap = new WrapIModelObject(ppObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
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
