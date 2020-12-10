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
import com.sun.jna.platform.win32.WinDef.ULONGLONG;
import com.sun.jna.platform.win32.WinDef.ULONGLONGByReference;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.main.KeyStore;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.impl.dbgmodel.main.ModelObjectImpl;
import agent.dbgmodel.jna.dbgmodel.concept.IIndexableConcept;

public class IndexableConceptImpl implements IndexableConceptInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IIndexableConcept jnaData;

	private ModelObject indexers;
	private KeyStore metadata;

	public IndexableConceptImpl(IIndexableConcept jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public long getDimensionality(ModelObject contextObject) {
		Pointer pContextObject = contextObject.getPointer();
		ULONGLONGByReference pDimensionality = new ULONGLONGByReference();
		COMUtils.checkRC(jnaData.GetDimensionality(pContextObject, pDimensionality));
		return pDimensionality.getValue().longValue();
	}

	@Override
	public ModelObject getAt(ModelObject contextObject, long indexerCount,
			Pointer[] ppIndexers) {
		Pointer pContextObject = contextObject.getPointer();
		ULONGLONG ulIndexerCount = new ULONGLONG(indexerCount);
		PointerByReference ppObject = new PointerByReference();
		PointerByReference ppMetadata = new PointerByReference();
		COMUtils.checkRC(
			jnaData.GetAt(pContextObject, ulIndexerCount, ppIndexers,
				ppObject, ppMetadata));

		return ModelObjectImpl.getObjectWithMetadata(ppObject, ppMetadata);
	}

	public ModelObject getIndexers() {
		return indexers;
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
