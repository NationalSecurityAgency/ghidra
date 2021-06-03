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
import com.sun.jna.platform.win32.WinDef.ULONGLONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.COMUtilsExtra;
import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.main.*;
import agent.dbgmodel.impl.dbgmodel.main.ModelIteratorInternal;
import agent.dbgmodel.jna.dbgmodel.concept.IIterableConcept;
import agent.dbgmodel.jna.dbgmodel.main.WrapIModelIterator;

public class IterableConceptImpl implements IterableConceptInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IIterableConcept jnaData;

	private ModelIterator iterator;
	private KeyStore metadata;

	public IterableConceptImpl(IIterableConcept jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public long getDefaultIndexDimensionality(ModelObject contextObject) {
		Pointer pContextObject = contextObject.getPointer();
		ULONGLONGByReference pDimensionality = new ULONGLONGByReference();
		COMUtils.checkRC(jnaData.GetDefaultIndexDimensionality(pContextObject, pDimensionality));
		return pDimensionality.getValue().longValue();
	}

	@Override
	public ModelIterator getIterator(ModelObject contextObject) {
		Pointer pContextObject = contextObject.getPointer();
		PointerByReference ppIndexers = new PointerByReference();
		HRESULT hr = jnaData.GetIterator(pContextObject, ppIndexers);
		if (hr.equals(COMUtilsExtra.E_FAIL)) {
			return null;
		}
		if (hr.equals(COMUtilsExtra.E_COM_EXC)) {
			return null;
		}
		COMUtils.checkRC(hr);

		WrapIModelIterator wrap = new WrapIModelIterator(ppIndexers.getValue());
		try {
			return ModelIteratorInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	public ModelIterator getIterator() {
		return iterator;
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
