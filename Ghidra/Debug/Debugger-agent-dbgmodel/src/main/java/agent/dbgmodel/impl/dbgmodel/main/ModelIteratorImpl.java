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

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinDef.ULONGLONG;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.COMUtilsExtra;
import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.jna.dbgmodel.main.IModelIterator;
import agent.dbgmodel.jna.dbgmodel.main.WrapIModelObject;

public class ModelIteratorImpl implements ModelIteratorInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IModelIterator jnaData;

	private ModelObject indexers;

	public ModelIteratorImpl(IModelIterator jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public void reset() {
		COMUtils.checkRC(jnaData.Reset());
	}

	@Override
	public ModelObject getNext(long dimensions) {
		PointerByReference ppObject = new PointerByReference();
		ULONGLONG ulDimensions = new ULONGLONG(dimensions);
		PointerByReference ppIndexers = new PointerByReference();
		PointerByReference ppMetadata = new PointerByReference();
		HRESULT hr = jnaData.GetNext(ppObject, ulDimensions, ppIndexers, ppMetadata);
		if (hr.equals(COMUtilsExtra.E_BOUNDS)) {
			return null;
		}
		COMUtils.checkRC(hr);

		if (ppIndexers.getValue() != null) {
			WrapIModelObject wrap = new WrapIModelObject(ppIndexers.getValue());
			try {
				indexers = ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
			}
			finally {
				wrap.Release();
			}
		}

		return ModelObjectImpl.getObjectWithMetadata(ppObject, ppMetadata);
	}

	@Override
	public ModelObject getIndexers() {
		return indexers;
	}

}
