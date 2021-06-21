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
import com.sun.jna.platform.win32.OleAuto;
import com.sun.jna.platform.win32.WTypes.BSTR;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.COMUtilsExtra;
import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.jna.dbgmodel.main.IKeyEnumerator;

public class KeyEnumeratorImpl implements KeyEnumeratorInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IKeyEnumerator jnaData;

	private ModelObject value;

	public KeyEnumeratorImpl(IKeyEnumerator jnaData) {
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
	public String getNext() {
		BSTRByReference bref = new BSTRByReference();
		PointerByReference ppValue = new PointerByReference();
		PointerByReference ppMetaData = new PointerByReference();
		HRESULT hr = jnaData.GetNext(bref, ppValue, ppMetaData);
		if (hr.equals(COMUtilsExtra.E_BOUNDS) || hr.equals(COMUtilsExtra.E_FAIL)) {
			//System.err.println("ret null");
			return null;
		}
		COMUtils.checkRC(hr);

		Pointer val = ppValue.getValue();
		if (val != null) {
			value = ModelObjectImpl.getObjectWithMetadata(ppValue, ppMetaData);
		}
		else {
			value = null;
		}
		BSTR bstr = bref.getValue();
		String key = bstr.getValue();
		OleAuto.INSTANCE.SysFreeString(bstr);
		return key;
	}

	@Override
	public ModelObject getValue() {
		return value;
	}

}
