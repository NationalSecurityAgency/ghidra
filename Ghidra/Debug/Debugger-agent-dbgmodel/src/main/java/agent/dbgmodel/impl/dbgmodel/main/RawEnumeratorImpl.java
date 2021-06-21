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
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.COMUtilsExtra;
import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.impl.dbgmodel.UnknownExImpl;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.ModelObjectKind;
import agent.dbgmodel.jna.dbgmodel.main.IRawEnumerator;
import agent.dbgmodel.jna.dbgmodel.main.WrapIModelObject;

public class RawEnumeratorImpl extends UnknownExImpl implements RawEnumeratorInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IRawEnumerator jnaData;

	private ULONG kind;
	private ModelObject value;

	public RawEnumeratorImpl(IRawEnumerator jnaData) {
		super(jnaData);
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
		ULONGByReference ulKind = new ULONGByReference();
		PointerByReference ppValue = new PointerByReference();
		HRESULT hr = jnaData.GetNext(bref, ulKind, ppValue);
		if (hr.equals(COMUtilsExtra.E_BOUNDS)) {
			return null;
		}
		COMUtils.checkRC(hr);

		kind = ulKind.getValue();

		WrapIModelObject wrap = new WrapIModelObject(ppValue.getValue());
		try {
			value = ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
		BSTR bstr = bref.getValue();
		String key = bstr.getValue();
		OleAuto.INSTANCE.SysFreeString(bstr);
		return key;
	}

	@Override
	public ModelObjectKind getKind() {
		return ModelObjectKind.values()[kind.intValue()];
	}

	@Override
	public ModelObject getValue() {
		return value;
	}
}
