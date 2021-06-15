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
import com.sun.jna.WString;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.COMUtilsExtra;
import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.jna.dbgmodel.main.IModelPropertyAccessor;
import agent.dbgmodel.jna.dbgmodel.main.WrapIModelObject;

public class ModelPropertyAccessorImpl implements ModelPropertyAccessorInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IModelPropertyAccessor jnaData;

	public ModelPropertyAccessorImpl(IModelPropertyAccessor jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public ModelObject getValue(String key, ModelObject contextObject) {
		Pointer pContextObject = contextObject.getPointer();
		PointerByReference ppValue = new PointerByReference();
		HRESULT hr = jnaData.GetValue(new WString(key), pContextObject, ppValue);
		if (hr.equals(COMUtilsExtra.E_INVALID_PARAM)) {
			System.err.println(key + " invalid param ");
			return null;
		}
		COMUtils.checkRC(hr);

		WrapIModelObject wrap = new WrapIModelObject(ppValue.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public void setValue(String key, ModelObject contextObject, ModelObject value) {
		Pointer pContextObject = contextObject.getPointer();
		Pointer pValue = value.getPointer();
		COMUtils.checkRC(jnaData.SetValue(new WString(key), pContextObject, pValue));
	}

}
