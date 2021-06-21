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
package agent.dbgmodel.impl.dbgmodel.datamodel.script;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.COMUtilsExtra;
import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.datamodel.script.DataModelScriptTemplate;
import agent.dbgmodel.jna.dbgmodel.datamodel.script.IDataModelScriptTemplateEnumerator;
import agent.dbgmodel.jna.dbgmodel.datamodel.script.WrapIDataModelScriptTemplate;

public class DataModelScriptTemplateEnumeratorImpl
		implements DataModelScriptTemplateEnumeratorInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDataModelScriptTemplateEnumerator jnaData;

	public DataModelScriptTemplateEnumeratorImpl(IDataModelScriptTemplateEnumerator jnaData) {
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
	public DataModelScriptTemplate getNext() {
		PointerByReference ppTemplateContent = new PointerByReference();
		HRESULT hr = jnaData.GetNext(ppTemplateContent);
		if (hr.equals(COMUtilsExtra.E_BOUNDS)) {
			return null;
		}
		COMUtils.checkRC(hr);

		WrapIDataModelScriptTemplate wrap =
			new WrapIDataModelScriptTemplate(ppTemplateContent.getValue());
		try {
			return DataModelScriptTemplateInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}
}
