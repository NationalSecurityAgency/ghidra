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
import com.sun.jna.platform.win32.OleAuto;
import com.sun.jna.platform.win32.WTypes.BSTR;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.datamodel.script.DataModelScriptTemplate;
import agent.dbgmodel.dbgmodel.datamodel.script.DataModelScriptTemplateEnumerator;
import agent.dbgmodel.jna.dbgmodel.datamodel.script.*;

public class DataModelScriptProviderImpl implements DataModelScriptProviderInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDataModelScriptProvider jnaData;

	public DataModelScriptProviderImpl(IDataModelScriptProvider jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public String getName() {
		BSTRByReference bref = new BSTRByReference();
		COMUtils.checkRC(jnaData.GetName(bref));
		BSTR bstr = bref.getValue();
		String name = bstr.getValue();
		OleAuto.INSTANCE.SysFreeString(bstr);
		return name;
	}

	@Override
	public String getExtension() {
		BSTRByReference bref = new BSTRByReference();
		COMUtils.checkRC(jnaData.GetExtension(bref));
		BSTR bstr = bref.getValue();
		String extension = bstr.getValue();
		OleAuto.INSTANCE.SysFreeString(bstr);
		return extension;
	}

	@Override
	public DataModelScriptTemplate createScript() {
		PointerByReference ppScript = new PointerByReference();
		COMUtils.checkRC(jnaData.CreateScript(ppScript));

		WrapIDataModelScriptTemplate wrap =
			new WrapIDataModelScriptTemplate(ppScript.getValue());
		try {
			return DataModelScriptTemplateInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DataModelScriptTemplate getDefaultTemplateContent() {
		PointerByReference ppTemplateContent = new PointerByReference();
		COMUtils.checkRC(jnaData.GetDefaultTemplateContent(ppTemplateContent));

		WrapIDataModelScriptTemplate wrap =
			new WrapIDataModelScriptTemplate(ppTemplateContent.getValue());
		try {
			return DataModelScriptTemplateInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DataModelScriptTemplateEnumerator enumerateTemplates() {
		PointerByReference ppTemplateContent = new PointerByReference();
		COMUtils.checkRC(jnaData.EnumerateTemplates(ppTemplateContent));

		WrapIDataModelScriptTemplateEnumerator wrap =
			new WrapIDataModelScriptTemplateEnumerator(ppTemplateContent.getValue());
		try {
			return DataModelScriptTemplateEnumeratorInternal.tryPreferredInterfaces(
				wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}
}
