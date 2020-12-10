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
import agent.dbgmodel.dbgmodel.UnknownEx;
import agent.dbgmodel.impl.dbgmodel.UnknownExInternal;
import agent.dbgmodel.jna.dbgmodel.WrapIUnknownEx;
import agent.dbgmodel.jna.dbgmodel.datamodel.script.IDataModelScriptTemplate;

public class DataModelScriptTemplateImpl implements DataModelScriptTemplateInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDataModelScriptTemplate jnaData;

	public DataModelScriptTemplateImpl(IDataModelScriptTemplate jnaData) {
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
		String templateName = bstr.getValue();
		OleAuto.INSTANCE.SysFreeString(bstr);
		return templateName;
	}

	@Override
	public String getDescription() {
		BSTRByReference bref = new BSTRByReference();
		COMUtils.checkRC(jnaData.GetName(bref));
		BSTR bstr = bref.getValue();
		String templateDescription = bstr.getValue();
		OleAuto.INSTANCE.SysFreeString(bstr);
		return templateDescription;
	}

	@Override
	public UnknownEx getContent() {
		PointerByReference ppContentStream = new PointerByReference();
		COMUtils.checkRC(jnaData.GetContent(ppContentStream));

		WrapIUnknownEx wrap = new WrapIUnknownEx(ppContentStream.getValue());
		try {
			return UnknownExInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}
}
