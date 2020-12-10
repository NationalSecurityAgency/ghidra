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
import com.sun.jna.WString;
import com.sun.jna.platform.win32.OleAuto;
import com.sun.jna.platform.win32.WTypes.BSTR;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.WinDef.BOOLByReference;
import com.sun.jna.platform.win32.COM.COMUtils;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.datamodel.script.DataModelScriptClient;
import agent.dbgmodel.jna.dbgmodel.datamodel.script.IDataModelScript;

public class DataModelScriptImpl implements DataModelScriptInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDataModelScript jnaData;

	public DataModelScriptImpl(IDataModelScript jnaData) {
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
		String scriptName = bstr.getValue();
		OleAuto.INSTANCE.SysFreeString(bstr);
		return scriptName;
	}

	@Override
	public void rename(WString scriptName) {
		COMUtils.checkRC(jnaData.Rename(scriptName));
	}

	@Override
	public void populate(Pointer contentStream) {
		COMUtils.checkRC(jnaData.Populate(contentStream));
	}

	@Override
	public void execute(DataModelScriptClient client) {
		Pointer pClient = client.getPointer();
		COMUtils.checkRC(jnaData.Execute(pClient));
	}

	@Override
	public void unlink() {
		COMUtils.checkRC(jnaData.Unlink());
	}

	@Override
	public boolean isInvocable() {
		BOOLByReference bIsInvocable = new BOOLByReference();
		COMUtils.checkRC(jnaData.IsInvocable(bIsInvocable));
		return bIsInvocable.getValue().booleanValue();
	}

	@Override
	public void invokeMain(DataModelScriptClient client) {
		Pointer pClient = client.getPointer();
		COMUtils.checkRC(jnaData.InvokeMain(pClient));
	}

}
