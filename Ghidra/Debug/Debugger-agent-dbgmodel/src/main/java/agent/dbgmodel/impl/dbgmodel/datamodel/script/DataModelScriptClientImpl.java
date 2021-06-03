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
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.jna.dbgmodel.datamodel.script.IDataModelScriptClient;

import com.sun.jna.platform.win32.COM.COMUtils;

public class DataModelScriptClientImpl implements DataModelScriptClientInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDataModelScriptClient jnaData;

	public DataModelScriptClientImpl(IDataModelScriptClient jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public void reportError(int errorClass, HRESULT hrFail, WString message,
			int line, int position) {
		ULONG ulErrorClass = new ULONG(errorClass);
		ULONG ulLine = new ULONG(line);
		ULONG ulPosition = new ULONG(position);
		COMUtils.checkRC(
			jnaData.ReportError(ulErrorClass, hrFail, message, ulLine, ulPosition));
	}
}
