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
package agent.dbgmodel.impl.dbgmodel.debughost;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.datamodel.script.DataModelScript;
import agent.dbgmodel.dbgmodel.debughost.DebugHostContext;
import agent.dbgmodel.jna.dbgmodel.debughost.IDebugHostScriptHost;
import agent.dbgmodel.jna.dbgmodel.debughost.WrapIDebugHostContext;

public class DebugHostScriptHostImpl implements DebugHostScriptHostInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDebugHostScriptHost jnaData;

	public DebugHostScriptHostImpl(IDebugHostScriptHost jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public DebugHostContext createContext(DataModelScript script) {
		Pointer pScript = script.getPointer();
		PointerByReference ppScriptContext = new PointerByReference();
		COMUtils.checkRC(jnaData.CreateContext(pScript, ppScriptContext));

		WrapIDebugHostContext wrap = new WrapIDebugHostContext(ppScriptContext.getValue());
		try {
			return DebugHostContextInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

}
