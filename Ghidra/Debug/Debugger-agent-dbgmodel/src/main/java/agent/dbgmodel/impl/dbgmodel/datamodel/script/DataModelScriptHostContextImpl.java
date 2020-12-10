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
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.datamodel.script.DataModelScript;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.impl.dbgmodel.main.ModelObjectInternal;
import agent.dbgmodel.jna.dbgmodel.datamodel.script.IDataModelScriptHostContext;
import agent.dbgmodel.jna.dbgmodel.main.WrapIModelObject;

public class DataModelScriptHostContextImpl implements DataModelScriptHostContextInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDataModelScriptHostContext jnaData;

	public DataModelScriptHostContextImpl(IDataModelScriptHostContext jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public void notifyScriptChange(DataModelScript script, int changeKind) {
		Pointer pScript = script.getPointer();
		ULONG ulChangeKind = new ULONG(changeKind);
		COMUtils.checkRC(jnaData.NotifyScriptChange(pScript, ulChangeKind));
	}

	@Override
	public ModelObject getNamespaceObject() {
		PointerByReference ppNamespaceObject = new PointerByReference();
		COMUtils.checkRC(jnaData.GetNamespaceObject(ppNamespaceObject));

		WrapIModelObject wrap = new WrapIModelObject(ppNamespaceObject.getValue());
		try {
			return ModelObjectInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

}
