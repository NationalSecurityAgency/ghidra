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
import com.sun.jna.WString;
import com.sun.jna.platform.win32.COM.COMUtils;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.jna.dbgmodel.debughost.IDebugHostExtensability;

public class DebugHostExtensabilityImpl implements DebugHostExtensabilityInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDebugHostExtensability jnaData;

	public DebugHostExtensabilityImpl(IDebugHostExtensability jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public void createFunctionAlias(WString aliasName, ModelObject functionObject) {
		Pointer pFunctionObject = functionObject.getPointer();
		COMUtils.checkRC(jnaData.CreateFunctionAlias(aliasName, pFunctionObject));
	}

	@Override
	public void destroyFunctionAlias(WString aliasName) {
		COMUtils.checkRC(jnaData.DestroyFunctionAlias(aliasName));
	}

}
