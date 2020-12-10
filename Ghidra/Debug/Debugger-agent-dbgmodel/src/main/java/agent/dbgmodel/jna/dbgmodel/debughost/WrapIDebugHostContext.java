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
package agent.dbgmodel.jna.dbgmodel.debughost;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef.BOOLByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;

public class WrapIDebugHostContext extends UnknownWithUtils implements IDebugHostContext {
	public static class ByReference extends WrapIDebugHostContext implements Structure.ByReference {
	}

	public WrapIDebugHostContext() {
	}

	public WrapIDebugHostContext(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT IsEqualTo(Pointer pContext, BOOLByReference pIsEqual) {
		return _invokeHR(VTIndices.IS_EQUAL_TO, getPointer(), pContext, pIsEqual);
	}

}
