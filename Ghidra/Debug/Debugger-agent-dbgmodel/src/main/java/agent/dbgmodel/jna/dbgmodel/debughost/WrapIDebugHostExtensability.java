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

import com.sun.jna.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;

public class WrapIDebugHostExtensability extends UnknownWithUtils
		implements IDebugHostExtensability {
	public static class ByReference extends WrapIDebugHostExtensability
			implements Structure.ByReference {
	}

	public WrapIDebugHostExtensability() {
	}

	public WrapIDebugHostExtensability(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT CreateFunctionAlias(WString aliasName, Pointer functionObject) {
		return _invokeHR(VTIndices.CREATE_FUNCTION_ALIAS, getPointer(), aliasName, functionObject);
	}

	@Override
	public HRESULT DestroyFunctionAlias(WString aliasName) {
		return _invokeHR(VTIndices.DESTROY_FUNCTION_ALIAS, getPointer(), aliasName);
	}

}
