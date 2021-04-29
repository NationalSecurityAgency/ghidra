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
package agent.dbgeng.jna.dbgeng.client;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.event.IDebugEventContextCallbacks;

/**
 * Wrapper class for the IDebugClient interface
 */
public class WrapIDebugClient6 extends WrapIDebugClient5 implements IDebugClient6 {
	public static class ByReference extends WrapIDebugClient6 implements Structure.ByReference {
	}

	public WrapIDebugClient6() {
	}

	public WrapIDebugClient6(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT SetEventContextCallbacks(IDebugEventContextCallbacks Callbacks) {
		return _invokeHR(VTIndices6.SET_EVENT_CONTEXT_CALLBACKS, getPointer(), Callbacks);
	}
}
