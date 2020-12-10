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
package agent.dbgeng.jna.dbgeng.dataspaces;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef.ULONGLONG;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.WinNTExtra.MEMORY_BASIC_INFORMATION64;
import agent.dbgeng.jna.dbgeng.sysobj.WrapIDebugSystemObjects2;

public class WrapIDebugDataSpaces2 extends WrapIDebugDataSpaces implements IDebugDataSpaces2 {
	public static class ByReference extends WrapIDebugSystemObjects2
			implements Structure.ByReference {
	}

	public WrapIDebugDataSpaces2() {
	}

	public WrapIDebugDataSpaces2(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT QueryVirtual(ULONGLONG Offset, MEMORY_BASIC_INFORMATION64.ByReference Info) {
		return _invokeHR(VTIndices2.QUERY_VIRTUAL, getPointer(), Offset, Info);
	}
}
