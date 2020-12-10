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
package agent.dbgeng.jna.dbgeng.sysobj;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;

public class WrapIDebugSystemObjects3 extends WrapIDebugSystemObjects2
		implements IDebugSystemObjects3 {
	public static class ByReference extends WrapIDebugSystemObjects3
			implements Structure.ByReference {
	}

	public WrapIDebugSystemObjects3() {
	}

	public WrapIDebugSystemObjects3(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetEventSystem(ULONGByReference Id) {
		return _invokeHR(VTIndices3.GET_EVENT_SYSTEM, getPointer(), Id);
	}

	@Override
	public HRESULT GetCurrentSystemId(ULONGByReference Id) {
		return _invokeHR(VTIndices3.GET_CURRENT_SYSTEM_ID, getPointer(), Id);
	}

	@Override
	public HRESULT SetCurrentSystemId(ULONG Id) {
		return _invokeHR(VTIndices3.SET_CURRENT_SYSTEM_ID, getPointer(), Id);
	}

	@Override
	public HRESULT GetNumberSystems(ULONGByReference Number) {
		return _invokeHR(VTIndices3.GET_NUMBER_SYSTEMS, getPointer(), Number);
	}

	@Override
	public HRESULT GetSystemIdsByIndex(ULONG Start, ULONG Count, ULONG[] Ids, ULONG[] SysIds) {
		return _invokeHR(VTIndices3.GET_SYSTEM_IDS_BY_INDEX, getPointer(), Start, Count, Ids,
			SysIds);
	}

}
