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
package agent.dbgeng.impl.dbgeng.dataspaces;

import com.sun.jna.platform.win32.WinDef.ULONGLONG;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;

import agent.dbgeng.dbgeng.COMUtilsExtra;
import agent.dbgeng.jna.dbgeng.WinNTExtra.MEMORY_BASIC_INFORMATION64;
import agent.dbgeng.jna.dbgeng.dataspaces.IDebugDataSpaces2;
import ghidra.comm.util.BitmaskSet;

public class DebugDataSpacesImpl2 extends DebugDataSpacesImpl1 {
	private final IDebugDataSpaces2 jnaData;

	public DebugDataSpacesImpl2(IDebugDataSpaces2 jnaData) {
		super(jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public DebugMemoryBasicInformation queryVirtual(long offset) {
		ULONGLONG ullOffset = new ULONGLONG(offset);
		MEMORY_BASIC_INFORMATION64.ByReference pInfo = new MEMORY_BASIC_INFORMATION64.ByReference();
		HRESULT hr = jnaData.QueryVirtual(ullOffset, pInfo);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED)) {
			return null;
		}
		COMUtils.checkRC(hr);

		return new DebugMemoryBasicInformation(pInfo.BaseAddress.longValue(),
			pInfo.AllocationBase.longValue(),
			new BitmaskSet<>(PageProtection.class, pInfo.AllocationProtect.intValue()),
			pInfo.RegionSize.longValue(), PageState.byValue(pInfo.State.intValue()),
			new BitmaskSet<>(PageProtection.class, pInfo.Protect.intValue()),
			PageType.byValue(pInfo.Type.intValue()));
	}
}
