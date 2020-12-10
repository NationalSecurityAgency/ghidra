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
package agent.dbgeng.impl.dbgeng.sysobj;

import java.util.*;

import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinDef.ULONGByReference;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;

import agent.dbgeng.dbgeng.COMUtilsExtra;
import agent.dbgeng.dbgeng.DebugSessionId;
import agent.dbgeng.jna.dbgeng.sysobj.IDebugSystemObjects3;

public class DebugSystemObjectsImpl3 extends DebugSystemObjectsImpl2 {
	@SuppressWarnings("unused")
	private final IDebugSystemObjects3 jnaSysobj;

	public DebugSystemObjectsImpl3(IDebugSystemObjects3 jnaSysobj) {
		super(jnaSysobj);
		this.jnaSysobj = jnaSysobj;
	}

	@Override
	public DebugSessionId getEventSystem() {
		ULONGByReference pulId = new ULONGByReference();
		HRESULT hr = jnaSysobj.GetEventSystem(pulId);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED)) {
			return new DebugSessionId(-1);
		}
		COMUtils.checkRC(hr);
		return new DebugSessionId(pulId.getValue().intValue());
	}

	@Override
	public DebugSessionId getCurrentSystemId() {
		ULONGByReference pulId = new ULONGByReference();
		HRESULT hr = jnaSysobj.GetCurrentSystemId(pulId);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED)) {
			return new DebugSessionId(-1);
		}
		COMUtils.checkRC(hr);
		return new DebugSessionId(pulId.getValue().intValue());
	}

	@Override
	public void setCurrentSystemId(DebugSessionId id) {
		HRESULT hr = jnaSysobj.SetCurrentSystemId(new ULONG(id.id));
		if (!hr.equals(COMUtilsExtra.E_UNEXPECTED)) {
			COMUtils.checkRC(hr);
		}
	}

	@Override
	public int getNumberSystems() {
		ULONGByReference pulNumber = new ULONGByReference();
		HRESULT hr = jnaSysobj.GetNumberSystems(pulNumber);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED)) {
			return -1;
		}
		COMUtils.checkRC(hr);
		return pulNumber.getValue().intValue();
	}

	@Override
	public List<DebugSessionId> getSystems(int start, int count) {
		if (count == 0) {
			return Collections.emptyList();
		}
		// TODO: Does dbgeng do the bounds checking?
		ULONG ulStart = new ULONG(start);
		ULONG ulCount = new ULONG(count);
		ULONG[] aulIds = new ULONG[count];
		COMUtils.checkRC(jnaSysobj.GetSystemIdsByIndex(ulStart, ulCount, aulIds, null));
		List<DebugSessionId> result = new ArrayList<>(count);
		for (int i = 0; i < count; i++) {
			result.add(new DebugSessionId(aulIds[i].intValue()));
		}
		return result;
	}

}
