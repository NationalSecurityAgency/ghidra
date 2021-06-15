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

import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DbgEng.OpaqueCleanable;
import agent.dbgeng.jna.dbgeng.sysobj.IDebugSystemObjects;

public class DebugSystemObjectsImpl1 implements DebugSystemObjectsInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDebugSystemObjects jnaSysobj;

	public DebugSystemObjectsImpl1(IDebugSystemObjects jnaSysobj) {
		this.cleanable = DbgEng.releaseWhenPhantom(this, jnaSysobj);
		this.jnaSysobj = jnaSysobj;
	}

	@Override
	public DebugThreadId getEventThread() {
		ULONGByReference pulId = new ULONGByReference();
		HRESULT hr = jnaSysobj.GetEventThread(pulId);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED)) {
			return new DebugThreadId(-1);
		}
		COMUtils.checkRC(hr);
		return new DebugThreadId(pulId.getValue().intValue());
	}

	@Override
	public DebugProcessId getEventProcess() {
		ULONGByReference pulId = new ULONGByReference();
		HRESULT hr = jnaSysobj.GetEventProcess(pulId);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED)) {
			return new DebugProcessId(-1);
		}
		COMUtils.checkRC(hr);
		return new DebugProcessId(pulId.getValue().intValue());
	}

	@Override
	public DebugThreadId getCurrentThreadId() {
		ULONGByReference pulId = new ULONGByReference();
		HRESULT hr = jnaSysobj.GetCurrentThreadId(pulId);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED)) {
			return new DebugThreadId(-1);
		}
		COMUtils.checkRC(hr);
		return new DebugThreadId(pulId.getValue().intValue());
	}

	@Override
	public void setCurrentThreadId(DebugThreadId id) {
		HRESULT hr = jnaSysobj.SetCurrentThreadId(new ULONG(id.id));
		if (!hr.equals(COMUtilsExtra.E_UNEXPECTED)) {
			COMUtils.checkRC(hr);
		}
	}

	@Override
	public DebugProcessId getCurrentProcessId() {
		ULONGByReference pulId = new ULONGByReference();
		HRESULT hr = jnaSysobj.GetCurrentProcessId(pulId);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED)) {
			return new DebugProcessId(-1);
		}
		COMUtils.checkRC(hr);
		return new DebugProcessId(pulId.getValue().intValue());
	}

	@Override
	public void setCurrentProcessId(DebugProcessId id) {
		HRESULT hr = jnaSysobj.SetCurrentProcessId(new ULONG(id.id));
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED)) {
			//System.err.println("Failure on setCurrentProcessId(" + id + ")");
			return;
		}
		if (hr.equals(COMUtilsExtra.E_NOINTERFACE)) {
			return;
		}
		COMUtils.checkRC(hr);
	}

	@Override
	public int getNumberThreads() {
		ULONGByReference pulNumber = new ULONGByReference();
		HRESULT hr = jnaSysobj.GetNumberThreads(pulNumber);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED)) {
			return 0;
		}
		COMUtils.checkRC(hr);
		return pulNumber.getValue().intValue();
	}

	@Override
	public int getTotalNumberThreads() {
		ULONGByReference pulTotal = new ULONGByReference();
		ULONGByReference pulLargestProcess = new ULONGByReference();
		COMUtils.checkRC(jnaSysobj.GetTotalNumberThreads(pulTotal, pulLargestProcess));
		return pulTotal.getValue().intValue();
	}

	@Override
	public List<DebugThreadId> getThreads(int start, int count) {
		if (count == 0) {
			return Collections.emptyList();
		}
		// TODO: Does dbgeng do the bounds checking?
		ULONG ulStart = new ULONG(start);
		ULONG ulCount = new ULONG(count);
		ULONG[] aulIds = new ULONG[count];
		COMUtils.checkRC(jnaSysobj.GetThreadIdsByIndex(ulStart, ulCount, aulIds, null));
		List<DebugThreadId> result = new ArrayList<>(count);
		for (int i = 0; i < count; i++) {
			result.add(new DebugThreadId(aulIds[i].intValue()));
		}
		return result;
	}

	@Override
	public DebugThreadId getThreadIdByHandle(long handle) {
		ULONGLONG ullHandle = new ULONGLONG(handle);
		ULONGByReference pulId = new ULONGByReference();
		COMUtils.checkRC(jnaSysobj.GetThreadIdByHandle(ullHandle, pulId));
		return new DebugThreadId(pulId.getValue().intValue());
	}

	@Override
	public DebugThreadId getThreadIdBySystemId(int systemId) {
		ULONG ulHandle = new ULONG(systemId);
		ULONGByReference pulId = new ULONGByReference();
		HRESULT hr = jnaSysobj.GetThreadIdBySystemId(ulHandle, pulId);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED) || hr.equals(COMUtilsExtra.E_NOTIMPLEMENTED) ||
			hr.equals(COMUtilsExtra.E_NOINTERFACE)) {
			return null;
		}
		COMUtils.checkRC(hr);
		return new DebugThreadId(pulId.getValue().intValue());
	}

	@Override
	public DebugProcessId getProcessIdByHandle(long handle) {
		ULONGLONG ullHandle = new ULONGLONG(handle);
		ULONGByReference pulId = new ULONGByReference();
		COMUtils.checkRC(jnaSysobj.GetProcessIdByHandle(ullHandle, pulId));
		return new DebugProcessId(pulId.getValue().intValue());
	}

	@Override
	public DebugProcessId getProcessIdBySystemId(int systemId) {
		ULONG ulHandle = new ULONG(systemId);
		ULONGByReference pulId = new ULONGByReference();
		HRESULT hr = jnaSysobj.GetProcessIdBySystemId(ulHandle, pulId);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED) || hr.equals(COMUtilsExtra.E_NOTIMPLEMENTED) ||
			hr.equals(COMUtilsExtra.E_NOINTERFACE)) {
			return null;
		}
		COMUtils.checkRC(hr);
		return new DebugProcessId(pulId.getValue().intValue());
	}

	@Override
	public int getNumberProcesses() {
		ULONGByReference pulNumber = new ULONGByReference();
		HRESULT hr = jnaSysobj.GetNumberProcesses(pulNumber);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED)) {
			return -1;
		}
		COMUtils.checkRC(hr);
		return pulNumber.getValue().intValue();
	}

	@Override
	public List<DebugProcessId> getProcesses(int start, int count) {
		if (count == 0) {
			return Collections.emptyList();
		}
		// TODO: Does dbgeng do the bounds checking?
		ULONG ulStart = new ULONG(start);
		ULONG ulCount = new ULONG(count);
		ULONG[] aulIds = new ULONG[count];
		COMUtils.checkRC(jnaSysobj.GetProcessIdsByIndex(ulStart, ulCount, aulIds, null));
		List<DebugProcessId> result = new ArrayList<>(count);
		for (int i = 0; i < count; i++) {
			result.add(new DebugProcessId(aulIds[i].intValue()));
		}
		return result;
	}

	@Override
	public int getCurrentThreadSystemId() {
		ULONGByReference pulSysId = new ULONGByReference();
		HRESULT hr = jnaSysobj.GetCurrentThreadSystemId(pulSysId);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED) || hr.equals(COMUtilsExtra.E_NOTIMPLEMENTED)) {
			return -1;
		}
		COMUtils.checkRC(hr);
		return pulSysId.getValue().intValue();
	}

	@Override
	public int getCurrentProcessSystemId() {
		ULONGByReference pulSysId = new ULONGByReference();
		HRESULT hr = jnaSysobj.GetCurrentProcessSystemId(pulSysId);
		if (hr.equals(COMUtilsExtra.E_UNEXPECTED) || hr.equals(COMUtilsExtra.E_NOTIMPLEMENTED)) {
			return -1;
		}
		COMUtils.checkRC(hr);
		return pulSysId.getValue().intValue();
	}

	@Override
	public DebugSessionId getEventSystem() {
		throw new UnsupportedOperationException("Not supported by this interface");
	}

	@Override
	public DebugSessionId getCurrentSystemId() {
		throw new UnsupportedOperationException("Not supported by this interface");
	}

	@Override
	public void setCurrentSystemId(DebugSessionId id) {
		throw new UnsupportedOperationException("Not supported by this interface");
	}

	@Override
	public int getNumberSystems() {
		throw new UnsupportedOperationException("Not supported by this interface");
	}

	@Override
	public List<DebugSessionId> getSystems(int start, int count) {
		throw new UnsupportedOperationException("Not supported by this interface");
	}
}
