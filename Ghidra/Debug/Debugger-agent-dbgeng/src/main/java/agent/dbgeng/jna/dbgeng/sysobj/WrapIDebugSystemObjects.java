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
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils;

public class WrapIDebugSystemObjects extends UnknownWithUtils implements IDebugSystemObjects {
	public static class ByReference extends WrapIDebugSystemObjects
			implements Structure.ByReference {
	}

	public WrapIDebugSystemObjects() {
	}

	public WrapIDebugSystemObjects(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetEventThread(ULONGByReference Id) {
		return _invokeHR(VTIndices.GET_EVENT_THREAD, getPointer(), Id);
	}

	@Override
	public HRESULT GetEventProcess(ULONGByReference Id) {
		return _invokeHR(VTIndices.GET_EVENT_PROCESS, getPointer(), Id);
	}

	@Override
	public HRESULT GetCurrentThreadId(ULONGByReference Id) {
		return _invokeHR(VTIndices.GET_CURRENT_THREAD_ID, getPointer(), Id);
	}

	@Override
	public HRESULT SetCurrentThreadId(ULONG Id) {
		return _invokeHR(VTIndices.SET_CURRENT_THREAD_ID, getPointer(), Id);
	}

	@Override
	public HRESULT GetCurrentProcessId(ULONGByReference Id) {
		return _invokeHR(VTIndices.GET_CURRENT_PROCESS_ID, getPointer(), Id);
	}

	@Override
	public HRESULT SetCurrentProcessId(ULONG Id) {
		return _invokeHR(VTIndices.SET_CURRENT_PROCESS_ID, getPointer(), Id);
	}

	@Override
	public HRESULT GetNumberThreads(ULONGByReference Number) {
		return _invokeHR(VTIndices.GET_NUMBER_THREADS, getPointer(), Number);
	}

	@Override
	public HRESULT GetTotalNumberThreads(ULONGByReference Total, ULONGByReference LargestProcess) {
		return _invokeHR(VTIndices.GET_TOTAL_NUMBER_THREADS, getPointer(), Total, LargestProcess);
	}

	@Override
	public HRESULT GetThreadIdsByIndex(ULONG Start, ULONG Count, ULONG[] Ids, ULONG[] SysIds) {
		return _invokeHR(VTIndices.GET_THREAD_IDS_BY_INDEX, getPointer(), Start, Count, Ids,
			SysIds);
	}

	@Override
	public HRESULT GetThreadIdByHandle(ULONGLONG Handle, ULONGByReference Id) {
		return _invokeHR(VTIndices.GET_THREAD_ID_BY_HANDLE, getPointer(), Handle, Id);
	}

	@Override
	public HRESULT GetThreadIdBySystemId(ULONG SystemId, ULONGByReference Id) {
		return _invokeHR(VTIndices.GET_THREAD_ID_BY_SYSTEM_ID, getPointer(), SystemId, Id);
	}

	@Override
	public HRESULT GetProcessIdBySystemId(ULONG SystemId, ULONGByReference Id) {
		return _invokeHR(VTIndices.GET_PROCESS_ID_BY_SYSTEM_ID, getPointer(), SystemId, Id);
	}

	@Override
	public HRESULT GetNumberProcesses(ULONGByReference Number) {
		return _invokeHR(VTIndices.GET_NUMBER_PROCESSES, getPointer(), Number);
	}

	@Override
	public HRESULT GetProcessIdsByIndex(ULONG Start, ULONG Count, ULONG[] Ids, ULONG[] SysIds) {
		return _invokeHR(VTIndices.GET_PROCESS_IDS_BY_INDEX, getPointer(), Start, Count, Ids,
			SysIds);
	}

	@Override
	public HRESULT GetProcessIdByHandle(ULONGLONG Handle, ULONGByReference Id) {
		return _invokeHR(VTIndices.GET_PROCESS_ID_BY_HANDLE, getPointer(), Handle, Id);
	}

	@Override
	public HRESULT GetCurrentThreadSystemId(ULONGByReference SysId) {
		return _invokeHR(VTIndices.GET_CURRENT_THREAD_SYSTEM_ID, getPointer(), SysId);
	}

	@Override
	public HRESULT GetCurrentProcessSystemId(ULONGByReference SysId) {
		return _invokeHR(VTIndices.GET_CURRENT_PROCESS_SYSTEM_ID, getPointer(), SysId);
	}
}
