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

import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.IUnknown;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugSystemObjects extends IUnknown {
	final IID IID_IDEBUG_SYSTEM_OBJECTS = new IID("6b86fe2c-2c4f-4f0c-9da2-174311acc327");

	enum VTIndices implements VTableIndex {
		GET_EVENT_THREAD, //
		GET_EVENT_PROCESS, //
		GET_CURRENT_THREAD_ID, //
		SET_CURRENT_THREAD_ID, //
		GET_CURRENT_PROCESS_ID, //
		SET_CURRENT_PROCESS_ID, //
		GET_NUMBER_THREADS, //
		GET_TOTAL_NUMBER_THREADS, //
		GET_THREAD_IDS_BY_INDEX, //
		GET_THREAD_ID_BY_PROCESSOR, //
		GET_CURRENT_THREAD_DATA_OFFSET, //
		GET_THREAD_ID_BY_DATA_OFFSET, //
		GET_CURRENT_THREAD_TEB, //
		GET_THREAD_ID_BY_TEB, //
		GET_CURRENT_THREAD_SYSTEM_ID, //
		GET_THREAD_ID_BY_SYSTEM_ID, //
		GET_CURRENT_THREAD_HANDLE, //
		GET_THREAD_ID_BY_HANDLE, //
		GET_NUMBER_PROCESSES, //
		GET_PROCESS_IDS_BY_INDEX, //
		GET_CURRENT_PROCESS_DATA_OFFSET, //
		GET_PROCESS_ID_BY_DATA_OFFSET, //
		GET_CURRENT_PROCESS_PEB, //
		GET_PROCESS_ID_BY_PEB, //
		GET_CURRENT_PROCESS_SYSTEM_ID, //
		GET_PROCESS_ID_BY_SYSTEM_ID, //
		GET_CURRENT_PROCESS_HANDLE, //
		GET_PROCESS_ID_BY_HANDLE, //
		GET_CURRENT_PROCESS_EXECUTABLE_NAME, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetEventThread(ULONGByReference Id);

	HRESULT GetEventProcess(ULONGByReference Id);

	HRESULT GetCurrentThreadId(ULONGByReference Id);

	HRESULT SetCurrentThreadId(ULONG Id);

	HRESULT GetCurrentProcessId(ULONGByReference Id);

	HRESULT SetCurrentProcessId(ULONG Id);

	HRESULT GetNumberThreads(ULONGByReference Number);

	HRESULT GetTotalNumberThreads(ULONGByReference Total, ULONGByReference LargestProcess);

	HRESULT GetThreadIdsByIndex(ULONG Start, ULONG Count, ULONG[] Ids, ULONG[] SysIds);

	HRESULT GetThreadIdByHandle(ULONGLONG Handle, ULONGByReference Id);

	HRESULT GetNumberProcesses(ULONGByReference Number);

	HRESULT GetProcessIdsByIndex(ULONG Start, ULONG Count, ULONG[] Ids, ULONG[] SysIds);

	HRESULT GetProcessIdByHandle(ULONGLONG Handle, ULONGByReference Id);

	HRESULT GetCurrentThreadSystemId(ULONGByReference SysId);

	HRESULT GetCurrentProcessSystemId(ULONGByReference SysId);

	HRESULT GetThreadIdBySystemId(ULONG SystemId, ULONGByReference Id);

	HRESULT GetProcessIdBySystemId(ULONG SystemId, ULONGByReference Id);
}
