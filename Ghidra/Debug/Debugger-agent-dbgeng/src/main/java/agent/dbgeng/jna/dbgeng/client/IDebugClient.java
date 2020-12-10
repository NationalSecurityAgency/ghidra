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
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.IUnknown;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;
import agent.dbgeng.jna.dbgeng.event.IDebugEventCallbacks;
import agent.dbgeng.jna.dbgeng.io.IDebugInputCallbacks;
import agent.dbgeng.jna.dbgeng.io.IDebugOutputCallbacks;

public interface IDebugClient extends IUnknown {
	final IID IID_IDEBUG_CLIENT = new IID("27fe5639-8407-4f47-8364-ee118fb08ac8");

	enum VTIndices implements VTableIndex {
		ATTACH_KERNEL, //
		GET_KERNEL_CONNECTION_OPTIONS, //
		SET_KERNEL_CONNECTION_OPTIONS, //
		START_PROCESS_SERVER, //
		CONNECT_PROCESS_SERVER, // 
		DISCONNECT_PROCESS_SERVER, //
		GET_RUNNING_PROCESS_SYSTEM_IDS, //
		GET_RUNNING_PROCESS_SYSTEM_ID_BY_EXECUTABLE_NAME, //
		GET_RUNNING_PROCESS_DESCRIPTION, //
		ATTACH_PROCESS, //
		CREATE_PROCESS, //
		CREATE_PROCESS_AND_ATTACH, //
		GET_PROCESS_OPTIONS, //
		ADD_PROCESS_OPTIONS, //
		REMOVE_PROCESS_OPTIONS, //
		SET_PROCESS_OPTIONS, //
		OPEN_DUMP_FILE, //
		WRITE_DUMP_FILE, //
		CONNECTION_SESSION, //
		START_SERVER, //
		OUTPUT_SERVERS, //
		TERMINATE_PROCESSES, //
		DETACH_PROCESSES, //
		END_SESSION, //
		GET_EXIT_CODE, //
		DISPATCH_CALLBACKS, //
		EXIT_DISPATCH, //
		CREATE_CLIENT, //
		GET_INPUT_CALLBACKS, //
		SET_INPUT_CALLBACKS, //
		GET_OUTPUT_CALLBACKS, //
		SET_OUTPUT_CALLBACKS, //
		GET_OUTPUT_MASK, //
		SET_OUTPUT_MASK, //
		GET_OTHER_OUTPUT_MASK, //
		SET_OTHER_OUTPUT_MASK, //
		GET_OUTPUT_WIDTH, //
		SET_OUTPUT_WIDTH, //
		GET_OUTPUT_LINE_PREFIX, //
		SET_OUTPUT_LINE_PREFIX, //
		GET_IDENTITY, //
		OUTPUT_IDENTITY, //
		GET_EVENT_CALLBACKS, //
		SET_EVENT_CALLBACKS, //
		FLUSH_CALLBACKS, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT AttachKernel(ULONG Flags, String ConnectOptions);

	HRESULT GetKernelConnectionOptions(byte[] Buffer, ULONG BufferSize,
			ULONGByReference OptionsSize);

	HRESULT SetKernelConnectionOptions(String Options);

	HRESULT StartProcessServer(ULONG Flags, String Options, Pointer Reserved);

	HRESULT ConnectProcessServer(String RemoteOptions, ULONGLONGByReference Server);

	HRESULT DisconnectProcessServer(ULONGLONG Server);

	HRESULT GetRunningProcessSystemIds(ULONGLONG Server, int[] Ids, ULONG Count,
			ULONGByReference ActualCount);

	HRESULT GetRunningProcessSystemIdByExecutableName(ULONGLONG Server, String ExeName, ULONG Flags,
			ULONGByReference Id);

	HRESULT GetRunningProcessDescription(ULONGLONG Server, ULONG SystemId, ULONG Flags,
			byte[] ExeName, ULONG ExeNameSize, ULONGByReference ActualExeNameSize,
			byte[] Description, ULONG DescriptionSize, ULONGByReference ActualDescriptionSize);

	HRESULT AttachProcess(ULONGLONG Server, ULONG ProcessId, ULONG AttachFlags);

	HRESULT CreateProcess(ULONGLONG Server, String CommandLine, ULONG CreateFlags);

	HRESULT CreateProcessAndAttach(ULONGLONG Server, String CommandLine, ULONG CreateFlags,
			ULONG pid, ULONG AttachFlags);

	HRESULT GetProcessOptions(ULONGByReference Options);

	HRESULT AddProcessOptions(ULONG Options);

	HRESULT RemoveProcessOptions(ULONG Options);

	HRESULT SetProcessOptions(ULONG Options);

	HRESULT OpenDumpFile(String DumpFile);

	HRESULT WriteDumpFile(String DumpFile, ULONG Qualifier);

	HRESULT ConnectSession(ULONG Flags, ULONG HistoryLimit);

	HRESULT StartServer(String Options);

	HRESULT OutputServers(ULONG OutputControl, String Machine, ULONG Flags);

	HRESULT TerminateProcesses();

	HRESULT DetachProcesses();

	HRESULT EndSession(ULONG Flags);

	HRESULT GetExitCode(ULONGByReference Code);

	HRESULT DispatchCallbacks(ULONG Timeout);

	HRESULT ExitDispatch(IDebugClient Client);

	HRESULT CreateClient(PointerByReference Client);

	HRESULT GetInputCallbacks(PointerByReference Callbacks);

	HRESULT SetInputCallbacks(IDebugInputCallbacks Callbacks);

	HRESULT GetOutputCallbacks(Pointer Callbacks);

	HRESULT SetOutputCallbacks(IDebugOutputCallbacks Callbacks);

	HRESULT GetOutputMask(ULONGByReference Mask);

	HRESULT SetOutputMask(ULONG Mask);

	HRESULT GetOtherOutputMask(IDebugClient Client, ULONGByReference Mask);

	HRESULT SetOtherOutputMask(IDebugClient Client, ULONG Mask);

	HRESULT GetOutputWidth(ULONGByReference Columns);

	HRESULT SetOutputWidth(ULONG Columns);

	HRESULT GetOutputLinePrefix(byte[] Buffer, ULONG BufferSize, ULONGByReference PrefixSize);

	HRESULT SetOutputLinePrefix(String Prefix);

	HRESULT GetIdentity(byte[] Buffer, ULONG BufferSize, ULONGByReference IdentitySize);

	HRESULT OutputIdentity(ULONG OutputControl, ULONG Flags, String Format);

	HRESULT GetEventCallbacks(Pointer Callbacks);

	HRESULT SetEventCallbacks(IDebugEventCallbacks Callbacks);

	HRESULT FlushCallbacks();
}
