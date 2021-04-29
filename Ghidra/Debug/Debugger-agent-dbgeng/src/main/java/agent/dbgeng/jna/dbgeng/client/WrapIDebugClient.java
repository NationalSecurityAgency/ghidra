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
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils;
import agent.dbgeng.jna.dbgeng.event.IDebugEventCallbacks;
import agent.dbgeng.jna.dbgeng.io.IDebugInputCallbacks;
import agent.dbgeng.jna.dbgeng.io.IDebugOutputCallbacks;

/**
 * Wrapper class for the IDebugClient interface
 */
public class WrapIDebugClient extends UnknownWithUtils implements IDebugClient {
	public static class ByReference extends WrapIDebugClient implements Structure.ByReference {
	}

	public WrapIDebugClient() {
	}

	public WrapIDebugClient(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT AttachKernel(ULONG Flags, String ConnectOptions) {
		return _invokeHR(VTIndices.ATTACH_KERNEL, getPointer(), Flags, ConnectOptions);
	}

	@Override
	public HRESULT GetKernelConnectionOptions(byte[] Buffer, ULONG BufferSize,
			ULONGByReference OptionsSize) {
		return _invokeHR(VTIndices.GET_KERNEL_CONNECTION_OPTIONS, getPointer(), Buffer, BufferSize,
			OptionsSize);
	}

	@Override
	public HRESULT SetKernelConnectionOptions(String Options) {
		return _invokeHR(VTIndices.SET_KERNEL_CONNECTION_OPTIONS, getPointer(), Options);
	}

	@Override
	public HRESULT StartProcessServer(ULONG Flags, String Options, Pointer Reserved) {
		return _invokeHR(VTIndices.START_PROCESS_SERVER, getPointer(), Flags, Options, Reserved);
	}

	@Override
	public HRESULT ConnectProcessServer(String RemoteOptions, ULONGLONGByReference Server) {
		return _invokeHR(VTIndices.CONNECT_PROCESS_SERVER, getPointer(), RemoteOptions, Server);
	}

	@Override
	public HRESULT DisconnectProcessServer(ULONGLONG Server) {
		return _invokeHR(VTIndices.DISCONNECT_PROCESS_SERVER, getPointer(), Server);
	}

	@Override
	public HRESULT GetRunningProcessSystemIds(ULONGLONG Server, int[] Ids, ULONG Count,
			ULONGByReference ActualCount) {
		return _invokeHR(VTIndices.GET_RUNNING_PROCESS_SYSTEM_IDS, getPointer(), Server, Ids, Count,
			ActualCount);
	}

	@Override
	public HRESULT GetRunningProcessSystemIdByExecutableName(ULONGLONG Server, String ExeName,
			ULONG Flags, ULONGByReference Id) {
		return _invokeHR(VTIndices.GET_RUNNING_PROCESS_SYSTEM_ID_BY_EXECUTABLE_NAME, getPointer(),
			Server, ExeName, Flags, Id);
	}

	@Override
	public HRESULT GetRunningProcessDescription(ULONGLONG Server, ULONG SystemId, ULONG Flags,
			byte[] ExeName, ULONG ExeNameSize, ULONGByReference ActualExeNameSize,
			byte[] Description, ULONG DescriptionSize, ULONGByReference ActualDescriptionSize) {
		return _invokeHR(VTIndices.GET_RUNNING_PROCESS_DESCRIPTION, getPointer(), Server, SystemId,
			Flags, ExeName, ExeNameSize, ActualExeNameSize, Description, DescriptionSize,
			ActualDescriptionSize);
	}

	@Override
	public HRESULT AttachProcess(ULONGLONG Server, ULONG ProcessId, ULONG AttachFlags) {
		return _invokeHR(VTIndices.ATTACH_PROCESS, getPointer(), Server, ProcessId, AttachFlags);
	}

	@Override
	public HRESULT CreateProcess(ULONGLONG Server, String CommandLine, ULONG CreateFlags) {
		return _invokeHR(VTIndices.CREATE_PROCESS, getPointer(), Server, CommandLine, CreateFlags);
	}

	@Override
	public HRESULT CreateProcessAndAttach(ULONGLONG Server, String CommandLine, ULONG CreateFlags,
			ULONG ProcessId, ULONG AttachFlags) {
		return _invokeHR(VTIndices.CREATE_PROCESS_AND_ATTACH, getPointer(), Server, CommandLine,
			CreateFlags, ProcessId, AttachFlags);
	}

	@Override
	public HRESULT GetProcessOptions(ULONGByReference Options) {
		return _invokeHR(VTIndices.GET_PROCESS_OPTIONS, getPointer(), Options);
	}

	@Override
	public HRESULT AddProcessOptions(ULONG Options) {
		return _invokeHR(VTIndices.ADD_PROCESS_OPTIONS, getPointer(), Options);
	}

	@Override
	public HRESULT RemoveProcessOptions(ULONG Options) {
		return _invokeHR(VTIndices.REMOVE_PROCESS_OPTIONS, getPointer(), Options);
	}

	@Override
	public HRESULT SetProcessOptions(ULONG Options) {
		return _invokeHR(VTIndices.SET_PROCESS_OPTIONS, getPointer(), Options);
	}

	@Override
	public HRESULT OpenDumpFile(String DumpFile) {
		return _invokeHR(VTIndices.OPEN_DUMP_FILE, getPointer(), DumpFile);
	}

	@Override
	public HRESULT WriteDumpFile(String DumpFile, ULONG Qualifier) {
		return _invokeHR(VTIndices.WRITE_DUMP_FILE, getPointer(), DumpFile, Qualifier);
	}

	@Override
	public HRESULT ConnectSession(ULONG Flags, ULONG HistoryLimit) {
		return _invokeHR(VTIndices.CONNECTION_SESSION, getPointer(), Flags, HistoryLimit);
	}

	@Override
	public HRESULT StartServer(String Options) {
		return _invokeHR(VTIndices.START_SERVER, getPointer(), Options);
	}

	@Override
	public HRESULT OutputServers(ULONG OutputControl, String Machine, ULONG Flags) {
		return _invokeHR(VTIndices.OUTPUT_SERVERS, getPointer(), OutputControl, Machine, Flags);
	}

	@Override
	public HRESULT TerminateProcesses() {
		return _invokeHR(VTIndices.TERMINATE_PROCESSES, getPointer());
	}

	@Override
	public HRESULT DetachProcesses() {
		return _invokeHR(VTIndices.DETACH_PROCESSES, getPointer());
	}

	@Override
	public HRESULT EndSession(ULONG Flags) {
		return _invokeHR(VTIndices.END_SESSION, getPointer(), Flags);
	}

	@Override
	public HRESULT GetExitCode(ULONGByReference Code) {
		return _invokeHR(VTIndices.GET_EXIT_CODE, getPointer(), Code);
	}

	@Override
	public HRESULT DispatchCallbacks(ULONG Timeout) {
		return _invokeHR(VTIndices.DISPATCH_CALLBACKS, getPointer(), Timeout);
	}

	@Override
	public HRESULT ExitDispatch(IDebugClient Client) {
		return _invokeHR(VTIndices.EXIT_DISPATCH, getPointer(), Client);
	}

	@Override
	public HRESULT CreateClient(PointerByReference Client) {
		return _invokeHR(VTIndices.CREATE_CLIENT, getPointer(), Client);
	}

	@Override
	public HRESULT GetInputCallbacks(PointerByReference Callbacks) {
		return _invokeHR(VTIndices.GET_INPUT_CALLBACKS, getPointer(), Callbacks);
	}

	@Override
	public HRESULT SetInputCallbacks(IDebugInputCallbacks Callbacks) {
		return _invokeHR(VTIndices.SET_INPUT_CALLBACKS, getPointer(), Callbacks);
	}

	@Override
	public HRESULT GetOutputCallbacks(Pointer Callbacks) {
		return _invokeHR(VTIndices.GET_OUTPUT_CALLBACKS, getPointer(), Callbacks);
	}

	@Override
	public HRESULT SetOutputCallbacks(IDebugOutputCallbacks Callbacks) {
		return _invokeHR(VTIndices.SET_OUTPUT_CALLBACKS, getPointer(), Callbacks);
	}

	@Override
	public HRESULT GetOutputMask(ULONGByReference Mask) {
		return _invokeHR(VTIndices.GET_OUTPUT_MASK, getPointer(), Mask);
	}

	@Override
	public HRESULT SetOutputMask(ULONG Mask) {
		return _invokeHR(VTIndices.SET_OUTPUT_MASK, getPointer(), Mask);
	}

	@Override
	public HRESULT GetOtherOutputMask(IDebugClient Client, ULONGByReference Mask) {
		return _invokeHR(VTIndices.GET_OTHER_OUTPUT_MASK, getPointer(), Client, Mask);
	}

	@Override
	public HRESULT SetOtherOutputMask(IDebugClient Client, ULONG Mask) {
		return _invokeHR(VTIndices.SET_OTHER_OUTPUT_MASK, getPointer(), Client, Mask);
	}

	@Override
	public HRESULT GetOutputWidth(ULONGByReference Columns) {
		return _invokeHR(VTIndices.GET_OUTPUT_WIDTH, getPointer(), Columns);
	}

	@Override
	public HRESULT SetOutputWidth(ULONG Columns) {
		return _invokeHR(VTIndices.SET_OUTPUT_WIDTH, getPointer(), Columns);
	}

	@Override
	public HRESULT GetOutputLinePrefix(byte[] Buffer, ULONG BufferSize,
			ULONGByReference PrefixSize) {
		return _invokeHR(VTIndices.GET_OUTPUT_LINE_PREFIX, getPointer(), Buffer, BufferSize,
			PrefixSize);
	}

	@Override
	public HRESULT SetOutputLinePrefix(String Prefix) {
		return _invokeHR(VTIndices.SET_OUTPUT_LINE_PREFIX, getPointer(), Prefix);
	}

	@Override
	public HRESULT GetIdentity(byte[] Buffer, ULONG BufferSize, ULONGByReference IdentitySize) {
		return _invokeHR(VTIndices.GET_IDENTITY, getPointer(), Buffer, BufferSize, IdentitySize);
	}

	@Override
	public HRESULT OutputIdentity(ULONG OutputControl, ULONG Flags, String Format) {
		return _invokeHR(VTIndices.OUTPUT_IDENTITY, getPointer(), OutputControl, Flags, Format);
	}

	@Override
	public HRESULT GetEventCallbacks(Pointer Callbacks) {
		return _invokeHR(VTIndices.GET_EVENT_CALLBACKS, getPointer(), Callbacks);
	}

	@Override
	public HRESULT SetEventCallbacks(IDebugEventCallbacks Callbacks) {
		return _invokeHR(VTIndices.SET_EVENT_CALLBACKS, getPointer(), Callbacks);
	}

	@Override
	public HRESULT FlushCallbacks() {
		return _invokeHR(VTIndices.FLUSH_CALLBACKS, getPointer());
	}
}
