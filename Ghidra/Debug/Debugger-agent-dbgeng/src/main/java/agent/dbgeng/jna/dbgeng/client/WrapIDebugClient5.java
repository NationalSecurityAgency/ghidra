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

import com.sun.jna.*;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.event.IDebugEventCallbacksWide;
import agent.dbgeng.jna.dbgeng.io.IDebugOutputCallbacksWide;

/**
 * Wrapper class for the IDebugClient interface
 */
public class WrapIDebugClient5 extends WrapIDebugClient4 implements IDebugClient5 {
	public static class ByReference extends WrapIDebugClient5 implements Structure.ByReference {
	}

	public WrapIDebugClient5() {
	}

	public WrapIDebugClient5(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT AttachKernelWide(ULONG Flags, WString ConnectOptions) {
		return _invokeHR(VTIndices5.ATTACH_KERNEL_WIDE, getPointer(), Flags, ConnectOptions);
	}

	@Override
	public HRESULT GetKernelConnectionOptionsWide(char[] Buffer, ULONG BufferSize,
			ULONGByReference OptionsSize) {
		return _invokeHR(VTIndices5.GET_KERNEL_CONNECTION_OPTIONS_WIDE, getPointer(), Buffer,
			BufferSize, OptionsSize);
	}

	@Override
	public HRESULT SetKernelConnectionOptionsWide(WString Options) {
		return _invokeHR(VTIndices5.SET_KERNEL_CONNECTION_OPTIONS_WIDE, getPointer(), Options);
	}

	@Override
	public HRESULT StartProcessServerWide(ULONG Flags, WString Options, Pointer Reserved) {
		return _invokeHR(VTIndices5.START_PROCESS_SERVER_WIDE, getPointer(), Flags, Options,
			Reserved);
	}

	@Override
	public HRESULT ConnectProcessServerWide(WString RemoteOptions, ULONGLONGByReference Server) {
		return _invokeHR(VTIndices5.CONNECT_PROCESS_SERVER_WIDE, getPointer(), RemoteOptions,
			Server);
	}

	@Override
	public HRESULT StartServerWide(WString Options) {
		return _invokeHR(VTIndices5.START_SERVER_WIDE, getPointer(), Options);
	}

	@Override
	public HRESULT OutputServersWide(WString Options) {
		return _invokeHR(VTIndices5.OUTPUT_SERVERS_WIDE, getPointer(), Options);
	}

	@Override
	public HRESULT GetOutputCallbacksWide(Pointer Callbacks) {
		return _invokeHR(VTIndices5.GET_OUTPUT_CALLBACKS_WIDE, getPointer(), Callbacks);
	}

	@Override
	public HRESULT SetOutputCallbacksWide(IDebugOutputCallbacksWide Callbacks) {
		return _invokeHR(VTIndices5.SET_OUTPUT_CALLBACKS_WIDE, getPointer(), Callbacks);
	}

	@Override
	public HRESULT GetOutputLinePrefixWide(char[] Buffer, ULONG BufferSize,
			ULONGByReference PrefixSize) {
		return _invokeHR(VTIndices5.GET_OUTPUT_LINE_PREFIX_WIDE, getPointer(), Buffer, BufferSize,
			PrefixSize);
	}

	@Override
	public HRESULT SetOuutputLinePrefixWide(WString Prefix) {
		return _invokeHR(VTIndices5.SET_OUTPUT_LINE_PREFIX_WIDE, getPointer(), Prefix);
	}

	@Override
	public HRESULT GetIdentityWide(char[] Buffer, ULONG BufferSize, ULONGByReference IdentitySize) {
		return _invokeHR(VTIndices5.GET_IDENTITY_WIDE, getPointer(), Buffer, BufferSize,
			IdentitySize);
	}

	@Override
	public HRESULT OutputIdentityWide(ULONG OutputControl, ULONG Flags, WString Format) {
		return _invokeHR(VTIndices5.OUTPUT_IDENTITY_WIDE, getPointer(), OutputControl, Flags,
			Format);
	}

	@Override
	public HRESULT GetEventCallbacksWide(Pointer Callbacks) {
		return _invokeHR(VTIndices5.GET_EVENT_CALLBACKS_WIDE, getPointer(), Callbacks);
	}

	@Override
	public HRESULT SetEventCallbacksWide(IDebugEventCallbacksWide Callbacks) {
		return _invokeHR(VTIndices5.SET_EVENT_CALLBACKS_WIDE, getPointer(), Callbacks);
	}

	@Override
	public HRESULT CreateProcess2(ULONGLONG Server, String CommandLine, Pointer OptionsBuffer,
			ULONG OptionsBufferSize, String InitialDirectory, String Environment) {
		return _invokeHR(VTIndices5.CREATE_PROCESS2, getPointer(), Server, CommandLine,
			OptionsBuffer, OptionsBufferSize, InitialDirectory, Environment);
	}

	@Override
	public HRESULT CreateProcess2Wide(ULONGLONG Server, WString CommandLine, Pointer OptionsBuffer,
			ULONG OptionsBufferSize, WString InitialDirectory, WString Environment) {
		return _invokeHR(VTIndices5.CREATE_PROCESS2_WIDE, getPointer(), Server, CommandLine,
			OptionsBuffer, OptionsBufferSize, InitialDirectory, Environment);
	}

	@Override
	public HRESULT CreateProcessAndAttach2(ULONGLONG Server, String CommandLine,
			Pointer OptionsBuffer, ULONG OptionsBufferSize, String InitialDirectory,
			String Environment, ULONG ProcessId, ULONG AttachFlags) {
		return _invokeHR(VTIndices5.CREATE_PROCESS_AND_ATTACH2, getPointer(), Server, CommandLine,
			OptionsBuffer, OptionsBufferSize, InitialDirectory, Environment, ProcessId,
			AttachFlags);
	}

	@Override
	public HRESULT CreateProcessAndAttach2Wide(ULONGLONG Server, WString CommandLine,
			Pointer OptionsBuffer, ULONG OptionsBufferSize, WString InitialDirectory,
			WString Environment, ULONG ProcessId, ULONG AttachFlags) {
		return _invokeHR(VTIndices5.CREATE_PROCESS_AND_ATTACH2_WIDE, getPointer(), Server,
			CommandLine, OptionsBuffer, OptionsBufferSize, InitialDirectory, Environment, ProcessId,
			AttachFlags);
	}

	@Override
	public HRESULT PushOutputLinePrefix(String NewPrefix, ULONGLONGByReference Handle) {
		return _invokeHR(VTIndices5.PUSH_OUTPUT_LINE_PREFIX, getPointer(), NewPrefix, Handle);
	}

	@Override
	public HRESULT PushOutputLinePrefixWide(WString NewPrefix, ULONGLONGByReference Handle) {
		return _invokeHR(VTIndices5.PUSH_OUTPUT_LINE_PREFIX_WIDE, getPointer(), NewPrefix, Handle);
	}

	@Override
	public HRESULT PopOutputLinePrefix(ULONGLONG Handle) {
		return _invokeHR(VTIndices5.POP_OUTPUT_LINE_PREFIX, getPointer(), Handle);
	}

	@Override
	public HRESULT GetNumberInputCallbacks(ULONGByReference Count) {
		return _invokeHR(VTIndices5.GET_NUMBER_INPUT_CALLBACKS, getPointer(), Count);
	}

	@Override
	public HRESULT GetNumberOutputCallbacks(ULONGByReference Count) {
		return _invokeHR(VTIndices5.GET_NUMBER_OUTPUT_CALLBACKS, getPointer(), Count);
	}

	@Override
	public HRESULT GetNumberEventCallbacks(ULONG EventFlags, ULONGByReference Count) {
		return _invokeHR(VTIndices5.GET_NUMBER_EVENT_CALLBACKS, getPointer(), Count);
	}

	@Override
	public HRESULT GetQuitLockString(byte[] Buffer, ULONG BufferSize, ULONGByReference StringSize) {
		return _invokeHR(VTIndices5.GET_QUIT_LOCK_STRING, getPointer(), Buffer, BufferSize,
			StringSize);
	}

	@Override
	public HRESULT SetQuitLockString(String String) {
		return _invokeHR(VTIndices5.SET_QUIT_LOCK_STRING, getPointer(), String);
	}

	@Override
	public HRESULT GetQuitLockStringWide(char[] Buffer, ULONG BufferSize,
			ULONGByReference StringSize) {
		return _invokeHR(VTIndices5.GET_QUIT_LOCK_STRING_WIDE, getPointer(), Buffer, BufferSize,
			StringSize);
	}

	@Override
	public HRESULT SetQuitLockStringWide(WString String) {
		return _invokeHR(VTIndices5.SET_QUIT_LOCK_STRING_WIDE, getPointer(), String);
	}
}
