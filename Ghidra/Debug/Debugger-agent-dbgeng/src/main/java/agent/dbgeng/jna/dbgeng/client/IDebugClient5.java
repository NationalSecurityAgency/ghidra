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
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;
import agent.dbgeng.jna.dbgeng.event.IDebugEventCallbacksWide;
import agent.dbgeng.jna.dbgeng.io.IDebugOutputCallbacksWide;

public interface IDebugClient5 extends IDebugClient4 {
	final IID IID_IDEBUG_CLIENT5 = new IID("e3acb9d7-7ec2-4f0c-a0da-e81e0cbbe628");

	enum VTIndices5 implements VTableIndex {
		ATTACH_KERNEL_WIDE, //
		GET_KERNEL_CONNECTION_OPTIONS_WIDE, //
		SET_KERNEL_CONNECTION_OPTIONS_WIDE, //
		START_PROCESS_SERVER_WIDE, //
		CONNECT_PROCESS_SERVER_WIDE, //
		START_SERVER_WIDE, //
		OUTPUT_SERVERS_WIDE, //
		GET_OUTPUT_CALLBACKS_WIDE, //
		SET_OUTPUT_CALLBACKS_WIDE, //
		GET_OUTPUT_LINE_PREFIX_WIDE, //
		SET_OUTPUT_LINE_PREFIX_WIDE, //
		GET_IDENTITY_WIDE, //
		OUTPUT_IDENTITY_WIDE, //
		GET_EVENT_CALLBACKS_WIDE, //
		SET_EVENT_CALLBACKS_WIDE, //
		CREATE_PROCESS2, //
		CREATE_PROCESS2_WIDE, //
		CREATE_PROCESS_AND_ATTACH2, //
		CREATE_PROCESS_AND_ATTACH2_WIDE, //
		PUSH_OUTPUT_LINE_PREFIX, //
		PUSH_OUTPUT_LINE_PREFIX_WIDE, //
		POP_OUTPUT_LINE_PREFIX, //
		GET_NUMBER_INPUT_CALLBACKS, //
		GET_NUMBER_OUTPUT_CALLBACKS, //
		GET_NUMBER_EVENT_CALLBACKS, //
		GET_QUIT_LOCK_STRING, //
		SET_QUIT_LOCK_STRING, //
		GET_QUIT_LOCK_STRING_WIDE, //
		SET_QUIT_LOCK_STRING_WIDE, //
		;

		static int start = VTableIndex.follow(VTIndices4.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT AttachKernelWide(ULONG Flags, WString ConnectOptions);

	HRESULT GetKernelConnectionOptionsWide(char[] Buffer, ULONG BufferSize,
			ULONGByReference OptionsSize);

	HRESULT SetKernelConnectionOptionsWide(WString Options);

	HRESULT StartProcessServerWide(ULONG Flags, WString Options, Pointer Reserved);

	HRESULT ConnectProcessServerWide(WString RemoteOptions, ULONGLONGByReference Server);

	HRESULT StartServerWide(WString Options);

	HRESULT OutputServersWide(WString Options);

	HRESULT GetOutputCallbacksWide(Pointer Callbacks);

	HRESULT SetOutputCallbacksWide(IDebugOutputCallbacksWide Callbacks);

	HRESULT GetOutputLinePrefixWide(char[] Buffer, ULONG BufferSize, ULONGByReference PrefixSize);

	HRESULT SetOuutputLinePrefixWide(WString Prefix);

	HRESULT GetIdentityWide(char[] Buffer, ULONG BufferSize, ULONGByReference IdentitySize);

	HRESULT OutputIdentityWide(ULONG OutputControl, ULONG Flags, WString Format);

	HRESULT GetEventCallbacksWide(Pointer Callbacks);

	HRESULT SetEventCallbacksWide(IDebugEventCallbacksWide Callbacks);

	HRESULT CreateProcess2(ULONGLONG Server, String CommandLine, Pointer OptionsBuffer,
			ULONG OptionsBufferSize, String InitialDirectory, String Environment);

	HRESULT CreateProcess2Wide(ULONGLONG Server, WString CommandLine, Pointer OptionsBuffer,
			ULONG OptionsBufferSize, WString InitialDirectory, WString Environment);

	HRESULT CreateProcessAndAttach2(ULONGLONG Server, String CommandLine, Pointer OptionsBuffer,
			ULONG OptionsBufferSize, String InitialDirectory, String Environment, ULONG ProcessId,
			ULONG AttachFlags);

	HRESULT CreateProcessAndAttach2Wide(ULONGLONG Server, WString CommandLine,
			Pointer OptionsBuffer, ULONG OptionsBufferSize, WString InitialDirectory,
			WString Environment, ULONG ProcessId, ULONG AttachFlags);

	HRESULT PushOutputLinePrefix(String NewPrefix, ULONGLONGByReference Handle);

	HRESULT PushOutputLinePrefixWide(WString NewPrefix, ULONGLONGByReference Handle);

	HRESULT PopOutputLinePrefix(ULONGLONG Handle);

	HRESULT GetNumberInputCallbacks(ULONGByReference Count);

	HRESULT GetNumberOutputCallbacks(ULONGByReference Count);

	HRESULT GetNumberEventCallbacks(ULONG EventFlags, ULONGByReference Count);

	HRESULT GetQuitLockString(byte[] Buffer, ULONG BufferSize, ULONGByReference StringSize);

	HRESULT SetQuitLockString(String String);

	HRESULT GetQuitLockStringWide(char[] Buffer, ULONG BufferSize, ULONGByReference StringSize);

	HRESULT SetQuitLockStringWide(WString String);
}
