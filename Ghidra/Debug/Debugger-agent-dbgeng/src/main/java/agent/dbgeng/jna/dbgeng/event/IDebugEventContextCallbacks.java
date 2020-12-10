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
package agent.dbgeng.jna.dbgeng.event;

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.WinNTExtra.EXCEPTION_RECORD64;
import agent.dbgeng.jna.dbgeng.breakpoint.WrapIDebugBreakpoint2;

public interface IDebugEventContextCallbacks {
	final IID IID_IDEBUG_EVENT_CONTEXT_CALLBACKS = new IID("61a4905b-23f9-4247-b3c5-53d087529ab7");

	HRESULT GetInterestMask(ULONGByReference Mask);

	HRESULT Breakpoint(WrapIDebugBreakpoint2.ByReference Bp, Pointer Context, ULONG ContextSize);

	HRESULT Exception(EXCEPTION_RECORD64.ByReference Exception, ULONG FirstChance, Pointer Context,
			ULONG ContextSize);

	HRESULT CreateThread(ULONGLONG Handle, ULONGLONG DataOffset, ULONGLONG StartOffset,
			Pointer Context, ULONG ContextSize);

	HRESULT ExitThread(ULONG ExitCode, Pointer Context, ULONG ContextSize);

	HRESULT CreateProcess(ULONGLONG ImageFileHandle, ULONGLONG Handle, ULONGLONG BaseOffset,
			ULONG ModuleSize, WString ModuleName, WString ImageName, ULONG CheckSum,
			ULONG TimeDateStamp, ULONGLONG InitialThreadHandle, ULONGLONG ThreadDataOffset,
			ULONGLONG StartOffset, Pointer Context, ULONG ContextSize);

	HRESULT ExitProcess(ULONG ExitCode, Pointer Context, ULONG ContextSize);

	HRESULT LoadModule(ULONGLONG ImageFileHandle, ULONGLONG BaseOffset, ULONG ModuleSize,
			WString ModuleName, WString ImageName, ULONG CheckSum, ULONG TimeDateStamp,
			Pointer Context, ULONG ContextSize);

	HRESULT UnloadModule(WString ImageBaseName, ULONGLONG BaseOffset, Pointer Context,
			ULONG ContextSize);

	HRESULT SystemError(ULONG Error, ULONG Level, Pointer Context, ULONG ContextSize);

	HRESULT SessionStatus(ULONG Status);

	HRESULT ChangeDebuggeeState(ULONG Flags, ULONGLONG Argument, Pointer Context,
			ULONG ContextSize);

	HRESULT ChangeEngineState(ULONG Flags, ULONGLONG Argument, Pointer Context, ULONG ContextSize);

	HRESULT ChangeSymbolState(ULONG Flags, ULONGLONG Argument);
}
