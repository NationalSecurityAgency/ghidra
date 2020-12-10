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

import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.WinNTExtra.EXCEPTION_RECORD64;
import agent.dbgeng.jna.dbgeng.breakpoint.WrapIDebugBreakpoint;

public interface IDebugEventCallbacks {
	final IID IID_IDEBUG_EVENT_CALLBACKS = new IID("337be28b-5036-4d72-b6bf-c45fbb9f2eaa");

	HRESULT GetInterestMask(ULONGByReference Mask);

	HRESULT Breakpoint(WrapIDebugBreakpoint.ByReference Bp);

	HRESULT Exception(EXCEPTION_RECORD64.ByReference Exception, ULONG FirstChance);

	HRESULT CreateThread(ULONGLONG Handle, ULONGLONG DataOffset, ULONGLONG StartOffset);

	HRESULT ExitThread(ULONG ExitCode);

	HRESULT CreateProcess(ULONGLONG ImageFileHandle, ULONGLONG Handle, ULONGLONG BaseOffset,
			ULONG ModuleSize, String ModuleName, String ImageName, ULONG CheckSum,
			ULONG TimeDateStamp, ULONGLONG InitialThreadHandle, ULONGLONG ThreadDataOffset,
			ULONGLONG StartOffset);

	HRESULT ExitProcess(ULONG ExitCode);

	HRESULT LoadModule(ULONGLONG ImageFileHandle, ULONGLONG BaseOffset, ULONG ModuleSize,
			String ModuleName, String ImageName, ULONG CheckSum, ULONG TimeDateStamp);

	HRESULT UnloadModule(String ImageBaseName, ULONGLONG BaseOffset);

	HRESULT SystemError(ULONG Error, ULONG Level);

	HRESULT SessionStatus(ULONG Status);

	HRESULT ChangeDebuggeeState(ULONG Flags, ULONGLONG Argument);

	HRESULT ChangeEngineState(ULONG Flags, ULONGLONG Argument);

	HRESULT ChangeSymbolState(ULONG Flags, ULONGLONG Argument);
}
