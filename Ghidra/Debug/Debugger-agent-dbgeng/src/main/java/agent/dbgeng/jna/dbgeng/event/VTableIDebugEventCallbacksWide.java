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

import java.util.List;

import com.sun.jna.*;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.win32.StdCallLibrary;

import agent.dbgeng.jna.dbgeng.WinNTExtra.EXCEPTION_RECORD64;
import agent.dbgeng.jna.dbgeng.breakpoint.WrapIDebugBreakpoint;
import agent.dbgeng.jna.dbgeng.io.VTableIDebugInputCallbacks.*;

public class VTableIDebugEventCallbacksWide extends Structure {
	public static class ByReference extends VTableIDebugEventCallbacksWide
			implements Structure.ByReference {
	}

	public static final List<String> FIELDS = createFieldsOrder("QueryInterfaceCallback",
		"AddRefCallback", "ReleaseCallback", "GetInterestMaskCallback", "BreakpointCallback",
		"ExceptionCallback", "CreateThreadCallback", "ExitThreadCallback", "CreateProcessCallback",
		"ExitProcessCallback", "LoadModuleCallback", "UnloadModuleCallback", "SystemErrorCallback",
		"SessionStatusCallback", "ChangeDebuggeeStateCallback", "ChangeEngineStateCallback",
		"ChangeSymbolStateCallback");

	public QueryInterfaceCallback QueryInterfaceCallback;
	public AddRefCallback AddRefCallback;
	public ReleaseCallback ReleaseCallback;
	public GetInterestMaskCallback GetInterestMaskCallback;
	public BreakpointCallback BreakpointCallback;
	public ExceptionCallback ExceptionCallback;
	public CreateThreadCallback CreateThreadCallback;
	public ExitThreadCallback ExitThreadCallback;
	public CreateProcessCallback CreateProcessCallback;
	public ExitProcessCallback ExitProcessCallback;
	public LoadModuleCallback LoadModuleCallback;
	public UnloadModuleCallback UnloadModuleCallback;
	public SystemErrorCallback SystemErrorCallback;
	public SessionStatusCallback SessionStatusCallback;
	public ChangeDebuggeeStateCallback ChangeDebuggeeStateCallback;
	public ChangeEngineStateCallback ChangeEngineStateCallback;
	public ChangeSymbolStateCallback ChangeSymbolStateCallback;

	@Override
	public List<String> getFieldOrder() {
		return FIELDS;
	}

	public static interface GetInterestMaskCallback extends StdCallLibrary.StdCallCallback {
		HRESULT invoke(Pointer thisPointer, ULONGByReference Mask);
	}

	public static interface BreakpointCallback extends StdCallLibrary.StdCallCallback {
		HRESULT invoke(Pointer thisPointer, WrapIDebugBreakpoint.ByReference Bp);
	}

	public static interface ExceptionCallback extends StdCallLibrary.StdCallCallback {
		HRESULT invoke(Pointer thisPointer, EXCEPTION_RECORD64.ByReference Exception,
				ULONG FirstChance);
	}

	public static interface CreateThreadCallback extends StdCallLibrary.StdCallCallback {
		HRESULT invoke(Pointer thisPointer, ULONGLONG Handle, ULONGLONG DataOffset,
				ULONGLONG StartOffset);
	}

	public static interface ExitThreadCallback extends StdCallLibrary.StdCallCallback {
		HRESULT invoke(Pointer thisPointer, ULONG ExitCode);
	}

	public static interface CreateProcessCallback extends StdCallLibrary.StdCallCallback {
		HRESULT invoke(Pointer thisPointer, ULONGLONG ImageFileHandle, ULONGLONG Handle,
				ULONGLONG BaseOffset, ULONG ModuleSize, WString ModuleName, WString ImageName,
				ULONG CheckSum, ULONG TimeDateStamp, ULONGLONG InitialThreadHandle,
				ULONGLONG ThreadDataOffset, ULONGLONG StartOffset);
	}

	public static interface ExitProcessCallback extends StdCallLibrary.StdCallCallback {
		HRESULT invoke(Pointer thisPointer, ULONG ExitCode);
	}

	public static interface LoadModuleCallback extends StdCallLibrary.StdCallCallback {
		HRESULT invoke(Pointer thisPointer, ULONGLONG ImageFileHandle, ULONGLONG BaseOffset,
				ULONG ModuleSize, WString ModuleName, WString ImageName, ULONG CheckSum,
				ULONG TimeDateStamp);
	}

	public static interface UnloadModuleCallback extends StdCallLibrary.StdCallCallback {
		HRESULT invoke(Pointer thisPointer, WString ImageBaseName, ULONGLONG BaseOffset);
	}

	public static interface SystemErrorCallback extends StdCallLibrary.StdCallCallback {
		HRESULT invoke(Pointer thisPointer, ULONG Error, ULONG Level);
	}

	public static interface SessionStatusCallback extends StdCallLibrary.StdCallCallback {
		HRESULT invoke(Pointer thisPointer, ULONG Status);
	}

	public static interface ChangeDebuggeeStateCallback extends StdCallLibrary.StdCallCallback {
		HRESULT invoke(Pointer thisPointer, ULONG Flags, ULONGLONG Argument);
	}

	public static interface ChangeEngineStateCallback extends StdCallLibrary.StdCallCallback {
		HRESULT invoke(Pointer thisPointer, ULONG Flags, ULONGLONG Argument);
	}

	public static interface ChangeSymbolStateCallback extends StdCallLibrary.StdCallCallback {
		HRESULT invoke(Pointer thisPointer, ULONG Flags, ULONGLONG Argument);
	}
}
