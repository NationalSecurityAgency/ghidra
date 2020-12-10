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

import agent.dbgeng.jna.dbgeng.WinNTExtra.EXCEPTION_RECORD64;
import agent.dbgeng.jna.dbgeng.breakpoint.WrapIDebugBreakpoint2;

public class ListenerIDebugEventContextCallbacks extends Structure
		implements IDebugEventContextCallbacks, MarkerEventCallbacks {
	public static final List<String> FIELDS = createFieldsOrder("vtbl");

	public ListenerIDebugEventContextCallbacks(CallbackIDebugEventContextCallbacks callback) {
		this.vtbl = this.constructVTable();
		this.initVTable(callback);
		super.write();
	}

	public VTableIDebugEventContextCallbacks.ByReference vtbl;

	@Override
	protected List<String> getFieldOrder() {
		return FIELDS;
	}

	protected VTableIDebugEventContextCallbacks.ByReference constructVTable() {
		return new VTableIDebugEventContextCallbacks.ByReference();
	}

	protected void initVTable(final CallbackIDebugEventContextCallbacks callback) {
		vtbl.QueryInterfaceCallback = (thisPointer, refid, ppvObject) -> {
			return callback.QueryInterface(refid, ppvObject);
		};
		vtbl.AddRefCallback = (thisPointer) -> {
			return callback.AddRef();
		};
		vtbl.ReleaseCallback = (thisPointer) -> {
			return callback.Release();
		};
		vtbl.GetInterestMaskCallback = (thisPointer, Mask) -> {
			return callback.GetInterestMask(Mask);
		};
		vtbl.BreakpointCallback = (thisPointer, Bp, Context, ContextSize) -> {
			return callback.Breakpoint(Bp, Context, ContextSize);
		};
		vtbl.ExceptionCallback = (thisPointer, Exception, FirstChance, Context, ContextSize) -> {
			return callback.Exception(Exception, FirstChance, Context, ContextSize);
		};
		vtbl.CreateThreadCallback =
			(thisPointer, Handle, DataOffset, StartOffset, Context, ContextSize) -> {
				return callback.CreateThread(Handle, DataOffset, StartOffset, Context, ContextSize);
			};
		vtbl.ExitThreadCallback = (thisPointer, ExitCode, Context, ContextSize) -> {
			return callback.ExitThread(ExitCode, Context, ContextSize);
		};
		vtbl.CreateProcessCallback = (thisPointer, ImageFileHandle, Handle, BaseOffset, ModuleSize,
				ModuleName, ImageName, CheckSum, TimeDateStamp, InitialThreadHandle,
				ThreadDataOffset, StartOffset, Context, ContextSize) -> {
			return callback.CreateProcess(ImageFileHandle, Handle, BaseOffset, ModuleSize,
				ModuleName, ImageName, CheckSum, TimeDateStamp, InitialThreadHandle,
				ThreadDataOffset, StartOffset, Context, ContextSize);
		};
		vtbl.ExitProcessCallback = (thisPointer, ExitCode, Context, ContextSize) -> {
			return callback.ExitProcess(ExitCode, Context, ContextSize);
		};
		vtbl.LoadModuleCallback = (thisPointer, ImageFileHandle, BaseOffset, ModuleSize, ModuleName,
				ImageName, CheckSum, TimeDateStamp, Context, ContextSize) -> {
			return callback.LoadModule(ImageFileHandle, BaseOffset, ModuleSize, ModuleName,
				ImageName, CheckSum, TimeDateStamp, Context, ContextSize);
		};
		vtbl.UnloadModuleCallback =
			(thisPointer, ImageBaseName, BaseOffset, Context, ContextSize) -> {
				return callback.UnloadModule(ImageBaseName, BaseOffset, Context, ContextSize);
			};
		vtbl.SystemErrorCallback = (thisPointer, Error, Level, Context, ContextSize) -> {
			return callback.SystemError(Error, Level, Context, ContextSize);
		};
		vtbl.SessionStatusCallback = (thisPointer, Status) -> {
			return callback.SessionStatus(Status);
		};
		vtbl.ChangeDebuggeeStateCallback = (thisPointer, Flags, Argument, Context, ContextSize) -> {
			return callback.ChangeDebuggeeState(Flags, Argument, Context, ContextSize);
		};
		vtbl.ChangeEngineStateCallback = (thisPointer, Flags, Argument, Context, ContextSize) -> {
			return callback.ChangeEngineState(Flags, Argument, Context, ContextSize);
		};
		vtbl.ChangeSymbolStateCallback = (thisPointer, Flags, Argument) -> {
			return callback.ChangeSymbolState(Flags, Argument);
		};
	}

	@Override
	public HRESULT GetInterestMask(ULONGByReference Mask) {
		return vtbl.GetInterestMaskCallback.invoke(getPointer(), Mask);
	}

	@Override
	public HRESULT Breakpoint(WrapIDebugBreakpoint2.ByReference Bp, Pointer Context,
			ULONG ContextSize) {
		return vtbl.BreakpointCallback.invoke(getPointer(), Bp, Context, ContextSize);
	}

	@Override
	public HRESULT Exception(EXCEPTION_RECORD64.ByReference Exception, ULONG FirstChance,
			Pointer Context, ULONG ContextSize) {
		return vtbl.ExceptionCallback.invoke(getPointer(), Exception, FirstChance, Context,
			ContextSize);
	}

	@Override
	public HRESULT CreateThread(ULONGLONG Handle, ULONGLONG DataOffset, ULONGLONG StartOffset,
			Pointer Context, ULONG ContextSize) {
		return vtbl.CreateThreadCallback.invoke(getPointer(), Handle, DataOffset, StartOffset,
			Context, ContextSize);
	}

	@Override
	public HRESULT ExitThread(ULONG ExitCode, Pointer Context, ULONG ContextSize) {
		return vtbl.ExitThreadCallback.invoke(getPointer(), ExitCode, Context, ContextSize);
	}

	@Override
	public HRESULT CreateProcess(ULONGLONG ImageFileHandle, ULONGLONG Handle, ULONGLONG BaseOffset,
			ULONG ModuleSize, WString ModuleName, WString ImageName, ULONG CheckSum,
			ULONG TimeDateStamp, ULONGLONG InitialThreadHandle, ULONGLONG ThreadDataOffset,
			ULONGLONG StartOffset, Pointer Context, ULONG ContextSize) {
		return vtbl.CreateProcessCallback.invoke(getPointer(), ImageFileHandle, Handle, BaseOffset,
			ModuleSize, ModuleName, ImageName, CheckSum, TimeDateStamp, InitialThreadHandle,
			ThreadDataOffset, StartOffset, Context, ContextSize);
	}

	@Override
	public HRESULT ExitProcess(ULONG ExitCode, Pointer Context, ULONG ContextSize) {
		return vtbl.ExitProcessCallback.invoke(getPointer(), ExitCode, Context, ContextSize);
	}

	@Override
	public HRESULT LoadModule(ULONGLONG ImageFileHandle, ULONGLONG BaseOffset, ULONG ModuleSize,
			WString ModuleName, WString ImageName, ULONG CheckSum, ULONG TimeDateStamp,
			Pointer Context, ULONG ContextSize) {
		return vtbl.LoadModuleCallback.invoke(getPointer(), ImageFileHandle, BaseOffset, ModuleSize,
			ModuleName, ImageName, CheckSum, TimeDateStamp, Context, ContextSize);
	}

	@Override
	public HRESULT UnloadModule(WString ImageBaseName, ULONGLONG BaseOffset, Pointer Context,
			ULONG ContextSize) {
		return vtbl.UnloadModuleCallback.invoke(getPointer(), ImageBaseName, BaseOffset, Context,
			ContextSize);
	}

	@Override
	public HRESULT SystemError(ULONG Error, ULONG Level, Pointer Context, ULONG ContextSize) {
		return vtbl.SystemErrorCallback.invoke(getPointer(), Error, Level, Context, ContextSize);
	}

	@Override
	public HRESULT SessionStatus(ULONG Status) {
		return vtbl.SessionStatusCallback.invoke(getPointer(), Status);
	}

	@Override
	public HRESULT ChangeDebuggeeState(ULONG Flags, ULONGLONG Argument, Pointer Context,
			ULONG ContextSize) {
		return vtbl.ChangeDebuggeeStateCallback.invoke(getPointer(), Flags, Argument, Context,
			ContextSize);
	}

	@Override
	public HRESULT ChangeEngineState(ULONG Flags, ULONGLONG Argument, Pointer Context,
			ULONG ContextSize) {
		return vtbl.ChangeEngineStateCallback.invoke(getPointer(), Flags, Argument, Context,
			ContextSize);
	}

	@Override
	public HRESULT ChangeSymbolState(ULONG Flags, ULONGLONG Argument) {
		return vtbl.ChangeSymbolStateCallback.invoke(getPointer(), Flags, Argument);
	}
}
