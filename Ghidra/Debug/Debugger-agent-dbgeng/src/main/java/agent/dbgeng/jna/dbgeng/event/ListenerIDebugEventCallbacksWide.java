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

import com.sun.jna.Structure;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.WinNTExtra.EXCEPTION_RECORD64;
import agent.dbgeng.jna.dbgeng.breakpoint.WrapIDebugBreakpoint;

public class ListenerIDebugEventCallbacksWide extends Structure
		implements IDebugEventCallbacksWide, MarkerEventCallbacks {
	public static final List<String> FIELDS = createFieldsOrder("vtbl");

	public ListenerIDebugEventCallbacksWide(CallbackIDebugEventCallbacksWide callback) {
		this.vtbl = this.constructVTable();
		this.initVTable(callback);
		super.write();
	}

	public VTableIDebugEventCallbacksWide.ByReference vtbl;

	@Override
	protected List<String> getFieldOrder() {
		return FIELDS;
	}

	protected VTableIDebugEventCallbacksWide.ByReference constructVTable() {
		return new VTableIDebugEventCallbacksWide.ByReference();
	}

	protected void initVTable(final CallbackIDebugEventCallbacksWide callback) {
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
		vtbl.BreakpointCallback = (thisPointer, Bp) -> {
			return callback.Breakpoint(Bp);
		};
		vtbl.ExceptionCallback = (thisPointer, Exception, FirstChance) -> {
			return callback.Exception(Exception, FirstChance);
		};
		vtbl.CreateThreadCallback = (thisPointer, Handle, DataOffset, StartOffset) -> {
			return callback.CreateThread(Handle, DataOffset, StartOffset);
		};
		vtbl.ExitThreadCallback = (thisPointer, ExitCode) -> {
			return callback.ExitThread(ExitCode);
		};
		vtbl.CreateProcessCallback = (thisPointer, ImageFileHandle, Handle, BaseOffset, ModuleSize,
				ModuleName, ImageName, CheckSum, TimeDateStamp, InitialThreadHandle,
				ThreadDataOffset, StartOffset) -> {
			return callback.CreateProcess(ImageFileHandle, Handle, BaseOffset, ModuleSize,
				ModuleName, ImageName, CheckSum, TimeDateStamp, InitialThreadHandle,
				ThreadDataOffset, StartOffset);
		};
		vtbl.ExitProcessCallback = (thisPointer, ExitCode) -> {
			return callback.ExitProcess(ExitCode);
		};
		vtbl.LoadModuleCallback = (thisPointer, ImageFileHandle, BaseOffset, ModuleSize, ModuleName,
				ImageName, CheckSum, TimeDateStamp) -> {
			return callback.LoadModule(ImageFileHandle, BaseOffset, ModuleSize, ModuleName,
				ImageName, CheckSum, TimeDateStamp);
		};
		vtbl.UnloadModuleCallback = (thisPointer, ImageBaseName, BaseOffset) -> {
			return callback.UnloadModule(ImageBaseName, BaseOffset);
		};
		vtbl.SystemErrorCallback = (thisPointer, Error, Level) -> {
			return callback.SystemError(Error, Level);
		};
		vtbl.SessionStatusCallback = (thisPointer, Status) -> {
			return callback.SessionStatus(Status);
		};
		vtbl.ChangeDebuggeeStateCallback = (thisPointer, Flags, Argument) -> {
			return callback.ChangeDebuggeeState(Flags, Argument);
		};
		vtbl.ChangeEngineStateCallback = (thisPointer, Flags, Argument) -> {
			return callback.ChangeEngineState(Flags, Argument);
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
	public HRESULT Breakpoint(WrapIDebugBreakpoint.ByReference Bp) {
		return vtbl.BreakpointCallback.invoke(getPointer(), Bp);
	}

	@Override
	public HRESULT Exception(EXCEPTION_RECORD64.ByReference Exception, ULONG FirstChance) {
		return vtbl.ExceptionCallback.invoke(getPointer(), Exception, FirstChance);
	}

	@Override
	public HRESULT CreateThread(ULONGLONG Handle, ULONGLONG DataOffset, ULONGLONG StartOffset) {
		return vtbl.CreateThreadCallback.invoke(getPointer(), Handle, DataOffset, StartOffset);
	}

	@Override
	public HRESULT ExitThread(ULONG ExitCode) {
		return vtbl.ExitThreadCallback.invoke(getPointer(), ExitCode);
	}

	@Override
	public HRESULT CreateProcess(ULONGLONG ImageFileHandle, ULONGLONG Handle, ULONGLONG BaseOffset,
			ULONG ModuleSize, WString ModuleName, WString ImageName, ULONG CheckSum,
			ULONG TimeDateStamp, ULONGLONG InitialThreadHandle, ULONGLONG ThreadDataOffset,
			ULONGLONG StartOffset) {
		return vtbl.CreateProcessCallback.invoke(getPointer(), ImageFileHandle, Handle, BaseOffset,
			ModuleSize, ModuleName, ImageName, CheckSum, TimeDateStamp, InitialThreadHandle,
			ThreadDataOffset, StartOffset);
	}

	@Override
	public HRESULT ExitProcess(ULONG ExitCode) {
		return vtbl.ExitProcessCallback.invoke(getPointer(), ExitCode);
	}

	@Override
	public HRESULT LoadModule(ULONGLONG ImageFileHandle, ULONGLONG BaseOffset, ULONG ModuleSize,
			WString ModuleName, WString ImageName, ULONG CheckSum, ULONG TimeDateStamp) {
		return vtbl.LoadModuleCallback.invoke(getPointer(), ImageFileHandle, BaseOffset, ModuleSize,
			ModuleName, ImageName, CheckSum, TimeDateStamp);
	}

	@Override
	public HRESULT UnloadModule(WString ImageBaseName, ULONGLONG BaseOffset) {
		return vtbl.UnloadModuleCallback.invoke(getPointer(), ImageBaseName, BaseOffset);
	}

	@Override
	public HRESULT SystemError(ULONG Error, ULONG Level) {
		return vtbl.SystemErrorCallback.invoke(getPointer(), Error, Level);
	}

	@Override
	public HRESULT SessionStatus(ULONG Status) {
		return vtbl.SessionStatusCallback.invoke(getPointer(), Status);
	}

	@Override
	public HRESULT ChangeDebuggeeState(ULONG Flags, ULONGLONG Argument) {
		return vtbl.ChangeDebuggeeStateCallback.invoke(getPointer(), Flags, Argument);
	}

	@Override
	public HRESULT ChangeEngineState(ULONG Flags, ULONGLONG Argument) {
		return vtbl.ChangeEngineStateCallback.invoke(getPointer(), Flags, Argument);
	}

	@Override
	public HRESULT ChangeSymbolState(ULONG Flags, ULONGLONG Argument) {
		return vtbl.ChangeSymbolStateCallback.invoke(getPointer(), Flags, Argument);
	}
}
