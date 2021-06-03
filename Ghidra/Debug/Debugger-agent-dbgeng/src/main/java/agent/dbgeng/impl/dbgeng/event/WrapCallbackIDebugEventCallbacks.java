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
package agent.dbgeng.impl.dbgeng.event;

import java.util.ArrayList;
import java.util.List;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Guid.REFIID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.IUnknown;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DebugClient.DebugStatus;
import agent.dbgeng.dbgeng.DebugClient.SessionStatus;
import agent.dbgeng.dbgeng.DebugEventCallbacks.DebugEvent;
import agent.dbgeng.impl.dbgeng.breakpoint.DebugBreakpointInternal;
import agent.dbgeng.impl.dbgeng.client.DebugClientImpl1;
import agent.dbgeng.impl.dbgeng.client.DebugClientInternal;
import agent.dbgeng.jna.dbgeng.WinNTExtra.EXCEPTION_RECORD64;
import agent.dbgeng.jna.dbgeng.breakpoint.WrapIDebugBreakpoint;
import agent.dbgeng.jna.dbgeng.event.*;
import ghidra.comm.util.BitmaskSet;
import ghidra.util.Msg;

public class WrapCallbackIDebugEventCallbacks implements CallbackIDebugEventCallbacks {
	private static final HRESULT ERROR_RESULT = new HRESULT(WinError.E_UNEXPECTED);

	private final DebugClientInternal client;
	private final DebugEventCallbacks cb;
	private ListenerIDebugEventCallbacks listener;

	public WrapCallbackIDebugEventCallbacks(DebugClientImpl1 client, DebugEventCallbacks cb) {
		this.client = client;
		this.cb = cb;
	}

	public void setListener(ListenerIDebugEventCallbacks listener) {
		this.listener = listener;
	}

	@Override
	public Pointer getPointer() {
		return listener.getPointer();
	}

	@Override
	public HRESULT QueryInterface(REFIID refid, PointerByReference ppvObject) {
		if (null == ppvObject) {
			return new HRESULT(WinError.E_POINTER);
		}
		else if (refid.getValue().equals(IDebugEventCallbacks.IID_IDEBUG_EVENT_CALLBACKS)) {
			ppvObject.setValue(this.getPointer());
			return WinError.S_OK;
		}
		else if (refid.getValue().equals(IUnknown.IID_IUNKNOWN)) {
			ppvObject.setValue(this.getPointer());
			return WinError.S_OK;
		}
		return new HRESULT(WinError.E_NOINTERFACE);
	}

	@Override
	public int AddRef() {
		return 0;
	}

	@Override
	public int Release() {
		return 0;
	}

	@Override
	public HRESULT GetInterestMask(ULONGByReference Mask) {
		try {
			BitmaskSet<DebugEvent> interest = cb.getInterestMask();
			ULONG ulInterest = new ULONG(interest.getBitmask());
			Mask.setValue(ulInterest);
			return WinError.S_OK;
		}
		catch (Throwable e) {
			Msg.error(this, "Error during callback", e);
			return new HRESULT(WinError.E_UNEXPECTED);
		}
	}

	@Override
	public HRESULT Breakpoint(WrapIDebugBreakpoint.ByReference Bp) {
		try {
			DebugBreakpoint bpt = DebugBreakpointInternal
					.tryPreferredInterfaces(client.getControlInternal(), Bp::QueryInterface);
			DebugStatus status = cb.breakpoint(bpt);
			return new HRESULT(status.ordinal());
		}
		catch (Throwable e) {
			Msg.error(this, "Error during callback", e);
			return ERROR_RESULT;
		}
	}

	@Override
	public HRESULT Exception(EXCEPTION_RECORD64.ByReference Exception, ULONG FirstChance) {
		try {
			int numParams = Exception.NumberParameters.intValue();
			List<Long> information = new ArrayList<>(numParams);
			for (int i = 0; i < numParams; i++) {
				information.set(i, Exception.ExceptionInformation[i].longValue());
			}
			DebugExceptionRecord64 exc =
				new DebugExceptionRecord64(Exception.ExceptionCode.intValue(),
					Exception.ExceptionFlags.intValue(), Exception.ExceptionRecord.longValue(),
					Exception.ExceptionAddress.longValue(), information);
			boolean firstChance = FirstChance.intValue() != 0;
			DebugStatus status = cb.exception(exc, firstChance);
			return new HRESULT(status.ordinal());
		}
		catch (Throwable e) {
			Msg.error(this, "Error during callback", e);
			return ERROR_RESULT;
		}
	}

	@Override
	public HRESULT CreateThread(ULONGLONG Handle, ULONGLONG DataOffset, ULONGLONG StartOffset) {
		try {
			DebugStatus status = cb.createThread(new DebugThreadInfo(Handle.longValue(),
				DataOffset.longValue(), StartOffset.longValue()));
			return new HRESULT(status.ordinal());
		}
		catch (Throwable e) {
			Msg.error(this, "Error during callback", e);
			return ERROR_RESULT;
		}
	}

	@Override
	public HRESULT ExitThread(ULONG ExitCode) {
		try {
			DebugStatus status = cb.exitThread(ExitCode.intValue());
			return new HRESULT(status.ordinal());
		}
		catch (Throwable e) {
			Msg.error(this, "Error during callback", e);
			return ERROR_RESULT;
		}
	}

	@Override
	public HRESULT CreateProcess(ULONGLONG ImageFileHandle, ULONGLONG Handle, ULONGLONG BaseOffset,
			ULONG ModuleSize, String ModuleName, String ImageName, ULONG CheckSum,
			ULONG TimeDateStamp, ULONGLONG InitialThreadHandle, ULONGLONG ThreadDataOffset,
			ULONGLONG StartOffset) {
		try {
			// TODO: Associate thread with process
			// TODO: Record All these other parameters?
			DebugStatus status = cb.createProcess(new DebugProcessInfo(Handle.longValue(),
				new DebugModuleInfo(ImageFileHandle.longValue(), BaseOffset.longValue(),
					ModuleSize.intValue(), ModuleName, ImageName, CheckSum.intValue(),
					TimeDateStamp.intValue()),
				new DebugThreadInfo(InitialThreadHandle.longValue(), ThreadDataOffset.longValue(),
					StartOffset.longValue())));
			return new HRESULT(status.ordinal());
		}
		catch (Throwable e) {
			Msg.error(this, "Error during callback", e);
			return ERROR_RESULT;
		}
	}

	@Override
	public HRESULT ExitProcess(ULONG ExitCode) {
		try {
			DebugStatus status = cb.exitProcess(ExitCode.intValue());
			return new HRESULT(status.ordinal());
		}
		catch (Throwable e) {
			Msg.error(this, "Error during callback", e);
			return ERROR_RESULT;
		}
	}

	@Override
	public HRESULT LoadModule(ULONGLONG ImageFileHandle, ULONGLONG BaseOffset, ULONG ModuleSize,
			String ModuleName, String ImageName, ULONG CheckSum, ULONG TimeDateStamp) {
		try {
			// All of these are potentially null
			long imageFileHandle = ImageFileHandle == null ? -1L : ImageFileHandle.longValue();
			long baseOffset = BaseOffset == null ? -1L : BaseOffset.longValue();
			int moduleSize = ModuleSize == null ? -1 : ModuleSize.intValue();
			String moduleName = ModuleName == null ? "" : ModuleName.toString();
			String imageName = ImageName == null ? "" : ImageName.toString();
			int checkSum = CheckSum == null ? -1 : CheckSum.intValue();

			DebugStatus status = cb.loadModule(new DebugModuleInfo(imageFileHandle, baseOffset,
				moduleSize, moduleName, imageName, checkSum, TimeDateStamp.intValue()));
			return new HRESULT(status.ordinal());
		}
		catch (Throwable e) {
			Msg.error(this, "Error during callback", e);
			return ERROR_RESULT;
		}
	}

	@Override
	public HRESULT UnloadModule(String ImageBaseName, ULONGLONG BaseOffset) {
		try {
			DebugStatus status = cb.unloadModule(ImageBaseName, BaseOffset.longValue());
			return new HRESULT(status.ordinal());
		}
		catch (Throwable e) {
			Msg.error(this, "Error during callback", e);
			return ERROR_RESULT;
		}
	}

	@Override
	public HRESULT SystemError(ULONG Error, ULONG Level) {
		try {
			DebugStatus status = cb.systemError(Error.intValue(), Level.intValue());
			return new HRESULT(status.ordinal());
		}
		catch (Throwable e) {
			Msg.error(this, "Error during callback", e);
			return ERROR_RESULT;
		}
	}

	@Override
	public HRESULT SessionStatus(ULONG Status) {
		try {
			SessionStatus ss = SessionStatus.values()[Status.intValue()];
			DebugStatus status = cb.sessionStatus(ss);
			return new HRESULT(status.ordinal());
		}
		catch (Throwable e) {
			Msg.error(this, "Error during callback", e);
			return ERROR_RESULT;
		}
	}

	@Override
	public HRESULT ChangeDebuggeeState(ULONG Flags, ULONGLONG Argument) {
		try {
			BitmaskSet<DebugClient.ChangeDebuggeeState> flags =
				new BitmaskSet<>(DebugClient.ChangeDebuggeeState.class, Flags.intValue());
			DebugStatus status = cb.changeDebuggeeState(flags, Argument.longValue());
			return new HRESULT(status.ordinal());
		}
		catch (Throwable e) {
			Msg.error(this, "Error during callback", e);
			return ERROR_RESULT;
		}
	}

	@Override
	public HRESULT ChangeEngineState(ULONG Flags, ULONGLONG Argument) {
		try {
			BitmaskSet<DebugClient.ChangeEngineState> flags =
				new BitmaskSet<>(DebugClient.ChangeEngineState.class, Flags.intValue());
			DebugStatus status = cb.changeEngineState(flags, Argument.longValue());
			return new HRESULT(status.ordinal());
		}
		catch (Throwable e) {
			Msg.error(this, "Error during callback", e);
			return ERROR_RESULT;
		}
	}

	@Override
	public HRESULT ChangeSymbolState(ULONG Flags, ULONGLONG Argument) {
		try {
			BitmaskSet<DebugClient.ChangeSymbolState> flags =
				new BitmaskSet<>(DebugClient.ChangeSymbolState.class, Flags.intValue());
			DebugStatus status = cb.changeSymbolState(flags, Argument.longValue());
			return new HRESULT(status.ordinal());
		}
		catch (Throwable e) {
			Msg.error(this, "Error during callback", e);
			return ERROR_RESULT;
		}
	}
}
