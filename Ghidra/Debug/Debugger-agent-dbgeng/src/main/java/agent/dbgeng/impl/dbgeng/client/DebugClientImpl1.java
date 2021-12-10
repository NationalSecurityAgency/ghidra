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
package agent.dbgeng.impl.dbgeng.client;

import java.util.ArrayList;
import java.util.List;

import com.sun.jna.Native;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DbgEng.OpaqueCleanable;
import agent.dbgeng.impl.dbgeng.DebugRunningProcessImpl;
import agent.dbgeng.impl.dbgeng.advanced.DebugAdvancedInternal;
import agent.dbgeng.impl.dbgeng.control.DebugControlInternal;
import agent.dbgeng.impl.dbgeng.dataspaces.DebugDataSpacesInternal;
import agent.dbgeng.impl.dbgeng.event.WrapCallbackIDebugEventCallbacks;
import agent.dbgeng.impl.dbgeng.io.WrapCallbackIDebugInputCallbacks;
import agent.dbgeng.impl.dbgeng.io.WrapCallbackIDebugOutputCallbacks;
import agent.dbgeng.impl.dbgeng.registers.DebugRegistersInternal;
import agent.dbgeng.impl.dbgeng.symbols.DebugSymbolsInternal;
import agent.dbgeng.impl.dbgeng.sysobj.DebugSystemObjectsInternal;
import agent.dbgeng.jna.dbgeng.client.IDebugClient;
import agent.dbgeng.jna.dbgeng.event.ListenerIDebugEventCallbacks;
import agent.dbgeng.jna.dbgeng.event.MarkerEventCallbacks;
import agent.dbgeng.jna.dbgeng.io.*;
import ghidra.comm.util.BitmaskSet;

public class DebugClientImpl1 implements DebugClientInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDebugClient jnaClient;

	private DebugAdvancedInternal advanced;
	private DebugControlInternal control;
	private DebugDataSpaces data;
	private DebugRegisters registers;
	private DebugSymbols symbols;
	private DebugSystemObjects sysobjs;

	// Keep references to callbacks here, since JNA doesn't keep one for things handed to natives.
	protected MarkerOutputCallbacks listenerOutput;
	protected MarkerInputCallbacks listenerInput;
	protected MarkerEventCallbacks listenerEvent;

	public DebugClientImpl1(IDebugClient jnaClient) {
		// TODO: Debug and verify COM resource management
		this.cleanable = DbgEng.releaseWhenPhantom(this, jnaClient);
		this.jnaClient = jnaClient;
	}

	@Override
	public IDebugClient getJNAClient() {
		return jnaClient;
	}

	@Override
	public DebugAdvanced getAdvanced() {
		if (advanced == null) {
			advanced = DebugAdvancedInternal.tryPreferredInterfaces(jnaClient::QueryInterface);
		}
		return advanced;
	}

	@Override
	public DebugControlInternal getControlInternal() {
		if (control == null) {
			control = DebugControlInternal.tryPreferredInterfaces(jnaClient::QueryInterface);
		}
		return control;
	}

	@Override
	public DebugControl getControl() {
		return getControlInternal();
	}

	@Override
	public DebugDataSpaces getDataSpaces() {
		if (data == null) {
			data = DebugDataSpacesInternal.tryPreferredInterfaces(jnaClient::QueryInterface);
		}
		return data;
	}

	@Override
	public DebugRegisters getRegisters() {
		if (registers == null) {
			registers = DebugRegistersInternal.tryPreferredInterfaces(jnaClient::QueryInterface);
		}
		return registers;
	}

	@Override
	public DebugSymbols getSymbols() {
		if (symbols == null) {
			symbols = DebugSymbolsInternal.tryPreferredInterfaces(jnaClient::QueryInterface);
		}
		return symbols;
	}

	@Override
	public DebugSystemObjects getSystemObjects() {
		if (sysobjs == null) {
			sysobjs = DebugSystemObjectsInternal.tryPreferredInterfaces(jnaClient::QueryInterface);
		}
		return sysobjs;
	}

	@Override
	public DebugServerId getLocalServer() {
		return new DebugServerId(0);
	}

	@Override
	public void startProcessServer(String options) {
		COMUtils.checkRC(jnaClient.StartProcessServer(new ULONG(DebugClass.USER_WINDOWS.ordinal()),
			options, null));
	}

	@Override
	public DebugServerId connectProcessServer(String options) {
		ULONGLONGByReference pulServer = new ULONGLONGByReference();
		COMUtils.checkRC(jnaClient.ConnectProcessServer(options, pulServer));
		return new DebugServerId(pulServer.getValue().longValue());
	}

	@Override
	public List<DebugRunningProcess> getRunningProcesses(DebugServerId si) {
		ULONGLONG server = new ULONGLONG(si.id);
		ULONGByReference actualCount = new ULONGByReference();
		COMUtils.checkRC(
			jnaClient.GetRunningProcessSystemIds(server, null, new ULONG(0), actualCount));

		int[] ids = new int[actualCount.getValue().intValue()];
		COMUtils.checkRC(
			jnaClient.GetRunningProcessSystemIds(server, ids, actualCount.getValue(), null));

		List<DebugRunningProcess> result = new ArrayList<>(ids.length);
		for (int id : ids) {
			result.add(new DebugRunningProcessImpl(this, si, id));
		}
		return result;
	}

	@Override
	public DebugRunningProcess.Description getProcessDescription(DebugServerId si, int systemId,
			BitmaskSet<DebugRunningProcess.Description.ProcessDescriptionFlags> flags) {
		ULONGLONG ullServer = new ULONGLONG(si.id);
		ULONG ulId = new ULONG(systemId);
		ULONG ulFlags = new ULONG(flags.getBitmask());

		ULONGByReference actualExeNameSize = new ULONGByReference();
		ULONGByReference actualDescriptionSize = new ULONGByReference();
		COMUtils.checkRC(jnaClient.GetRunningProcessDescription(ullServer, ulId, ulFlags, null,
			new ULONG(0), actualExeNameSize, null, new ULONG(0), actualDescriptionSize));

		byte[] exeName = new byte[actualExeNameSize.getValue().intValue()];
		byte[] description = new byte[actualDescriptionSize.getValue().intValue()];
		COMUtils.checkRC(jnaClient.GetRunningProcessDescription(ullServer, ulId, ulFlags, exeName,
			actualExeNameSize.getValue(), null, description, actualDescriptionSize.getValue(),
			null));

		return new DebugRunningProcess.Description(systemId, Native.toString(exeName),
			Native.toString(description));
	}

	@Override
	public void attachProcess(DebugServerId si, long processId,
			BitmaskSet<DebugAttachFlags> attachFlags) {
		ULONGLONG ullServer = new ULONGLONG(si.id);
		ULONG ulPid = new ULONG(processId);
		ULONG ulFlags = new ULONG(attachFlags.getBitmask());
		COMUtils.checkRC(jnaClient.AttachProcess(ullServer, ulPid, ulFlags));
	}

	@Override
	public void createProcess(DebugServerId si, String commandLine,
			BitmaskSet<DebugCreateFlags> createFlags) {
		ULONGLONG ullServer = new ULONGLONG(si.id);
		ULONG ulFlags = new ULONG(createFlags.getBitmask());
		COMUtils.checkRC(jnaClient.CreateProcess(ullServer, commandLine, ulFlags));
	}

	@Override
	public void createProcessAndAttach(DebugServerId si, String commandLine,
			BitmaskSet<DebugCreateFlags> createFlags, int processId,
			BitmaskSet<DebugAttachFlags> attachFlags) {
		ULONGLONG ullServer = new ULONGLONG(si.id);
		ULONG ulFlags1 = new ULONG(createFlags.getBitmask());
		ULONG ulPid = new ULONG(processId);
		ULONG ulFlags2 = new ULONG(attachFlags.getBitmask());
		COMUtils.checkRC(
			jnaClient.CreateProcessAndAttach(ullServer, commandLine, ulFlags1, ulPid, ulFlags2));
	}

	@Override
	public void startServer(String options) {
		COMUtils.checkRC(jnaClient.StartServer(options));
	}

	@Override
	public boolean dispatchCallbacks(int timeout) {
		HRESULT hr = jnaClient.DispatchCallbacks(new ULONG(timeout));
		COMUtils.checkRC(hr);
		return hr.equals(WinNT.S_OK);
	}

	@Override
	public void flushCallbacks() {
		HRESULT hr = jnaClient.FlushCallbacks();
		COMUtils.checkRC(hr);
	}

	@Override
	public void exitDispatch(DebugClient client) {
		DebugClientInternal ic = (DebugClientInternal) client;
		COMUtils.checkRC(jnaClient.ExitDispatch(ic.getJNAClient()));
	}

	@Override
	public DebugClient createClient() {
		PointerByReference ppClient = new PointerByReference();
		COMUtils.checkRC(jnaClient.CreateClient(ppClient));
		return DebugClientInternal.tryPreferredInterfaces(jnaClient::QueryInterface);
	}

	@Override
	public void setInputCallbacks(DebugInputCallbacks cb) {
		ListenerIDebugInputCallbacks listener = null;
		if (cb != null) {
			WrapCallbackIDebugInputCallbacks callback =
				new WrapCallbackIDebugInputCallbacks(this, cb);
			listener = new ListenerIDebugInputCallbacks(callback);
			callback.setListener(listener);
		}
		COMUtils.checkRC(jnaClient.SetInputCallbacks(listener));
		listenerInput = listener;
	}

	@Override
	public void setOutputCallbacks(DebugOutputCallbacks cb) {
		ListenerIDebugOutputCallbacks listener = null;
		if (cb != null) {
			WrapCallbackIDebugOutputCallbacks callback = new WrapCallbackIDebugOutputCallbacks(cb);
			listener = new ListenerIDebugOutputCallbacks(callback);
			callback.setListener(listener);
		}
		COMUtils.checkRC(jnaClient.SetOutputCallbacks(listener));
		listenerOutput = listener;
	}

	@Override
	public void setEventCallbacks(DebugEventCallbacks cb) {
		ListenerIDebugEventCallbacks listener = null;
		if (cb != null) {
			WrapCallbackIDebugEventCallbacks callback =
				new WrapCallbackIDebugEventCallbacks(this, cb);
			listener = new ListenerIDebugEventCallbacks(callback);
			callback.setListener(listener);
		}
		COMUtils.checkRC(jnaClient.SetEventCallbacks(listener));
		listenerEvent = listener;
	}

	@Override
	public void terminateCurrentProcess() {
		throw new UnsupportedOperationException("Not implemented by this interface");
	}

	@Override
	public void detachCurrentProcess() {
		throw new UnsupportedOperationException("Not implemented by this interface");
	}

	@Override
	public void abandonCurrentProcess() {
		throw new UnsupportedOperationException("Not implemented by this interface");
	}

	@Override
	public void waitForProcessServerEnd(int timeout) {
		throw new UnsupportedOperationException("Not implemented by this interface");
	}

	@Override
	public void endSession(DebugEndSessionFlags flags) {
		COMUtils.checkRC(jnaClient.EndSession(new ULONG(flags.getValue())));
	}

	@Override
	public void connectSession(int flags) {
		COMUtils.checkRC(jnaClient.ConnectSession(new ULONG(flags), new ULONG(10000)));
	}

	@Override
	public void openDumpFileWide(String fileName) {
		throw new UnsupportedOperationException("Not implemented by this interface");
	}

	@Override
	public void attachKernel(long flags, String options) {
		throw new UnsupportedOperationException("Not implemented by this interface");
	}

}
