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

import com.sun.jna.WString;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.COM.COMUtils;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.impl.dbgeng.event.WrapCallbackIDebugEventCallbacksWide;
import agent.dbgeng.impl.dbgeng.io.WrapCallbackIDebugOutputCallbacksWide;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_CREATE_PROCESS_OPTIONS;
import agent.dbgeng.jna.dbgeng.client.IDebugClient5;
import agent.dbgeng.jna.dbgeng.event.ListenerIDebugEventCallbacksWide;
import agent.dbgeng.jna.dbgeng.io.ListenerIDebugOutputCallbacksWide;
import ghidra.comm.util.BitmaskSet;

public class DebugClientImpl5 extends DebugClientImpl4 {
	private final IDebugClient5 jnaClient;

	public DebugClientImpl5(IDebugClient5 jnaClient) {
		super(jnaClient);
		this.jnaClient = jnaClient;
	}

	@Override
	public void createProcess(DebugServerId si, String commandLine,
			String initialDirectory, String environment,
			BitmaskSet<DebugCreateFlags> createFlags,
			BitmaskSet<DebugEngCreateFlags> engCreateFlags,
			BitmaskSet<DebugVerifierFlags> verifierFlags) {
		ULONGLONG ullServer = new ULONGLONG(si.id);
		DEBUG_CREATE_PROCESS_OPTIONS options = new DEBUG_CREATE_PROCESS_OPTIONS();
		options.CreateFlags = new ULONG(createFlags.getBitmask());
		options.EngCreateFlags = new ULONG(engCreateFlags.getBitmask());
		options.VerifierFlags = new ULONG(verifierFlags.getBitmask());
		ULONG ulOptionsBufferSize = new ULONG(options.size());
		WString cmdLine = new WString(commandLine);
		WString initDir = initialDirectory == null ? null : new WString(initialDirectory);
		WString env = environment == null ? null : new WString(environment);
		COMUtils.checkRC(jnaClient.CreateProcess2Wide(ullServer, cmdLine,
			options, ulOptionsBufferSize,
			initDir, env));
	}

	@Override
	public void attachKernel(long flags, String options) {
		ULONG connectFlags = new ULONG(flags);
		COMUtils.checkRC(jnaClient.AttachKernelWide(connectFlags, new WString(options)));
	}

	@Override
	public void startProcessServer(String options) {
		COMUtils.checkRC(jnaClient.StartProcessServerWide(
			new ULONG(DebugClass.USER_WINDOWS.ordinal()), new WString(options), null));
	}

	@Override
	public DebugServerId connectProcessServer(String options) {
		ULONGLONGByReference pulServer = new ULONGLONGByReference();
		COMUtils.checkRC(jnaClient.ConnectProcessServerWide(new WString(options), pulServer));
		return new DebugServerId(pulServer.getValue().longValue());
	}

	@Override
	public void setOutputCallbacks(DebugOutputCallbacks cb) {
		ListenerIDebugOutputCallbacksWide listener = null;
		if (cb != null) {
			WrapCallbackIDebugOutputCallbacksWide callback =
				new WrapCallbackIDebugOutputCallbacksWide(cb);
			listener = new ListenerIDebugOutputCallbacksWide(callback);
			callback.setListener(listener);
		}
		COMUtils.checkRC(jnaClient.SetOutputCallbacksWide(listener));
		listenerOutput = listener;
	}

	@Override
	public void setEventCallbacks(DebugEventCallbacks cb) {
		ListenerIDebugEventCallbacksWide listener = null;
		if (cb != null) {
			WrapCallbackIDebugEventCallbacksWide callback =
				new WrapCallbackIDebugEventCallbacksWide(this, cb);
			listener = new ListenerIDebugEventCallbacksWide(callback);
			callback.setListener(listener);
		}
		COMUtils.checkRC(jnaClient.SetEventCallbacksWide(listener));
		listenerEvent = listener;
	}
}
