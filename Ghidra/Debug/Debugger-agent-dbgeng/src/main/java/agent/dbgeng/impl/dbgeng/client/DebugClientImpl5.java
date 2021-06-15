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
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinDef.ULONGLONGByReference;
import com.sun.jna.platform.win32.COM.COMUtils;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.impl.dbgeng.event.WrapCallbackIDebugEventCallbacksWide;
import agent.dbgeng.impl.dbgeng.io.WrapCallbackIDebugOutputCallbacksWide;
import agent.dbgeng.jna.dbgeng.client.IDebugClient5;
import agent.dbgeng.jna.dbgeng.event.ListenerIDebugEventCallbacksWide;
import agent.dbgeng.jna.dbgeng.io.ListenerIDebugOutputCallbacksWide;

public class DebugClientImpl5 extends DebugClientImpl4 {
	private final IDebugClient5 jnaClient;

	public DebugClientImpl5(IDebugClient5 jnaClient) {
		super(jnaClient);
		this.jnaClient = jnaClient;
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
