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

import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.COM.COMUtils;

import agent.dbgeng.jna.dbgeng.client.IDebugClient2;

public class DebugClientImpl2 extends DebugClientImpl1 {
	private final IDebugClient2 jnaClient;

	public DebugClientImpl2(IDebugClient2 jnaClient) {
		super(jnaClient);
		this.jnaClient = jnaClient;
	}

	@Override
	public void terminateCurrentProcess() {
		COMUtils.checkRC(jnaClient.TerminateCurrentProcess());
	}

	@Override
	public void detachCurrentProcess() {
		COMUtils.checkRC(jnaClient.DetachCurrentProcess());
	}

	@Override
	public void abandonCurrentProcess() {
		COMUtils.checkRC(jnaClient.AbandonCurrentProcess());
	}

	@Override
	public void waitForProcessServerEnd(int timeout) {
		COMUtils.checkRC(jnaClient.WaitForProcessServerEnd(new ULONG(timeout)));
	}
}
