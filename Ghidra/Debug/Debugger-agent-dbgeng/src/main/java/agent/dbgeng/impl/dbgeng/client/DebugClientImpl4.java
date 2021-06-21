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
import com.sun.jna.platform.win32.WinDef.ULONGLONG;

import agent.dbgeng.jna.dbgeng.client.IDebugClient4;

import com.sun.jna.platform.win32.COM.COMUtils;

public class DebugClientImpl4 extends DebugClientImpl3 {
	@SuppressWarnings("unused")
	private final IDebugClient4 jnaClient;

	public DebugClientImpl4(IDebugClient4 jnaClient) {
		super(jnaClient);
		this.jnaClient = jnaClient;
	}

	@Override
	public void openDumpFileWide(String fileName) {
		ULONGLONG ullFileHandle = new ULONGLONG(0);
		COMUtils.checkRC(jnaClient.OpenDumpFileWide(new WString(fileName), ullFileHandle));
	}
}
