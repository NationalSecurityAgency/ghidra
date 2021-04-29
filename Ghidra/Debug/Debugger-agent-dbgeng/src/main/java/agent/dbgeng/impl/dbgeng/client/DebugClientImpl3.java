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

import com.sun.jna.Native;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.WinDef.*;

import agent.dbgeng.dbgeng.DebugRunningProcess;
import agent.dbgeng.dbgeng.DebugServerId;
import agent.dbgeng.dbgeng.DebugRunningProcess.Description.ProcessDescriptionFlags;
import agent.dbgeng.jna.dbgeng.client.IDebugClient3;

import com.sun.jna.platform.win32.COM.COMUtils;

import ghidra.comm.util.BitmaskSet;

public class DebugClientImpl3 extends DebugClientImpl2 {
	private final IDebugClient3 jnaClient;

	public DebugClientImpl3(IDebugClient3 jnaClient) {
		super(jnaClient);
		this.jnaClient = jnaClient;
	}

	@Override
	public void createProcess(DebugServerId si, String commandLine,
			BitmaskSet<DebugCreateFlags> createFlags) {
		ULONGLONG ullServer = new ULONGLONG(si.id);
		ULONG ulFlags = new ULONG(createFlags.getBitmask());
		COMUtils.checkRC(jnaClient.CreateProcessWide(ullServer, new WString(commandLine), ulFlags));
	}

	@Override
	public DebugRunningProcess.Description getProcessDescription(DebugServerId si, int systemId,
			BitmaskSet<ProcessDescriptionFlags> flags) {
		ULONGLONG server = new ULONGLONG(si.id);
		ULONG id = new ULONG(systemId);
		ULONG f = new ULONG(flags.getBitmask());

		ULONGByReference actualExeNameSize = new ULONGByReference();
		ULONGByReference actualDescriptionSize = new ULONGByReference();
		COMUtils.checkRC(jnaClient.GetRunningProcessDescriptionWide(server, id, f, null,
			new ULONG(0), actualExeNameSize, null, new ULONG(0), actualDescriptionSize));

		char[] exeName = new char[actualExeNameSize.getValue().intValue()];
		char[] description = new char[actualDescriptionSize.getValue().intValue()];
		COMUtils.checkRC(jnaClient.GetRunningProcessDescriptionWide(server, id, f, exeName,
			actualExeNameSize.getValue(), null, description, actualDescriptionSize.getValue(),
			null));

		return new DebugRunningProcess.Description(systemId, Native.toString(exeName),
			Native.toString(description));
	}
}
