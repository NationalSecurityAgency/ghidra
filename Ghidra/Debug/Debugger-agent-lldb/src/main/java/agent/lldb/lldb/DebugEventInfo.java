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
package agent.lldb.lldb;

import SWIG.*;
import ghidra.comm.util.BitmaskSet;

/**
 * Information about an event (target, process, or thread).
 */
public class DebugEventInfo {

	public SBEvent event;
	public Long id;

	public DebugEventInfo(SBEvent event) {
		this.event = event;
		this.id = event.GetType();
	}

	@Override
	public String toString() {
		return Long.toHexString(id);
	}

	public BitmaskSet<?> getFlags() {
		if (SBTarget.EventIsTargetEvent(event)) {
			BitmaskSet<DebugClient.ChangeSessionState> flags =
				new BitmaskSet<>(DebugClient.ChangeSessionState.class, event.GetType());
			return flags;
		}
		if (SBProcess.EventIsProcessEvent(event)) {
			BitmaskSet<DebugClient.ChangeProcessState> flags =
				new BitmaskSet<>(DebugClient.ChangeProcessState.class, event.GetType());
			return flags;
		}
		if (SBThread.EventIsThreadEvent(event)) {
			BitmaskSet<DebugClient.ChangeThreadState> flags =
				new BitmaskSet<>(DebugClient.ChangeThreadState.class, event.GetType());
			return flags;
		}
		return null;
	}

}
