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

import SWIG.SBEvent;
import SWIG.SBTarget;
import ghidra.comm.util.BitmaskSet;

/**
 * Information about a session.
 * 
 * The fields correspond to the parameters taken by {@code LoadModule} of
 * {@code IDebugEventCallbacks}. They also appear as a subset of parameters taken by
 * {@code CreateProcess} of {@code IDebugEventCallbacks}.
 */
public class DebugSessionInfo {

	public SBEvent event;
	public SBTarget session;
	public String id;

	public DebugSessionInfo(SBEvent event) {
		this.event = event;
		this.session = SBTarget.GetTargetFromEvent(event);
		this.id = DebugClient.getId(session);
	}

	public DebugSessionInfo(SBTarget session) {
		this.event = null;
		this.session = session;
		this.id = DebugClient.getId(session);
	}

	public String toString() {
		return id;
	}

	public BitmaskSet<?> getFlags() {
		return new BitmaskSet<>(DebugClient.ChangeSessionState.class, event.GetType());
	}
}
