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
 * Information about a module (program or library image).
 * 
 * The fields correspond to the parameters taken by {@code LoadModule} of
 * {@code IDebugEventCallbacks}. They also appear as a subset of parameters taken by
 * {@code CreateProcess} of {@code IDebugEventCallbacks}.
 */
public class DebugProcessInfo {

	public SBEvent event;
	public SBProcess process;
	public StateType state;
	public String id;

	public DebugProcessInfo(SBEvent event) {
		this.event = event;
		this.process = SBProcess.GetProcessFromEvent(event);
		this.state = SBProcess.GetStateFromEvent(event);
		this.id = DebugClient.getId(process);
	}

	public DebugProcessInfo(SBProcess process) {
		this.process = process;
		this.state = process.GetState();
		this.id = DebugClient.getId(process);
	}

	public String toString() {
		return id;
	}

	public BitmaskSet<?> getFlags() {
		return new BitmaskSet<>(DebugClient.ChangeProcessState.class, event.GetType());
	}

}
