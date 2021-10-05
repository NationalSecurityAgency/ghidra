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
package agent.lldb.manager.evt;

import SWIG.SBFrame;
import SWIG.SBThread;
import SWIG.StateType;
import agent.lldb.lldb.DebugProcessInfo;

/**
 * The event corresponding with SBProcess.eBroadcastBitStateChanged
 */
public class LldbStateChangedEvent extends AbstractLldbEvent<DebugProcessInfo> {

	private long argument;
	private StateType state = null;

	public LldbStateChangedEvent(DebugProcessInfo info) {
		super(info);
	}

	public long getArgument() {
		return argument;
	}

	public void setArgument(long argument) {
		this.argument = argument;
	}

	public SBFrame getFrame(SBThread thread) {
		return null;
	}

	@Override
	public StateType newState() {
		return state;
	}

	public void setState(StateType state) {
		this.state = state;
	}
}
