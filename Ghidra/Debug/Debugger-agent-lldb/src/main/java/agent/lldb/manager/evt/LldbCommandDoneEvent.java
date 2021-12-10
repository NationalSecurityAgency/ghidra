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

import SWIG.StateType;
import agent.lldb.manager.LldbCommand;

public class LldbCommandDoneEvent extends AbstractLldbCompletedCommandEvent {

	private LldbCommand<?> cmd;

	/**
	 * Construct a new event, parsing the tail for information
	 */
	public LldbCommandDoneEvent() {
		super();
	}

	public LldbCommandDoneEvent(LldbCommand<?> cmd) {
		super(cmd.toString());
		this.cmd = cmd;
	}

	@Override
	public StateType newState() {
		return StateType.eStateStopped;
	}

	public LldbCommand<?> getCmd() {
		return cmd;
	}

}
