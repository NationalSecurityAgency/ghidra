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
package agent.lldb.manager.cmd;

import SWIG.SBDebugger;
import SWIG.SBProcess;
import agent.lldb.lldb.DebugClientImpl;
import agent.lldb.manager.impl.LldbManagerImpl;

public class LldbSetActiveProcessCommand extends AbstractLldbCommand<Void> {

	private SBProcess process;

	/**
	 * Set the active process
	 * 
	 * @param manager the manager to execute the command
	 * @param process the desired process
	 */
	public LldbSetActiveProcessCommand(LldbManagerImpl manager, SBProcess process) {
		super(manager);
		this.process = process;
	}

	@Override
	public void invoke() {
		DebugClientImpl client = (DebugClientImpl) manager.getClient();
		SBDebugger debugger = client.getDebugger();
		debugger.SetSelectedTarget(process.GetTarget());
	}
}
