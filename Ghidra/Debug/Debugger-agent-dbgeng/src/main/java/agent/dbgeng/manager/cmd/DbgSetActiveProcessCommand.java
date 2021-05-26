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
package agent.dbgeng.manager.cmd;

import agent.dbgeng.dbgeng.DebugProcessId;
import agent.dbgeng.dbgeng.DebugSystemObjects;
import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.manager.impl.DbgManagerImpl;

public class DbgSetActiveProcessCommand extends AbstractDbgCommand<Void> {

	private DbgProcess process;

	/**
	 * Set the active process
	 * 
	 * @param manager the manager to execute the command
	 * @param process the desired process
	 */
	public DbgSetActiveProcessCommand(DbgManagerImpl manager, DbgProcess process) {
		super(manager);
		this.process = process;
	}

	@Override
	public void invoke() {
		if (process != null) {
			DebugProcessId id = process.getId();
			if (id != null) {
				DebugSystemObjects so = manager.getSystemObjects();
				DebugProcessId currentProcessId = so.getCurrentProcessId();
				if (id.id != currentProcessId.id) {
					so.setCurrentProcessId(id);
				}
			}
		}
	}
}
