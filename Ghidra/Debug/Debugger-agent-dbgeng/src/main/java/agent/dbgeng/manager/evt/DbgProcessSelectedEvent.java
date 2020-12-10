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
package agent.dbgeng.manager.evt;

import agent.dbgeng.dbgeng.DebugProcessId;
import agent.dbgeng.manager.impl.DbgProcessImpl;

/**
 * The event corresponding with "{@code =thread-selected}"
 */
public class DbgProcessSelectedEvent extends AbstractDbgEvent<DebugProcessId> {
	private final DebugProcessId id;
	private DbgProcessImpl process;

	/**
	 * The selected process ID must be specified by dbgeng.
	 * 
	 * @param id dbgeng-defined id
	 */
	public DbgProcessSelectedEvent(DbgProcessImpl process) {
		super(process.getId());
		this.process = process;
		this.id = process.getId();
	}

	/**
	 * Get the selected process ID
	 * 
	 * @return the process ID
	 */
	public DebugProcessId getProcessId() {
		return id;
	}

	public DbgProcessImpl getProcess() {
		return process;
	}

}
