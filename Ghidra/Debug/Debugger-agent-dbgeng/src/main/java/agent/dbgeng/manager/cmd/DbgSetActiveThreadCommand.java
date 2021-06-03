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

import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.impl.DbgManagerImpl;

public class DbgSetActiveThreadCommand extends AbstractDbgCommand<Void> {

	private DbgThread thread;
	private Integer frameId;

	/**
	 * Set the active thread
	 * 
	 * @param manager the manager to execute the command
	 * @param thread the desired thread
	 * @param frameId the desired frame level
	 */
	public DbgSetActiveThreadCommand(DbgManagerImpl manager, DbgThread thread, Integer frameId) {
		super(manager);
		this.thread = thread;
		this.frameId = frameId;
	}

	@Override
	public void invoke() {
		DebugThreadId id = thread.getId();
		if (id != null) {
			manager.getSystemObjects().setCurrentThreadId(id);
			if (frameId != null) {
				manager.getSymbols().setCurrentScopeFrameIndex(frameId);
			}
		}
	}
}
