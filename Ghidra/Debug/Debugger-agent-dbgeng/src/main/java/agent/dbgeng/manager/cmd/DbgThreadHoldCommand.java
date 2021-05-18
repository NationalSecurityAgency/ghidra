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

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.impl.DbgManagerImpl;

public class DbgThreadHoldCommand extends AbstractDbgCommand<Void> {

	static final String FREEZE_ALL_THREADS_COMMAND = "~* f";
	static final String FREEZE_CURRENT_THREAD_COMMAND = "~. f";
	static final String UNFREEZE_CURRENT_THREAD_COMMAND = "~. u";
	static final String UNFREEZE_ALL_THREADS_COMMAND = "~* u";

	static final String SUSPEND_ALL_THREADS_COMMAND = "~* n";
	static final String SUSPEND_CURRENT_THREAD_COMMAND = "~. n";
	static final String RESUME_CURRENT_THREAD_COMMAND = "~. m";
	static final String RESUME_ALL_THREADS_COMMAND = "~* m";

	static final Boolean preferFreeze = true;

	private DbgThread thread;
	private Boolean set;

	/**
	 * Select the given thread and frame level
	 * 
	 * To simply select a thread, you should use frame 0 as the default.
	 * 
	 * @param manager the manager to execute the command
	 * @param thread the desired thread
	 * @param set hold or release
	 */
	public DbgThreadHoldCommand(DbgManagerImpl manager, DbgThread thread, Boolean set) {
		super(manager);
		this.thread = thread;
		this.set = set;
	}

	@Override
	public void invoke() {
		DebugThreadId id = thread.getId();
		if (id != null) {
			DebugSystemObjects so = manager.getSystemObjects();
			DebugThreadId previous = so.getCurrentThreadId();
			so.setCurrentThreadId(id);
			if (!manager.isKernelMode()) {
				DebugControl control = manager.getControl();
				if (preferFreeze) {
					control.execute(
						set ? FREEZE_CURRENT_THREAD_COMMAND : UNFREEZE_CURRENT_THREAD_COMMAND);
				}
				else {
					control.execute(
						set ? SUSPEND_CURRENT_THREAD_COMMAND : RESUME_CURRENT_THREAD_COMMAND);
				}
			}
			so.setCurrentThreadId(previous);
		}
	}
}
