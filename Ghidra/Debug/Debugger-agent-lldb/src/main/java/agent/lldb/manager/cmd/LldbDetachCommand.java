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

import SWIG.SBProcess;
import SWIG.SBThread;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.LldbCause;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link LldbProcess#detach()}
 */
public class LldbDetachCommand extends AbstractLldbCommand<Void> {
	private final SBProcess process;

	public LldbDetachCommand(LldbManagerImpl manager, SBProcess process) {
		super(manager);
		this.process = process;
	}

	@Override
	public Void complete(LldbPendingCommand<?> pending) {
		String pid = DebugClient.getId(process);
		for (int i = 0; i < process.GetNumThreads(); i++) {
			SBThread t = process.GetThreadAtIndex(i);
			manager.removeThread(pid, DebugClient.getId(t));
		}
		manager.getEventListeners().fire.processRemoved(pid, LldbCause.Causes.UNCLAIMED);
		return null;
	}

	@Override
	public void invoke() {
		DebugClient client = manager.getClient();
		client.detachCurrentProcess();
	}
}
