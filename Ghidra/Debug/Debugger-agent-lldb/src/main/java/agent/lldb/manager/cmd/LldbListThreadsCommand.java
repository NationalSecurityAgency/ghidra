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

import java.util.*;

import SWIG.SBProcess;
import SWIG.SBThread;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.impl.LldbManagerImpl;

public class LldbListThreadsCommand extends AbstractLldbCommand<Map<String, SBThread>> {

	protected final SBProcess process;
	private Map<String, SBThread> updatedThreadIds = new HashMap<>();

	public LldbListThreadsCommand(LldbManagerImpl manager, SBProcess process) {
		super(manager);
		this.process = process;
	}

	@Override
	public Map<String, SBThread> complete(LldbPendingCommand<?> pending) {
		Map<String, SBThread> threads = manager.getKnownThreads(process);
		Set<String> cur = threads.keySet();
		for (String id : updatedThreadIds.keySet()) {
			if (cur.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			manager.addThreadIfAbsent(process, updatedThreadIds.get(id));
		}
		for (String id : new ArrayList<>(cur)) {
			if (updatedThreadIds.containsKey(id)) {
				continue; // Do nothing, we're in sync
			}
			manager.removeThread(DebugClient.getId(process), id);
		}
		return manager.getKnownThreads(process);
	}

	@Override
	public void invoke() {
		updatedThreadIds.clear();
		long n = process.GetNumThreads();
		for (int i = 0; i < n; i++) {
			SBThread thread = process.GetThreadAtIndex(i);
			updatedThreadIds.put(DebugClient.getId(thread), thread);
		}
	}

}
