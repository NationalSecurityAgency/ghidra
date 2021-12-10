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
import SWIG.SBTarget;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.LldbCause.Causes;
import agent.lldb.manager.LldbManager;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link LldbManager#listProcesses()}
 */
public class LldbListProcessesCommand extends AbstractLldbCommand<Map<String, SBProcess>> {
	private Map<String, SBProcess> updatedProcesses;
	private SBTarget session;

	public LldbListProcessesCommand(LldbManagerImpl manager, SBTarget session) {
		super(manager);
		this.session = session;
	}

	@Override
	public Map<String, SBProcess> complete(LldbPendingCommand<?> pending) {
		Map<String, SBProcess> allProcesses = manager.getKnownProcesses(session);
		Set<String> cur = allProcesses.keySet();
		for (String id : updatedProcesses.keySet()) {
			if (cur.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			manager.addProcessIfAbsent(session, updatedProcesses.get(id));
		}
		String sessionId = DebugClient.getId(session);
		for (String id : new ArrayList<>(cur)) {
			if (updatedProcesses.containsKey(id)) {
				continue; // Do nothing, we're in sync
			}
			manager.removeProcess(sessionId, id, Causes.UNCLAIMED);
		}
		return allProcesses;
	}

	@Override
	public void invoke() {
		SBProcess p = session.GetProcess();
		updatedProcesses = new HashMap<>();
		updatedProcesses.put(DebugClient.getId(p), p);
	}
}
