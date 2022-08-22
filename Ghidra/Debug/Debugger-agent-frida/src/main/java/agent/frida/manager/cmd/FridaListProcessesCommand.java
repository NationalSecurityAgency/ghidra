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
package agent.frida.manager.cmd;

import java.util.*;

import agent.frida.frida.FridaClient;
import agent.frida.manager.*;
import agent.frida.manager.FridaCause.Causes;
import agent.frida.manager.impl.FridaManagerImpl;

/**
 * Implementation of {@link FridaManager#listProcesses(FridaSession session)}
 */
public class FridaListProcessesCommand extends AbstractFridaCommand<Map<String, FridaProcess>> {
	private Map<String, FridaProcess> updatedProcesses;
	private FridaSession session;

	public FridaListProcessesCommand(FridaManagerImpl manager, FridaSession session) {
		super(manager);
		this.session = session;
	}

	@Override
	public Map<String, FridaProcess> complete(FridaPendingCommand<?> pending) {
		Map<String, FridaProcess> allProcesses = manager.getKnownProcesses(session);
		Set<String> cur = allProcesses.keySet();
		for (String id : updatedProcesses.keySet()) {
			if (cur.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			manager.addProcessIfAbsent(session, updatedProcesses.get(id));
		}
		String sessionId = FridaClient.getId(session);
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
		FridaProcess p = session.getProcess();
		updatedProcesses = new HashMap<>();
		updatedProcesses.put(FridaClient.getId(p), p);
	}
}
