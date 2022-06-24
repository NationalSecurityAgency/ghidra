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

import java.util.ArrayList;
import java.util.Map;
import java.util.Set;

import agent.frida.manager.FridaCause.Causes;
import agent.frida.manager.FridaManager;
import agent.frida.manager.FridaSession;
import agent.frida.manager.impl.FridaManagerImpl;

/**
 * Implementation of {@link FridaManager#listSessions()}
 */
public class FridaListSessionsCommand extends AbstractFridaCommand<Map<String, FridaSession>> {
	private Map<String, FridaSession> updatedSessions;

	public FridaListSessionsCommand(FridaManagerImpl manager) {
		super(manager);
	}

	@Override
	public Map<String, FridaSession> complete(FridaPendingCommand<?> pending) {
		Map<String, FridaSession> allSessions = manager.getKnownSessions();
		Set<String> cur = allSessions.keySet();
		for (String id : updatedSessions.keySet()) {
			if (cur.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			manager.addSessionIfAbsent(updatedSessions.get(id));
		}
		for (String id : new ArrayList<>(cur)) {
			if (updatedSessions.containsKey(id)) {
				continue; // Do nothing, we're in sync
			}
			manager.removeSession(id, Causes.UNCLAIMED);
		}
		return allSessions;
	}

	@Override
	public void invoke() {
		updatedSessions = manager.getClient().listSessions();
	}

}
