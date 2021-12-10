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

import java.util.ArrayList;
import java.util.Map;
import java.util.Set;

import SWIG.SBTarget;
import agent.lldb.manager.LldbCause.Causes;
import agent.lldb.manager.LldbManager;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link LldbManager#listSessions()}
 */
public class LldbListSessionsCommand extends AbstractLldbCommand<Map<String, SBTarget>> {
	private Map<String, SBTarget> updatedSessions;

	public LldbListSessionsCommand(LldbManagerImpl manager) {
		super(manager);
	}

	@Override
	public Map<String, SBTarget> complete(LldbPendingCommand<?> pending) {
		Map<String, SBTarget> allSessions = manager.getKnownSessions();
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
