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

import SWIG.SBModule;
import SWIG.SBTarget;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.impl.LldbManagerImpl;

public class LldbListModulesCommand extends AbstractLldbCommand<Map<String, SBModule>> {
	protected final SBTarget session;
	private Map<String, SBModule> updatedModules = new HashMap<>();

	public LldbListModulesCommand(LldbManagerImpl manager, SBTarget session) {
		super(manager);
		this.session = session;
	}

	@Override
	public Map<String, SBModule> complete(LldbPendingCommand<?> pending) {
		Map<String, SBModule> modules = manager.getKnownModules(session);
		Set<String> cur = modules.keySet();
		for (String id : updatedModules.keySet()) {
			if (cur.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			manager.addModuleIfAbsent(session, updatedModules.get(id));
		}
		for (String id : new ArrayList<>(cur)) {
			if (updatedModules.containsKey(id)) {
				continue; // Do nothing, we're in sync
			}
			manager.removeModule(session, id);
		}
		return manager.getKnownModules(session);
	}

	@Override
	public void invoke() {
		long n = session.GetNumModules();
		for (int i = 0; i < n; i++) {
			SBModule module = session.GetModuleAtIndex(i);
			updatedModules.put(DebugClient.getId(module), module);
		}
	}

}
