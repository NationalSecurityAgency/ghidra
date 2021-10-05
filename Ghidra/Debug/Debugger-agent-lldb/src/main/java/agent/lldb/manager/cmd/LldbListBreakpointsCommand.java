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
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import SWIG.*;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link LldbProcess#listBreakpoints()}
 */
public class LldbListBreakpointsCommand extends AbstractLldbCommand<Map<String, Object>> {

	protected final SBTarget session;
	private Map<String, Object> updatedBreakpoints = new HashMap<>();

	public LldbListBreakpointsCommand(LldbManagerImpl manager, SBTarget session) {
		super(manager);
		this.session = session;
	}

	@Override
	public Map<String, Object> complete(LldbPendingCommand<?> pending) {
		Map<String, Object> breakpoints = manager.getKnownBreakpoints(session);
		Set<String> cur = breakpoints.keySet();
		for (String id : updatedBreakpoints.keySet()) {
			if (cur.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			manager.addBreakpointIfAbsent(session, updatedBreakpoints.get(id));
		}
		for (String id : new ArrayList<>(cur)) {
			if (updatedBreakpoints.containsKey(id)) {
				continue; // Do nothing, we're in sync
			}
			manager.removeBreakpoint(session, id);
		}
		return manager.getKnownBreakpoints(session);
	}

	@Override
	public void invoke() {
		updatedBreakpoints.clear();
		long n = session.GetNumBreakpoints();
		for (int i = 0; i < n; i++) {
			SBBreakpoint bpt = session.GetBreakpointAtIndex(i);
			updatedBreakpoints.put(DebugClient.getId(bpt), bpt);
		}
		n = session.GetNumWatchpoints();
		for (int i = 0; i < n; i++) {
			SBWatchpoint bpt = session.GetWatchpointAtIndex(i);
			updatedBreakpoints.put(DebugClient.getId(bpt), bpt);
		}
	}
}
