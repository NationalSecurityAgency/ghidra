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

import java.util.Map;

import SWIG.*;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link LldbManager#enableBreakpoints(long)}
 */
public class LldbEnableBreakpointsCommand extends AbstractLldbCommand<Void> {

	private final String[] ids;

	public LldbEnableBreakpointsCommand(LldbManagerImpl manager, String... ids) {
		super(manager);
		this.ids = ids;
	}

	@Override
	public Void complete(LldbPendingCommand<?> pending) {
		SBTarget currentSession = manager.getCurrentSession();
		for (String id : ids) {
			manager.doBreakpointEnabled(currentSession, id, pending);
		}
		return null;
	}

	@Override
	public void invoke() {
		Map<String, Object> knownBreakpoints =
			manager.getKnownBreakpoints(manager.getCurrentSession());
		for (String id : ids) {
			if (knownBreakpoints.containsKey(id)) {
				Object obj = knownBreakpoints.get(id);
				if (obj instanceof SBBreakpoint) {
					((SBBreakpoint) obj).SetEnabled(true);
				}
				if (obj instanceof SBWatchpoint) {
					((SBWatchpoint) obj).SetEnabled(true);
				}
			}
		}
	}
}
