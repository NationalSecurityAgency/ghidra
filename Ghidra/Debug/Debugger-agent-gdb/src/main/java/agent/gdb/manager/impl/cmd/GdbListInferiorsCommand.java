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
package agent.gdb.manager.impl.cmd;

import java.util.*;

import agent.gdb.manager.*;
import agent.gdb.manager.GdbCause.Causes;
import agent.gdb.manager.evt.GdbCommandDoneEvent;
import agent.gdb.manager.impl.*;
import ghidra.util.Msg;

/**
 * Implementation of {@link GdbManager#listInferiors()}
 */
public class GdbListInferiorsCommand extends AbstractGdbCommand<Map<Integer, GdbInferior>> {
	public GdbListInferiorsCommand(GdbManagerImpl manager) {
		super(manager);
	}

	@Override
	public String encode() {
		return "-list-thread-groups";
	}

	@Override
	public Map<Integer, GdbInferior> complete(GdbPendingCommand<?> pending) {
		GdbCommandDoneEvent done = pending.checkCompletion(GdbCommandDoneEvent.class);
		List<GdbInferiorThreadGroup> groups = done.assumeInferiorGroups();
		Set<Integer> ids = new HashSet<>();
		Map<Integer, GdbInferiorImpl> allInferiors = manager.getKnownInferiorsInternal();
		Set<Integer> curIds = allInferiors.keySet();
		for (GdbInferiorThreadGroup g : groups) {
			ids.add(g.getInferiorId());
			GdbInferiorImpl exists = allInferiors.get(g.getInferiorId());
			if (exists != null) {
				exists.update(g);
				continue; // Otherwise, we're in sync
			}
			// Need to create the inferior as if we received =thread-group-created
			Msg.warn(this, "Resync: Was missing group: i" + g);
			manager.addInferior(new GdbInferiorImpl(manager, g), Causes.UNCLAIMED);
		}
		for (int id : new ArrayList<>(curIds)) {
			if (ids.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			// Need to remove the inferior as if we received =thread-group-removed
			Msg.warn(this, "Resync: Had extra group: i" + id);
			manager.removeInferior(id, Causes.UNCLAIMED);
		}
		return manager.getKnownInferiors();
	}
}
