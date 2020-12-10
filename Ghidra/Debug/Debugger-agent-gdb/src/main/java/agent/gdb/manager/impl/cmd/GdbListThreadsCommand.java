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

import agent.gdb.manager.GdbThread;
import agent.gdb.manager.evt.AbstractGdbCompletedCommandEvent;
import agent.gdb.manager.evt.GdbCommandDoneEvent;
import agent.gdb.manager.impl.*;
import ghidra.util.Msg;

public class GdbListThreadsCommand extends AbstractGdbCommand<Map<Integer, GdbThread>> {
	protected final GdbInferiorImpl inferior;

	public GdbListThreadsCommand(GdbManagerImpl manager, GdbInferiorImpl inferior) {
		super(manager);
		this.inferior = inferior;
	}

	@Override
	public String encode() {
		return "-list-thread-groups i" + inferior.getId();
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (evt instanceof AbstractGdbCompletedCommandEvent) {
			pending.claim(evt);
			return true;
		}
		return false;
	}

	@Override
	public Map<Integer, GdbThread> complete(GdbPendingCommand<?> pending) {
		GdbCommandDoneEvent done = pending.checkCompletion(GdbCommandDoneEvent.class);
		List<Integer> ids = done.assumeThreadIds();
		Map<Integer, GdbThread> infThreads = inferior.getKnownThreads();
		Set<Integer> cur = infThreads.keySet();
		for (int id : ids) {
			if (cur.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			// Need to create the thread as if we receive =thread-created
			Msg.warn(this, "Resync: Was missing thread: " + id);
			new GdbThreadImpl(manager, inferior, id).add();
		}
		for (int id : new ArrayList<>(cur)) {
			if (ids.contains(id)) {
				continue; // Do nothing, we're in sync
			}
			// Need to remove the thread as if we received =thread-exited
			Msg.warn(this, "Resync: Had extra thread: " + id);
			inferior.removeThread(id);
			manager.removeThread(id);
		}
		return infThreads;
	}

}
