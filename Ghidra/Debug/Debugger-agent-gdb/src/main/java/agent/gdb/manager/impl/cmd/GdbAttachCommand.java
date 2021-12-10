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

import java.util.LinkedHashSet;
import java.util.Set;

import agent.gdb.manager.GdbInferior;
import agent.gdb.manager.GdbThread;
import agent.gdb.manager.evt.GdbCommandDoneEvent;
import agent.gdb.manager.evt.GdbThreadCreatedEvent;
import agent.gdb.manager.impl.*;

/**
 * Implementation of {@link GdbInferior#attach(long)}
 */
public class GdbAttachCommand extends AbstractGdbCommand<Set<GdbThread>> {

	private final long pid;

	public GdbAttachCommand(GdbManagerImpl manager, long pid) {
		super(manager);
		this.pid = pid;
	}

	@Override
	public String encode() {
		return "-target-attach " + pid;
	}

	@Override
	public boolean handle(GdbEvent<?> evt, GdbPendingCommand<?> pending) {
		if (super.handle(evt, pending)) {
			return true;
		}
		else if (evt instanceof GdbThreadCreatedEvent) {
			pending.claim(evt);
		}
		return false;
	}

	@Override
	public Set<GdbThread> complete(GdbPendingCommand<?> pending) {
		pending.checkCompletion(GdbCommandDoneEvent.class);

		Set<GdbThread> threads = new LinkedHashSet<>();
		for (GdbThreadCreatedEvent created : pending.findAllOf(GdbThreadCreatedEvent.class)) {
			int tid = created.getThreadId();
			threads.add(manager.getThread(tid));
		}
		return threads;
	}
}
