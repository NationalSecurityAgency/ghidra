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

import java.util.LinkedHashSet;
import java.util.Set;

import SWIG.SBThread;
import agent.lldb.lldb.DebugClient;
import agent.lldb.lldb.DebugThreadInfo;
import agent.lldb.manager.LldbEvent;
import agent.lldb.manager.evt.*;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link LldbProcess#connect()}
 */
public class LldbRemoteConnectionCommand extends AbstractLldbCommand<Set<SBThread>> {

	private LldbProcessCreatedEvent created = null;
	private boolean completed = false;
	private String key;
	private boolean auto = true;
	private boolean async = false;

	public LldbRemoteConnectionCommand(LldbManagerImpl manager, String key) {
		this(manager, key, true, false);
	}

	public LldbRemoteConnectionCommand(LldbManagerImpl manager, String key, boolean auto,
			boolean async) {
		super(manager);
		this.key = key;
		this.auto = auto;
		this.async = async;
	}

	@Override
	public boolean handle(LldbEvent<?> evt, LldbPendingCommand<?> pending) {
		if (evt instanceof AbstractLldbCompletedCommandEvent && pending.getCommand().equals(this)) {
			completed = true;
		}
		else if (evt instanceof LldbProcessCreatedEvent) {
			created = (LldbProcessCreatedEvent) evt;
		}
		else if (evt instanceof LldbThreadCreatedEvent) {
			pending.claim(evt);
		}
		else if (evt instanceof LldbStoppedEvent) {
			pending.claim(evt);
		}
		return completed && (created != null);
	}

	@Override
	public Set<SBThread> complete(LldbPendingCommand<?> pending) {
		Set<SBThread> threads = new LinkedHashSet<>();
		for (LldbThreadCreatedEvent adds : pending.findAllOf(LldbThreadCreatedEvent.class)) {
			DebugThreadInfo info = adds.getInfo();
			threads.add(info.thread);
		}
		return threads;
	}

	@Override
	public void invoke() {
		DebugClient client = manager.getClient();
		client.connectRemote(client.getLocalServer(), key, auto, async);
	}
}
