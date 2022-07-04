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

import java.math.BigInteger;
import java.util.LinkedHashSet;
import java.util.Set;

import agent.frida.frida.FridaClient;
import agent.frida.frida.FridaThreadInfo;
import agent.frida.manager.*;
import agent.frida.manager.evt.*;
import agent.frida.manager.impl.FridaManagerImpl;

/**
 * Implementation of {@link FridaTarget#attach(BigInteger processId, FridaError error)}
 */
public class FridaAttachCommand extends AbstractFridaCommand<Set<FridaThread>> {

	private FridaProcessCreatedEvent created = null;
	private boolean completed = false;
	private String key;
	private int keyType = 0;
	private boolean wait = true;
	private boolean async = false;

	public FridaAttachCommand(FridaManagerImpl manager, String key) {
		this(manager, key, true, false);
		this.keyType = 0;
	}

	public FridaAttachCommand(FridaManagerImpl manager, String key, boolean wait) {
		this(manager, key, wait, false);
		this.keyType = 1;
	}

	public FridaAttachCommand(FridaManagerImpl manager, String key, boolean wait, boolean async) {
		super(manager);
		this.key = key;
		this.wait = wait;
		this.async = async;
		this.keyType = 2;
	}

	@Override
	public boolean handle(FridaEvent<?> evt, FridaPendingCommand<?> pending) {
		if (evt instanceof AbstractFridaCompletedCommandEvent && pending.getCommand().equals(this)) {
			completed = true;
		}
		else if (evt instanceof FridaProcessCreatedEvent) {
			created = (FridaProcessCreatedEvent) evt;
		}
		else if (evt instanceof FridaThreadCreatedEvent) {
			pending.claim(evt);
		}
		else if (evt instanceof FridaStoppedEvent) {
			pending.claim(evt);
		}
		return completed && (created != null);
	}

	@Override
	public Set<FridaThread> complete(FridaPendingCommand<?> pending) {
		Set<FridaThread> threads = new LinkedHashSet<>();
		for (FridaThreadCreatedEvent adds : pending.findAllOf(FridaThreadCreatedEvent.class)) {
			FridaThreadInfo info = adds.getInfo();
			threads.add(info.thread);
		}
		return threads;
	}

	@Override
	public void invoke() {
		FridaClient client = manager.getClient();
		client.attachProcess(client.getLocalServer(), keyType, key, wait, async);
		// NB: manager.waitForEventEx - embedded in attach
	}
}
