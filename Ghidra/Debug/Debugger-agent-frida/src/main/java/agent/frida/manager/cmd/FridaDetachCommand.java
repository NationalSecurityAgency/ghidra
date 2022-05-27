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
import java.util.List;
import java.util.Map;

import agent.frida.frida.FridaClient;
import agent.frida.manager.*;
import agent.frida.manager.impl.FridaManagerImpl;
import ghidra.util.Msg;

/**
 * Implementation of {@link FridaProcess#detach()}
 */
public class FridaDetachCommand extends AbstractFridaCommand<Void> {
	
	private final FridaSession session;

	public FridaDetachCommand(FridaManagerImpl manager, FridaSession session) {
		super(manager);
		this.session = session;
	}

	@Override
	public Void complete(FridaPendingCommand<?> pending) {
		FridaProcess process = session.getProcess();
		String pid = FridaClient.getId(process);
		Map<String, FridaThread> threads = manager.getKnownThreads(process);	
		List<FridaThread> list= new ArrayList<>();
		list.addAll(threads.values());
		for (FridaThread thread : list) {
			manager.removeThread(pid, FridaClient.getId(thread));
		}
		manager.getEventListeners().fire.processRemoved(pid, FridaCause.Causes.UNCLAIMED);
		return null;
	}

	@Override
	public void invoke() {
		FridaError res = session.detach();
		if (!res.success()) {
			Msg.error(this, res.getDescription());
		}
	}
}
