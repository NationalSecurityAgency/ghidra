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

import agent.frida.frida.FridaClient;
import agent.frida.manager.evt.FridaProcessExitedEvent;
import agent.frida.manager.impl.FridaManagerImpl;

/**
 * Implementation of {@link FridaManager#destroy()}
 */
public class FridaDestroyCommand extends AbstractFridaCommand<Void> {
	public FridaDestroyCommand(FridaManagerImpl manager) {
		super(manager);
	}

	@Override
	public void invoke() {
		FridaClient client = manager.getClient();
		// NB: process the event before terminating
		manager.processEvent(new FridaProcessExitedEvent(0));
		client.terminateCurrentProcess(manager.getCurrentTarget());
		//client.detachCurrentProcess();
	}
}
