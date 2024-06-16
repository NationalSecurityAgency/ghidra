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

import agent.frida.frida.FridaClientImpl;
import agent.frida.manager.*;
import agent.frida.manager.impl.FridaManagerImpl;

/**
 * Implementation of {@link FridaTarget#attach(BigInteger processId, FridaError error)}
 */
public class FridaAttachDeviceByTypeCommand extends AbstractFridaCommand<Void> {

	private String key;

	public FridaAttachDeviceByTypeCommand(FridaManagerImpl manager, String key) {
		super(manager);
		this.key = key;
	}

	@Override
	public boolean handle(FridaEvent<?> evt, FridaPendingCommand<?> pending) {
		return true;
	}

	@Override
	public Void complete(FridaPendingCommand<?> pending) {
		return null;
	}

	@Override
	public void invoke() {
		FridaClientImpl client = (FridaClientImpl) manager.getClient();
		client.createTargetByType(key);
		// NB: manager.waitForEventEx - embedded in attach
	}
}
