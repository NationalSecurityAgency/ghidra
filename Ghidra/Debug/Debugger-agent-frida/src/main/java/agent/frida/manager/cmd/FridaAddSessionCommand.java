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

import agent.frida.manager.FridaManager;
import agent.frida.manager.FridaSession;
import agent.frida.manager.impl.FridaManagerImpl;

/**
 * Implementation of {@link FridaManager#addSession()}
 */
public class FridaAddSessionCommand extends AbstractFridaCommand<FridaSession> {

	public FridaAddSessionCommand(FridaManagerImpl manager) {
		super(manager);
	}

	@Override
	public FridaSession complete(FridaPendingCommand<?> pending) {
		// Not apparent this is needed
		return null;
	}

}
