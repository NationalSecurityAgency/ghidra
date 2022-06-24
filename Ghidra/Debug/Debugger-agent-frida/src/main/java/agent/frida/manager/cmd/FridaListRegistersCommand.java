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

import java.util.Map;

import com.google.gson.JsonElement;

import agent.frida.manager.FridaContext;
import agent.frida.manager.FridaThread;
import agent.frida.manager.impl.FridaManagerImpl;

public class FridaListRegistersCommand extends AbstractFridaCommand<Map<String, String>> {
	protected final FridaThread thread;
	private Map<String, String> result;

	public FridaListRegistersCommand(FridaManagerImpl manager, FridaThread thread) {
		super(manager);
		this.thread = thread;
	}

	@Override
	public Map<String, String> complete(FridaPendingCommand<?> pending) {
		return result;
	}

	@Override
	public void invoke() {
		FridaContext context = thread.getContext();
		result = context.getChildren();
	}
}
