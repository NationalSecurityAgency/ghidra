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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import agent.frida.manager.FridaContext;
import agent.frida.manager.FridaProcess;
import agent.frida.manager.FridaState;
import agent.frida.manager.FridaThread;
import agent.frida.manager.impl.FridaManagerImpl;
import ghidra.util.Msg;

public class FridaListThreadsCommand extends AbstractFridaCommand<Void> {

	protected final FridaProcess process;
	private List<FridaThread> threads = new ArrayList<>();

	public FridaListThreadsCommand(FridaManagerImpl manager, FridaProcess process) {
		super(manager);
		this.process = process;
	}

	@Override
	public void invoke() {
		manager.loadScript(this, "list_threads", "result = Process.enumerateThreads();");
		for (FridaThread thread : threads) {
			manager.addThreadIfAbsent(process, thread);
		}
	}
	
	@Override
	public void parseSpecifics(JsonElement element) {
		FridaThread thread = new FridaThread(process);
		if (element.isJsonPrimitive()) {
			Msg.error(this, element.getAsString());
			return;
		}
		JsonObject modDetails = element.getAsJsonObject();
		thread.setTid(modDetails.get("id").getAsLong());
		String state = modDetails.get("state").getAsString();
		thread.setState(FridaState.byValue(state));
		JsonObject cpuContext = (JsonObject) modDetails.get("context");
		thread.setContext(new FridaContext(cpuContext));
		threads.add(thread);
	}
	
}
