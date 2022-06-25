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

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import agent.frida.frida.FridaClient;
import agent.frida.manager.FridaFrame;
import agent.frida.manager.FridaThread;
import agent.frida.manager.impl.FridaManagerImpl;

public class FridaListStackFramesCommand extends AbstractFridaCommand<Map<String, FridaFrame>> {
	protected final FridaThread thread;
	private Map<String, FridaFrame> frames = new HashMap<>();
	private int frameCount = 0;

	public FridaListStackFramesCommand(FridaManagerImpl manager, FridaThread thread) {
		super(manager);
		this.thread = thread;
	}

	@Override
	public Map<String, FridaFrame> complete(FridaPendingCommand<?> pending) {
		return frames;
	}

	@Override
	public void invoke() {
		manager.loadScript(this, "list_stack_frames",     
				"result = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);");
				//"console.log(JSON.stringify(Thread.backtrace(this.context, Backtracer.ACCURATE)));");
	}
	
	@Override
	public void parseSpecifics(JsonElement element) {
		JsonObject jobj = element.getAsJsonObject();
		Map<String, JsonElement> map = new HashMap<>();
		for (Entry<String, JsonElement> l : jobj.entrySet()) {
			map.put(l.getKey(), l.getValue());
		}
		FridaFrame frame = new FridaFrame(map, frameCount++);
		frames.put(FridaClient.getId(frame), frame);
	}
}
