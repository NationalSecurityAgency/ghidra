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

import agent.frida.manager.FridaSession;
import agent.frida.manager.impl.FridaManagerImpl;

public class FridaGetSessionAttributesCommand extends AbstractFridaCommand<Void> {

	protected final FridaSession session;
	private Map<String, Object> attributes = new HashMap<>();

	public FridaGetSessionAttributesCommand(FridaManagerImpl manager, FridaSession session) {
		super(manager);
		this.session = session;
	}

	@Override
	public void invoke() {
		manager.setCurrentSession(session);
		manager.loadScript(this, "get_session_attributes",     
				"var d = {};" +
			    "d['version'] = Frida.version;" +
			    "d['heapSize'] = Frida.heapSize;" +
				"d['id'] = Process.id;" +
				"d['arch'] = Process.arch;" +
			    "d['os'] = Process.platform;" +
			    "d['pageSize'] = Process.pageSize;" +
			    "d['pointerSize'] = Process.pointerSize;" +
			    "d['codeSigning'] = Process.codeSigningPolicy;" +
			    "d['debugger'] = Process.isDebuggerAttached();" +
				"d['runtime'] = Script.runtime;" +
				"d['kernel'] = Kernel.available;" +
				"if (Kernel.available) {" +
				"   d['kbase'] = Kernel.base;" +
				"   d['kPageSize'] = Kernel.pageSize;" +
				"}" +
			    "result = d;");
		session.setAttributes(attributes);
	}
	
	@Override
	public void parseSpecifics(JsonElement element) {
		attributes = new HashMap<>();
		for (Entry<String, JsonElement> entry : element.getAsJsonObject().entrySet()) {
			attributes.put(entry.getKey(), entry.getValue().getAsString());
		}
	}

}
