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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import agent.frida.frida.FridaClient;
import agent.frida.manager.FridaExport;
import agent.frida.manager.FridaModule;
import agent.frida.manager.impl.FridaManagerImpl;

public class FridaListModuleExportsCommand extends AbstractFridaCommand<Map<String, FridaExport>> {
	protected final FridaModule module;
	private Map<String, FridaExport> exports;

	public FridaListModuleExportsCommand(FridaManagerImpl manager, FridaModule module) {
		super(manager);
		this.module = module;
	}

	@Override
	public Map<String, FridaExport> complete(FridaPendingCommand<?> pending) {
		return exports;
	}

	@Override
	public void invoke() {
		exports = new HashMap<>();
		manager.loadScript(this, "list_module_Exports",     
				"result = Process.findModuleByAddress('"+module.getRangeAddress()+"').enumerateExports();");
		for (FridaExport imp : exports.values()) {
			exports.put(FridaClient.getId(imp), imp);
		}
	}
	
	@Override
	public void parseSpecifics(JsonElement element) {
		FridaExport export = new FridaExport(module);
		JsonObject symDetails = element.getAsJsonObject();
		export.setAddress(symDetails.get("address").getAsString());
		export.setName(symDetails.get("name").getAsString());
		export.setType(symDetails.get("type").getAsString());
		exports.put(FridaClient.getId(export), export);
	}

}
