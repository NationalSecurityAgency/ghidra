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
import agent.frida.manager.FridaImport;
import agent.frida.manager.FridaModule;
import agent.frida.manager.impl.FridaManagerImpl;

public class FridaListModuleImportsCommand extends AbstractFridaCommand<Map<String, FridaImport>> {
	protected final FridaModule module;
	private Map<String, FridaImport> imports;

	public FridaListModuleImportsCommand(FridaManagerImpl manager, FridaModule module) {
		super(manager);
		this.module = module;
	}

	@Override
	public Map<String, FridaImport> complete(FridaPendingCommand<?> pending) {
		return imports;
	}

	@Override
	public void invoke() {
		imports = new HashMap<>();
		manager.loadScript(this, "list_module_imports",     
				"result = Process.findModuleByAddress('"+module.getRangeAddress()+"').enumerateImports();");
		for (FridaImport imp : imports.values()) {
			imports.put(FridaClient.getId(imp), imp);
		}
	}
	
	@Override
	public void parseSpecifics(JsonElement element) {
		FridaImport imp = new FridaImport(module);
		JsonObject symDetails = element.getAsJsonObject();
		imp.setName(symDetails.get("name").getAsString());
		imp.setAddress(symDetails.get("address").getAsString());
		imp.setType(symDetails.get("type").getAsString());
		imp.setMod(symDetails.get("module").getAsString());
		JsonElement slot = symDetails.get("slot");
		if (slot != null) {
			imp.setSlot(slot.getAsString());
		}
		imports.put(FridaClient.getId(imp), imp);
	}

}
