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
import agent.frida.manager.FridaModule;
import agent.frida.manager.FridaSymbol;
import agent.frida.manager.impl.FridaManagerImpl;

public class FridaListModuleSymbolsCommand extends AbstractFridaCommand<Map<String, FridaSymbol>> {
	protected final FridaModule module;
	private Map<String, FridaSymbol> symbols;

	public FridaListModuleSymbolsCommand(FridaManagerImpl manager, FridaModule module) {
		super(manager);
		this.module = module;
	}

	@Override
	public Map<String, FridaSymbol> complete(FridaPendingCommand<?> pending) {
		return symbols;
	}

	@Override
	public void invoke() {
		symbols = new HashMap<>();
		manager.loadScript(this, "list_module_symbols",     
				"result = Process.findModuleByAddress('"+module.getRangeAddress()+"').enumerateSymbols();");
		for (FridaSymbol symbol : symbols.values()) {
			symbols.put(FridaClient.getId(symbol), symbol);
		}
	}
	
	@Override
	public void parseSpecifics(JsonElement element) {
		FridaSymbol symbol = new FridaSymbol(module);
		JsonObject symDetails = element.getAsJsonObject();
		symbol.setAddress(symDetails.get("address").getAsString());
		symbol.setSize(symDetails.get("size").getAsLong());
		symbol.setType(symDetails.get("type").getAsString());
		symbol.setName(symDetails.get("name").getAsString());
		symbol.setGlobal(symDetails.get("isGlobal").getAsBoolean());
		Object sect = symDetails.get("section");
		if (sect != null) {
			JsonObject section = (JsonObject) sect;
			symbol.setSectionId(section.get("id").getAsString());
		}
		symbols.put(FridaClient.getId(symbol), symbol);
	}

}
