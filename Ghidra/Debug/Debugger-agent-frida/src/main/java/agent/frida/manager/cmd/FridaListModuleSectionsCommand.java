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
import agent.frida.manager.FridaSection;
import agent.frida.manager.impl.FridaManagerImpl;

public class FridaListModuleSectionsCommand extends AbstractFridaCommand<Map<String, FridaSection>> {
	protected final FridaModule module;
	private Map<String, FridaSection> sections;

	public FridaListModuleSectionsCommand(FridaManagerImpl manager, FridaModule module) {
		super(manager);
		this.module = module;
	}

	@Override
	public Map<String, FridaSection> complete(FridaPendingCommand<?> pending) {
		return sections;
	}

	@Override
	public void invoke() {
		sections = new HashMap<>();
		manager.loadScript(this, "list_module_ranges",      
				"result = Process.findModuleByAddress('"+module.getRangeAddress()+"').enumerateRanges('---');");
		for (FridaSection section : sections.values()) {
			sections.put(FridaClient.getId(section), section);
		}
	}
	
	@Override
	public void parseSpecifics(JsonElement element) {
		FridaSection section = new FridaSection(module);
		JsonObject sectionDetails = element.getAsJsonObject();
		section.setRangeAddress((String) sectionDetails.get("base").getAsString());
		section.setRangeSize((Long) sectionDetails.get("size").getAsLong());
		section.setProtection((String) sectionDetails.get("protection").getAsString());
		JsonObject sectionFile = (JsonObject) sectionDetails.get("file");
		if (sectionFile != null) {
			section.setFilePath(sectionFile.get("path").getAsString());
			section.setFileOffset(sectionFile.get("offset").getAsLong());
			section.setFileSize(sectionFile.get("size").getAsLong());
		}
		sections.put(FridaClient.getId(section), section);
	}

}
