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

import agent.frida.manager.FridaKernelModule;
import agent.frida.manager.impl.FridaManagerImpl;

public class FridaListKernelModulesCommand extends AbstractFridaCommand<Void> {
	
	private List<FridaKernelModule> modules = new ArrayList<>();

	public FridaListKernelModulesCommand(FridaManagerImpl manager) {
		super(manager);
	}

	@Override
	public void invoke() {
		manager.loadScript(this, "list_modules",     	
				"result = Kernel.enumerateModules();");
		for (FridaKernelModule module : modules) {
			manager.addKernelModuleIfAbsent(module);
		}
	}

	@Override
	public void parseSpecifics(JsonElement element) {
		FridaKernelModule module = new FridaKernelModule();
		JsonObject modDetails = element.getAsJsonObject();
		module.setName(modDetails.get("name").getAsString());
		module.setRangeAddress(modDetails.get("base").getAsString());
		module.setRangeSize(modDetails.get("size").getAsLong());
		modules.add(module);
	}
}
