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

import agent.frida.manager.FridaKernelMemoryRegionInfo;
import agent.frida.manager.impl.FridaManagerImpl;

public class FridaListKernelMemoryRegionsCommand extends AbstractFridaCommand<Void> {

	private List<FridaKernelMemoryRegionInfo> regions = new ArrayList<>();

	public FridaListKernelMemoryRegionsCommand(FridaManagerImpl manager) {
		super(manager);
	}

	@Override
	public void invoke() {
		manager.loadScript(this, "list_ranges",     
				"result = Kernel.enumerateRanges('---');");
		for (FridaKernelMemoryRegionInfo region : regions) {
			manager.addKernelMemoryRegionIfAbsent(region);
		}
	}

	@Override
	public void parseSpecifics(JsonElement element) {
		FridaKernelMemoryRegionInfo region = new FridaKernelMemoryRegionInfo();
		JsonObject memDetails = element.getAsJsonObject();
		region.setRangeAddress(memDetails.get("base").getAsString());
		region.setRangeSize(memDetails.get("size").getAsLong());
		region.setProtection(memDetails.get("protection").getAsString());
		regions.add(region);
	}
}
