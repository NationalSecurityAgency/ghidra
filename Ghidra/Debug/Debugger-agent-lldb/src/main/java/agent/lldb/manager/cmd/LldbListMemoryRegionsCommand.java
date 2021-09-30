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
package agent.lldb.manager.cmd;

import java.util.ArrayList;
import java.util.List;

import SWIG.*;
import agent.lldb.manager.impl.LldbManagerImpl;

public class LldbListMemoryRegionsCommand extends AbstractLldbCommand<List<SBMemoryRegionInfo>> {

	private SBProcess process;
	private List<SBMemoryRegionInfo> memoryRegions = new ArrayList<>();

	public LldbListMemoryRegionsCommand(LldbManagerImpl manager, SBProcess process) {
		super(manager);
		this.process = process;
	}

	@Override
	public List<SBMemoryRegionInfo> complete(LldbPendingCommand<?> pending) {
		return memoryRegions;
	}

	@Override
	public void invoke() {
		SBMemoryRegionInfoList regions = process.GetMemoryRegions();
		for (int i = 0; i < regions.GetSize(); i++) {
			SBMemoryRegionInfo info = new SBMemoryRegionInfo();
			boolean success = regions.GetMemoryRegionAtIndex(i, info);
			if (success) {
				memoryRegions.add(info);
			}
		}
	}

}
