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
package ghidra.app.plugin.core.debug.gui.action;

import java.util.*;

import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.ProgramManager;
import ghidra.debug.api.modules.MapProposal;
import ghidra.debug.api.modules.RegionMapProposal;
import ghidra.debug.api.modules.RegionMapProposal.RegionMapEntry;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceMemoryRegionChangeType;
import ghidra.trace.util.TraceChangeType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ByRegionAutoMapSpec implements AutoMapSpec {
	public static final String CONFIG_NAME = "1_MAP_BY_REGION";

	@Override
	public String getConfigName() {
		return CONFIG_NAME;
	}

	@Override
	public String getMenuName() {
		return "Auto-Map by Region";
	}

	@Override
	public Collection<TraceChangeType<?, ?>> getChangeTypes() {
		return List.of(TraceMemoryRegionChangeType.ADDED);
	}

	@Override
	public void performMapping(DebuggerStaticMappingService mappingService, Trace trace,
			ProgramManager programManager, TaskMonitor monitor) throws CancelledException {
		List<Program> programs = Arrays.asList(programManager.getAllOpenPrograms());
		Map<?, RegionMapProposal> maps = mappingService
				.proposeRegionMaps(trace.getMemoryManager().getAllRegions(), programs);
		Collection<RegionMapEntry> entries = MapProposal.flatten(maps.values());
		entries = MapProposal.removeOverlapping(entries);
		mappingService.addRegionMappings(entries, monitor, false);
	}
}
