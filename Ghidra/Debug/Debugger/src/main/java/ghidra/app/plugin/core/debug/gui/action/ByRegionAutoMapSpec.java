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
import java.util.stream.Collectors;

import javax.swing.Icon;

import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.ProgramManager;
import ghidra.debug.api.action.AutoMapSpec;
import ghidra.debug.api.modules.MapProposal;
import ghidra.debug.api.modules.RegionMapProposal;
import ghidra.debug.api.modules.RegionMapProposal.RegionMapEntry;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.util.TraceEvent;
import ghidra.trace.util.TraceEvents;
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
	public Icon getMenuIcon() {
		return DebuggerResources.ICON_CONFIG;
	}

	@Override
	public Collection<TraceEvent<?, ?>> getChangeTypes() {
		return List.of(TraceEvents.REGION_ADDED);
	}

	@Override
	public boolean objectHasType(TraceObjectValue value) {
		return value.getParent().queryInterface(TraceMemoryRegion.class) != null;
	}

	static String getInfoForRegions(Trace trace, long snap) {
		return trace.getMemoryManager()
				.getRegionsAtSnap(snap)
				.stream()
				.map(r -> r.getName(snap) + ":" + r.getMinAddress(snap))
				.sorted()
				.collect(Collectors.joining(","));
	}

	@Override
	public String getInfoForObjects(Trace trace, long snap) {
		return getInfoForRegions(trace, snap);
	}

	@Override
	public List<Program> programs(ProgramManager programManager) {
		return Arrays.asList(programManager.getAllOpenPrograms());
	}

	@Override
	public boolean performMapping(DebuggerStaticMappingService mappingService, Trace trace,
			long snap, List<Program> programs, TaskMonitor monitor) throws CancelledException {
		Map<?, RegionMapProposal> maps = mappingService
				.proposeRegionMaps(trace.getMemoryManager().getRegionsAtSnap(snap), snap, programs);
		Collection<RegionMapEntry> entries = MapProposal.flatten(maps.values());
		entries = MapProposal.removeOverlapping(entries);
		mappingService.addRegionMappings(entries, monitor, false);
		return !entries.isEmpty();
	}
}
