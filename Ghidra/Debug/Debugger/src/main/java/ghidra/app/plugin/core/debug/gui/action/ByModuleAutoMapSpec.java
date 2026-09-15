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
import ghidra.debug.api.modules.ModuleMapProposal;
import ghidra.debug.api.modules.ModuleMapProposal.ModuleMapEntry;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.util.TraceEvent;
import ghidra.trace.util.TraceEvents;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ByModuleAutoMapSpec implements AutoMapSpec {
	public static final String CONFIG_NAME = "1_MAP_BY_MODULE";

	/**
	 * Get the instance.
	 * 
	 * <p>
	 * Note this will not work until after the class searcher is done.
	 * 
	 * @return the instance
	 */
	public static ByModuleAutoMapSpec instance() {
		return (ByModuleAutoMapSpec) AutoMapSpec.fromConfigName(CONFIG_NAME);
	}

	@Override
	public String getConfigName() {
		return CONFIG_NAME;
	}

	@Override
	public String getMenuName() {
		return "Auto-Map by Module";
	}

	@Override
	public Icon getMenuIcon() {
		return DebuggerResources.ICON_CONFIG;
	}

	@Override
	public Collection<TraceEvent<?, ?>> getChangeTypes() {
		return List.of(
			TraceEvents.MODULE_ADDED, TraceEvents.MODULE_CHANGED,
			TraceEvents.REGION_ADDED, TraceEvents.REGION_CHANGED);
	}

	@Override
	public boolean objectHasType(TraceObjectValue value) {
		return value.getParent().queryInterface(TraceModule.class) != null ||
			value.getParent().queryInterface(TraceMemoryRegion.class) != null;
	}

	@Override
	public String getInfoForObjects(Trace trace, long snap) {
		String modPart = trace.getModuleManager()
				.getLoadedModules(snap)
				.stream()
				.map(m -> m.getName(snap) + ":" + m.getBase(snap))
				.sorted()
				.collect(Collectors.joining(","));
		String regPart = ByRegionAutoMapSpec.getInfoForRegions(trace, snap);
		return modPart + ";" + regPart;
	}

	@Override
	public List<Program> programs(ProgramManager programManager) {
		return Arrays.asList(programManager.getAllOpenPrograms());
	}

	@Override
	public boolean performMapping(DebuggerStaticMappingService mappingService, Trace trace,
			long snap, List<Program> programs, TaskMonitor monitor) throws CancelledException {
		Map<?, ModuleMapProposal> maps = mappingService
				.proposeModuleMaps(trace.getModuleManager().getLoadedModules(snap), snap, programs);
		Collection<ModuleMapEntry> entries = MapProposal.flatten(maps.values());
		entries = MapProposal.removeOverlapping(entries);
		mappingService.addModuleMappings(entries, monitor, false);
		return !entries.isEmpty();
	}
}
