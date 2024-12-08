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
package ghidra.app.plugin.core.debug.gui.memory;

import java.awt.Component;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

import docking.ComponentProvider;
import docking.DefaultActionContext;
import docking.widgets.table.GTable;
import ghidra.trace.model.memory.TraceMemoryRegion;

public class DebuggerRegionActionContext extends DefaultActionContext {
	private final Set<TraceMemoryRegion> selectedRegions;
	private final boolean forcedSingle;

	private static Set<TraceMemoryRegion> toRegions(Collection<RegionRow> rows) {
		return rows.stream().map(RegionRow::getRegion).collect(Collectors.toUnmodifiableSet());
	}

	public DebuggerRegionActionContext(DebuggerRegionsProvider provider,
			Collection<RegionRow> rows, GTable table) {
		this(provider, toRegions(rows), table, false);
	}

	public DebuggerRegionActionContext(ComponentProvider provider,
			Set<TraceMemoryRegion> selected, Component sourceComponent, boolean forcedSingle) {
		super(provider, selected, sourceComponent);
		this.selectedRegions = selected;
		this.forcedSingle = forcedSingle;
	}

	public Set<TraceMemoryRegion> getSelectedRegions() {
		return selectedRegions;
	}

	public boolean isForcedSingle() {
		return forcedSingle;
	}
}
