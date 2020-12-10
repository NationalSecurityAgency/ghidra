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

import java.util.Collection;
import java.util.Set;

import docking.ActionContext;
import docking.widgets.table.GTable;

public class DebuggerRegionActionContext extends ActionContext {
	private final Set<RegionRow> selectedRegions;

	public DebuggerRegionActionContext(DebuggerRegionsProvider provider,
			Collection<RegionRow> selected, GTable table) {
		super(provider, selected, table);
		this.selectedRegions = Set.copyOf(selected);
	}

	public Set<RegionRow> getSelectedRegions() {
		return selectedRegions;
	}
}
