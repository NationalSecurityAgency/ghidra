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
package ghidra.app.plugin.core.debug.gui.breakpoint;

import java.awt.Component;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.docking.settings.Settings;
import ghidra.util.table.column.AbstractGColumnRenderer;

public class DebuggerBreakpointEnablementTableCellRenderer
		extends AbstractGColumnRenderer<Boolean> {
	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {
		super.getTableCellRendererComponent(data);
		Boolean enabled = (Boolean) data.getValue();
		if (enabled == null) {
			/**
			 * TODO: Distinguish DE from ED. Will need Enablement, not just Boolean. Will also
			 * require custom "cell editor".
			 */
			setIcon(DebuggerResources.ICON_BREAKPOINT_MIXED_ED_MARKER);
		}
		else if (enabled) {
			setIcon(DebuggerResources.ICON_BREAKPOINT_ENABLED_MARKER);
		}
		else {
			setIcon(DebuggerResources.ICON_BREAKPOINT_DISABLED_MARKER);
		}
		setText("");
		return this;
	}

	@Override
	public String getFilterString(Boolean t, Settings settings) {
		return t == null ? "Mixed" : t ? "Enabled" : "Disabled";
	}
}
