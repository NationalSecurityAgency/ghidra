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

import javax.swing.Icon;
import javax.swing.SwingConstants;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.docking.settings.Settings;
import ghidra.util.table.column.AbstractGColumnRenderer;

public class DebuggerBreakpointLocEnabledTableCellRenderer
		extends AbstractGColumnRenderer<Boolean> {

	protected static Icon iconForEnabled(Boolean enabled) {
		return enabled == null ? null
				: enabled
						? DebuggerResources.ICON_BREAKPOINT_ENABLED_MARKER
						: DebuggerResources.ICON_BREAKPOINT_DISABLED_MARKER;
	}

	public DebuggerBreakpointLocEnabledTableCellRenderer() {
		setHorizontalAlignment(SwingConstants.CENTER);
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {
		super.getTableCellRendererComponent(data);
		Boolean en = (Boolean) data.getValue();
		setIcon(iconForEnabled(en));
		setHorizontalAlignment(SwingConstants.CENTER);
		setText("");
		setToolTipText(en ? "ENABLED" : "DISABLED");
		return this;
	}

	@Override
	public String getFilterString(Boolean t, Settings settings) {
		return t == null ? "null" : t ? "enabled" : "disabled";
	}
}
