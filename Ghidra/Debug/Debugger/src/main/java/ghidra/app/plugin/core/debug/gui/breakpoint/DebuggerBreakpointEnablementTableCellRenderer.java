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
import ghidra.app.services.LogicalBreakpoint.Enablement;
import ghidra.docking.settings.Settings;
import ghidra.util.table.column.AbstractGColumnRenderer;

public class DebuggerBreakpointEnablementTableCellRenderer
		extends AbstractGColumnRenderer<Enablement> {

	protected static Icon iconForEnablement(Enablement en) {
		switch (en) {
			case NONE:
				return null;
			case ENABLED:
				return DebuggerResources.ICON_BREAKPOINT_ENABLED_MARKER;
			case DISABLED:
				return DebuggerResources.ICON_BREAKPOINT_DISABLED_MARKER;
			case INEFFECTIVE_ENABLED:
				return DebuggerResources.ICON_BREAKPOINT_INEFFECTIVE_E_MARKER;
			case INEFFECTIVE_DISABLED:
				return DebuggerResources.ICON_BREAKPOINT_INEFFECTIVE_D_MARKER;
			case ENABLED_DISABLED:
				return DebuggerResources.ICON_BREAKPOINT_MIXED_ED_MARKER;
			case DISABLED_ENABLED:
				return DebuggerResources.ICON_BREAKPOINT_MIXED_DE_MARKER;
			default:
				throw new AssertionError(en);
		}
	}

	public DebuggerBreakpointEnablementTableCellRenderer() {
		setHorizontalAlignment(SwingConstants.CENTER);
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {
		super.getTableCellRendererComponent(data);
		Enablement en = (Enablement) data.getValue();
		setIcon(iconForEnablement(en));
		setHorizontalAlignment(SwingConstants.CENTER);
		setText("");
		return this;
	}

	@Override
	public String getFilterString(Enablement t, Settings settings) {
		return t.name();
	}
}
