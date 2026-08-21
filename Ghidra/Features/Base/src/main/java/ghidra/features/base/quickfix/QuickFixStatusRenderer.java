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
package ghidra.features.base.quickfix;

import java.awt.Component;

import javax.swing.Icon;
import javax.swing.JLabel;

import docking.widgets.table.GTableCellRenderingData;
import generic.theme.GIcon;
import ghidra.docking.settings.Settings;
import ghidra.util.exception.AssertException;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;
import resources.Icons;

/**
 * Renderer for the {@link QuickFixStatus} column
 */
public class QuickFixStatusRenderer extends AbstractGhidraColumnRenderer<QuickFixStatus> {

	private static final Icon DONE_ICON = new GIcon("icon.base.plugin.quickfix.done");
	private static final Icon ERROR_ICON = Icons.ERROR_ICON;
	private static final Icon WARNING_ICON = Icons.WARNING_ICON;
	private static final Icon DELETE_ICON = Icons.DELETE_ICON;

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);
		QuickFixStatus status = (QuickFixStatus) data.getValue();

		Icon icon = getIcon(status);
		renderer.setIcon(icon);
		renderer.setText("");
		QuickFix rowObject = (QuickFix) data.getRowObject();
		renderer.setToolTipText(rowObject.getStatusMessage());

		return renderer;
	}

	private Icon getIcon(QuickFixStatus status) {
		switch (status) {
			case DONE:
				return DONE_ICON;
			case WARNING:
			case CHANGED:
				return WARNING_ICON;
			case ERROR:
				return ERROR_ICON;
			case DELETED:
				return DELETE_ICON;
			case NONE:
				return null;
			default:
				throw new AssertException("Unexpected QuickFix status: " + status);
		}
	}

	@Override
	public String getFilterString(QuickFixStatus t, Settings settings) {
		return t.toString();
	}

}
