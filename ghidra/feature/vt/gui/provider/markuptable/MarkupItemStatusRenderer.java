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
package ghidra.feature.vt.gui.provider.markuptable;

import static ghidra.feature.vt.gui.provider.markuptable.MarkupStatusIcons.*;

import javax.swing.JLabel;
import javax.swing.JTable;

import docking.widgets.table.GTableCellRenderer;
import docking.widgets.table.GTableCellRenderingData;
import ghidra.docking.settings.Settings;
import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.api.main.VTMarkupItemStatus;
import ghidra.util.exception.AssertException;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;
import resources.ResourceManager;

/**
 * Renderer for the status of a {@link VTMarkupItem}
 */
public class MarkupItemStatusRenderer extends AbstractGhidraColumnRenderer<VTMarkupItemStatus> {

	// dummy used to call methods without affecting the real renderer
	private GTableCellRenderer dummy = new GTableCellRenderer();

	@Override
	public java.awt.Component getTableCellRendererComponent(GTableCellRenderingData data) {

		JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

		Object value = data.getValue();
		JTable table = data.getTable();
		int row = data.getRowViewIndex();

		if (!(value instanceof VTMarkupItemStatus)) {
			throw new AssertException("Incorrect column value for the markup item status column");
		}

		VTMarkupItemStatus status = (VTMarkupItemStatus) value;
		configureRendererForMarkupStatus(table, row, renderer, status);

		return renderer;
	}

	private JLabel configureRendererForMarkupStatus(JTable table, int row, JLabel renderer,
			VTMarkupItemStatus value) {
		renderer.setText("");
		renderer.setHorizontalAlignment(CENTER);
		VTMarkupItemStatus status = value;
		switch (status) {
			case UNAPPLIED:
				renderer.setIcon(null);
				renderer.setToolTipText("Not Applied");
				break;
			case SAME:
				renderer.setIcon(SAME_ICON);
				renderer.setToolTipText("Destination already has same value as source");
				break;
			case ADDED:
				renderer.setIcon(APPLIED_ADDED_ICON);
				renderer.setToolTipText("Applied - Added");
				break;
			case REPLACED:
				renderer.setIcon(APPLIED_REPLACED_ICON);
				renderer.setToolTipText("Applied - Replaced");
				break;
			case REJECTED:
				renderer.setIcon(REJECTED_ICON);
				renderer.setToolTipText("Rejected");
				break;
			case FAILED_APPLY:
				renderer.setIcon(FAILED_ICON);
				renderer.setToolTipText(getFailedTooltipText(table, row));
				break;
			case DONT_KNOW:
				renderer.setIcon(DONT_KNOW_ICON);
				renderer.setToolTipText("Don't Know");
				break;
			case DONT_CARE:
				renderer.setIcon(DONT_CARE_ICON);
				renderer.setToolTipText("Don't Care");
				break;
			case CONFLICT:
				renderer.setIcon(CONFLICT_ICON);
				renderer.setToolTipText(
					"This markup item conflicts with another item that is already applied");
				break;
			default:
				renderer.setIcon(ResourceManager.loadImage("images/core.png"));
				renderer.setToolTipText("Unexpected match status state!: " + status);
				break;
		}

		return renderer;
	}

	private String getFailedTooltipText(JTable table, int row) {
		if (table == null) {
			return "Apply Failed";
		}

		VTMarkupItemsTableModel model = (VTMarkupItemsTableModel) table.getModel();
		VTMarkupItem item = model.getRowObject(row);
		String description = item.getStatusDescription();
		if (description != null) {
			return description;
		}
		return "Apply Failed";
	}

	@Override
	public String getFilterString(VTMarkupItemStatus t, Settings settings) {
		// This is a bit squinky, but this method above sets icons and tooltips on the renderer.
		// We want the tooltip, but do not want the icon to change the main renderer.  This 
		// should be refactored.   Also, we can't get the exact text for 'FAILED_APPLY', since
		// we cannot get the item, since we don't have the table model or row number.
		configureRendererForMarkupStatus(null, -1, dummy, t);
		return dummy.getText();
	}
}
