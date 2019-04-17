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

import java.awt.Color;
import java.awt.Component;

import javax.swing.JLabel;
import javax.swing.JTable;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.feature.vt.api.main.VTAssociation;
import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.gui.provider.matchtable.MatchTableRenderer;
import ghidra.util.table.CompositeGhidraTableCellRenderer;

public class MarkupItemRenderer extends CompositeGhidraTableCellRenderer {

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

		JTable table = data.getTable();
		boolean isSelected = data.isSelected();
		if (!isSelected) {
			// gray out our background if we are locked-out
			renderer.setBackground(getBackgroundColor(table, renderer.getBackground()));
		}

		return renderer;
	}

	private Color getBackgroundColor(JTable table, Color defaultColor) {
		// we need to see if our association is locked-out        
		VTMarkupItemsTableModel model = (VTMarkupItemsTableModel) table.getModel();
		VTMarkupItem markupItem = model.getRowObject(0);
		VTAssociation association = markupItem.getAssociation();
		return MatchTableRenderer.getBackgroundColor(association, table, defaultColor);
	}
}
