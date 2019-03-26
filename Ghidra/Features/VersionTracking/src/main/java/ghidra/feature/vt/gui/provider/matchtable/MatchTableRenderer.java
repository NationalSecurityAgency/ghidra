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
package ghidra.feature.vt.gui.provider.matchtable;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JTable;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.feature.vt.api.main.*;
import ghidra.util.table.CompositeGhidraTableCellRenderer;

public class MatchTableRenderer extends CompositeGhidraTableCellRenderer {
	private static final Color LOCKED_OUT_BACKGROUND_COLOR = new Color(239, 239, 239);

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		// We are here to just render the background, so let our parent render the cell and we 
		// will just add our decoration.
		Component rendererComponent =
			super.getTableCellRendererComponent(data);

		JTable table = data.getTable();
		Object rowObject = data.getRowObject();
		boolean isSelected = data.isSelected();

		VTMatch match = (VTMatch) rowObject;
		if (match == null) {
			// This can happen when matches are applied.  The match table will trigger an
			// add/remove job on the ThreadedTableModel.  This job will manipulate the table's 
			// data from off the Swing thread, which could lead to the rug being pulled out from
			// under the renderer whilst it is repainting.
			return rendererComponent;
		}

		VTAssociation association = match.getAssociation();
		if (!isSelected && association != null) {
			// gray out our background if we are locked-out            
			rendererComponent.setBackground(getBackgroundColor(association, table,
				rendererComponent.getBackground()));
		}

		return rendererComponent;
	}

	public static Color getBackgroundColor(VTAssociation association, JTable table,
			Color defaultBackgroundColor) {
		// we need to see if our association is blocked
		VTAssociationStatus status = association.getStatus();
		if (status == VTAssociationStatus.BLOCKED) {
			return LOCKED_OUT_BACKGROUND_COLOR;
		}

		return defaultBackgroundColor;
	}
}
