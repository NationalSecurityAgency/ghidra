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
package ghidra.app.plugin.core.equate;

import static ghidra.app.plugin.core.equate.EquateTableModel.*;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JLabel;
import javax.swing.JTable;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.app.util.ToolTipUtils;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.util.UniversalID;
import ghidra.util.table.GhidraTableCellRenderer;

class EquateRenderer extends GhidraTableCellRenderer {

	private EquateTableProvider equateProvider;

	EquateRenderer(EquateTableProvider equateProvider) {
		this.equateProvider = equateProvider;
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		JLabel label = (JLabel) super.getTableCellRendererComponent(data);

		Object value = data.getValue();
		JTable table = data.getTable();
		int column = data.getColumnViewIndex();
		boolean isSelected = data.isSelected();

		label.setText(" ");

		Equate eq = (Equate) value;
		if (eq == null) {
			return label;
		}

		String columnName = table.getColumnName(column);
		if (columnName.equals(NAME_COL_NAME)) {
			if (!eq.isValidUUID()) { // Error equate
				label.setForeground((isSelected) ? Color.WHITE : Color.RED);
			}
			else if (!eq.isEnumBased()) { // User label
				label.setForeground((isSelected) ? Color.WHITE : Color.BLUE.brighter());
			}

			label.setText(eq.getDisplayName());

			String tooltip = getEquateToolTip(eq);
			label.setToolTipText(tooltip);
		}
		else if (columnName.equals(VALUE_COL_NAME)) {
			label.setText(eq.getDisplayValue());
		}
		else if (columnName.equals(REFS_COL_NAME)) {
			int referenceCount = eq.getReferenceCount();
			String text = Integer.toString(referenceCount);
			label.setText(text);
		}

		return label;
	}

	private String getEquateToolTip(Equate eq) {
		Program program = equateProvider.getProgram();
		DataTypeManager dtm = program.getDataTypeManager();
		UniversalID id = eq.getEnumUUID();
		if (id == null) {
			return eq.getName();
		}

		Enum enoom = (Enum) dtm.findDataTypeForID(id);
		if (enoom == null) {
			return null;
		}
		String tooltip = ToolTipUtils.getToolTipText(enoom);
		return tooltip;
	}
}
