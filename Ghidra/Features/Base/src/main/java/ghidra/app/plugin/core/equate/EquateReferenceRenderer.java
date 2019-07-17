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

import java.awt.Component;

import javax.swing.JLabel;
import javax.swing.JTable;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.program.model.symbol.EquateReference;
import ghidra.util.table.GhidraTableCellRenderer;

public class EquateReferenceRenderer extends GhidraTableCellRenderer {

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		JLabel label = (JLabel) super.getTableCellRendererComponent(data);

		Object value = data.getValue();
		JTable table = data.getTable();
		int column = data.getColumnViewIndex();

		label.setText(" ");

		EquateReference eqref = (EquateReference) value;
		if (table.getColumnName(column).equals(EquateReferenceTableModel.ADDR_COL_NAME)) {
			label.setText(eqref.getAddress().toString());
		}
		else if (table.getColumnName(column).equals(EquateReferenceTableModel.OPINDEX_COL_NAME)) {
			label.setText(Short.toString(eqref.getOpIndex()));
		}

		return label;
	}
}
