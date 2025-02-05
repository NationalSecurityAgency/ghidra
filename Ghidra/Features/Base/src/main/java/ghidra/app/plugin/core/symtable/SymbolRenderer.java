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
package ghidra.app.plugin.core.symtable;

import java.awt.Color;
import java.awt.Component;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.app.util.SymbolInspector;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.table.GhidraTableCellRenderer;

public class SymbolRenderer extends GhidraTableCellRenderer {
	private SymbolInspector inspector;

	public void setSymbolInspector(SymbolInspector inspector) {
		this.inspector = inspector;
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		super.getTableCellRendererComponent(data);

		Object value = data.getValue();
		int column = data.getColumnModelIndex();
		if (value == null && column == AbstractSymbolTableModel.LABEL_COL) {
			setText("<< REMOVED >>");
		}
		else if (value instanceof Symbol s) {
			setBold();
			Color color = inspector.getColor(s);

			if (!data.isSelected()) {
				setForeground(color);
			}
		}

		return this;
	}
}
