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

import java.awt.Component;

import javax.swing.*;

import ghidra.program.model.symbol.Symbol;

class SymbolEditor extends DefaultCellEditor {

	private JTextField symbolField = null;

	SymbolEditor() {
		super(new JTextField());
		symbolField = (JTextField) super.getComponent();
		symbolField.setBorder(BorderFactory.createEmptyBorder());
	}

	@Override
	public Object getCellEditorValue() {
		return symbolField.getText().trim();
	}

	@Override
	public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected,
			int row, int column) {

		Symbol symbol = (Symbol) value;
		if (symbol != null) {
			symbolField.setText(symbol.getName());
		}
		else {
			symbolField.setText("");
		}
		return symbolField;
	}
}
