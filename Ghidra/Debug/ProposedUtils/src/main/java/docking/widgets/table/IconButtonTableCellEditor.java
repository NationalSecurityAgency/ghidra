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
package docking.widgets.table;

import java.awt.Component;
import java.awt.event.ActionEvent;

import javax.swing.*;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableModel;

public abstract class IconButtonTableCellEditor<R> extends AbstractCellEditor
		implements TableCellEditor {
	protected static final String BLANK = "";
	protected JButton button = new JButton(BLANK);

	private final Class<R> cls;

	protected R row;
	protected TableModel model;

	public IconButtonTableCellEditor(Class<R> cls, Icon icon) {
		this.cls = cls;
		button.setIcon(icon);
		button.addActionListener(this::doClicked);
	}

	@Override
	public Object getCellEditorValue() {
		return BLANK;
	}

	@Override
	@SuppressWarnings("hiding")
	public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected,
			int row, int column) {
		if (!(table instanceof GTable gtable)) {
			return null;
		}
		GTableFilterPanel<?> filterPanel = gtable.getTableFilterPanel();
		if (filterPanel == null) {
			// There has to be some other way to get a "row object", no?
			return null;
		}
		Object rowObj = filterPanel.getRowObject(row);
		if (!cls.isInstance(rowObj)) {
			return null;
		}
		this.row = cls.cast(rowObj);
		button.setToolTipText(value.toString());
		this.model = gtable.getUnwrappedTableModel();

		return button;
	}

	private void doClicked(ActionEvent e) {
		fireEditingStopped();
		clicked();
	}

	protected abstract void clicked();
}
