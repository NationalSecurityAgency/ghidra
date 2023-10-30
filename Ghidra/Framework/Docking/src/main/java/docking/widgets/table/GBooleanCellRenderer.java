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

import java.awt.*;

import javax.swing.JTable;

import docking.widgets.checkbox.GCheckBox;

public class GBooleanCellRenderer extends GTableCellRenderer {

	protected GCheckBox cb = new GCheckBox();

	public GBooleanCellRenderer() {
		super();
		setLayout(new BorderLayout());
		cb.setHorizontalAlignment(CENTER);
		cb.setOpaque(false);
		add(cb);
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		super.getTableCellRendererComponent(data);

		Object value = data.getValue();

		JTable table = data.getTable();
		int row = data.getRowViewIndex();
		int col = data.getColumnViewIndex();
		boolean isEditable = table.isCellEditable(row, col);

		cb.setEnabled(isEditable);
		setValue(value, isEditable);

		return this;
	}

	public boolean isSelected() {
		return cb.isSelected();
	}

	@Override
	public void invalidate() {
		superValidate();
	}

	@Override
	public void validate() {
		synchronized (getTreeLock()) {
			validateTree();
		}
	}

	@Override
	public Dimension getMaximumSize() {
		return cb.getMaximumSize();
	}

	@Override
	public Dimension getMinimumSize() {
		return cb.getMinimumSize();
	}

	@Override
	public Dimension getPreferredSize() {
		return cb.getPreferredSize();
	}

	protected void setValue(Object value, boolean isEditable) {
		if (value == null) {
			setText("N/A");
			cb.setVisible(false);
		}
		else {
			setText("");
			cb.setVisible(true);
			boolean isSelected = ((Boolean) value).booleanValue();
			cb.setSelected(isSelected);
			setToolTipText(isSelected ? "true" : "false" + (!isEditable ? " (uneditable)" : ""));
		}
	}
}
