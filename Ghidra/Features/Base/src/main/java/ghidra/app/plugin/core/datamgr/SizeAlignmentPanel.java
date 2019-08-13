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
package ghidra.app.plugin.core.datamgr;

import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.event.TableModelListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

import ghidra.program.model.data.DataOrganizationImpl;
import ghidra.util.Msg;
import ghidra.util.exception.NoValueException;
import ghidra.util.table.GhidraTable;

public class SizeAlignmentPanel extends JPanel {

	GhidraTable table;
	DataOrganizationImpl dataOrganization;

	public SizeAlignmentPanel() {
		super(new BorderLayout());
		TableModel tableModel = new SizeAlignmentTableModel();
		table = new GhidraTable(tableModel);
		table.setAutoEditEnabled(true);
		JScrollPane sp = new JScrollPane(table);
		table.setPreferredScrollableViewportSize(new Dimension(200, 80));
		add(sp, BorderLayout.CENTER);
	}

	public void setOrganization(DataOrganizationImpl dataOrganization) {
		this.dataOrganization = dataOrganization;
		((SizeAlignmentTableModel) table.getModel()).fireTableDataChanged();
	}

	class SizeAlignmentTableModel extends AbstractTableModel {

		private final String[] columnNames = new String[] { "Size", "Alignment" };
		private final int SIZE_COLUMN = 0;
		private final int ALIGNMENT_COLUMN = 1;

		SizeAlignmentTableModel() {
			super();
		}

		@Override
		public void addTableModelListener(TableModelListener l) {
			// TODO Auto-generated method stub

		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			return Integer.class;
		}

		@Override
		public int getColumnCount() {
			return columnNames.length;
		}

		@Override
		public String getColumnName(int columnIndex) {
			return columnNames[columnIndex];
		}

		@Override
		public int getRowCount() {
			return dataOrganization.getSizeAlignmentCount() + 1;
		}

		@Override
		public Object getValueAt(int rowIndex, int columnIndex) {
			int[] sizes = dataOrganization.getSizes();
			if (rowIndex < sizes.length) {
				int size = sizes[rowIndex];
				if (columnIndex == SIZE_COLUMN) {
					return size;
				}
				else if (columnIndex == ALIGNMENT_COLUMN) {
					try {
						return dataOrganization.getSizeAlignment(size);
					}
					catch (NoValueException e) {
						return null;
					}
				}
			}
			return null;
		}

		@Override
		public boolean isCellEditable(int rowIndex, int columnIndex) {
			if (rowIndex == dataOrganization.getSizeAlignmentCount()) {
				return columnIndex == SIZE_COLUMN;
			}
			return columnIndex == ALIGNMENT_COLUMN;
		}

		@Override
		public void removeTableModelListener(TableModelListener l) {
			// TODO Auto-generated method stub

		}

		@Override
		public void setValueAt(Object value, int rowIndex, int columnIndex) {
			if (value == null) {
				return;
			}
			int[] sizes = dataOrganization.getSizes();
			if (rowIndex < sizes.length) {
				int alignment = ((Integer) value).intValue();
				int size = sizes[rowIndex];
				dataOrganization.setSizeAlignment(size, alignment);
			}
			if (rowIndex == sizes.length) {
				int size = ((Integer) value).intValue();
				// Check that we don't already have this size.
				try {
					dataOrganization.getSizeAlignment(size);
					setStatusMessage("An alignment is already defined for a size of " + size + ".");
					return;
				}
				catch (NoValueException e) {
					// Actually don't want to find a value so we can set one below.
				}
				int alignment = size; // Set the alignment to match the size initially.
				dataOrganization.setSizeAlignment(size, alignment);
				fireTableDataChanged();
			}
		}
	}

	public void setStatusMessage(String message) {
		// TODO Change this to write to the status line in the dialog.
		Msg.showError(this, this, "Invalid Input", message);
	}

}
