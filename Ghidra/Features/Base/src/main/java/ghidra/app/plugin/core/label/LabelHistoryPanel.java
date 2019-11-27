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
package ghidra.app.plugin.core.label;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.widgets.GenericDateCellRenderer;
import docking.widgets.table.GTableCellRenderer;
import docking.widgets.table.GTableCellRenderingData;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.LabelHistory;
import ghidra.util.table.GhidraTable;

/**
 * Main panel that shows the history of labels at a specific address, or
 * shows all history for all addresses. When all addresses are displayed, 
 * the user can navigate by clicking on a row in the history table.
 */
class LabelHistoryPanel extends JPanel {
	private static final long serialVersionUID = 1L;

	private LabelHistoryTableModel tableModel;
	private JTable historyTable;
	private LabelHistoryListener listener;
	private boolean showAddresses;
	private final Program program;

	/**
	 * Construct a new history panel
	 * 
	 * @param program the program
	 * @param list list of LabelHistory objects
	 * @param listener listener that is notified when the user clicks on a
	 * row in the table; null if only label history at a specific address
	 * is being shown, in which case the address column is not displayed.
	 */
	LabelHistoryPanel(Program program, List<LabelHistory> list, LabelHistoryListener listener) {
		super(new BorderLayout());
		this.program = program;
		showAddresses = listener != null;
		this.listener = listener;

		create(list);
	}

	void setCurrentAddress(java.util.List<LabelHistory> list) {
		tableModel = new LabelHistoryTableModel(list, true);
	}

	private void create(java.util.List<LabelHistory> list) {
		tableModel = new LabelHistoryTableModel(list, showAddresses);

		// set up table sorter stuff
		//sorter.sortByColumn(tableModel.getDefaultSortColumn());

		historyTable = new GhidraTable(tableModel);
		JScrollPane sp = new JScrollPane(historyTable);

		Dimension d = new Dimension(showAddresses ? 600 : 520, 200);
		historyTable.setPreferredScrollableViewportSize(d);
		historyTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		add(sp, BorderLayout.CENTER);

		TableColumnModel columnModel = historyTable.getColumnModel();

		for (int i = 0; i < columnModel.getColumnCount(); i++) {
			TableColumn column = columnModel.getColumn(i);
			String name = (String) column.getIdentifier();
			if (name.equals(LabelHistoryTableModel.DATE)) {
				column.setCellRenderer(new GenericDateCellRenderer());
				column.setPreferredWidth(190);
			}
			else if (name.equals(LabelHistoryTableModel.LABEL)) {
				column.setPreferredWidth(280);
				column.setCellRenderer(new LabelCellRenderer());
			}
			else if (name.equals(LabelHistoryTableModel.ADDRESS)) {
				column.setPreferredWidth(130);
			}
			else if (name.equals(LabelHistoryTableModel.USER)) {
				column.setPreferredWidth(190);
			}
		}
		historyTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (!e.isPopupTrigger()) {
					handleMouseClicked();
				}
			}
		});

	}

	private void handleMouseClicked() {
		if (listener == null) {
			return;
		}
		for (LabelHistory h : tableModel.getLastSelectedObjects()) {
			listener.addressSelected(program, h.getAddress());
		}
	}

	private class LabelCellRenderer extends GTableCellRenderer {
		private static final long serialVersionUID = 1L;

		private Font monoFont;

		LabelCellRenderer() {
			Font f = getFont();
			monoFont = new Font("monospaced", f.getStyle(), f.getSize());
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			Component c = super.getTableCellRendererComponent(data);
			c.setFont(monoFont);
			return c;
		}
	}
}
