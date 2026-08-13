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
package docking.widgets.gtreetable;

import java.awt.BorderLayout;
import java.awt.Rectangle;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.JPanel;
import javax.swing.JScrollPane;

import docking.widgets.table.GTable;
import docking.widgets.table.GTableFilterPanel;

public class GTreeTable<T extends GTreeTableNode> extends JPanel {
	private final GTable table;
	private final GTableFilterPanel<T> filterPanel;

	private final GTreeTableModel<T> tableModel;

	public GTreeTable(GTreeTableModel<T> model) {
		tableModel = model;
		table = new GTable(tableModel);
		setLayout(new BorderLayout());

		addTableToPanel(table);

		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				final int row = table.rowAtPoint(e.getPoint());
				final int col = table.columnAtPoint(e.getPoint());
				final GTreeTableNode selected = filterPanel.getSelectedItem();
				if (selected == null) {
					return;
				}
				if (table.getCellRenderer(row,
					col) instanceof final GTreeTableCellRenderer renderer) {
					final Rectangle cellRect = table.getCellRect(row, col, false);

					if (renderer.inExpandIcon(selected, e.getX() - cellRect.x)) {
						selected.setExpanded(!selected.isExpanded());
						tableModel.reload();
					}
				}
			}
		});

		filterPanel = new GTableFilterPanel<>(table, tableModel);
		add(filterPanel, BorderLayout.SOUTH);
	}

	/**
	 * Sort of a hack to allow extending classes the ability to add any wrappers around the GTable
	 * if desired
	 *
	 * @param table
	 * 		Table to add to the panel
	 */
	protected void addTableToPanel(GTable table) {
		add(new JScrollPane(table));
	}

	/**
	 * Get the filter panel of this table
	 *
	 * @return The filter panel
	 */
	public GTableFilterPanel<T> getFilterPanel() {
		return filterPanel;
	}

	/**
	 * Get the GTable of this GTreeTable
	 *
	 * @return The table
	 */
	public GTable getTable() {
		return table;
	}

	/**
	 * Get the model tied to this GTreeTable
	 *
	 * @return The model
	 */
	public GTreeTableModel<T> getTableModel() {
		return tableModel;
	}
}
