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
package ghidra.util.charset.picker;

import java.awt.BorderLayout;
import java.nio.charset.Charset;
import java.util.function.Consumer;

import javax.swing.*;
import javax.swing.table.TableColumn;

import ghidra.util.charset.CharsetInfo;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

/**
 * JPanel that displays a table of all charsets on top and a detail panel on bottom.
 */
public class CharsetPickerPanel extends JPanel {

	private GhidraTable table;
	private CharsetTableModel tableModel = new CharsetTableModel();
	private GhidraTableFilterPanel<CharsetTableRow> tableFilterPanel;
	private Consumer<Charset> charsetListener;
	private CharsetInfo selectedCSI;

	public CharsetPickerPanel(Consumer<Charset> charsetListener) {
		super(new BorderLayout());
		build();
		this.charsetListener = charsetListener;
	}

	private void build() {

		table = new GhidraTable(tableModel);
		table.setVisibleRowCount(10);
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		tableFilterPanel = new GhidraTableFilterPanel<>(table, tableModel);

		JScrollPane scrollPane = new JScrollPane(table);

		CharsetInfoPanel detailsPanel = new CharsetInfoPanel();
		detailsPanel.getAccessibleContext().setAccessibleName("Details");
		detailsPanel.setBorder(BorderFactory.createTitledBorder("Details"));

		JPanel innerPanel = new JPanel(new BorderLayout());
		innerPanel.add(scrollPane, BorderLayout.CENTER);
		innerPanel.add(tableFilterPanel, BorderLayout.SOUTH);
		innerPanel.getAccessibleContext().setAccessibleName("Table Filter");

		add(innerPanel, BorderLayout.CENTER);
		add(detailsPanel, BorderLayout.SOUTH);

		table.getSelectionModel().addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				CharsetTableRow row = tableFilterPanel.getSelectedItem();
				if (row != null) {
					selectedCSI = row.csi();
					detailsPanel.setCharset(row.csi());
					if (charsetListener != null) {
						charsetListener.accept(row.csi().getCharset());
					}
				}
			}
		});
		TableColumn col = table.getColumnModel().getColumn(CharsetTableModel.MINLEN_COL);
		col.setMaxWidth(100);
		col = table.getColumnModel().getColumn(CharsetTableModel.MAXLEN_COL);
		col.setMaxWidth(100);
		col = table.getColumnModel().getColumn(CharsetTableModel.FIXEDLEN_COL);
		col.setMaxWidth(100);
	}

	public void setSelectedCharset(CharsetInfo csi) {
		int rowNum = tableModel.findCharset(csi);
		if (rowNum >= 0) {
			table.getSelectionManager().setSelectionInterval(rowNum, rowNum);
			table.scrollToSelectedRow();
		}
	}

	public void setCharsetListener(Consumer<Charset> charsetListener) {
		this.charsetListener = charsetListener;
	}

	public CharsetInfo getSelectedCharset() {
		return selectedCSI;
	}

}
