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

import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import org.jdom.Element;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.table.DefaultRowFilterTransformer;
import docking.widgets.table.RowFilterTransformer;
import ghidra.app.plugin.core.symtable.AbstractSymbolTableModel.OriginalNameColumn;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.*;

class SymbolPanel extends JPanel {

	private static final boolean FILTER_NAME_ONLY_DEFAULT = true;

	private static final String FILTER_SETTINGS_ELEMENT_NAME = "FILTER_SETTINGS";

	private SymbolProvider symbolProvider;
	private SymbolTableModel symbolModel;
	private GhidraTable gTable;
	private TableModelListener listener;
	private FilterDialog filterDialog;
	private GhidraThreadedTablePanel<SymbolRowObject> threadedTablePanel;
	private GhidraTableFilterPanel<SymbolRowObject> tableFilterPanel;

	SymbolPanel(SymbolProvider provider, SymbolTableModel model, SymbolRenderer renderer,
			PluginTool tool) {
		super(new BorderLayout());

		this.symbolProvider = provider;
		this.symbolModel = model;
		this.threadedTablePanel = new GhidraThreadedTablePanel<>(model);
		this.listener = e -> symbolProvider.updateTitle();

		gTable = threadedTablePanel.getTable();
		gTable.setAutoLookupColumn(AbstractSymbolTableModel.LABEL_COL);
		gTable.setRowSelectionAllowed(true);
		gTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		gTable.getModel().addTableModelListener(listener);
		gTable.getSelectionModel().addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				handleTableSelection();
				tool.contextChanged(symbolProvider);
			}
		});

		gTable.setAccessibleNamePrefix("Symbol");

		gTable.installNavigation(tool);

		for (int i = 0; i < gTable.getColumnCount(); i++) {
			TableColumn column = gTable.getColumnModel().getColumn(i);
			column.setCellRenderer(renderer);
			if (column.getModelIndex() == AbstractSymbolTableModel.LABEL_COL) {
				column.setCellEditor(new SymbolEditor());
			}
		}

		add(threadedTablePanel, BorderLayout.CENTER);
		add(createFilterFieldPanel(), BorderLayout.SOUTH);

		filterDialog = new FilterDialog(tool);

		// enable dragging symbols out of the symbol table
		new SymbolTableDragProvider(gTable, model);
	}

	private JPanel createFilterFieldPanel() {
		tableFilterPanel = new GhidraTableFilterPanel<>(gTable, symbolModel);
		tableFilterPanel.setToolTipText("Filters the contents of the table on symbol " +
			"names that start with the given pattern");

		tableFilterPanel.add(Box.createHorizontalStrut(5));

		final JCheckBox nameColumnOnlyCheckbox = new GCheckBox("Name Only");
		nameColumnOnlyCheckbox.setName("NameOnly"); // used by JUnit
		nameColumnOnlyCheckbox.setToolTipText(
			"<html><b>Selected</b> causes filter to only consider the symbol's name.");
		nameColumnOnlyCheckbox.setFocusable(false);
		nameColumnOnlyCheckbox.setSelected(FILTER_NAME_ONLY_DEFAULT);
		tableFilterPanel
				.setFilterRowTransformer(updateRowDataTransformer(FILTER_NAME_ONLY_DEFAULT));
		nameColumnOnlyCheckbox.addItemListener(e -> {
			boolean nameOnly = nameColumnOnlyCheckbox.isSelected();
			tableFilterPanel.setFilterRowTransformer(updateRowDataTransformer(nameOnly));
		});

		tableFilterPanel.add(nameColumnOnlyCheckbox);

		tableFilterPanel.setAccessibleNamePrefix("Symbol");
		return tableFilterPanel;
	}

	void locationChanged(ProgramLocation location) {

		Program program = location.getProgram();
		SymbolTable symbolTable = program.getSymbolTable();
		Address address = location.getAddress();
		Symbol primarySymbol = symbolTable.getPrimarySymbol(address);
		if (primarySymbol == null) {
			return;
		}

		SymbolRowObject rowObject = new SymbolRowObject(primarySymbol);
		int index = symbolModel.getRowIndex(rowObject);
		if (index >= 0) {
			gTable.selectRow(index);
			gTable.scrollToSelectedRow();
		}
	}

	protected RowFilterTransformer<SymbolRowObject> updateRowDataTransformer(boolean nameOnly) {
		TableColumnModel columnModel = gTable.getColumnModel();
		if (nameOnly) {
			return new NameOnlyRowTransformer(symbolModel, columnModel);
		}
		return new DefaultRowFilterTransformer<>(symbolModel, columnModel);
	}

	void dispose() {
		gTable.getModel().removeTableModelListener(listener);
		gTable.dispose();
		threadedTablePanel.dispose();
		tableFilterPanel.dispose();
		filterDialog.dispose();
	}

	void setFilter() {
		if (filterDialog == null) {
			return;
		}
		if (gTable.isEditing()) {
			gTable.editingCanceled(null);
		}
		symbolProvider.setCurrentSymbol(null);
		gTable.clearSelection();

		filterDialog.adjustFilter(symbolProvider, symbolModel);
	}

	SymbolFilter getFilter() {
		return symbolModel.getFilter();
	}

	void readConfigState(SaveState saveState) {
		Element filterElement = saveState.getXmlElement(FILTER_SETTINGS_ELEMENT_NAME);
		if (filterElement != null) {
			filterDialog.restoreFilter(filterElement);
			symbolModel.setFilter(filterDialog.getFilter());
		}
	}

	void writeConfigState(SaveState saveState) {
		Element filterElement = filterDialog.saveFilter();
		saveState.putXmlElement(FILTER_SETTINGS_ELEMENT_NAME, filterElement);
	}

	private void handleTableSelection() {
		int selectedRowCount = gTable.getSelectedRowCount();

		if (selectedRowCount == 1) {
			int selectedRow = gTable.getSelectedRow();
			Symbol symbol = symbolProvider.getSymbolForRow(selectedRow);
			symbolProvider.setCurrentSymbol(symbol); // null allowed
		}
		else {
			symbolProvider.setCurrentSymbol(null);
		}
	}

	int getActualSymbolCount() {
		return gTable.getRowCount();
	}

	List<Symbol> getSelectedSymbols() {
		List<Symbol> list = new ArrayList<>();
		int[] rows = gTable.getSelectedRows();
		for (SymbolRowObject rowObject : symbolModel.getRowObjects(rows)) {
			Symbol s = rowObject.getSymbol();
			if (s != null) {
				list.add(s);
			}
		}
		return list;
	}

	GhidraTable getTable() {
		return gTable;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class NameOnlyRowTransformer
			extends DefaultRowFilterTransformer<SymbolRowObject> {

		private List<String> list = new ArrayList<>();
		private SymbolTableModel symbolTableModel;

		NameOnlyRowTransformer(SymbolTableModel symbolTableModel, TableColumnModel columnModel) {
			super(symbolTableModel, columnModel);
			this.symbolTableModel = symbolTableModel;
		}

		@Override
		public List<String> transform(SymbolRowObject rowObject) {
			list.clear();
			if (rowObject != null) {
				// The toString() returns the name for the symbol, which may be cached.  Calling
				// toString() will also avoid locking for cached values.
				list.add(rowObject.toString());

				// Add the 'Original Imported Name' value as well, which may feel intuitive to the
				// user when filtering on the name.
				addOriginalName(rowObject);
			}
			return list;
		}

		private void addOriginalName(SymbolRowObject rowObject) {
			int index = symbolTableModel.getColumnIndex(OriginalNameColumn.class);
			String originalName = getStringValue(rowObject, index);
			if (originalName != null) {
				list.add(originalName);
			}
		}

		@Override
		public int hashCode() {
			// not meant to put in hashing structures; the data for equals may change over time
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			return true;
		}
	}
}
