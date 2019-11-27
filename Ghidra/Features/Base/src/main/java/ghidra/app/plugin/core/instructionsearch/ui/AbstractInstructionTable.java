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
package ghidra.app.plugin.core.instructionsearch.ui;

import java.awt.Font;

import javax.swing.JToolBar;
import javax.swing.table.TableCellRenderer;

import docking.widgets.table.GTable;
import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;
import ghidra.app.plugin.core.instructionsearch.model.*;
import ghidra.util.table.GhidraTable;

/**
 * Defines basic attributes of tables in the {@link InstructionSearchDialog}.
 */
public abstract class AbstractInstructionTable extends GhidraTable {

	/**
	 * Defines the states that a cell can take on. ACTIVE means it is in the
	 * 'up' state (not masked). INACTIVE means has been depressed (will be
	 * masked). PREVIEW means that this is a cell in the preview table. NA means
	 * it is not a valid field (ie: a blank cell because the instruction has no
	 * operand for the particular column).
	 */
	public static enum OperandState {
		MASKED, NOT_MASKED, NA, PREVIEW
	}

	// The standard cell height is a bit too small for our liking, so we expand it vertically a
	// bit.
	private int CELL_HEIGHT_PADDING = 6;

	/**
	 * {@link InstructionTableDataObject} instances constitute the contents of
	 * the table. This array is effectively the table data model.
	 */
	protected InstructionTableDataObject[][] tableContentsDO = null;

	protected int numColumns;
	protected Object[] columnNames;

	protected InstructionSearchDialog dialog;

	protected JToolBar toolbar;

	protected InstructionTableCellRenderer renderer =
		new InstructionTableCellRenderer(new Font("Courier", Font.PLAIN, 14));

	protected InstructionSearchData searchData;

	protected static InstructionTableModel tableModel;

	public AbstractInstructionTable(int columns, InstructionSearchDialog dialog) {
		this.numColumns = columns;
		this.dialog = dialog;
		this.searchData = dialog.getSearchData();

		columnNames = createColumnHeaders();
		tableContentsDO = createDataObjects();
		tableModel = new InstructionTableModel(tableContentsDO, columnNames);
		setModel(tableModel);
		toolbar = createToolbar();

		// Disable reorder of columns.  Allowing this would cause the table
		// to become unstable; we rely on knowing that mnemonics are always in
		// the first column, and that operand columns are in a particular order.
		this.getTableHeader().setReorderingAllowed(false);

		// The default cell size is a bit small and makes the text a bit hard 
		// to read, so increase it to provide some space around the text.
		this.setRowHeight(this.getRowHeight() + CELL_HEIGHT_PADDING);
	}

	InstructionSearchPlugin getPlugin() {
		return dialog.getPlugin();
	}

	/**
	 * Returns the data object at the given cell location. We need to check
	 * first to make sure the row/col values map to a valid cell.
	 * 
	 * @param row
	 * @param col
	 * @return
	 */
	public InstructionTableDataObject getCellData(int row, int col) {
		if (getModel() == null) {
			return null;
		}
		if (row < 0 || col < 0) {
			return null;
		}
		if (getModel().getRowCount() <= row || getModel().getColumnCount() <= col) {
			return null;
		}
		return (InstructionTableDataObject) getModel().getValueAt(row, col);
	}

	/**
	 * Must override so it doesn't return an instance of the base
	 * {@link TableCellRenderer}, which will override our changes in the
	 * {@link InstructionTableCellRenderer}.
	 */
	@Override
	public TableCellRenderer getDefaultRenderer(Class<?> columnClass) {
		return renderer;
	}

	/**
	 * 
	 * @return
	 */
	public JToolBar getToolbar() {
		return this.toolbar;
	}

	/**
	 * Adds the renderers for {@link InstructionTableDataObject} cell contents
	 * to the {@link GTable} renderer list.
	 */
	@Override
	protected void initDefaultRenderers() {
		setDefaultRenderer(InstructionTableDataObject.class, renderer);
		defaultGTableRendererList.add(renderer);
	}

	/**
	 * Returns the value of the {@link InstructionTableDataObject} for the given
	 * cell (indicated by row and column name).
	 */
	protected String getColumnValue(int row, String colName) {
		for (int i = 0; i < this.getColumnCount(); i++) {
			if (this.getColumnName(i).equals(colName)) {
				return this.getCellData(row, i).getData();
			}
		}

		return null;
	}

	/**
	 * Creates the array of strings that will be our column headers. Clients
	 * must implement this since each implementation will be unique.
	 * 
	 * @return array of column names
	 */
	protected abstract Object[] createColumnHeaders();

	/**
	 * Clients must implement to create all the data objects used to render the
	 * table.
	 */
	protected abstract InstructionTableDataObject[][] createDataObjects();

	/**
	 * Clients must implement to have a toolbar visible above the table.
	 */
	protected abstract JToolBar createToolbar();

}
