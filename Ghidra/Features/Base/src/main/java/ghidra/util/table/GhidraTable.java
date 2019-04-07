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
package ghidra.util.table;

import java.awt.Point;
import java.awt.event.*;

import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableModel;

import docking.widgets.table.DefaultSortedTableModel;
import docking.widgets.table.GTable;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

/**
 * Navigation is only supported if the underlying table model
 * implements <code>ProgramTableModel</code> and the <code>setGoToService()</code> method
 * has been called with a valid reference.  When both of these conditions are met, then the 
 * table will navigate on a user's double-click or on an <tt>Enter</tt> key press.  Also, if 
 * selection navigation is enabled, then this table will navigate <b>any time the selection of
 * the table changes</b>.  To prevent this feature call 
 * {@link #setNavigateOnSelectionEnabled(boolean)} with a value of false.
 * <p>
 */
@SuppressWarnings("deprecation")
// Suppress - we are using the deprecated reference to DefaultSortedTableModel to handle old code
public class GhidraTable extends GTable {

	private Navigatable navigatable;
	private GoToService gotoService;
	private boolean navigateOnSelection;
	private KeyListener navigationKeyListener;
	private MouseListener navigationMouseListener;
	private ListSelectionListener navigationSelectionListener;

	public GhidraTable() {
		super();

	}

	public GhidraTable(TableModel model) {
		super(model);

	}

	/**
	 * Constructs a new GhidraTable using the specified table model.
	 * If <code>allowAutoEdit</code> is true, then automatic editing is enabled.
	 * Auto-editing implies that typing in an editable cell will automatically
	 * force the cell into edit mode.
	 * If <code>allowAutoEdit</code> is false, then <code>F2</code> must be hit before editing may commence.
	 * @param dm the table model
	 * @param allowAutoEdit true if auto-editing is allowed
	 */
	public GhidraTable(TableModel dm, boolean allowAutoEdit) {
		super(dm, allowAutoEdit);

	}

	/**
	 * Constructs a <code>GhidraTable</code> to display the values in the two dimensional array,
	 * <code>rowData</code>, with column names, <code>columnNames</code>.
	 * <code>rowData</code> is an array of rows, so the value of the cell at row 1,
	 * column 5 can be obtained with the following code:
	 * <p>
	 * <pre> rowData[1][5]; </pre>
	 * <p>
	 * All rows must be of the same length as <code>columnNames</code>.
	 * <p>
	 * @param rowData           the data for the new table
	 * @param columnNames       names of each column
	 */
	public GhidraTable(Object[][] rowData, Object[] columnNames) {
		super(rowData, columnNames);
	}

	/**
	 * Constructs a <code>GhidraTable</code> to display the values in the two dimensional array,
	 * <code>rowData</code>, with column names, <code>columnNames</code>.
	 * <code>rowData</code> is an array of rows, so the value of the cell at row 1,
	 * column 5 can be obtained with the following code:
	 * <p>
	 * <pre> rowData[1][5]; </pre>
	 * <p>
	 * All rows must be of the same length as <code>columnNames</code>.
	 * <p>
	 * If <code>allowAutoEdit</code> is true, then automatic editing is enabled.
	 * Auto-editing implies that typing in an editable cell will automatically
	 * force the cell into edit mode.
	 * If <code>allowAutoEdit</code> is false, then <code>F2</code> must be hit before editing may commence.
	 * 
	 * @param rowData           the data for the new table
	 * @param columnNames       names of each column
	 * @param allowAutoEdit     true if auto-editing is allowed
	 */
	public GhidraTable(Object[][] rowData, Object[] columnNames, boolean allowAutoEdit) {
		super(rowData, columnNames, allowAutoEdit);
	}

	/** 
	 * Installs the default {@link TableCellRenderer}s for known Ghidra table cell data classes.
	 * Subclasses can override this method to add additional types or to change the default
	 * associations.
	 */
	@Override
	protected void initDefaultRenderers() {

		super.initDefaultRenderers();

		GhidraTableCellRenderer ghidraTableCellRenderer = new GhidraTableCellRenderer();
		setDefaultRenderer(String.class, ghidraTableCellRenderer);
		setDefaultRenderer(Enum.class, ghidraTableCellRenderer);
		defaultGTableRendererList.add(ghidraTableCellRenderer);

		PreviewDataTableCellRenderer previewRenderer = new PreviewDataTableCellRenderer();
		setDefaultRenderer(PreviewTableCellData.class, previewRenderer);
		defaultGTableRendererList.add(previewRenderer);
	}

	/**
	 * Sets the GoTo service to use when navigation is enabled on this table.
	 * @param goToService the GoTo service.
	 * @param nav the navigable
	 */
	public void installNavigation(GoToService goToService, Navigatable nav) {
		if (nav == null) {
			return;
		}

		if (this.navigatable == null) {
			navigationKeyListener = new KeyAdapter() {
				@Override
				public void keyPressed(KeyEvent e) {
					if (e.getKeyCode() == KeyEvent.VK_ENTER) {
						int selectedRow = getSelectedRow();
						int selectedColumn = getSelectedColumn();
						if (selectedRow < 0 || selectedColumn < 0) {
							return;
						}
						navigate(selectedRow, selectedColumn);
						e.consume();
					}
				}
			};

			addKeyListener(navigationKeyListener);

			navigationMouseListener = new MouseAdapter() {
				@Override
				public void mouseReleased(MouseEvent e) {
					if (e.getClickCount() == 2 && !isEditing()) {
						Point point = e.getPoint();
						navigate(rowAtPoint(point), columnAtPoint(point));
					}
				}
			};

			addMouseListener(navigationMouseListener);

			navigationSelectionListener = new SelectionListener();
			selectionModel.addListSelectionListener(navigationSelectionListener);
		}

		this.gotoService = goToService;
		this.navigatable = nav;
	}

	public void removeNavigation() {
		removeKeyListener(navigationKeyListener);
		removeMouseListener(navigationMouseListener);
		selectionModel.removeListSelectionListener(navigationSelectionListener);

		this.gotoService = null;
		this.navigatable = null;
	}

	/**
	 * Returns the program selection equivalent
	 * to the rows currently selected in the table. This method
	 * is only valid when the underlying table model implements
	 * <code>ProgramTableModel</code>.
	 * Returns null if no rows are selected or
	 * the underlying model does not implement <code>ProgramTableModel</code>.
	 * @return the program selection or null.
	 */
	public ProgramSelection getProgramSelection() {
		ProgramTableModel programTableModel = getProgramTableModel(dataModel);
		if (programTableModel == null) {
			return null;
		}
		return programTableModel.getProgramSelection(getSelectedRows());
	}

	private ProgramTableModel getProgramTableModel(TableModel model) {
		if (model instanceof ProgramTableModel) {
			return (ProgramTableModel) model;
		}
		else if (model instanceof DefaultSortedTableModel) {
			DefaultSortedTableModel defaultSortedTableModel = (DefaultSortedTableModel) model;
			return getProgramTableModel(defaultSortedTableModel.getModel());
		}
		return null;
	}

	/**
	 * Does nothing if no {@link GoToService} has been installed from 
	 * {@link #installNavigation(GoToService, Navigatable)}.  Also, this method will do 
	 * nothing if this table's <tt>TableModel</tt> is not an instance of {@link ProgramTableModel}.  
	 * Otherwise, this method will attempt to go to the program location denoted by the 
	 * given row and column.
	 * 
	 * @param row the row 
	 * @param column the column
	 */
	public void navigate(int row, int column) {
		if (navigatable == null) {
			return;
		}
		column = convertColumnIndexToModel(column);

		if (row < 0 || column < 0) {
			return;
		}

		if (!(dataModel instanceof ProgramTableModel)) {
			return;
		}

		ProgramTableModel ptm = (ProgramTableModel) dataModel;
		ProgramLocation loc = ptm.getProgramLocation(row, column);
		if (loc != null && loc.getAddress().isExternalAddress()) {
			gotoService.goTo(loc.getAddress(), ptm.getProgram());
			return;
		}
		Program program = ptm.getProgram();
		gotoService.goTo(navigatable, loc, program);
	}

	/**
	 * Does nothing if no {@link GoToService} has been installed from 
	 * {@link #installNavigation(GoToService, Navigatable)}.  Otherwise, this method will attempt 
	 * to go to the program location denoted by the given row and column.
	 * <p>
	 * This method differs from {@link #navigate(int, int)} in that this method will not 
	 * navigate if {@link #navigateOnSelection} is <tt>false</tt>.
	 */
	private void navigateOnCurrentSelection(int row, int column) {
		if (!navigateOnSelection) {
			return;
		}

		if (!isFocusOwner()) {
			return;
		}

		navigate(row, column);
	}

	/**
	 * Allows the user to enable and disable the table's feature that triggers navigation on
	 * certain selection events, like mouse clicking and pressing the 'Enter' key.
	 * @param enabled true enables the navigation on selection feature.
	 */
	public void setNavigateOnSelectionEnabled(boolean enabled) {
		navigateOnSelection = enabled;
	}

	@Override
	public void setValueAt(Object aValue, int row, int column) {

		//
		// Protect against a timing issue whereby program-based table models have had their
		// program closed while an edit is open.  Sometimes, when the table repaints, the table
		// will trigger an editingStopped(), which attempts to commit the active edit.  This can
		// trigger an exception when the model attempts to access the program.  Here we are 
		// attempting to prevent the edit from being committed.
		// 
		if (programIsClosed()) {
			return;
		}

		super.setValueAt(aValue, row, column);
	}

	private boolean programIsClosed() {

		if (!(dataModel instanceof ProgramTableModel)) {
			// not a program-based model; no program
			return false;
		}

		ProgramTableModel ptm = (ProgramTableModel) dataModel;
		Program program = ptm.getProgram();
		return program == null;
	}

	/**
	 * Selects the given row and performs a goto, if applicable.
	 * @param row The row to select
	 */
	@Override
	public void selectRow(int row) {
		super.selectRow(row);
		navigateOnCurrentSelection(row, 0);
	}

	@Override
	public void dispose() {
		super.dispose();

		navigationKeyListener = null;
		navigationMouseListener = null;
		navigationSelectionListener = null;
	}

	private class SelectionListener implements ListSelectionListener {
		@Override
		public void valueChanged(ListSelectionEvent e) {
			if (e.getValueIsAdjusting()) {
				return;
			}

			if (getSelectedRowCount() != 1) {
				return;
			}

			int column = Math.max(0, getSelectedColumn());
			navigateOnCurrentSelection(getSelectedRow(), column);
		}
	}

}
