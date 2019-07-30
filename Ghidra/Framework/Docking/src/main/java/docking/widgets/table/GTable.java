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

import static docking.DockingUtils.CONTROL_KEY_MODIFIER_MASK;
import static docking.action.MenuData.NO_MNEMONIC;
import static java.awt.event.InputEvent.SHIFT_DOWN_MASK;

import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;

import docking.*;
import docking.action.*;
import docking.actions.KeyBindingUtils;
import docking.actions.PopupActionProvider;
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.SettingsDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.docking.settings.*;
import ghidra.framework.preferences.Preferences;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import resources.ResourceManager;

/**
 * A sub-class of <code>JTable</code> that provides navigation and auto-lookup.
 * By default, both of these features are disabled.
 * <p>
 * Auto-lookup is only supported on one column and must be specified
 * using the <code>setAutoLookupColumn()</code> method.
 * <p>
 * Auto-lookup allows a user to begin typing the first few letters
 * of a desired row. The table will attempt to locate the first row
 * that contains the letters typed up to that point. There is an
 * 800ms timeout between typed letters, at which point the list of
 * typed letters will be flushed.
 * <p>
 * Auto-lookup is much faster if the underlying table model implements
 * <code>SortedTableModel</code>, because a binary search can used
 * to locate the desired row. A linear search is used if the model is not sorted.
 * <p>
 * Other features provided:
 * <ul>
 * 	<li>Column hiding/showing</li>
 *  <li>Multi-column sorting</li>
 *  <li>Column settings</li>
 *  <li>Column state saving (visibility, size, positioning, sort values)</li>
 *  <li>Selection management (saving/restoring selection when used with a filter panel)</li>
 * </ul>
 *
 * @see GTableFilterPanel
 */
public class GTable extends JTable implements KeyStrokeConsumer, PopupActionProvider {

	private static final String LAST_EXPORT_FILE = "LAST_EXPORT_DIR";

	private int userDefinedRowHeight;

	private boolean allowActions;
	private KeyListener autoLookupListener;
	private long lastLookupTime;
	private String lookupString;
	private int lookupColumn = -1;
	private AutoLookupKeyStrokeConsumer autoLookupKeyStrokeConsumer =
		new AutoLookupKeyStrokeConsumer();

	/** A list of default renderers created by this table */
	protected List<TableCellRenderer> defaultGTableRendererList = new ArrayList<>();
	private boolean htmlRenderingEnabled;
	private String preferenceKey;

	private GTableMouseListener headerMouseListener;
	private JPopupMenu tableHeaderPopupMenu;
	private boolean columnHeaderPopupEnabled = true;
	private int lastPopupColumnIndex;

	/** A flag to signal that a copy operation is being performed. */
	private boolean copying;
	private DockingAction copyAction;
	private DockingAction copyColumnsAction;
	private DockingAction copyCurrentColumnAction;
	private DockingAction selectAllAction;
	private DockingAction exportAction;
	private DockingAction exportColumnsAction;

	private String actionMenuGroup = "zzzTableGroup";

	private SelectionManager selectionManager;
	private Integer visibleRowCount;

	public static final long KEY_TIMEOUT = 800;//made public for JUnits...
	private static final KeyStroke ESCAPE = KeyStroke.getKeyStroke("ESCAPE");

	private TableModelListener rowHeightListener = e -> adjustRowHeight();
	private TableColumnModelListener tableColumnModelListener = null;
	private final Map<Integer, GTableCellRenderingData> columnRenderingDataMap = new HashMap<>();

	/**
	 * Constructs a new GTable.
	 */
	public GTable() {
		super();
		init(false);
	}

	/**
	 * Constructs a new GTable using the specified table model.
	 * @param dm the table model
	 */
	public GTable(TableModel dm) {
		this(dm, false);
	}

	/**
	 * Constructs a new GTable using the specified table model.
	 * If <code>allowAutoEdit</code> is true, then automatic editing is enabled.
	 * Auto-editing implies that typing in an editable cell will automatically
	 * force the cell into edit mode.
	 * If <code>allowAutoEdit</code> is false, then <code>F2</code> must be hit before editing may commence.
	 * @param dm the table model
	 * @param allowAutoEdit true if auto-editing is allowed
	 *
	 */
	public GTable(TableModel dm, boolean allowAutoEdit) {
		super(dm);
		init(allowAutoEdit);
	}

	/**
	 * Constructs a <code>GTable</code> to display the values of the given 2d array of data.
	 * <p>
	 * @param rowData  the array of data to display in the table.
	 * @param columnNames an array of names to use for the column names.
	 */
	public GTable(Object[][] rowData, Object[] columnNames) {
		this(rowData, columnNames, false);
	}

	/**
	 * Constructs a <code>GTable</code> to display the values of the given 2d array of data.
	 * <p>
	 * @param rowData  the array of data to display in the table.
	 * @param columnNames an array of names to use for the column names.
	 * @param allowAutoEdit     true if auto-editing is allowed
	 */
	public GTable(Object[][] rowData, Object[] columnNames, boolean allowAutoEdit) {
		super(rowData, columnNames);
		init(allowAutoEdit);
	}

	public void setVisibleRowCount(int visibleRowCount) {
		this.visibleRowCount = visibleRowCount;
	}

	@Override
	public Dimension getPreferredScrollableViewportSize() {
		Dimension size = super.getPreferredScrollableViewportSize();
		if (visibleRowCount != null) {
			int height = getRowHeight() * visibleRowCount.intValue();
			size.height = Math.max(size.height, height);
		}
		return size;
	}

	@Override
	public void tableChanged(TableModelEvent e) {
		super.tableChanged(e);
		if (getTableHeader() != null) {
			getTableHeader().repaint(); // needed for settings changes which affect header labels
		}
	}

	/**
	 * Selects the given row.  This is a convenience method for
	 * {@link #setRowSelectionInterval(int, int)}.
	 * @param row The row to select
	 */
	public void selectRow(int row) {
		setRowSelectionInterval(row, row);
	}

	/**
	 * Selects the row under the given mouse point.  This method is useful when the user
	 * triggers a popup mouse action and you would like to have the table select that row if it
	 * is not already selected.  This allows you to guarantee that there is always a selection
	 * when the user triggers a popup menu.
	 *
	 * @param event The event that triggered the popup menu
	 * @return true if the row is selected or was already selected.
	 */
	public boolean selectRow(MouseEvent event) {
		if (event.getSource() != this) {
			return false;
		}
		int row = rowAtPoint(event.getPoint());
		if (row >= 0) {
			if (!isRowSelected(row)) {
				setRowSelectionInterval(row, row);
			}
			return true;
		}
		return false;
	}

	@Override
	protected TableColumnModel createDefaultColumnModel() {
		return new GTableColumnModel(this);
	}

	@Override
	public void setColumnModel(TableColumnModel columnModel) {
		super.setColumnModel(columnModel);
		setTableHeader(new GTableHeader(this));
		JTableHeader header = getTableHeader();
		initializeHeader(header);
	}

	@Override
	// overridden to cleanup our SelectionManager
	public void setSelectionModel(ListSelectionModel newModel) {
		if (selectionManager != null) {
			selectionManager.dispose();
			selectionManager = null;
		}

		super.setSelectionModel(newModel);
	}

	@Override
	// overridden to install our SelectionManager
	public void setModel(TableModel dataModel) {
		if (selectionManager != null) {
			selectionManager.dispose();
		}

		super.setModel(dataModel);

		initializeRowHeight();

		selectionManager = createSelectionManager(dataModel);
	}

	@SuppressWarnings("unchecked")
	// The (RowObjectTableModel<T>) is safe, since we are create a new SelectionManager of
	// an arbitrary type T defined here.  So, T doesn't really exist and therefore the cast isn't
	// really casting to anything.  The SelectionManager will take on the type of the given model.
	// The T is just there on the SelectionManager to make its internal methods consistent.
	protected <T> SelectionManager createSelectionManager(TableModel model) {
		if (model instanceof RowObjectTableModel) {
			return new RowObjectSelectionManager<>(this, (RowObjectTableModel<T>) model);
		}

		return null;
	}

	/**
	 * Returns the {@link SelectionManager} in use by this GTable.  <tt>null</tt> is returned
	 * if the user has installed their own {@link ListSelectionModel}.
	 * 
	 * @return the selection manager
	 */
	public SelectionManager getSelectionManager() {
		return selectionManager;
	}

	/**
	 * A method that allows clients to signal to this GTable and its internals that the table
	 * model has changed.  Usually, {@link #tableChanged(TableModelEvent)} is called, but clients
	 * alter the table, but do not do so through the model.  In this case, they need a way to
	 * signal to the table that the model has been updated.
	 *
	 * @param event the event for the change
	 */
	public void notifyTableChanged(TableModelEvent event) {
		if (selectionManager != null) {
			selectionManager.tableChanged(event);
		}
		tableChanged(event);
	}

	/**
	 * Call this when the table will no longer be used
	 */
	public void dispose() {
		if (dataModel instanceof AbstractGTableModel) {
			((AbstractGTableModel<?>) dataModel).dispose();
		}

		if (columnModel instanceof GTableColumnModel) {
			((GTableColumnModel) columnModel).dispose();
		}
	}

	private int getRow(TableModel model, String keyString) {
		if (keyString == null) {
			return -1;
		}

		int currRow = getSelectedRow();
		if (currRow >= 0 && currRow < getRowCount() - 1) {
			if (keyString.length() == 1) {
				++currRow;
			}
			Object obj = getValueAt(currRow, convertColumnIndexToView(lookupColumn));
			if (obj != null && obj.toString().toLowerCase().startsWith(keyString.toLowerCase())) {
				return currRow;
			}
		}
		if (model instanceof SortedTableModel) {
			SortedTableModel sortedModel = (SortedTableModel) model;
			if (lookupColumn == sortedModel.getPrimarySortColumnIndex()) {
				return autoLookupBinary(sortedModel, keyString);
			}
		}
		return autoLookupLinear(keyString);
	}

	private int autoLookupLinear(String keyString) {
		int rowCount = getRowCount();
		int startRow = getSelectedRow();
		int counter = 0;
		int col = convertColumnIndexToView(lookupColumn);
		for (int i = startRow + 1; i < rowCount; i++) {
			Object obj = getValueAt(i, col);
			if (obj != null && obj.toString().toLowerCase().startsWith(keyString.toLowerCase())) {
				return i;
			}
			if (counter++ > TableUtils.MAX_SEARCH_ROWS) {
				return -1;
			}
		}
		for (int i = 0; i < startRow; i++) {
			Object obj = getValueAt(i, col);
			if (obj != null && obj.toString().toLowerCase().startsWith(keyString.toLowerCase())) {
				return i;
			}
			if (counter++ > TableUtils.MAX_SEARCH_ROWS) {
				return -1;
			}
		}
		return -1;
	}

	private int autoLookupBinary(SortedTableModel model, String keyString) {
		String modifiedLookupString = keyString;

		int sortedOrder = 1;
		int primarySortColumnIndex = model.getPrimarySortColumnIndex();
		TableSortState columnSortState = model.getTableSortState();
		ColumnSortState sortState = columnSortState.getColumnSortState(primarySortColumnIndex);

		if (!sortState.isAscending()) {
			sortedOrder = -1;
			int lastCharPos = modifiedLookupString.length() - 1;
			char lastChar = modifiedLookupString.charAt(lastCharPos);
			++lastChar;
			modifiedLookupString = modifiedLookupString.substring(0, lastCharPos) + lastChar;
		}

		int min = 0;
		int max = model.getRowCount() - 1;
		int col = convertColumnIndexToView(lookupColumn);
		while (min < max) {
			int i = (min + max) / 2;

			Object obj = getValueAt(i, col);
			if (obj == null) {
				obj = "";
			}

			int compare = modifiedLookupString.toString().compareToIgnoreCase(obj.toString());
			compare *= sortedOrder;

			if (compare < 0) {
				max = i - 1;
			}
			else if (compare > 0) {
				min = i + 1;
			}
			else {//compare == 0, MATCH!
				return i;
			}
		}

		String value = getValueAt(min, col).toString();
		if (value.toLowerCase().startsWith(keyString.toLowerCase())) {
			return min;
		}
		if (min - 1 >= 0) {
			value = getValueAt(min - 1, col).toString();
			if (value.toLowerCase().startsWith(keyString.toLowerCase())) {
				return min - 1;
			}
		}
		if (min + 1 < dataModel.getRowCount()) {
			value = getValueAt(min + 1, col).toString();
			if (value.toLowerCase().startsWith(keyString.toLowerCase())) {
				return min + 1;
			}
		}

		return -1;
	}

	/**
	 * Sets the column in which auto-lookup will be enabled.
	 * @param lookupColumn the column in which auto-lookup will be enabled
	 */
	public void setAutoLookupColumn(int lookupColumn) {
		this.lookupColumn = lookupColumn;

		if (autoLookupListener == null) {
			autoLookupListener = new KeyAdapter() {
				@Override
				public void keyPressed(KeyEvent e) {
					if (getRowCount() == 0) {
						return;
					}

					if (isIgnorableKeyEvent(e)) {
						return;
					}

					long when = e.getWhen();
					if (when - lastLookupTime > KEY_TIMEOUT) {
						lookupString = "" + e.getKeyChar();
					}
					else {
						lookupString += "" + e.getKeyChar();
					}

					int row = getRow(dataModel, lookupString);
					if (row >= 0) {
						setRowSelectionInterval(row, row);
						Rectangle rect = getCellRect(row, 0, false);
						scrollRectToVisible(rect);
					}
					lastLookupTime = when;
				}

				private boolean isIgnorableKeyEvent(KeyEvent event) {
					// ignore modified keys
					if (event.isAltDown() || event.isAltGraphDown() || event.isControlDown() ||
						event.isMetaDown()) {
						return true;
					}

					if (event.isActionKey() || event.getKeyChar() == KeyEvent.CHAR_UNDEFINED ||
						Character.isISOControl(event.getKeyChar())) {
						return true;
					}

					return false;
				}
			};
		}

		if (lookupColumn >= 0 && lookupColumn < getModel().getColumnCount()) {
			addKeyListener(autoLookupListener);
		}
		else {
			removeKeyListener(autoLookupListener);
		}
	}

	/**
	 * Enables the keyboard actions to pass through this table
	 * and up the component hierarchy.
	 * @param b true allows keyboard actions to pass up the component hierarchy.
	 */
	public void setActionsEnabled(boolean b) {
		allowActions = b;
	}

	/**
	 * This method is implemented to signal interest in any typed text that may help the user
	 * change the row in the table.  For example, if the user types 'a', then the table will move
	 * to the first symbol that begins with the letter 'a'.  This method also wants to handle
	 * text when the 'shift' key is down.  This method will return false if the control key is
	 * pressed.
	 *
	 * @see docking.KeyStrokeConsumer#isKeyConsumed(javax.swing.KeyStroke)
	 */
	@Override
	public boolean isKeyConsumed(KeyStroke keyStroke) {
		if (allowActions) {
			return false;
		}

		return autoLookupKeyStrokeConsumer.isKeyConsumed(keyStroke);
	}

	@Override
	public List<DockingActionIf> getPopupActions(ActionContext context) {

		// we want these top-level groups to all appear together, with no separator
		DockingWindowManager dwm = DockingWindowManager.getInstance(this);
		dwm.setMenuGroup(new String[] { "Copy" }, actionMenuGroup, "1");
		dwm.setMenuGroup(new String[] { "Export" }, actionMenuGroup, "2");
		dwm.setMenuGroup(new String[] { "Select All" }, actionMenuGroup, "3");

		List<DockingActionIf> list = new ArrayList<>();
		list.add(copyAction);
		list.add(copyCurrentColumnAction);
		list.add(copyColumnsAction);
		list.add(selectAllAction);
		list.add(exportAction);
		list.add(exportColumnsAction);
		return list;
	}

	private void init(boolean allowAutoEdit) {
		ToolTipManager.sharedInstance().unregisterComponent(this);
		ToolTipManager.sharedInstance().registerComponent(this);
		setTableHeader(new GTableHeader(this));
		if (!allowAutoEdit) {
			putClientProperty("JTable.autoStartsEdit", Boolean.FALSE);

			AbstractAction action = new AbstractAction("StartEdit") {
				@Override
				public void actionPerformed(ActionEvent ev) {
					int row = getSelectedRow();
					int col = getSelectedColumn();
					if (col == -1) {
						Toolkit.getDefaultToolkit().beep();
					}
					KeyEvent evt = new KeyEvent(GTable.this, 0, 0, 0, KeyEvent.VK_UNDEFINED,
						KeyEvent.CHAR_UNDEFINED);
					editCellAt(row, col, evt);
				}
			};

			KeyStroke ks = KeyStroke.getKeyStroke(KeyEvent.VK_F2, 0);
			KeyBindingUtils.registerAction(this, ks, action, JComponent.WHEN_FOCUSED);
		}

		initDefaultRenderers();

		disableGridLines();

		JTableHeader header = getTableHeader();
		initializeHeader(header);

		setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);

		addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				if (e.getButton() == MouseEvent.BUTTON3) {
					int row = rowAtPoint(e.getPoint());
					if (row >= 0) {
						if (!isRowSelected(row)) {
							setRowSelectionInterval(row, row);
						}
					}
				}
			}
		});

		createPopupActions();
		initializeRowHeight();

		DockingWindowManager.registerComponentLoadedListener(this, dwm -> {

			if (dwm == null) {
				return;
			}

			dwm.getTool().addPopupActionProvider(this);
		});
	}

	private void initializeHeader(JTableHeader header) {
		header.setUpdateTableInRealTime(true);
		headerMouseListener = new GTableMouseListener(this);
		header.addMouseListener(headerMouseListener);
		header.addMouseMotionListener(headerMouseListener);

		tableColumnModelListener = new MyTableColumnModelListener();
		header.getColumnModel().addColumnModelListener(tableColumnModelListener);
	}

	private void initializeRowHeight() {
		ConfigurableColumnTableModel configurableModel = getConfigurableColumnTableModel();
		if (configurableModel != null) {
			configurableModel.removeTableModelListener(rowHeightListener);
			configurableModel.addTableModelListener(rowHeightListener);
		}
		adjustRowHeight();
	}

	private void adjustRowHeight() {
		if (copyAction == null) { // crude test to know if our constructor has finished
			return; // must be initializing
		}

		int linesPerRow = getLinesPerRow();
		int preferredHeight = calculatePreferredRowHeight();
		int newHeight = linesPerRow * preferredHeight;
		if (newHeight != getRowHeight()) {
			doSetRowHeight(newHeight);
		}
	}

	private int calculatePreferredRowHeight() {
		if (userDefinedRowHeight != 16) { // default size
			return userDefinedRowHeight; // prefer user-defined settings
		}

		TableCellRenderer defaultRenderer = getDefaultRenderer(String.class);
		try {
			Component component =
				defaultRenderer.getTableCellRendererComponent(this, "Ghidra", false, false, 0, 0);
			Dimension preferredSize = component.getPreferredSize();
			return preferredSize.height + 3; // What is this fudge?
		}
		catch (Throwable t) {
			// some renderers can't handle being asked to render with dummy data; use default value
			return userDefinedRowHeight;
		}
	}

	private int getLinesPerRow() {
		int linesPerRow = 1;
		ConfigurableColumnTableModel configurableModel = getConfigurableColumnTableModel();
		if (configurableModel != null) {
			int columnCnt = getColumnCount();
			for (int i = 0; i < columnCnt; i++) {
				int modelColumnIndex = convertColumnIndexToModel(i);
				int cnt = configurableModel.getMaxLines(modelColumnIndex);
				if (cnt > linesPerRow) {
					linesPerRow = cnt;
				}
			}
		}
		return linesPerRow;
	}

	@Override
	public void setRowHeight(int height) {
		doSetRowHeight(height);
		userDefinedRowHeight = height;
	}

	private void doSetRowHeight(int height) {
		super.setRowHeight(height);
	}

	@Override
	public void columnAdded(TableColumnModelEvent e) {
		adjustRowHeight();
		super.columnAdded(e);
	}

	@Override
	public void columnRemoved(TableColumnModelEvent e) {
		adjustRowHeight();
		super.columnRemoved(e);
	}

	/**
	 * Returns the underlying ConfigurableColumnTableModel if one is in-use
	 * @return the underlying ConfigurableColumnTableModel if one is in-use
	 */
	public ConfigurableColumnTableModel getConfigurableColumnTableModel() {
		TableModel model = getUnwrappedTableModel();
		if (model instanceof ConfigurableColumnTableModel) {
			return (ConfigurableColumnTableModel) model;
		}
		return null;
	}

	/**
	 * Unrolls the current model by checking if the current model is inside of a wrapper table
	 * model.
	 * @return this class's table model, unwrapped as needed
	 */
	protected TableModel getUnwrappedTableModel() {
		TableModel model = getModel();
		return RowObjectTableModel.unwrap(model);
	}

	@Override
	protected boolean processKeyBinding(KeyStroke ks, KeyEvent e, int condition, boolean pressed) {

		if (ks == ESCAPE && !isEditing()) {
			return false;
		}
		return super.processKeyBinding(ks, e, condition, pressed);
	}

	/**
	 * @see javax.swing.JTable#getDefaultRenderer(java.lang.Class)
	 */
	@Override
	public TableCellRenderer getDefaultRenderer(Class<?> columnClass) {
		if (columnClass == null) {
			// 
			// 		Unusual Code Alert!
			// Normally we would like to do as the JTable and just return null here.  However, 
			// some client code (JTable.AccessibleJTable) does not check for null in this case.
			// Prevent that code from exploding by returning a suitable non-null default.
			// 
			return super.getDefaultRenderer(String.class);
		}

		TableCellRenderer renderer = super.getDefaultRenderer(columnClass);
		if (renderer == null) {
			renderer = super.getDefaultRenderer(String.class);
		}
		return wrapDefaultTableCellRenderer(renderer, columnClass);
	}

	protected TableCellRenderer wrapDefaultTableCellRenderer(TableCellRenderer renderer,
			Class<?> columnClass) {

		if (renderer instanceof DefaultTableCellRendererWrapper) {
			return renderer; // already wrapped
		}
		if (renderer instanceof GTableCellRenderer) {
			setDefaultRenderer(columnClass, renderer);
			return renderer;
		}
		DefaultTableCellRendererWrapper wrapper = new DefaultTableCellRendererWrapper(renderer);
		setDefaultRenderer(columnClass, wrapper); // cache for later use    	
		return wrapper;
	}

	/**
	 * Installs the default {@link TableCellRenderer}s for known Ghidra table cell data classes.
	 * Subclasses can override this method to add additional types or to change the default
	 * associations.
	 */
	protected void initDefaultRenderers() {
		GTableCellRenderer gTableCellRenderer = new GTableCellRenderer();
		setDefaultRenderer(String.class, gTableCellRenderer);
		setDefaultRenderer(Enum.class, gTableCellRenderer);

		setDefaultRenderer(Byte.class, gTableCellRenderer);
		setDefaultRenderer(Short.class, gTableCellRenderer);
		setDefaultRenderer(Integer.class, gTableCellRenderer);
		setDefaultRenderer(Long.class, gTableCellRenderer);

		setDefaultRenderer(Float.class, gTableCellRenderer);
		setDefaultRenderer(Double.class, gTableCellRenderer);

		setDefaultRenderer(Boolean.class, new GBooleanCellRenderer());

		defaultGTableRendererList.add(gTableCellRenderer);
	}

	private void disableGridLines() {
		// note: while we are alternating row colors (inside of the GTableCellRenderer), we
		//       do not need grid lines
		setShowGrid(false);
		setIntercellSpacing(new Dimension(0, 0));
	}

	/**
	 * Overridden in order to set the column header renderer on newly created columns.
	 * @see javax.swing.JTable#createDefaultColumnsFromModel()
	 */
	@Override
	public void createDefaultColumnsFromModel() {

		TableModel tableModel = getModel();
		if (tableModel == null) {
			return;
		}

		TableColumnModel cm = getColumnModel();
		if (!(cm instanceof GTableColumnModel)) {
			// some tables do not use dynamic column
			super.createDefaultColumnsFromModel();
			return;
		}

		// Disable the column model updates here, as we know that the removal and adding of
		// columns we are about to do will trigger copious update events.  Restore when done.
		// This helps prevent flashing of columns as they are added and removed.
		GTableColumnModel tableColumnModel = (GTableColumnModel) getColumnModel();
		boolean wasEnabled = tableColumnModel.setEventsEnabled(false);

		removeAllColumns();

		// Create new columns from the model
		int columnCount = tableModel.getColumnCount();
		for (int i = 0; i < columnCount; i++) {
			TableColumn newColumn = new TableColumn(i);
			initialTableColumnSize(newColumn, tableModel, i);
			newColumn.setHeaderRenderer(new GTableHeaderRenderer());
			addColumn(newColumn);
		}

		tableColumnModel.setEventsEnabled(wasEnabled);
	}

	private void removeAllColumns() {
		if (columnModel instanceof GTableColumnModel) {
			((GTableColumnModel) columnModel).removeAllColumns();
			return;
		}

		// use the default removal method
		while (columnModel.getColumnCount() > 0) {
			columnModel.removeColumn(columnModel.getColumn(0));
		}
	}

	private void initialTableColumnSize(TableColumn column, TableModel tableModel,
			int columnIndex) {
		TableModel wrappedModel = RowObjectTableModel.unwrap(tableModel);
		if (!(wrappedModel instanceof AbstractGTableModel<?>)) {
			return;
		}
		AbstractGTableModel<?> gTableModel = (AbstractGTableModel<?>) wrappedModel;
		int width = gTableModel.getPreferredColumnWidth(columnIndex);
		if (width != AbstractGTableModel.WIDTH_UNDEFINED) {
			column.setPreferredWidth(width);
		}
	}

	/**
	 * @see javax.swing.JComponent#getToolTipText(java.awt.event.MouseEvent)
	 */
	@Override
	public String getToolTipText(MouseEvent e) {
		String str = super.getToolTipText(e);
		if (str != null) {
			return str;
		}

		int row = rowAtPoint(e.getPoint());
		int col = columnAtPoint(e.getPoint());

		if (row < 0 || col < 0 || row >= getRowCount() || col >= getColumnCount()) {
			return null;
		}

		Object value = getValueAt(row, col);
		if (value != null) {
			Component component = getCellRenderer(row, col).getTableCellRendererComponent(this,
				value, false, false, row, col);
			int cellWidth = getCellRect(row, col, false).width;
			int prefWidth = component.getPreferredSize().width;
			if (prefWidth > cellWidth) {
				String string = value.toString();
				if (component instanceof JLabel) {
					string = ((JLabel) component).getText();
				}
				if (string == null) {
					return null;
				}

				if (htmlRenderingEnabled) {
					// render AS HTML
					return HTMLUtilities.toHTML(string);
				}

				// render contents literally, wrapped in HTML
				String html = HTMLUtilities.toLiteralHTMLForTooltip(string);
				return html;
			}
		}
		return null;
	}

	/**
	 * Enables and disables the rendering of HTML content in this table.  If enabled, this table
	 * will:
	 * <ul>
	 *     <li>Wrap tooltip text content with an &lt;html&gt; tag so that it is possible for
	 *         the content to be formatted in a manner that is easier for the user read, and</li>
	 *     <li>Enable any <tt>default</tt> {@link GTableCellRenderer} instances to render
	 *         HTML content, which they do not do by default.</li>
	 * </ul>
	 * <p>
	 * As mentioned above, this class only enables/disables the HTML rendering on
	 * {@link GTableCellRenderer} instances that were created by this class (or subclasses)
	 * during initialization in {@link #initDefaultRenderers()} and that have been added to the
	 * {@link #defaultGTableRendererList}.  If users of this class have changed or added new
	 * renderers, then those renderers will not be changed by calling this method.  Typically,
	 * this method should be called just after created an instance of this class, which will work
	 * as described by this method.
	 * <p>
	 * HTML rendering is disabled by default.
	 *
	 * @param enable true to enable HTML rendering; false to disable it
	 */
	public void setHTMLRenderingEnabled(boolean enable) {
		htmlRenderingEnabled = enable;

		for (TableCellRenderer renderer : defaultGTableRendererList) {
			if (renderer instanceof GTableCellRenderer) {
				GTableCellRenderer gRenderer = (GTableCellRenderer) renderer;
				gRenderer.setHTMLRenderingEnabled(enable);
			}
		}
	}

	/**
	 * Sets the key for saving and restoring column configuration state.  Use this if you have
	 * multiple instances of a table and you want different column settings for each instance.
	 *
	 * @param preferenceKey the unique string to use a key for this instance.
	 */
	public void setPreferenceKey(String preferenceKey) {

		this.preferenceKey = preferenceKey;
		if (!(columnModel instanceof GTableColumnModel)) {
			throw new AssertException(
				"Setting preference key has no effect if not using a GTableColumnModel");
		}
		((GTableColumnModel) columnModel).restoreState();
	}

	/**
	 * @see #setPreferenceKey(String)
	 * @return the preference key
	 */
	public String getPreferenceKey() {
		return preferenceKey;
	}

	/**
	 * Signals that the preferences of this table (visible columns, sort order, etc.) should be
	 * saved.  Most clients never need to call this method, as changes are saved for free when
	 * the user manipulates columns.  However, sometimes the client can change the state of the
	 * columns programmatically, which is not guaranteed to get saved; for example, setting
	 * the sort state of a sorted table model programmatically will not get saved.
	 */
	public void savePreferences() {
		if (!(columnModel instanceof GTableColumnModel)) {
			throw new AssertException(
				"Saving preferences has no effect if not using a GTableColumnModel");
		}
		((GTableColumnModel) columnModel).saveState();
	}

	/**
	 * Allows for the disabling of the user's ability to sort an instance of
	 * {@link AbstractSortedTableModel} by clicking the table's headers.  The default setting is
	 * enabled.
	 *
	 * @param enabled true to enable; false to disable
	 */
	public void setUserSortingEnabled(boolean enabled) {
		headerMouseListener.setSortingEnabled(enabled);
	}

	public void setColumnHeaderPopupEnabled(boolean enabled) {
		this.columnHeaderPopupEnabled = enabled;
	}

	public boolean isColumnHeaderPopupEnabled() {
		return columnHeaderPopupEnabled;
	}

	public JPopupMenu getTableColumnPopupMenu(int columnIndex) {
		if (!columnHeaderPopupEnabled) {
			return null;
		}
		if (columnModel instanceof GTableColumnModel) {
			return getHeaderPopupMenu(columnIndex);
		}
		return null;
	}

	@Override
	public TableCellRenderer getCellRenderer(int row, int col) {
		return getCellRendererOverride(row, col);
	}

	/**
	 * Performs custom work to locate renderers for special table model types.  This method
	 * allows clients to bypass the {@link #getCellRenderer(int, int)}, which is sometimes
	 * overridden by subclasses to return a hard-coded renderer.  In that case, some clients
	 * still want a way to perform normal cell renderer lookup.
	 * 
	 * @param row the row
	 * @param col the column
	 * @return the cell renderer
	 */
	public final TableCellRenderer getCellRendererOverride(int row, int col) {
		ConfigurableColumnTableModel configurableModel = getConfigurableColumnTableModel();
		if (configurableModel != null) {
			int modelIndex = convertColumnIndexToModel(col);
			TableCellRenderer renderer = configurableModel.getRenderer(modelIndex);
			if (renderer != null) {
				return renderer;
			}
		}
		return super.getCellRenderer(row, col);
	}

	/**
	 * If you just begin typing into an editable cell in
	 * a JTable, then the cell editor will be displayed. However,
	 * the editor component will not have a focus. This
	 * method has been overridden to request
	 * focus on the editor component.
	 *
	 * @see javax.swing.JTable#editCellAt(int, int)
	 */
	@Override
	public boolean editCellAt(int row, int column) {
		boolean editAtCell = super.editCellAt(row, column);
		if (editAtCell) {
			Component editor = getEditorComponent();
			editor.requestFocus();
		}
		return editAtCell;
	}

	public void scrollToSelectedRow() {
		int[] selectedRows = getSelectedRows();
		if (selectedRows == null || selectedRows.length == 0) {
			return;
		}

		// just make sure that the first row is visible
		int row = selectedRows[0];

		// update the cell rectangle to be the entire row so that if the user is horizontally
		// scrolled, then we do not change that
		Rectangle visibleRect = getVisibleRect();
		Rectangle cellRect = getCellRect(row, 0, true);
		cellRect.x = visibleRect.x;
		cellRect.width = visibleRect.width;

		scrollRectToVisible(cellRect);
	}

	private JPopupMenu getHeaderPopupMenu(int columnIndex) {
		if (tableHeaderPopupMenu == null) {
			tableHeaderPopupMenu = buildTableHeaderPopupMenu();
		}

		JMenuItem item = (JMenuItem) tableHeaderPopupMenu.getComponent(1);
		boolean enableSettingsAction = false;

		ConfigurableColumnTableModel configurableModel = getConfigurableColumnTableModel();
		if (configurableModel != null) {
			lastPopupColumnIndex = convertColumnIndexToModel(columnIndex);
			SettingsDefinition[] settingsDefs =
				configurableModel.getColumnSettingsDefinitions(lastPopupColumnIndex);
			enableSettingsAction = (settingsDefs.length != 0);
		}
		item.setEnabled(enableSettingsAction);
		return tableHeaderPopupMenu;
	}

	private JPopupMenu buildTableHeaderPopupMenu() {
		HelpLocation helpLocation = new HelpLocation("Tables", "GhidraTableHeaders");

		final JPopupMenu newPopupMenu = new JPopupMenu();

		newPopupMenu.add(createAddRemoveColumnsMenuItem(helpLocation));
		newPopupMenu.add(createColumnSettingsMenuItem(helpLocation));

		newPopupMenu.addPopupMenuListener(new PopupMenuListener() {
			@Override
			public void popupMenuCanceled(PopupMenuEvent e) {
				// don't care
			}

			@Override
			public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
				// don't care
			}

			@Override
			public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
				DockingWindowManager.setMouseOverObject(newPopupMenu);
			}
		});

		DockingWindowManager.getHelpService().registerHelp(newPopupMenu, helpLocation);

		return newPopupMenu;
	}

	private JMenuItem createAddRemoveColumnsMenuItem(HelpLocation helpLocation) {
		JMenuItem item = new JMenuItem("Add/Remove Columns...");
		final TableModel model = getModel();
		item.addActionListener(e -> {
			SelectColumnsDialog dialog =
				new SelectColumnsDialog((GTableColumnModel) columnModel, model);
			DockingWindowManager.showDialog(GTable.this, dialog);
		});
		DockingWindowManager.getHelpService().registerHelp(item, helpLocation);
		return item;
	}

	private JMenuItem createColumnSettingsMenuItem(HelpLocation helpLocation) {
		JMenuItem item = new JMenuItem("Column Settings...");
		item.addActionListener(e -> {
			ConfigurableColumnTableModel configurableModel = getConfigurableColumnTableModel();
			if (configurableModel == null) {
				return;
			}

			SettingsDefinition[] settings =
				configurableModel.getColumnSettingsDefinitions(lastPopupColumnIndex);
			if (settings.length == 0) {
				return;
			}

			SettingsDialog dialog = new SettingsDialog(null);
			dialog.show(GTable.this,
				configurableModel.getColumnName(lastPopupColumnIndex) + " Settings", settings,
				configurableModel.getColumnSettings(lastPopupColumnIndex));
			((GTableColumnModel) getColumnModel()).saveState();
		});
		DockingWindowManager.getHelpService().registerHelp(item, helpLocation);
		return item;
	}

	/*
	 * Note: overridden to allow the Copy actions to record the text data of each cell
	 *       *without* using HTML.  When users copy the table data, having HTML markup makes the
	 *       data almost unreadable/unusable.
	 */
	@Override
	public Object getValueAt(int row, int column) {
		Object value = super.getValueAt(row, column);

		if (!copying) {
			return value;
		}

		Object updated = maybeConvertValue(value);
		return updated;
	}

	private Object maybeConvertValue(Object value) {
		if (value == null) {
			return null;
		}

		String asString = value.toString();
		String converted = HTMLUtilities.fromHTML(asString);
		return converted;
	}

	private void createPopupActions() {

		int subGroupIndex = 1; // order by insertion
		String owner = getClass().getSimpleName();
		owner = "GTable";
		copyAction = new DockingAction("Table Data Copy", owner, KeyBindingType.SHARED) {
			@Override
			public void actionPerformed(ActionContext context) {
				copying = true;
				Action builtinCopyAction = TransferHandler.getCopyAction();

				try {
					builtinCopyAction.actionPerformed(new ActionEvent(GTable.this, 0, "copy"));
				}
				finally {
					copying = false;
				}
			}
		};
		//@formatter:off
		copyAction.setPopupMenuData(new MenuData(
				new String[] { "Copy", "Copy" },
				ResourceManager.loadImage("images/page_white_copy.png"),
				actionMenuGroup, NO_MNEMONIC,
				Integer.toString(subGroupIndex++)
			)
		);
		copyAction.setKeyBindingData(new KeyBindingData(
			KeyStroke.getKeyStroke(KeyEvent.VK_C,
			CONTROL_KEY_MODIFIER_MASK)
			)
		);
		copyAction.setHelpLocation(new HelpLocation("Tables", "Copy"));
		//@formatter:on

		copyCurrentColumnAction =
			new DockingAction("Table Data Copy Current Column", owner, KeyBindingType.SHARED) {
				@Override
				public void actionPerformed(ActionContext context) {

					int column = getSelectedColumn();

					MouseEvent event = context.getMouseEvent();
					if (event != null) {
						column = columnAtPoint(event.getPoint());
					}

					if (column < 0) {
						Msg.debug(this, "Copy failed--no column selected");
						return;
					}

					copyColumns(column);
				}
			};
		//@formatter:off
		copyCurrentColumnAction.setPopupMenuData(new MenuData(
				new String[] { "Copy",
				"Copy Current Column" },
				ResourceManager.loadImage("images/page_white_copy.png"),
				actionMenuGroup,
				NO_MNEMONIC,
				Integer.toString(subGroupIndex++)
			)
		);
		copyCurrentColumnAction.setKeyBindingData(new KeyBindingData(
				KeyStroke.getKeyStroke(
				KeyEvent.VK_C, CONTROL_KEY_MODIFIER_MASK | SHIFT_DOWN_MASK)
			)
		);
		copyCurrentColumnAction.setHelpLocation(new HelpLocation("Tables", "Copy_Current_Column"));
		//@formatter:on

		copyColumnsAction =
			new DockingAction("Table Data Copy by Columns", owner, KeyBindingType.SHARED) {
				@Override
				public void actionPerformed(ActionContext context) {
					int[] userColumns = promptUserForColumns();
					if (userColumns == null) {
						return; // cancelled
					}

					copyColumns(userColumns);
				}
			};
		//@formatter:off
		copyColumnsAction.setPopupMenuData(new MenuData(
				new String[] { "Copy", "Copy Columns..." },
				ResourceManager.loadImage("images/page_white_copy.png"),
				actionMenuGroup,
				NO_MNEMONIC,
				Integer.toString(subGroupIndex++)
			)
		);
		copyColumnsAction.setHelpLocation(new HelpLocation("Tables", "Copy_Columns"));
		//@formatter:on

		exportAction = new DockingAction("Table Data CSV Export", owner, KeyBindingType.SHARED) {
			@Override
			public void actionPerformed(ActionContext context) {
				File file = chooseExportFile();
				if (file != null) {
					GTableToCSV.writeCSV(file, GTable.this);
				}
			}
		};
		//@formatter:off
		exportAction.setPopupMenuData(new MenuData(
				new String[] { "Export", GTableToCSV.TITLE + "..." },
				ResourceManager.loadImage("images/application-vnd.oasis.opendocument.spreadsheet-template.png"),
				actionMenuGroup,
				NO_MNEMONIC,
				Integer.toString(subGroupIndex++)
			)
		);
		exportAction.setHelpLocation(new HelpLocation("Tables", "ExportCSV"));
		//@formatter:on

		exportColumnsAction =
			new DockingAction("Table Data CSV Export (by Columns)", owner, KeyBindingType.SHARED) {
				@Override
				public void actionPerformed(ActionContext context) {
					int[] userColumns = promptUserForColumns();
					if (userColumns == null) {
						return; // cancelled
					}

					File file = chooseExportFile();
					if (file == null) {
						return;
					}

					List<Integer> columnList = new ArrayList<>();
					for (int userColumn : userColumns) {
						columnList.add(userColumn);
					}
					GTableToCSV.writeCSVUsingColunns(file, GTable.this, columnList);
				}
			};
		//@formatter:off
		exportColumnsAction.setPopupMenuData(new MenuData(
				new String[] { "Export", "Export Columns to CSV..." },
				ResourceManager.loadImage("images/application-vnd.oasis.opendocument.spreadsheet-template.png"),
				actionMenuGroup,
				NO_MNEMONIC,
				Integer.toString(subGroupIndex++)
			)
		);
		exportColumnsAction.setHelpLocation(new HelpLocation("Tables", "ExportCSV_Columns"));
		//@formatter:on

		selectAllAction = new DockingAction("Table Select All", owner, KeyBindingType.SHARED) {
			@Override
			public void actionPerformed(ActionContext context) {
				selectAll();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return getSelectionModel().getSelectionMode() != ListSelectionModel.SINGLE_SELECTION;
			}
		};
		//@formatter:off
		selectAllAction.setPopupMenuData(new MenuData(
				new String[] { "Select All" },
				null /*icon*/,
				actionMenuGroup,
				NO_MNEMONIC,
				Integer.toString(subGroupIndex++)
			)
		);
		selectAllAction.setKeyBindingData(new KeyBindingData(
				KeyStroke.getKeyStroke(KeyEvent.VK_A,
				CONTROL_KEY_MODIFIER_MASK)
			)
		);
		selectAllAction.setHelpLocation(new HelpLocation("Tables", "SelectAll"));
		//@formatter:on

		KeyBindingUtils.registerAction(this, copyAction);
		KeyBindingUtils.registerAction(this, copyCurrentColumnAction);
		KeyBindingUtils.registerAction(this, selectAllAction);
	}

	private void copyColumns(int... copyColumns) {

		int[] originalColumns = new int[0];
		boolean wasAllowed = getColumnSelectionAllowed();
		if (wasAllowed) {
			originalColumns = getSelectedColumns();
		}

		setColumnSelectionAllowed(true);
		setSelectedColumns(copyColumns);

		copying = true;
		try {

			Action builtinCopyAction = TransferHandler.getCopyAction();
			builtinCopyAction.actionPerformed(new ActionEvent(GTable.this, 0, "copy"));
		}
		finally {
			copying = false;

			// put back whatever selection existed before this action was executed
			setSelectedColumns(originalColumns);
			setColumnSelectionAllowed(wasAllowed);
		}
	}

	private void setSelectedColumns(int[] columns) {
		columnModel.getSelectionModel().clearSelection();
		for (int column : columns) {
			addColumnSelectionInterval(column, column);
		}
	}

	private int[] promptUserForColumns() {
		ChooseColumnsDialog dialog =
			new ChooseColumnsDialog((GTableColumnModel) columnModel, getModel());
		DockingWindowManager.showDialog(GTable.this, dialog);
		return dialog.getChosenColumns();
	}

	private GhidraFileChooser createExportFileChooser() {
		GhidraFileChooser chooser = new GhidraFileChooser(GTable.this);
		chooser.setTitle(GTableToCSV.TITLE);
		chooser.setApproveButtonText("OK");

		String filepath = Preferences.getProperty(LAST_EXPORT_FILE);
		if (filepath != null) {
			chooser.setSelectedFile(new File(filepath));
		}

		return chooser;
	}

	private File chooseExportFile() {
		GhidraFileChooser chooser = createExportFileChooser();
		File file = chooser.getSelectedFile();
		if (file == null) {
			return null;
		}
		if (file.exists()) {
			int result = OptionDialog.showYesNoDialog(GTable.this, "Overwrite?",
				"File exists. Do you want to overwrite?");

			if (result != OptionDialog.OPTION_ONE) {
				return null;
			}
		}
		storeLastExportDirectory(file);
		return file;
	}

	private void storeLastExportDirectory(File file) {
		Preferences.setProperty(LAST_EXPORT_FILE, file.getAbsolutePath());
		Preferences.store();
	}

	/**
	 * Maintain a {@link docking.widgets.table.GTableCellRenderingData} object
	 * associated with each column that maintains some state and references to
	 * useful data. These objects are created as needed, stored by the table for
	 * convenient re-use and to prevent per-cell creation, and cleared when columns
	 * are removed from the table.
	 * <p>
	 * Row and cell state is cleared before returning to the caller to ensure
	 * consistent state; when the client is done rendering a cell, row and cell
	 * state should also be cleared to minimize references.
	 *
	 * @param viewColumn
	 *            The columns' view index
	 * @return Data specific to the column. Row state is cleared before returning.
	 */
	GTableCellRenderingData getRenderingData(int viewColumn) {

		int modelColumn = convertColumnIndexToModel(viewColumn);

		GTableCellRenderingData renderData = columnRenderingDataMap.get(modelColumn);

		if (renderData == null) {
			Settings settings = SettingsImpl.NO_SETTINGS;
			ConfigurableColumnTableModel configurableModel = getConfigurableColumnTableModel();
			if (configurableModel != null) {
				settings = configurableModel.getColumnSettings(modelColumn);
			}

			renderData = new GTableCellRenderingData(this, viewColumn, settings);
			columnRenderingDataMap.put(modelColumn, renderData);
		}

		renderData.resetRowData();
		return renderData;

	}

	private class MyTableColumnModelListener implements TableColumnModelListener {
		@Override
		public void columnSelectionChanged(ListSelectionEvent e) {
			// ignored
		}

		@Override
		public void columnRemoved(TableColumnModelEvent e) {
			if (columnRenderingDataMap != null) {
				columnRenderingDataMap.clear();
			}
		}

		@Override
		public void columnMoved(TableColumnModelEvent e) {
			// ignored
		}

		@Override
		public void columnMarginChanged(ChangeEvent e) {
			// ignored
		}

		@Override
		public void columnAdded(TableColumnModelEvent e) {
			// ignored
		}
	}
}
