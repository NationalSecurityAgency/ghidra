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

import static docking.DockingUtils.*;
import static docking.action.MenuData.*;
import static java.awt.event.InputEvent.*;

import java.awt.*;
import java.awt.event.*;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;

import docking.*;
import docking.action.*;
import docking.actions.KeyBindingUtils;
import docking.actions.ToolActions;
import docking.widgets.AutoLookup;
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
public class GTable extends JTable {

	private static final KeyStroke COPY_KEY_STROKE =
		KeyStroke.getKeyStroke(KeyEvent.VK_C, CONTROL_KEY_MODIFIER_MASK);
	private static final KeyStroke COPY_COLUMN_KEY_STROKE =
		KeyStroke.getKeyStroke(KeyEvent.VK_C, CONTROL_KEY_MODIFIER_MASK | SHIFT_DOWN_MASK);
	private static final KeyStroke SELECT_ALL_KEY_STROKE =
		KeyStroke.getKeyStroke(KeyEvent.VK_A, CONTROL_KEY_MODIFIER_MASK);

	private static final String LAST_EXPORT_FILE = "LAST_EXPORT_DIR";
	private static final KeyStroke ESCAPE = KeyStroke.getKeyStroke("ESCAPE");

	private boolean isInitialized;
	private boolean enableActionKeyBindings;
	private KeyListener autoLookupListener;

	private AutoLookup autoLookup = createAutoLookup();

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

	private SelectionManager selectionManager;
	private Integer visibleRowCount;

	private int userDefinedRowHeight;
	private TableModelListener rowHeightListener = e -> adjustRowHeight();

	private TableColumnModelListener tableColumnModelListener = null;
	private final Map<Integer, GTableCellRenderingData> columnRenderingDataMap = new HashMap<>();

	/**
	 * Constructs a new GTable
	 */
	public GTable() {
		super();
		init();
	}

	/**
	 * Constructs a new GTable using the specified table model.
	 * @param dm the table model
	 */
	public GTable(TableModel dm) {
		super(dm);
		init();
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

	/**
	 * Allows subclasses to change the type of {@link AutoLookup} created by this table
	 * @return the auto lookup 
	 */
	protected AutoLookup createAutoLookup() {
		return new GTableAutoLookup(this);
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
		// we are going to create a new selection model, save off the old selectionMode and
		// restore it at the end.
		int selectionMode = selectionModel.getSelectionMode();

		if (selectionManager != null) {
			selectionManager.dispose();
		}

		super.setModel(dataModel);

		initializeRowHeight();

		selectionManager = createSelectionManager();
		selectionModel.setSelectionMode(selectionMode);
	}

	protected <T> SelectionManager createSelectionManager() {
		RowObjectTableModel<Object> rowModel = getRowObjectTableModel();
		if (rowModel != null) {
			return new RowObjectSelectionManager<>(this, rowModel);
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	// The (RowObjectTableModel<T>) is safe, since we are create a new SelectionManager of
	// an arbitrary type T defined here.  So, T doesn't really exist and therefore the cast isn't
	// really casting to anything.  The SelectionManager will take on the type of the given model.
	// The T is just there on the SelectionManager to make its internal methods consistent.
	private <T> RowObjectTableModel<T> getRowObjectTableModel() {
		TableModel model = getModel();
		if (model instanceof RowObjectTableModel) {
			return (RowObjectTableModel<T>) model;
		}

		return null;
	}

	/**
	 * Returns the {@link SelectionManager} in use by this GTable.  <code>null</code> is returned
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
		TableModel unwrappedeModel = getUnwrappedTableModel();
		if (unwrappedeModel instanceof AbstractGTableModel) {
			((AbstractGTableModel<?>) unwrappedeModel).dispose();
		}

		if (columnModel instanceof GTableColumnModel) {
			((GTableColumnModel) columnModel).dispose();
		}

		columnRenderingDataMap.clear();

		if (selectionManager != null) {
			selectionManager.dispose();
		}

		for (PropertyChangeListener listener : getPropertyChangeListeners()) {
			removePropertyChangeListener(listener);
		}
	}

	/**
	 * Sets the delay between keystrokes after which each keystroke is considered a new lookup
	 * @param timeout the timeout
	 * @see #setAutoLookupColumn(int)
	 * @see AutoLookup#KEY_TYPING_TIMEOUT
	 */
	public void setAutoLookupTimeout(long timeout) {
		autoLookup.setTimeout(timeout);
	}

	protected AutoLookup getAutoLookup() {
		return autoLookup;
	}

	/**
	 * Sets the column in which auto-lookup will be enabled.
	 * 
	 * <p>Note: calling this method with a valid column index will disable key binding support
	 * of actions.  See {@link #setActionsEnabled(boolean)}.  Passing an invalid column index
	 * will disable the auto-lookup feature.
	 * 
	 * @param lookupColumn the column in which auto-lookup will be enabled
	 */
	public void setAutoLookupColumn(int lookupColumn) {
		autoLookup.setColumn(convertColumnIndexToView(lookupColumn));

		if (autoLookupListener == null) {
			autoLookupListener = new KeyAdapter() {
				@Override
				public void keyPressed(KeyEvent e) {
					if (enableActionKeyBindings) {
						// actions will consume key bindings, so don't process them
						return;
					}

					if (getRowCount() == 0) {
						return;
					}

					autoLookup.keyTyped(e);
				}
			};
		}

		removeKeyListener(autoLookupListener);
		if (lookupColumn >= 0 && lookupColumn < getModel().getColumnCount()) {
			addKeyListener(autoLookupListener);
			enableActionKeyBindings = false;
		}
	}

	/**
	 * Enables the keyboard actions to pass through this table and up the component hierarchy.
	 * Specifically, passing true to this method allows unmodified keystrokes to work
	 * in the tool when this table is focused.  Modified keystrokes, like <code>
	 * Ctrl-C</code>, will work at all times.   Finally, if true is passed to this
	 * method, then the {@link #setAutoLookupColumn(int) auto lookup} feature is
	 * disabled.
	 * 
	 * <p>The default state is for actions to be disabled.
	 * 
	 * @param b true allows keyboard actions to pass up the component hierarchy.
	 */
	public void setActionsEnabled(boolean b) {
		enableActionKeyBindings = b;
	}

	/**
	 * Returns true if key strokes are used to trigger actions. 
	 * 
	 * <p>This method has a relationship with {@link #setAutoLookupColumn(int)}.  If this method 
	 * returns <code>true</code>, then the auto-lookup feature is disabled.  If this method 
	 * returns <code>false</code>, then the auto-lookup may or may not be enabled.
	 *   
	 * @return true if key strokes are used to trigger actions
	 * @see #setActionsEnabled(boolean)
	 * @see #setAutoLookupColumn(int)
	 */
	public boolean areActionsEnabled() {
		return enableActionKeyBindings;
	}

	/**
	 * Enables or disables auto-edit.  When enabled, the user can start typing to trigger an
	 * edit of an editable table cell.
	 * 
	 * @param allowAutoEdit true for auto-editing
	 */
	public void setAutoEditEnabled(boolean allowAutoEdit) {
		putClientProperty("JTable.autoStartsEdit", allowAutoEdit);
	}

	private void installEditKeyBinding() {
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

	private void init() {
		ToolTipManager.sharedInstance().unregisterComponent(this);
		ToolTipManager.sharedInstance().registerComponent(this);
		setTableHeader(new GTableHeader(this));

		setAutoEditEnabled(false); // clients can turn this on as needed
		installEditKeyBinding();

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

		removeActionKeyStrokes();

		// updating the row height requires the 'isInitialized' to be set, so do it first
		isInitialized = true;
		initializeRowHeight();
	}

	private void removeActionKeyStrokes() {
		// 
		// We remove these keybindings as we have replaced Java's version with our own.  To be
		// thorough, we should really clear all table keybindings, which would ensure that any
		// user-provided key stroke would not get blocked by the table.  At the time of writing, 
		// there are alternate key bindings for copy that do not use this table's copy action.
		// Also, there are many other built-in keybindings for table navigation, which we do not
		// wish to override.   For now, just clear these.  We can clear others if they become
		// a problem.
		//
		KeyBindingUtils.clearKeyBinding(this, COPY_KEY_STROKE);
		KeyBindingUtils.clearKeyBinding(this, COPY_COLUMN_KEY_STROKE);
		KeyBindingUtils.clearKeyBinding(this, SELECT_ALL_KEY_STROKE);
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

		if (!isInitialized) {
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

		if (getColumnCount() == 0) {
			return userDefinedRowHeight; // no columns yet defined
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
	 *     <li>Enable any <code>default</code> {@link GTableCellRenderer} instances to render
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
		if (!copying) {
			return super.getValueAt(row, column);
		}

		Object value = getCellValue(row, column);
		Object updated = maybeConvertValue(value);
		return updated;
	}

	private Object getCellValue(int row, int viewColumn) {
		RowObjectTableModel<Object> rowModel = getRowObjectTableModel();
		if (rowModel == null) {
			Object value = super.getValueAt(row, viewColumn);
			return maybeConvertValue(value);
		}

		Object rowObject = rowModel.getRowObject(row);
		int modelColumn = convertColumnIndexToModel(viewColumn);
		String stringValue = TableUtils.getTableCellStringValue(rowModel, rowObject, modelColumn);
		return maybeConvertValue(stringValue);
	}

	private Object maybeConvertValue(Object value) {
		if (value == null) {
			return null;
		}

		String asString = value.toString();
		String converted = HTMLUtilities.fromHTML(asString);
		return converted;
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

//==================================================================================================
// Actions
//==================================================================================================

	/**
	 * A method that subclasses can override to signal that they wish not to have this table's 
	 * built-in popup actions.   Subclasses will almost never need to override this method.
	 * 
	 * @return true if popup actions are supported
	 */
	protected boolean supportsPopupActions() {
		return true;
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

	private void doCopy() {
		copying = true;
		Action builtinCopyAction = TransferHandler.getCopyAction();

		try {
			builtinCopyAction.actionPerformed(new ActionEvent(GTable.this, 0, "copy"));
		}
		finally {
			copying = false;
		}
	}

	private void doCopyCurrentColumn(MouseEvent event) {
		int column = getSelectedColumn();
		if (event != null) {
			column = columnAtPoint(event.getPoint());
		}

		if (column < 0) {
			Msg.debug(this, "Copy failed--no column selected");
			return;
		}

		copyColumns(column);
	}

	private void doCopyColumns() {
		int[] userColumns = promptUserForColumns();
		if (userColumns == null) {
			return; // cancelled
		}

		copyColumns(userColumns);
	}

	private void doExport() {
		File file = chooseExportFile();
		if (file != null) {
			GTableToCSV.writeCSV(file, GTable.this);
		}
	}

	private void doExportColumns() {
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

	public static void createSharedActions(Tool tool, ToolActions toolActions, String owner) {

		String actionMenuGroup = "zzzTableGroup";
		tool.setMenuGroup(new String[] { "Copy" }, actionMenuGroup, "1");
		tool.setMenuGroup(new String[] { "Export" }, actionMenuGroup, "2");
		tool.setMenuGroup(new String[] { "Select All" }, actionMenuGroup, "3");

		int subGroupIndex = 1; // order by insertion
		GTableAction copyAction = new GTableAction("Table Data Copy", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				GTable gTable = (GTable) context.getSourceComponent();
				gTable.doCopy();
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
		copyAction.setKeyBindingData(new KeyBindingData(COPY_KEY_STROKE));
		copyAction.setHelpLocation(new HelpLocation("Tables", "Copy"));
		//@formatter:on

		GTableAction copyCurrentColumnAction =
			new GTableAction("Table Data Copy Current Column", owner) {
				@Override
				public void actionPerformed(ActionContext context) {
					GTable gTable = (GTable) context.getSourceComponent();
					gTable.doCopyCurrentColumn(context.getMouseEvent());
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
		copyCurrentColumnAction.setKeyBindingData(new KeyBindingData(COPY_COLUMN_KEY_STROKE));
		copyCurrentColumnAction.setHelpLocation(new HelpLocation("Tables", "Copy_Current_Column"));
		//@formatter:on

		GTableAction copyColumnsAction = new GTableAction("Table Data Copy by Columns", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				GTable gTable = (GTable) context.getSourceComponent();
				gTable.doCopyColumns();
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

		GTableAction exportAction = new GTableAction("Table Data CSV Export", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				GTable gTable = (GTable) context.getSourceComponent();
				gTable.doExport();
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

		GTableAction exportColumnsAction =
			new GTableAction("Table Data CSV Export (by Columns)", owner) {
				@Override
				public void actionPerformed(ActionContext context) {
					GTable gTable = (GTable) context.getSourceComponent();
					gTable.doExportColumns();
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

		GTableAction selectAllAction = new GTableAction("Table Select All", owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				GTable gTable = (GTable) context.getSourceComponent();
				gTable.selectAll();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!super.isEnabledForContext(context)) {
					return false;
				}
				GTable gTable = (GTable) context.getSourceComponent();
				int mode = gTable.getSelectionModel().getSelectionMode();
				return mode != ListSelectionModel.SINGLE_SELECTION;
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
		selectAllAction.setKeyBindingData(new KeyBindingData(SELECT_ALL_KEY_STROKE));
		selectAllAction.setHelpLocation(new HelpLocation("Tables", "SelectAll"));
		//@formatter:on

		toolActions.addGlobalAction(copyAction);
		toolActions.addGlobalAction(copyColumnsAction);
		toolActions.addGlobalAction(copyCurrentColumnAction);
		toolActions.addGlobalAction(exportAction);
		toolActions.addGlobalAction(exportColumnsAction);
		toolActions.addGlobalAction(selectAllAction);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

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

	private abstract static class GTableAction extends DockingAction
			implements ComponentBasedDockingAction {

		GTableAction(String name, String owner) {
			super(name, owner);
		}

		@Override
		public boolean isAddToPopup(ActionContext context) {
			if (!isEnabledForContext(context)) {
				return false;
			}
			GTable gTable = (GTable) context.getSourceComponent();
			return gTable.supportsPopupActions();
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			Component sourceComponent = context.getSourceComponent();
			return sourceComponent instanceof GTable;
		}

		@Override
		public boolean isValidComponentContext(ActionContext context) {
			Component sourceComponent = context.getSourceComponent();
			return sourceComponent instanceof GTable;
		}
	}
}
