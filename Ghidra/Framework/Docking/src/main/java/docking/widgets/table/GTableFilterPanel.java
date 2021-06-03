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

import java.awt.Component;
import java.awt.Rectangle;
import java.beans.PropertyChangeListener;
import java.util.*;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.event.*;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;

import org.jdom.Element;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.help.HelpService;
import docking.menu.*;
import docking.widgets.EmptyBorderButton;
import docking.widgets.EventTrigger;
import docking.widgets.filter.*;
import docking.widgets.label.GDLabel;
import docking.widgets.table.columnfilter.ColumnBasedTableFilter;
import docking.widgets.table.columnfilter.ColumnFilterSaveManager;
import docking.widgets.table.constraint.dialog.ColumnFilterDialog;
import ghidra.framework.options.PreferenceState;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.AssertException;
import ghidra.util.task.SwingUpdateManager;
import resources.Icons;
import resources.ResourceManager;
import utilities.util.reflection.ReflectionUtilities;
import utility.function.Callback;

/**
 * This class is a panel that provides a label and text field that allows users to input text that
 * filters the contents of the table.
 * <p>
 * This class also handles restoring selection for the client when the table has been filtered.
 * See <a href="#restore_selection">below</a> for a caveat.
 * <p>
 *
 * <u>Filter Reminder</u><br>
 * The filter text will flash as the table (by default) gains focus.  This is done to remind the
 * user that the data has been filtered.  To change the component that triggers the flashing use
 * {@link #setFocusComponent(Component)}, where the <code>Component</code> parameter is the
 * component that will trigger focus flashing when it gains focus.  To disable focus flashing,
 * pass in null to {@link #setFocusComponent(Component)}.
 * <p>
 *
 * <u>Filtering</u><br>
 * The filtering behavior is controlled by the filter button displayed to the right of this 
 * panel's text field.
 * <p>
 *
 * <b><u>Important Usage Notes</u></b>
 * <ul>
 *     <li><b><a id="translation"></a>You must translate row values retrieved from the table using
 *     this panel.</b>
 *     <p>
 *     Since this class wraps the given table with a new model, you must use this class to
 *     translate row number values.  For example, when getting the selected row, the normal Java
 *     code snippet below will give the incorrect value:
 *     <pre>
 *         JTable table = ...
 *         <span style="color:red">int selectedRowNumber = table.getSelectedRow();</span>
 *     </pre>
 *     Instead, you must translate the returned value from above, as in the following snippet:
 *     <pre>
 *         JTable table = ...
 *         <span style="color:green">
 *         int selectedRowNumber = table.getSelectedRow();
 *         int modelRowNumber = tableFilterPanel.getModelRow( selectedRowNumber );  // see {@link #getModelRow(int)}
 *         </span>
 *     </pre>
 *
 *     <li><b>This class may set a new model on the given table, which can affect how tables are sized.</b>
 *     <p>
 *      If {@link JTable#getAutoCreateColumnsFromModel()} returns true, then the columns will
 *      be recreated and resized when this class is constructed.
 *     <li>The {@link TableFilter} used by this class will be passed the empty string ("") when
 *     {@link TableFilter#acceptsRow(Object)} is called.
 *     <li><b>You cannot rely on {@link JTable#getRowCount()} to access all of the table data,
 *     since the data may be filtered.</b>
 *     <p>
 *     To get a row count that is always all of the model's data, call
 *     {@link #getUnfilteredRowCount()}.
 * </ul>
 * 
 * @param <ROW_OBJECT> the row object type for this given table and model
 */
public class GTableFilterPanel<ROW_OBJECT> extends JPanel {

	public static final String FILTER_TEXTFIELD_NAME = "filter.panel.textfield";
	private static final String FILTER_STATE = "FILTER_STATE";
	private static final String FILTER_EXTENSION = ".FilterExtension";
	private static final Icon FILTER_ON_ICON = ResourceManager.loadImage("images/filter_on.png");
	private static final Icon FILTER_OFF_ICON = ResourceManager.loadImage("images/filter_off.png");
	private static final Icon APPLY_FILTER_ICON = Icons.OPEN_FOLDER_ICON;
	private static final Icon CLEAR_FILTER_ICON = Icons.DELETE_ICON;

	private JTable table;
	private RowObjectFilterModel<ROW_OBJECT> textFilterModel;
	private JLabel searchLabel;

	private FilterTextField filterField;
	private FilterListener filterListener = new GTableFilterListener();

	private WeakSet<Callback> listeners =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();

	private FilterOptions filterOptions = new FilterOptions();
	private TableTextFilterFactory<ROW_OBJECT> filterFactory =
		new DefaultTableTextFilterFactory<>(filterOptions);
	private RowFilterTransformer<ROW_OBJECT> transformer;
	private TableFilter<ROW_OBJECT> secondaryTableFilter;
	private ColumnBasedTableFilter<ROW_OBJECT> columnTableFilter;
	private List<ColumnBasedTableFilter<ROW_OBJECT>> savedFilters = new ArrayList<>();
	private EmptyBorderButton filterStateButton;

	private String uniquePreferenceKey;

	private MultiStateDockingAction<ColumnBasedTableFilter<ROW_OBJECT>> columnFilterAction;
	private ColumnFilterDialog<ROW_OBJECT> columnFilterDialog;
	private ColumnBasedTableFilter<ROW_OBJECT> lastUsedColumnFilter;

	private SwingUpdateManager updateManager = new SwingUpdateManager(250, 1000, () -> {
		String text = filterField.getText();
		TableFilter<ROW_OBJECT> tableFilter = filterFactory.getTableFilter(text, transformer);
		textFilterModel.setTableFilter(
			getCombinedTableFilter(secondaryTableFilter, tableFilter, columnTableFilter));
	});

	/** I'm a field so that my weak reference won't go away */
	private TableColumnModelListener columnModelListener = new TableColumnModelListener() {
		@Override
		public void columnSelectionChanged(ListSelectionEvent e) {
			// don't care; table will repaint
		}

		@Override
		public void columnMarginChanged(ChangeEvent e) {
			// don't care; table will repaint
		}

		@Override
		public void columnMoved(TableColumnModelEvent e) {
			// don't care; table will repaint
		}

		@Override
		public void columnRemoved(TableColumnModelEvent e) {
			updateTableContents();
		}

		@Override
		public void columnAdded(TableColumnModelEvent e) {
			updateTableContents();
		}
	};

	private PropertyChangeListener badProgrammingPropertyChangeListener = evt -> {
		if (evt.getPropertyName().equals("model")) {
			throw new AssertException("HEY!  You can't change the model once you've " +
				"made the commitment to use a filter panel!...duh!");
		}
	};

	/**
	 * Creates a table filter panel that filters the contents of the given table.
	 *
	 * @param table The table whose contents will be filtered.
	 * @param tableModel The table model used by the table--passed in by the type that we require
	 */
	public GTableFilterPanel(JTable table, RowObjectTableModel<ROW_OBJECT> tableModel) {
		this(table, tableModel, " Filter: ");
	}

	public GTableFilterPanel(JTable table, RowObjectTableModel<ROW_OBJECT> tableModel,
			String filterLabel) {
		this.table = table;

		buildPanel(filterLabel);

		uniquePreferenceKey = createUniqueFilterPreferenceKey(table);

		transformer = new DefaultRowFilterTransformer<>(tableModel, table.getColumnModel());

		textFilterModel = installTableModel(tableModel);

		TableColumnModel columnModel = table.getColumnModel();
		columnModel.addColumnModelListener(columnModelListener);

		// we currently can't handle model changes, so just explode
		table.addPropertyChangeListener(badProgrammingPropertyChangeListener);

		DockingWindowManager.registerComponentLoadedListener(this,
			(windowManager, provider) -> initialize(windowManager));
	}

	private void initialize(DockingWindowManager windowManager) {
		loadFilterPreference(windowManager);
		initializeSavedFilters();
	}

	private void loadFilterPreference(DockingWindowManager dockingWindowManager) {
		if (dockingWindowManager != null) {
			PreferenceState preferenceState =
				dockingWindowManager.getPreferenceState(uniquePreferenceKey);
			if (preferenceState != null) {
				Element xmlElement = preferenceState.getXmlElement(FILTER_STATE);
				restoreFromXML(xmlElement);
			}
		}
	}

	private void doSaveState() {
		PreferenceState preferenceState = new PreferenceState();
		preferenceState.putXmlElement(FILTER_STATE, saveToXML());

		DockingWindowManager dockingWindowManager = DockingWindowManager.getInstance(table);
		if (dockingWindowManager != null) {
			dockingWindowManager.putPreferenceState(uniquePreferenceKey, preferenceState);
		}
	}

	private Element saveToXML() {
		return filterOptions.toXML();
	}

	private void restoreFromXML(Element xmlElement) {
		if (xmlElement != null) {
			this.filterOptions = FilterOptions.restoreFromXML(xmlElement);
			updateFilterFactory();
			updateTableContents();

		}
	}

	protected TableFilter<ROW_OBJECT> getCombinedTableFilter(TableFilter<ROW_OBJECT> filter1,
			TableFilter<ROW_OBJECT> filter2, TableFilter<ROW_OBJECT> filter3) {
		return new CombinedTableFilter<>(filter1, filter2, filter3);
	}

	/**
	 * Adds a listener that gets notified when the filter is changed
	 *
	 * <P>Note: this listener cannot be anonymous, as the underlying storage mechanism may be
	 * using a weak data structure.  This means that you will need to store the listener in
	 * a field inside of your class.
	 *
	 * @param l the listener
	 */
	public void addFilterChagnedListener(FilterListener l) {
		filterField.addFilterListener(l);
	}

	/**
	 * Adds a listener to this widget that is called when the user presses enter in the
	 * filtering area.
	 *
	 * <P>Note: this listener cannot be anonymous, as the underlying storage mechanism may be
	 * using a weak data structure.  This means that you will need to store the listener in
	 * a field inside of your class.
	 *
	 * @param callback the listener
	 */
	public void addEnterListener(Callback callback) {
		filterField.addEnterListener(callback);
	}

	/**
	 * Sets a ColumnTableFilter on this panel.
	 *
	 * @param newFilter the ColumnTableFilter to use for filtering this table.
	 */
	public void setColumnTableFilter(ColumnBasedTableFilter<ROW_OBJECT> newFilter) {
		if (Objects.equals(newFilter, this.columnTableFilter)) {
			return;
		}
		if (columnTableFilter != null && !columnTableFilter.isSaved()) {
			lastUsedColumnFilter = columnTableFilter;
		}
		columnTableFilter = newFilter;
		updateTableContents();
		updateColumnFilterButton();
		if (columnFilterDialog != null) {
			columnFilterDialog.filterChanged(newFilter);
		}
	}

	/**
	 * Sets a custom RowFilterTransformer.  The default row transformer will gather strings
	 * for each column in the table and use those strings for filtering.  This method allows
	 * the user to have complete control on generating the strings used to filter a table row;
	 * for example, to only filter on some columns but not others.
	 *
	 * @param transformer the custom row to string transformer used to generate strings from a
	 * row to be used for filtering.
	 */
	public void setFilterRowTransformer(RowFilterTransformer<ROW_OBJECT> transformer) {
		this.transformer = transformer;
		updateTableContents();
	}

	/**
	 * Sets a secondary filter that users can use to filter table rows by other criteria other than
	 * the text typed in at the bottom of a table.  This filter is an additional filter that will
	 * be applied with the typed text filter.
	 * @param tableFilter the additional filter to use for the table.
	 */
	public void setSecondaryFilter(TableFilter<ROW_OBJECT> tableFilter) {
		this.secondaryTableFilter = tableFilter;
		updateTableContents();
	}

	/**
	 * Sets the filter options used by the filter factory. The options are items like "starts with",
	 * "contains", "regex", etc.
	 * @param filterOptions the filter options to be used by the filter factory.
	 */
	public void setFilterOptions(FilterOptions filterOptions) {
		this.filterOptions = filterOptions;
		updateFilterFactory();
		updateTableContents();
		doSaveState();
	}

	private void buildPanel(String filterLabel) {
		setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
		setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));

		searchLabel = new GDLabel(filterLabel);
		searchLabel.setToolTipText("Include only table elements that match the given search text");

		filterField = new FilterTextField(table);
		filterField.setName(FILTER_TEXTFIELD_NAME);
		filterField.addFilterListener(filterListener);

		add(searchLabel);
		add(Box.createHorizontalStrut(5));
		add(filterField);
		add(buildFilterStateButton());
		if (isTableColumnFilterableModel()) {
			add(Box.createHorizontalStrut(5));
			add(buildColumnFilterStateButton());
		}

		HelpService helpService = DockingWindowManager.getHelpService();
		HelpLocation helpLocation = new HelpLocation("Trees", "Filters");
		helpService.registerHelp(filterStateButton, helpLocation);
		helpService.registerHelp(searchLabel, helpLocation);
		helpService.registerHelp(filterField, helpLocation);

	}

	private JComponent buildFilterStateButton() {
		filterStateButton = new EmptyBorderButton(filterOptions.getFilterStateIcon());
		filterStateButton.addActionListener(e -> {
			FilterOptionsEditorDialog dialog = new FilterOptionsEditorDialog(filterOptions);
			DockingWindowManager.showDialog(GTableFilterPanel.this, dialog);
			FilterOptions resultFilterOptions = dialog.getResultFilterOptions();
			if (resultFilterOptions != null) {
				setFilterOptions(resultFilterOptions);
			}
		});

		filterStateButton.setToolTipText("Filter Options");
		updateFilterFactory();
		return filterStateButton;
	}

	private boolean isTableColumnFilterableModel() {
		return table.getModel() instanceof RowObjectFilterModel;
	}

	@SuppressWarnings("unchecked")
	private JComponent buildColumnFilterStateButton() {

		RowObjectFilterModel<ROW_OBJECT> tableModel =
			(RowObjectFilterModel<ROW_OBJECT>) table.getModel();
		columnFilterAction =
			new NonToolbarMultiStateAction<>("Column Filter", "GTableFilterPanel") {

				@Override
				public void actionStateChanged(
						ActionState<ColumnBasedTableFilter<ROW_OBJECT>> newActionState,
						EventTrigger trigger) {
					if (trigger != EventTrigger.GUI_ACTION) {
						return;
					}
					ColumnFilterActionState state = (ColumnFilterActionState) newActionState;
					state.performAction();
				}

				@Override
				protected void doActionPerformed(ActionContext context) {
					showFilterDialog(tableModel);
				}

			};
		columnFilterAction.setPerformActionOnPrimaryButtonClick(true);
		HelpLocation helpLocation = new HelpLocation("Trees", "Column_Filters");
		columnFilterAction.setHelpLocation(helpLocation);

		updateFilterFactory();
		updateColumnFilterButton();
		JButton button = columnFilterAction.createButton();
		DockingWindowManager.getHelpService().registerHelp(button, helpLocation);

		return button;
	}

	private void initializeSavedFilters() {
		TableModel model = table.getModel();
		if (!(model instanceof GDynamicColumnTableModel)) {
			return;
		}
		@SuppressWarnings("unchecked")
		GDynamicColumnTableModel<ROW_OBJECT, ?> dynamicModel =
			(GDynamicColumnTableModel<ROW_OBJECT, ?>) model;

		ColumnFilterSaveManager<ROW_OBJECT> saveManager =
			new ColumnFilterSaveManager<>(this, table, dynamicModel, dynamicModel.getDataSource());
		savedFilters = saveManager.getSavedFilters();
		Collections.reverse(savedFilters);
		updateColumnFilterButton();
	}

	private void updateColumnFilterButton() {
		List<ActionState<ColumnBasedTableFilter<ROW_OBJECT>>> list = getActionStates();

		columnFilterAction.setActionStates(list);
	}

	private List<ActionState<ColumnBasedTableFilter<ROW_OBJECT>>> getActionStates() {
		List<ActionState<ColumnBasedTableFilter<ROW_OBJECT>>> list = new ArrayList<>();
		if (columnTableFilter == null) {
			list.add(new CreateFilterActionState());
		}
		else {
			list.add(new EditFilterActionState(columnTableFilter));
			list.add(new ClearFilterActionState());
		}
		if (lastUsedColumnFilter != null) {
			list.add(new ApplyLastUsedActionState(lastUsedColumnFilter));
		}
		for (ColumnBasedTableFilter<ROW_OBJECT> filter : savedFilters) {
			list.add(new ApplyFilterActionState(filter));
		}
		return list;
	}

	private void showFilterDialog(RowObjectFilterModel<ROW_OBJECT> tableModel) {
		if (columnFilterDialog == null) {
			if (ColumnFilterDialog.hasFilterableColumns(table, tableModel)) {
				DockingWindowManager dockingWindowManager = DockingWindowManager.getInstance(table);
				loadFilterPreference(dockingWindowManager);
				columnFilterDialog = new ColumnFilterDialog<>(this, table, tableModel);
			}
			else {
				Msg.showError(this, this, "Column Filter Error",
					"This table contains no filterable columns!");
				return;
			}

		}

		columnFilterDialog.setCloseCallback(() -> {
			doSaveState();
			updateFilterFactory();
			columnFilterDialog = null;
		});

		DockingWindowManager.showDialog(GTableFilterPanel.this, columnFilterDialog);
	}

	private void updateFilterFactory() {
		filterStateButton.setIcon(filterOptions.getFilterStateIcon());
		filterStateButton.setToolTipText(filterOptions.getFilterDescription());
		filterFactory = new DefaultTableTextFilterFactory<>(filterOptions);
	}

	protected RowObjectFilterModel<ROW_OBJECT> installTableModel(
			RowObjectTableModel<ROW_OBJECT> currentModel) {

		ListSelectionModel selectionModel = table.getSelectionModel();
		int selectionMode = selectionModel.getSelectionMode();
		RowObjectFilterModel<ROW_OBJECT> newModel = createTextFilterModel(currentModel);

		// only wrapped models are set on tables, since they have to replace the original
		if (newModel instanceof TableModelWrapper) {
			table.setModel(newModel);

			TableModelWrapper<ROW_OBJECT> wrapper = (TableModelWrapper<ROW_OBJECT>) newModel;
			currentModel.addTableModelListener(new TranslatingTableModelListener(wrapper));
		}

		currentModel.addTableModelListener(new UpdateTableModelListener());

		table.setSelectionMode(selectionMode);
		return newModel;
	}

	// Cast from ThreadedTableModel...
	protected RowObjectFilterModel<ROW_OBJECT> createTextFilterModel(
			RowObjectTableModel<ROW_OBJECT> model) {
		RowObjectFilterModel<ROW_OBJECT> newModel = null;

		// NOTE: order is important here, since RowObjectFilterModel<?> can also be sorted table
		// models.  We want to handle those first!
		if (model instanceof RowObjectFilterModel<?>) {
			newModel = (RowObjectFilterModel<ROW_OBJECT>) model;
		}
		else if (model instanceof SortedTableModel) {
			if (model instanceof AbstractSortedTableModel<?>) {
				AbstractSortedTableModel<ROW_OBJECT> abstractSortedTableModel =
					(AbstractSortedTableModel<ROW_OBJECT>) model;
				newModel = new SortedTableModelWrapper(table, abstractSortedTableModel);
			}
			else {
				Msg.debug(this,
					"You will not get sorting capability while using a " +
						getClass().getSimpleName() +
						".  Your table model should be changed to extend " +
						AbstractSortedTableModel.class.getSimpleName());
			}
		}
		else {
			newModel = new TableModelWrapper<>(model);
		}
		return newModel;
	}

	protected JTable getTable() {
		return table;
	}

	public RowObjectFilterModel<ROW_OBJECT> getTableFilterModel() {
		return textFilterModel;
	}

	/** Convenience method to refilter the table's contents */
	private void updateTableContents() {
		updateManager.updateLater();
		notifyFilterChanged();
	}

	private void notifyFilterChanged() {
		listeners.forEach(callback -> callback.call());
	}

	public void dispose() {
		// Unusual Code Alert: we have to remove this particular listener due to a memory leak.
		// Removing the listener or null-ing out the reference both allow us to be garbage
		// collected.  If we do neither, then we are not collected for some strange reason (even
		// when our column model uses a Weak listener setup).
		TableColumnModel columnModel = table.getColumnModel();
		columnModel.removeColumnModelListener(columnModelListener);
		columnModelListener = null;

		table.removePropertyChangeListener(badProgrammingPropertyChangeListener);

		updateManager.dispose();
		if (table instanceof GTable) {
			((GTable) table).dispose();
		}
	}

	/**
	 * Setting this component will trigger the filter field to flash when the component gains focus.
	 * If you do not want the filter field to flash as focus returns to the client,
	 * then pass in null.
	 *
	 * @param component The component that will trigger the filter field to flash when it gains
	 *        focus.
	 */
	public void setFocusComponent(Component component) {
		filterField.setFocusComponent(component);
	}

	/** Overridden to focus the text field if requestFocus() is called on this panel */
	@Override
	public void requestFocus() {
		filterField.requestFocus();
	}

	/**
	 * Allows the caller to set tooltip text on the filter's search label.  This can be used
	 * to provide an indication as to exactly how the filter text field will filter the table.
	 *
	 * @param text The tooltip text.
	 */
	@Override
	public void setToolTipText(String text) {
		searchLabel.setToolTipText(text);
	}

	/**
	 * Sets the contents of the filter's text field to the given text.
	 * @param text The text to set.
	 */
	public void setFilterText(String text) {
		filterField.setText(text);
	}

	/**
	 * Gets the contents of the filter's text field.
	 * @return The filter text field text.
	 */
	public String getFilterText() {
		return filterField.getText();
	}

	/**
	 * Returns a row number for this panel's underlying table model that is tied to the given
	 * row number that represents a row in a table's display.  For example, if a user clicks a
	 * table row in a filtered table, then this method can be used to return the table's
	 * underlying TableModel row index for that row. <a href="#translation">Click here</a> for more
	 * information.
	 * <p>
	 * <b>Update</b>: The simpler way of getting the selected object is to call the newly
	 * added {@link #getSelectedItem()} method(s), which saves the client from having to get the
	 * index and then lookup the data.  Further, it handles differences in filtering across
	 * different model implementations.
	 * <p>
	 * This method is used as a means for models to translate user actions on a table to the
	 * underlying data model, since table models maintain a complete list of data, some of which
	 * may not be displayed, due to user filtering.
	 * <p>
	 * This is the companion method to {@link #getViewRow(int)}
	 *
	 * @param viewRow The table's row, as seen in the display.
	 * @return the corresponding model row, based upon the table's row.
	 * @see #getSelectedItem()
	 * @see #getSelectedItems()
	 */
	public int getModelRow(int viewRow) {
		if (viewRow < 0) {
			// for convenience, since table models return < 0 when no selection is made, we
			// do the same here.
			return viewRow;
		}

		return textFilterModel.getModelRow(viewRow);
	}

	/**
	 * Returns a row number in the table (the view) for the given table model row number (the
	 * model).  The given value is the <b>unfiltered</b> row value and the returned value is the
	 * <b>filtered</b> value.
	 * <p>
	 * This is the companion method to {@link #getModelRow(int)}
	 *
	 * @param modelRow the row number in the unfiltered model.
	 * @return the row in the table for the given model row.
	 */
	public int getViewRow(int modelRow) {
		return textFilterModel.getViewRow(modelRow);
	}

	/**
	 * Returns the row object for the given view row index.
	 *
	 * @param viewRow the desired row in terms of the UI (e.g., the table's row index)
	 * @return the row object matching the given index
	 */
	public ROW_OBJECT getRowObject(int viewRow) {
		ROW_OBJECT rowObject = textFilterModel.getRowObject(viewRow);
		return rowObject;
	}

	/**
	 * Select the given row object.  No selection will be made if the object is filtered out of
	 * view.
	 *
	 * @param t the row object to select
	 */
	public void setSelectedItem(ROW_OBJECT t) {
		int viewRow = textFilterModel.getViewIndex(t);
		if (viewRow >= 0) {
			table.setRowSelectionInterval(viewRow, viewRow);
			scrollToSelectedRow();
		}
	}

	/**
	 * Scrolls the view to the currently selected item.
	 */
	public void scrollToSelectedRow() {
		int[] selectedRows = table.getSelectedRows();
		if (selectedRows == null || selectedRows.length == 0) {
			return;
		}

		// just make sure that the first row is visible
		int row = selectedRows[0];

		// update the cell rectangle to be the entire row so that if the user is horizontally
		// scrolled, then we do not change that
		Rectangle visibleRect = getVisibleRect();
		Rectangle cellRect = table.getCellRect(row, 0, true);
		cellRect.x = visibleRect.x;
		cellRect.width = visibleRect.width;

		table.scrollRectToVisible(cellRect);
	}

	/**
	 * Returns the currently selected row object or null if there is no table selection.
	 *
	 * @return the currently selected row object or null if there is no table selection.
	 */
	public ROW_OBJECT getSelectedItem() {
		int row = table.getSelectedRow();
		if (row < 0) {
			return null;
		}
		return textFilterModel.getRowObject(row);
	}

	/**
	 * Returns the currently selected row objects or an empty list if there is no selection.
	 *
	 * @return the currently selected row objects or an empty list if there is no selection.
	 */
	public List<ROW_OBJECT> getSelectedItems() {
		int[] rows = table.getSelectedRows();
		if (rows.length == 0) {
			return Collections.emptyList();
		}

		List<ROW_OBJECT> list = new ArrayList<>(rows.length);
		for (int row : rows) {
			list.add(textFilterModel.getRowObject(row));
		}
		return list;
	}

	/**
	 * Returns true if the given row object is currently in the view of the table; false implies
	 * the object has been filtered out of view.
	 *
	 * @param o the row object
	 * @return true if in the view
	 */
	public boolean isInView(ROW_OBJECT o) {
		int rowIndex = textFilterModel.getRowIndex(o);
		return rowIndex >= 0;
	}

	public boolean isFiltered() {
		return getRowCount() != getUnfilteredRowCount();
	}

	public int getRowCount() {
		return textFilterModel.getRowCount();
	}

	public int getUnfilteredRowCount() {
		return textFilterModel.getUnfilteredRowCount();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * Created so that GhidraTable will still 'play nice' with our model wrapper pattern.  The
	 * wrapped model must be an instance of SortedTableModel for various things to work, such as
	 * keystroke lookup and column sorting.
	 */
	private class SortedTableModelWrapper extends TableModelWrapper<ROW_OBJECT>
			implements SortedTableModel {
		private AbstractSortedTableModel<ROW_OBJECT> sortedModel;

		private SortedTableModelWrapper(JTable table,
				AbstractSortedTableModel<ROW_OBJECT> sortedModel) {
			super(sortedModel);
			this.sortedModel = sortedModel;
		}

		@Override
		public int getPrimarySortColumnIndex() {
			return sortedModel.getPrimarySortColumnIndex();
		}

		@Override
		public boolean isSortable(int columnIndex) {
			return sortedModel.isSortable(columnIndex);
		}

		@Override
		public TableSortState getTableSortState() {
			return sortedModel.getTableSortState();
		}

		@Override
		public void setTableSortState(TableSortState tableSortState) {
			sortedModel.setTableSortState(tableSortState);
		}

		@Override
		public void addSortListener(SortListener l) {
			sortedModel.addSortListener(l);
		}
	}

	/**
	 * A listener to translate TableModelEvents from the <b>wrapped</b> model's indices to that
	 *  of the view, which may be filtered.  This listener will make sure the indices are
	 *  correct for the view and then broadcast the event to any listeners that have been added
	 *  (including the Table itself).
	 */
	private class TranslatingTableModelListener implements TableModelListener {

		private TableModelWrapper<ROW_OBJECT> tableModelWrapper;

		TranslatingTableModelListener(TableModelWrapper<ROW_OBJECT> tableModelWrapper) {
			this.tableModelWrapper = tableModelWrapper;
		}

		@Override
		public void tableChanged(TableModelEvent e) {
			//
			// We get all events from the wrapped model and translate them to the outside world
			// so that the indices used in the event are correct for the filtered state of the
			// view.
			//
			tableModelWrapper.fireTableDataChanged(translateEventForFilter(e));
		}

		private TableModelEvent translateEventForFilter(TableModelEvent event) {
			int rowCount = textFilterModel.getUnfilteredRowCount();
			if (rowCount == 0) {
				return event; // nothing to translate--no data
			}

			int firstRow = event.getFirstRow();
			int lastRow = event.getLastRow();

			if (firstRow == 0 && lastRow == Integer.MAX_VALUE) {
				// MAX_VALUE signals all rows (from TableModelEvent)--nothing to translate
				return event;
			}

			if (firstRow == 0 && lastRow == rowCount - 1) {
				firstRow = 0;
				lastRow = Math.max(0, textFilterModel.getRowCount() - 1);
			}
			else {
				// translate to the filtered view (from the wrapped model's full universe)
				firstRow = getViewRow(firstRow);
				lastRow = getViewRow(lastRow);
			}
			return new TableModelEvent(textFilterModel, firstRow, lastRow, event.getColumn(),
				event.getType());
		}
	}

	private class UpdateTableModelListener implements TableModelListener {
		private boolean isUpdatingModel;

		@Override
		public void tableChanged(TableModelEvent e) {
			if (isUpdatingModel) {
				return;
			}

			isUpdatingModel = true;
			if (textFilterModel instanceof TableModelWrapper) {
				TableModelWrapper<ROW_OBJECT> tableModelWrapper =
					(TableModelWrapper<ROW_OBJECT>) textFilterModel;
				tableModelWrapper.wrappedModelChangedFromTableChangedEvent();
			}
			filterField.alert();
			isUpdatingModel = false;
		}
	}

	private class GTableFilterListener implements FilterListener {

		@Override
		public void filterChanged(String text) {
			updateTableContents();
		}
	}

	/**
	 * Generates a key used to store user filter configuration state.  You can override this
	 * method to generate unique keys yourself.  You are required to override this method if
	 * you create multiple versions of a filter panel from the same place in your code, as
	 * multiple instances created in the same place will cause them all to share the same key and
	 * thus to have the same filter settings when they are created initially.
	 * <p>
	 * As an example, consider a plugin that creates <code>n</code> providers.  If each provider uses
	 * a filter panel, then each provider will share the same filter settings when that provider
	 * is created.  If this is not what you want, then you need to override this method to
	 * generate a unique key for each provider.
	 * 
	 * @param jTable the table
	 * @return a key used to store user filter configuration state.
	 */
	public String createUniqueFilterPreferenceKey(JTable jTable) {
		return generateFilterPreferenceKey(jTable, FILTER_EXTENSION);
	}

	/**
	 * Returns the ColumnTableFilter that has been set on this GTableFilterPanel or null if there
	 * is none.
	 *
	 * @return the ColumnTableFilter that has been set.
	 */
	public ColumnBasedTableFilter<ROW_OBJECT> getColumnTableFilter() {
		return columnTableFilter;
	}

	/**
	 * Return a unique key that can be used to store preferences for this table.
	 * @return a unique key that can be used to store preferences for this table.
	 */
	public String getPreferenceKey() {
		return uniquePreferenceKey;
	}

	/**
	 * Updates the "quick filter" multistate button.
	 * @param filter the filter to add or remove.
	 * @param add if true, the filter is added to the quick list. Otherwise, it is removed.
	 */
	public void updateSavedFilters(ColumnBasedTableFilter<ROW_OBJECT> filter, boolean add) {
		if (add) {
			ArrayList<ColumnBasedTableFilter<ROW_OBJECT>> list = new ArrayList<>();
			list.add(filter);
			list.addAll(savedFilters);
			savedFilters = list;
			if (filter.isEquivalent(columnTableFilter)) {
				setColumnTableFilter(filter);
			}
		}
		else {
			savedFilters.remove(filter);
		}

		updateColumnFilterButton();
	}

//==================================================================================================
// Static Methods
//==================================================================================================
	private static String generateFilterPreferenceKey(JTable jTable, String extension) {

		if (jTable instanceof GTable) {
			GTable gTable = (GTable) jTable;
			String preferenceKey = gTable.getPreferenceKey();
			if (preferenceKey != null) {
				return preferenceKey + extension; // use the user-defined key first
			}
		}

		return getInceptionInformationFromTheFirstClassThatIsNotUs();
	}

	private static String getInceptionInformationFromTheFirstClassThatIsNotUs() {

		Throwable throwable = new Throwable();
		StackTraceElement[] stackTrace = throwable.getStackTrace();
		String filterName = "Filter"; // this catches xyzFilterPane and xyzFilterTable
		StackTraceElement[] filteredTrace =
			ReflectionUtilities.filterStackTrace(stackTrace, filterName);
		String clientName = filteredTrace[0].getClassName();
		return clientName;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private abstract class ColumnFilterActionState
			extends ActionState<ColumnBasedTableFilter<ROW_OBJECT>> {

		ColumnFilterActionState(String name, Icon icon, ColumnBasedTableFilter<ROW_OBJECT> filter) {
			super(name, icon, filter);
		}

		abstract void performAction();
	}

	String getFilterName(ColumnBasedTableFilter<ROW_OBJECT> filter) {
		String filterName = filter.getName();
		return filterName == null ? "Unsaved" : filterName;
	}

	private class ClearFilterActionState extends ColumnFilterActionState {
		public ClearFilterActionState() {
			super("Clear Filter", CLEAR_FILTER_ICON, null);
		}

		@Override
		void performAction() {
			setColumnTableFilter(null);
		}
	}

	private class CreateFilterActionState extends ColumnFilterActionState {
		public CreateFilterActionState() {
			super("Create Column Filter", FILTER_OFF_ICON, null);
		}

		@Override
		void performAction() {
			showFilterDialog(textFilterModel);
		}
	}

	private class EditFilterActionState extends ColumnFilterActionState {
		public EditFilterActionState(ColumnBasedTableFilter<ROW_OBJECT> filter) {
			super("Edit: " + getFilterName(filter), FILTER_ON_ICON, filter);
		}

		@Override
		void performAction() {
			showFilterDialog(textFilterModel);
		}
	}

	private class ApplyFilterActionState extends ColumnFilterActionState {
		public ApplyFilterActionState(ColumnBasedTableFilter<ROW_OBJECT> filter) {
			super("Apply: " + getFilterName(filter), APPLY_FILTER_ICON, filter);
		}

		@Override
		void performAction() {
			setColumnTableFilter(getUserData());
		}
	}

	private class ApplyLastUsedActionState extends ColumnFilterActionState {
		public ApplyLastUsedActionState(ColumnBasedTableFilter<ROW_OBJECT> filter) {
			super("Apply Last Unsaved", FILTER_ON_ICON, filter);
		}

		@Override
		void performAction() {
			setColumnTableFilter(getUserData());
		}
	}
}
