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

import java.util.*;
import java.util.stream.Collectors;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.table.TableCellRenderer;

import docking.widgets.table.sort.*;
import ghidra.docking.settings.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import util.CollectionUtils;
import utilities.util.reflection.ReflectionUtilities;

/**
 * An abstract table model for showing DynamicTableColumns where each row is based on an
 * object of type ROW_TYPE.   The client is responsible for implementing
 * {@link #createTableColumnDescriptor()}.  This method specifies which default columns the
 * table should have and whether they should be visible or hidden.  Hidden columns can be
 * made visible through the UI.
 * <p>
 * This model will also discover other system columns that understand how to render
 * <code>ROW_TYPE</code> data directly.  Also, if you create a {@link TableRowMapper mapper}(s) for
 * your row type, then this model will load columns for each type for which a mapper was created,
 * all as optional, hidden columns.
 * <p>
 * The various attributes of the columns of this model (visibility, position, size, etc) are
 * saved to disk as tool preferences when the user exits the tool.
 * <p>
 * Implementation Note: this model loads all columns, specific and discovered, as being visible.
 *                      Then, during initialization, the {@link TableColumnModelState} class will
 *                      either hide all non-default columns, or reload the column state if any
 *                      previous saved state is found.
 *
 * @param <ROW_TYPE> the row object class for this table model.
 * @param <DATA_SOURCE> the type of data that will be returned from {@link #getDataSource()}.  This
 *                    object will be given to the {@link DynamicTableColumn} objects used by this
 *                    table model when
 *                    {@link DynamicTableColumn#getValue(Object, ghidra.docking.settings.Settings, Object, ServiceProvider)}
 *                    is called.
 */
public abstract class GDynamicColumnTableModel<ROW_TYPE, DATA_SOURCE>
		extends AbstractSortedTableModel<ROW_TYPE>
		implements ChangeListener, VariableColumnTableModel, DynamicColumnTableModel<ROW_TYPE> {

	protected ServiceProvider serviceProvider;

	private TableColumnDescriptor<ROW_TYPE> columnDescriptor;
	protected List<DynamicTableColumn<ROW_TYPE, ?, ?>> tableColumns = new ArrayList<>();
	private List<DynamicTableColumn<ROW_TYPE, ?, ?>> defaultTableColumns = new ArrayList<>();
	protected Map<DynamicTableColumn<ROW_TYPE, ?, ?>, Settings> columnSettings = new HashMap<>();

	private boolean ignoreSettingChanges = false;

	public GDynamicColumnTableModel(ServiceProvider serviceProvider) {

		SystemUtilities.assertTrue((serviceProvider != null), "ServiceProvider cannot be null");

		this.serviceProvider = serviceProvider;

		reloadColumns();
	}

	protected abstract TableColumnDescriptor<ROW_TYPE> createTableColumnDescriptor();

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	// compile-time guarantee it is the correct type
	protected void loadDiscoveredTableColumns() {

		Class<? extends GDynamicColumnTableModel> implementationClass = getClass();
		List<Class<?>> templateClasses = ReflectionUtilities.getTypeArguments(
			GDynamicColumnTableModel.class, implementationClass);
		Class<ROW_TYPE> runtimeRowObject = (Class<ROW_TYPE>) templateClasses.get(0);

		Collection<DynamicTableColumn<ROW_TYPE, ?, ?>> columns =
			DiscoverableTableUtils.getDynamicTableColumns(runtimeRowObject);
		for (DynamicTableColumn<ROW_TYPE, ?, ?> column : columns) {
			if (!tableColumns.contains(column)) {
				tableColumns.add(column);
			}
		}
	}

	private void loadDefaultTableColumns() {
		TableColumnDescriptor<ROW_TYPE> descriptor = getTableColumnDescriptor();
		List<DynamicTableColumn<ROW_TYPE, ?, ?>> defaultColumns =
			descriptor.getDefaultVisibleColumns();

		defaultTableColumns.addAll(defaultColumns);

		List<DynamicTableColumn<ROW_TYPE, ?, ?>> allColumns = descriptor.getAllColumns();
		tableColumns.addAll(allColumns);

		TableSortState sortState = descriptor.getDefaultTableSortState(this);
		if (sortState.getSortedColumnCount() == 0) {
			sortState = TableSortState.createDefaultSortState(0);
		}
		setDefaultTableSortState(sortState);
	}

	/**
	 * Allows clients to defer column creation until after this parent class's constructor has
	 * been called.   This method will not restore any column settings that have been changed
	 * after construction.  Thus, this method is intended only to be called during the 
	 * construction process.
	 */
	protected void reloadColumns() {

		// note: since we should only be called during construction, there is no need to
		//       fire an event to signal the table structure has changed

		columnDescriptor = null;
		tableColumns.clear();
		defaultTableColumns.clear();
		loadDefaultTableColumns();
		loadDiscoveredTableColumns();

		columnSettings.clear();
		for (DynamicTableColumn<ROW_TYPE, ?, ?> column : tableColumns) {
			columnSettings.put(column, new SettingsImpl(this, column));
		}
	}

	private TableColumnDescriptor<ROW_TYPE> getTableColumnDescriptor() {
		if (columnDescriptor == null) {
			columnDescriptor = createTableColumnDescriptor();
		}
		return columnDescriptor;
	}

	private DynamicTableColumn<ROW_TYPE, ?, ?> getColumnForDefaultColumnIdentifier(Class<?> clazz) {

		// note: we may have multiple columns with the same class.  It is not the normal case, 
		//       but it can happen for re-usable column classes.

		//@formatter:off
		List<DynamicTableColumn<ROW_TYPE, ?, ?>> matching =
			tableColumns.stream()
						.filter(c -> isColumnClassMatch(c, clazz))
						.collect(Collectors.toList())
						;
		//@formatter:on

		if (matching.size() > 1) {
			Msg.warn(this, "More than one column found matching class '" + clazz + "'");
		}

		return CollectionUtils.any(matching);
	}

	private boolean isColumnClassMatch(DynamicTableColumn<ROW_TYPE, ?, ?> column, Class<?> clazz) {

		if (clazz.equals(column.getClass())) {
			return true;
		}

		if (column instanceof MappedTableColumn) {
			MappedTableColumn<?, ?, ?, ?> mappedColumn = (MappedTableColumn<?, ?, ?, ?>) column;
			Class<?> columnClass = mappedColumn.getMappedColumnClass();
			if (clazz.equals(columnClass)) {
				return true;
			}
		}

		return false;
	}

	@Override
	protected Comparator<ROW_TYPE> createSortComparator(int columnIndex) {
		Comparator<Object> columnComparator = createSortComparatorForColumn(columnIndex);
		if (columnComparator != null) {
			// the given column has its own comparator; wrap and us that
			return new RowBasedColumnComparator<>(this, columnIndex, columnComparator);
		}

		return new RowBasedColumnComparator<>(this, columnIndex, new DefaultColumnComparator(),
			new ColumnRenderedValueBackupComparator<>(this, columnIndex));
	}

	/**
	 * This differs from {@link #createSortComparator(int)} in that the other method
	 * creates a comparator that operates on a full row value, whereas this method operates on
	 * column values.
	 *
	 * @param columnIndex the column index
	 * @return a comparator for the specific column values
	 */
	@SuppressWarnings("unchecked") // the column provides the values itself; safe cast
	protected Comparator<Object> createSortComparatorForColumn(int columnIndex) {
		DynamicTableColumn<ROW_TYPE, ?, ?> column = getColumn(columnIndex);
		Comparator<Object> comparator = (Comparator<Object>) column.getComparator();
		return comparator;
	}

	/**
	 * Callback when column settings have changed
	 */
	@Override
	public void stateChanged(ChangeEvent e) {
		if (ignoreSettingChanges) {
			return;
		}

		if (resortIfNeeded(e)) {
			return;
		}

		fireTableDataChanged();
	}

	private boolean resortIfNeeded(ChangeEvent e) {
		if (e == null) {
			return false;
		}

		Object source = e.getSource();
		TableSortState tableSortState = getTableSortState();
		Iterator<ColumnSortState> iterator = tableSortState.iterator();
		for (; iterator.hasNext();) {
			ColumnSortState columnSortState = iterator.next();
			int columnIndex = columnSortState.getColumnModelIndex();
			DynamicTableColumn<?, ?, ?> column = tableColumns.get(columnIndex);
			if (column == source) {
				reSort();
				return true;
			}
		}
		return false;
	}

	/**
	 * Adds the given column at the end of the list of columns.  This method is intended for
	 * implementations to add custom column objects, rather than relying on generic, discovered
	 * DynamicTableColumn implementations.
	 * 
	 * <p><b>Note: this method assumes that the columns have already been sorted</b>
	 * @param column The field to add
	 */
	protected void addTableColumn(DynamicTableColumn<ROW_TYPE, ?, ?> column) {
		addTableColumns(CollectionUtils.asSet(column));
	}

	/**
	 * Adds the given columns to the end of the list of columns.  This method is intended for
	 * implementations to add custom column objects, rather than relying on generic, discovered
	 * DynamicTableColumn implementations.
	 * 
	 * <p><b>Note: this method assumes that the columns have already been sorted.</b>
	 * 
	 * @param columns The columns to add
	 */
	protected void addTableColumns(Set<DynamicTableColumn<ROW_TYPE, ?, ?>> columns) {
		for (DynamicTableColumn<ROW_TYPE, ?, ?> column : columns) {
			doAddTableColumn(column, getDefaultTableColumns().size(), true);
		}
		fireTableStructureChanged();
	}

	/**
	 * Adds the given field at the given index to the list of fields in this class.
	 * This method is intended for implementations to add custom column objects, rather than
	 * relying on generic, discovered DynamicTableColumn implementations.
	 * <p>
	 * <b>Note: this method assumes that the columns have already been sorted.</b>
	 * @param column The field to add.
	 * @param index The index at which to add the field.  If the index value is invalid (negative
	 *        or greater than the number of columns), then the column will be added to the
	 *        end of the columns list.
	 * @param isDefault true if this is a default column
	 */
	protected void addTableColumn(DynamicTableColumn<ROW_TYPE, ?, ?> column, int index,
			boolean isDefault) {

		doAddTableColumn(column, index, isDefault);
		fireTableStructureChanged();
	}

	// Note: performs the work of adding the table column, but does NOT fire a changed event
	private void doAddTableColumn(DynamicTableColumn<ROW_TYPE, ?, ?> column, int index,
			boolean isDefault) {

		if (index < 0 || index > tableColumns.size()) {
			index = getDefaultTableColumns().size();
		}

		tableColumns.add(index, column);
		columnSettings.put(column, new SettingsImpl(this, column));
		if (isDefault) {
			List<DynamicTableColumn<ROW_TYPE, ?, ?>> defaultColumns = getDefaultTableColumns();
			defaultColumns.add(index, column);
		}
	}

	/**
	 * Removes the given column from this model
	 *
	 * @param column the column to remove
	 */
	protected void removeTableColumn(DynamicTableColumn<ROW_TYPE, ?, ?> column) {
		removeTableColumns(CollectionUtils.asSet(column));
	}

	/**
	 * Removes the given columns from this model.  This method allows the client to remove
	 * multiple columns at once, firing only one event when the work is finished.
	 *
	 * @param columns the columns to remove
	 */
	protected void removeTableColumns(Set<DynamicTableColumn<ROW_TYPE, ?, ?>> columns) {

		for (DynamicTableColumn<ROW_TYPE, ?, ?> column : columns) {
			List<DynamicTableColumn<ROW_TYPE, ?, ?>> defaultColumns = getDefaultTableColumns();
			defaultColumns.remove(column);
			tableColumns.remove(column);
			columnSettings.remove(column);
		}
		fireTableStructureChanged();
	}

	@Override
	public int getDefaultColumnCount() {
		return getDefaultTableColumns().size();
	}

	private List<DynamicTableColumn<ROW_TYPE, ?, ?>> getDefaultTableColumns() {
		return defaultTableColumns;
	}

	@Override
	public boolean isVisibleByDefault(int modelIndex) {
		if (modelIndex < 0 || modelIndex >= tableColumns.size()) {
			return false;
		}

		DynamicTableColumn<?, ?, ?> column = tableColumns.get(modelIndex);
		List<DynamicTableColumn<ROW_TYPE, ?, ?>> defaultColumns = getDefaultTableColumns();
		return defaultColumns.contains(column);
	}

	/**
	 * Returns true if the column indicated by the index in the model is a default column (meaning
	 * that it was specified by the model and not discovered).
	 * @param modelIndex the index of the column in the model.
	 * @return true if the column is a default.
	 */
	@Override
	public boolean isDefaultColumn(int modelIndex) {
		if (modelIndex < 0 || modelIndex >= tableColumns.size()) {
			return false;
		}

		DynamicTableColumn<?, ?, ?> column = tableColumns.get(modelIndex);

		// check the 'defaultColumns' first, as they may have been updated after initialization
		List<DynamicTableColumn<ROW_TYPE, ?, ?>> defaultColumns = getDefaultTableColumns();
		if (defaultColumns.contains(column)) {
			return true;
		}

		// now check the default values of the descriptor
		TableColumnDescriptor<ROW_TYPE> descriptor = getTableColumnDescriptor();
		List<DynamicTableColumn<ROW_TYPE, ?, ?>> modelSpecifiedColumns = descriptor.getAllColumns();
		return modelSpecifiedColumns.contains(column);
	}

	@Override
	public final int getColumnCount() {
		return tableColumns.size();
	}

	@Override
	public final Class<?> getColumnClass(int column) {
		if (column < 0 || column >= tableColumns.size()) {
			// hacky: this can happen when we are in the process of rebuilding our column structure,
			//        where the client calling us has an old index value (such as when we are
			//        adding/removing columns).
			return null;
		}
		return tableColumns.get(column).getColumnClass();
	}

	@Override
	public final String getColumnName(int column) {
		return tableColumns.get(column).getColumnName();
	}

	@Override
	public int getPreferredColumnWidth(int column) {
		if (column < 0 || column >= tableColumns.size()) {

			// hacky: this can happen when we are in the process of rebuilding our column structure,
			//        where the client calling us has an old index value (such as when we are
			//        adding/removing columns).
			return -1; // default
		}
		return tableColumns.get(column).getColumnPreferredWidth();
	}

	@Override
	public String getColumnDisplayName(int columnIndex) {
		DynamicTableColumn<ROW_TYPE, ?, ?> column = tableColumns.get(columnIndex);
		return column.getColumnDisplayName(columnSettings.get(column));
	}

	@Override
	public String getColumnDescription(int column) {
		return tableColumns.get(column).getColumnDescription();
	}

	@Override
	public String getUniqueIdentifier(int column) {
		return tableColumns.get(column).getUniqueIdentifier();
	}

	@Override
	public final Object getColumnValueForRow(ROW_TYPE t, int columnIndex) {
		if (columnIndex < 0 || columnIndex >= tableColumns.size()) {
			return null;
		}

		DATA_SOURCE dataSource = getDataSource();

		@SuppressWarnings("unchecked")
		// TODO: We are casting now, as in practice the type should never be different that
		//       the declared type.  We want to remove entirely the 'dataSource' value and then
		//       the templating will be simpler.
		DynamicTableColumn<ROW_TYPE, ?, DATA_SOURCE> column =
			(DynamicTableColumn<ROW_TYPE, ?, DATA_SOURCE>) tableColumns.get(columnIndex);

		if (t == null) {
			// sometimes happen if we are painting while being disposed
			return null;
		}

		return column.getValue(t, columnSettings.get(column), dataSource, serviceProvider);
	}

	/**
	 * Returns the table's context for the data.
	 * @return  the table's context for the data.
	 */
	public abstract DATA_SOURCE getDataSource();

	/**
	 * Returns the column index of the given column class
	 * 
	 * @param columnClass the class for the type of DynamicTableColumn you want to find.
	 * @return the column index for the specified DynamicTableColumn. -1 if not found.
	 */
	public int getColumnIndex(Class<?> columnClass) {
		DynamicTableColumn<ROW_TYPE, ?, ?> column =
			getColumnForDefaultColumnIdentifier(columnClass);
		return tableColumns.indexOf(column);
	}

	@Override
	public int getColumnIndex(DynamicTableColumn<ROW_TYPE, ?, ?> identifier) {
		int count = tableColumns.size();
		for (int listIndex = 0; listIndex < count; listIndex++) {
			DynamicTableColumn<?, ?, ?> tableField = tableColumns.get(listIndex);
			if (tableField.equals(identifier)) {
				return listIndex;
			}
		}
		return -1;
	}

	@Override
	public DynamicTableColumn<ROW_TYPE, ?, ?> getColumn(int index) {
		return tableColumns.get(index);
	}

	@Override
	public SettingsDefinition[] getColumnSettingsDefinitions(int index) {
		return tableColumns.get(index).getSettingsDefinitions();
	}

	@Override
	public Settings getColumnSettings(int index) {
		DynamicTableColumn<ROW_TYPE, ?, ?> column = tableColumns.get(index);
		return columnSettings.get(column);
	}

	private void applySettings(int index, Settings newSettings) {
		DynamicTableColumn<ROW_TYPE, ?, ?> column = tableColumns.get(index);
		Settings settings = columnSettings.get(column);
		settings.clearAllSettings();
		for (String name : newSettings.getNames()) {
			settings.setValue(name, newSettings.getValue(name));
		}
	}

	@Override
	public synchronized void setAllColumnSettings(Settings[] newSettings) {
		ignoreSettingChanges = true;
		for (int modelIndex = 0; modelIndex < newSettings.length; modelIndex++) {
			applySettings(modelIndex, newSettings[modelIndex]);
		}
		ignoreSettingChanges = false;
		stateChanged(new ChangeEvent(this));
	}

	/**
	 * Gets the special table cell renderer for the specified table field column.
	 * A null value indicates that this field uses a default cell renderer.
	 *
	 * @param index the model column index
	 * @return a table cell renderer for this field. Otherwise, null if a default
	 *         renderer should be used.
	 */
	@Override
	public TableCellRenderer getRenderer(int index) {
		return tableColumns.get(index).getColumnRenderer();
	}

	/**
	 * Gets the maximum number of text display lines needed for any given cell within the
	 * specified column.
	 * @param index column field index
	 * @return maximum number of lines needed for specified column
	 */
	@Override
	public int getMaxLines(int index) {
		if (index < 0 || index >= tableColumns.size()) {

			// hacky: this can happen when we are in the process of rebuilding our column structure,
			//        where the client calling us has an old index value (such as when we are
			//        adding/removing columns).
			return 1; // default
		}

		DynamicTableColumn<ROW_TYPE, ?, ?> column = tableColumns.get(index);
		return column.getMaxLines(columnSettings.get(column));
	}

	@Override
	public void dispose() {
		super.dispose();
		disposeDynamicColumnData();
	}

	protected void disposeDynamicColumnData() {
		tableColumns.clear();
		defaultTableColumns.clear();
		columnSettings.clear();
	}
}
