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

import java.util.ArrayList;
import java.util.List;

import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;

import org.jdom.*;

import docking.DockingWindowManager;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsImpl;
import ghidra.framework.options.PreferenceState;
import ghidra.util.SystemUtilities;
import ghidra.util.task.SwingUpdateManager;

/**
 * A class to keep track of and persist state for column models, including size, ordering and
 * visibility.
 * <p>
 * This class performs a bit of magic to accomplish its goals.  Resultingly, some of the code
 * herein may seem a bit odd or of poor quality.  These rough spots are documented as best as
 * possible.
 * <p>
 * The basic outline of how this class works:<br>
 * 
 * This class loads and save table column state via requests made by clients like the {@link GTable} or
 * the {@link GTableColumnModel}.  These requests are in response to direct users actions (like
 * showing a new column) or to table changes (like column resizing).  There are few things that 
 * make this code tricky.  Namely, when a change notification comes from the subsystem and not 
 * direct user intervention, we do not know if the change was motived by the user directly or 
 * by programmatic table configuration.  We would prefer to only save data when the user makes 
 * changes, but we can not always know the source of the change.  For example, column resizing
 * can happen due to user dragging or due to the table subsystem performing a column layout.
 * <p>
 * To facilitate this magic, we listen to all changes, attempting to: 1) ignore those that we know
 * are not from the user, and 2) buffer the changes so that they are not excessive and so they
 * happen in the correct order.
 * <p>
 * For 1, we ignore all changes until the table has been shown for the first time.  For 2, we use
 * SwingUpdate managers.
 * <p>
 * The complicated part is that we allow clients to add columns at any time.  If they do so 
 * after the table has been made visible, then we cannot ignore the event like we do when the
 * table has not yet been realized.  In our world view, the uniqueness of a table is based upon
 * it's class and its columns.  Thus, when a column is added or removed, it becomes a different
 * table and thus, saved settings must be applied.
 */
public class TableColumnModelState implements SortListener {

	/**
	 * A width that is large enough to consume the extra space when columns are getting
	 * resized.  This value is meant to be used when a column does not specify it's
	 * preferred width.
	 */
	private static final int LARGE_DEFAULT_COL_WIDTH = 500;

	/** Longer than the restore delay so that saving does not affect the pending restore */
	private static final int SAVE_DELAY = 1000;

	private static final String XML_COLUMN_VISIBLE = "VISIBLE";
	private static final String XML_COLUMN_WIDTH = "WIDTH";
	private static final String XML_COLUMN_NAME = "NAME";
	private static final String XML_SETTING_NAME = "NAME";
	private static final String XML_SETTING_VALUE = "VALUE";
	private static final String XML_SETTING_TYPE = "TYPE";

	private static final String XML_COLUMN = "COLUMN";
	private static final String XML_COLUMN_DATA = "COLUMN_DATA";
	private static final String XML_COLUMN_SETTING = "COLUMN_SETTING";

	private final GTableColumnModel columnModel;
	private final GTable table;
	private final SwingUpdateManager saveUpdateManager;
	private final SwingUpdateManager restoreUpdateManager;

	private boolean restoring = false;
	private boolean enabled = false;
	private TableSortState lastSortState;

	TableColumnModelState(final GTable table, GTableColumnModel columnModel) {
		this.table = table;
		this.columnModel = columnModel;
		saveUpdateManager = new SwingUpdateManager(SAVE_DELAY, () -> doSaveState());

		restoreUpdateManager = new SwingUpdateManager(250, () -> doRestoreState());

		installListeners();

		// We want to load our state after the column model is loaded.  We are using this
		// listener to know when the table has been added to the component hierarchy, as its
		// model has been loaded by then.
		DockingWindowManager.registerComponentLoadedListener(table, (windowManager, provider) -> {
			if (!enabled) {
				setEnabled(true);
				restoreState();
			}
		});
	}

	private void installListeners() {
		table.addPropertyChangeListener("model", evt -> installSortListener());

		installSortListener(); // this will do nothing if the table does not have a model
	}

	private void installSortListener() {
		TableModel model = table.getModel();
		if (model instanceof SortedTableModel) {
			SortedTableModel sortedModel = (SortedTableModel) model;
			sortedModel.addSortListener(this);
		}
	}

	@Override
	public void modelSorted(TableSortState sortState) {

		if (sortState.equals(lastSortState)) {
			return; // nothing to save
		}

		lastSortState = sortState;
		saveState();
	}

	// Note: calling this method repeatedly is OK *if done from the Swing thread*.   The
	//       JTable triggers the call when rebuilding, which removes and adds all columns,
	//       which sounds like it would clear the state, but since we are in the Swing
	//       thread, the save can't happen until the table is done.
	void saveState() {
		if (!restoring && enabled) {
			saveUpdateManager.updateLater();
		}
	}

	private void doSaveState() {
		if (restoreUpdateManager.isBusy()) {

			// do not save while there is a pending restore operation, as we want to save the
			// state of the table after being restored, which will be the most current state
			saveUpdateManager.updateLater();
			return;
		}

		doSaveState(saveToXML());
	}

	private void doSaveState(Element xmlElement) {
		PreferenceState preferenceState = new PreferenceState();
		preferenceState.putXmlElement(XML_COLUMN_DATA, xmlElement);

		DockingWindowManager dockingWindowManager = DockingWindowManager.getInstance(table);
		if (dockingWindowManager == null) {
			// I don' think this can happen now, as we ignore save requests when not 'enabled'
			return;
		}

		String preferenceKey = getPreferenceKey();
		dockingWindowManager.putPreferenceState(preferenceKey, preferenceState);
	}

	Element saveToXML() {
		Element xmlElement = new Element("Table_State");

		// String debug = XmlUtilities.toString(xmlElement);

		List<TableColumn> columnList = columnModel.getAllColumns();
		for (TableColumn column : columnList) {
			Element columnElement = new Element(XML_COLUMN);
			columnElement.setAttribute(XML_COLUMN_NAME, getColumnName(column));
			columnElement.setAttribute(XML_COLUMN_WIDTH, Integer.toString(column.getWidth()));
			columnElement.setAttribute(XML_COLUMN_VISIBLE,
				Boolean.toString(columnModel.isVisible(column)));
			saveColumnSettings(columnElement, column);
			xmlElement.addContent(columnElement);
		}
		saveSortedColumnState(xmlElement);
		return xmlElement;
	}

	/**
	 * Gets the most unique identifier possible for a given column.
	 */
	private String getColumnName(TableColumn column) {
		TableModel tableModel = table.getUnwrappedTableModel();
		if (tableModel instanceof VariableColumnTableModel) {
			VariableColumnTableModel variableTableModel = (VariableColumnTableModel) tableModel;
			return variableTableModel.getUniqueIdentifier(column.getModelIndex());
		}
		return column.getHeaderValue().toString();
	}

	private void saveSortedColumnState(Element xmlElement) {
		TableModel tableModel = table.getModel();
		if (!(tableModel instanceof SortedTableModel)) {
			return; // nothing to save
		}

		SortedTableModel sortedTableModel = (SortedTableModel) tableModel;
		TableSortState tableSortState = sortedTableModel.getTableSortState();
		Element sortStateElement = tableSortState.writeToXML();
		xmlElement.addContent(sortStateElement);
	}

	private void saveColumnSettings(Element columnElement, TableColumn column) {
		TableModel tableModel = table.getUnwrappedTableModel();
		if (!(tableModel instanceof ConfigurableColumnTableModel)) {
			return;
		}

		ConfigurableColumnTableModel configurableTableModel =
			(ConfigurableColumnTableModel) tableModel;
		Settings settings = configurableTableModel.getColumnSettings(column.getModelIndex());
		if (settings == null) {
			return;
		}

		for (String name : settings.getNames()) {
			Object value = settings.getValue(name);
			if (value instanceof String) {
				addSettingElement(columnElement, name, "String", (String) value);
			}
			else if (value instanceof Long) {
				addSettingElement(columnElement, name, "Long", value.toString());
			}
			// else if (value instanceof byte[]) // we don't handle this case; OBE?
		}
	}

	private void addSettingElement(Element columnElement, String name, String type, String value) {
		Element settingsElement = new Element(XML_COLUMN_SETTING);
		settingsElement.setAttribute(XML_SETTING_NAME, name);
		settingsElement.setAttribute(XML_SETTING_TYPE, type);
		settingsElement.setAttribute(XML_SETTING_VALUE, value);
		columnElement.addContent(settingsElement);
	}

	private Settings getColumnSettings(Element columnElement) throws DataConversionException {
		Settings settings = new SettingsImpl();
		for (Object obj : columnElement.getChildren(XML_COLUMN_SETTING)) {
			Element element = (Element) obj;
			parseSetting(element, settings);
		}
		return settings;
	}

	private void parseSetting(Element settingElement, Settings settings)
			throws DataConversionException {
		String name = settingElement.getAttributeValue(XML_SETTING_NAME);
		String type = settingElement.getAttributeValue(XML_SETTING_TYPE);
		String valueStr = settingElement.getAttributeValue(XML_SETTING_VALUE);
		if (name == null || type == null || valueStr == null) {
			throw new IllegalStateException(
				"Unexpected data format reading saved TableColumn state.");
		}
		if ("Long".equals(type)) {
			long value = settingElement.getAttribute(XML_SETTING_VALUE).getLongValue();
			settings.setLong(name, value);
		}
		else if ("String".equals(type)) {
			settings.setString(name, valueStr);
		}
		else {
			throw new IllegalStateException(
				"Unexpected data format reading saved TableColumn state.");
		}
	}

	void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	boolean isEnabled() {
		return enabled;
	}

	void restoreState() {
		if (!enabled) {
			return;
		}

		restoreUpdateManager.update();
	}

	void restoreStateNow() {
		restoreUpdateManager.updateNow();
	}

	private void doRestoreState() {

		restoring = true;

		try {
			DockingWindowManager dockingWindowManager = DockingWindowManager.getInstance(table);
			if (dockingWindowManager == null) {
				setDefaultColumnsVisible();
				return;
			}

			String key = getPreferenceKey();
			PreferenceState preferenceState = dockingWindowManager.getPreferenceState(key);
			if (preferenceState == null) {
				// If we don't have the column save state for an object based model, then set
				// the columns that are shown by default and their order.
				setDefaultColumnsVisible();
				return;
			}

			Element xmlElement = preferenceState.getXmlElement(XML_COLUMN_DATA);
			restoreFromXML(xmlElement);
		}
		finally {
			restoring = false;
		}
	}

	void restoreFromXML(Element xmlElement) {

		try {
			List<?> children = xmlElement.getChildren(XML_COLUMN);
			List<TableColumn> oldCompleteList = columnModel.getAllColumns();

			if (children.size() != oldCompleteList.size()) {
				// this implies that the available set of columns has changed
				setDefaultColumnsVisible();
				return;
			}

			List<TableColumn> visibleList = new ArrayList<>();
			List<TableColumn> completeList = new ArrayList<>();
			List<Settings> settingsList = new ArrayList<>();

			for (Object object : children) {
				Element element = (Element) object;
				String columnName = element.getAttributeValue(XML_COLUMN_NAME);
				TableColumn column = getColumn(columnName, oldCompleteList);
				if (column == null) {
					setDefaultColumnsVisible();
					return; // dynamic columns can be removed or somehow unavailable
				}

				Attribute widthAttribute = element.getAttribute(XML_COLUMN_WIDTH);
				int width = widthAttribute.getIntValue();

				Attribute visibleAttribute = element.getAttribute(XML_COLUMN_VISIBLE);
				boolean visible = visibleAttribute.getBooleanValue();

				Settings columnSettings = getColumnSettings(element);
				completeList.add(column);

				column.setWidth(width);
				column.setPreferredWidth(width);
				if (visible) {
					SystemUtilities.assertTrue(!visibleList.contains(column),
						"Duplicate columns being added to the visible columns of table: " +
							getTableModelName() + " - column: " + column.getHeaderValue());
					visibleList.add(column);
				}

				settingsList.add(columnSettings);
			}

			columnModel.restoreState(completeList, settingsList, visibleList);

			restoreColumnSortState(xmlElement);

			doSaveState(xmlElement);
		}
		catch (DataConversionException dce) {
			throw new IllegalStateException(
				"Unexpected data format reading saved TableColumn state.");
		}
	}

	private void restoreColumnSortState(Element xmlElement) {
		final TableSortState sortState = TableSortState.restoreFromXML(xmlElement);
		if (sortState == null) {
			return;
		}

		TableModel model = table.getModel();
		if (!(model instanceof SortedTableModel)) {
			// this implies a model has been changed and the preferences are for the old model
			return;
		}

		SortedTableModel sortedModel = (SortedTableModel) model;
		if (!isValidSortState(sortState, sortedModel)) {
			return; // no longer valid--don't restore
		}
		sortedModel.setTableSortState(sortState);
	}

	private boolean isValidSortState(TableSortState tableSortState, SortedTableModel model) {
		int columnCount = model.getColumnCount();
		int sortedColumnCount = tableSortState.getSortedColumnCount();
		if (sortedColumnCount > columnCount) {
			return false; // more columns than we have
		}

		for (int i = 0; i < columnCount; i++) {
			ColumnSortState state = tableSortState.getColumnSortState(i);
			if (state == null) {
				continue; // no sort state for this column--nothing to validate
			}

			if (!model.isSortable(i)) {
				return false; // the state wants to sort on an unsortable column
			}
		}

		return true;
	}

	/**
	 * This method will return a string key that uniquely describes a table model and its
	 * *default* columns (those initially added by the model) so that settings for column state
	 * can be persisted and retrieved.
	 */
	private String getPreferenceKey() {
		String preferenceKey = table.getPreferenceKey();
		if (preferenceKey != null) {
			return preferenceKey;
		}
		TableModel tableModel = table.getModel();

		int columnCount = getDefaultColumnCount();
		StringBuffer buffer = new StringBuffer();
		buffer.append(getTableModelName());
		buffer.append(":");
		for (int i = 0; i < columnCount; i++) {
			String columnName = tableModel.getColumnName(i);
			buffer.append(columnName).append(":");
		}
		return buffer.toString();
	}

	private int getDefaultColumnCount() {

		TableModel tableModel = table.getUnwrappedTableModel();
		if (tableModel instanceof VariableColumnTableModel) {
			VariableColumnTableModel variableTableModel = (VariableColumnTableModel) tableModel;
			// VariableColumnTableModels have default columns and 'found' columns.  We only want to
			// create a key based upon the default columns
			return variableTableModel.getDefaultColumnCount();
		}
		return tableModel.getColumnCount();
	}

	private void setDefaultColumnsVisible() {

		TableModel tableModel = table.getUnwrappedTableModel();

		// Assumption: normal table models already have their table columns visible
		List<TableColumn> columnList = columnModel.getAllColumns();
		if (tableModel instanceof VariableColumnTableModel) {
			VariableColumnTableModel variableModel = (VariableColumnTableModel) tableModel;
			int numVisible = 0;
			for (TableColumn column : columnList) {
				int modelIndex = column.getModelIndex();
				boolean isVisible = variableModel.isVisibleByDefault(modelIndex);
				columnModel.setVisible(column, isVisible);
				if (isVisible) {
					numVisible++;
				}
			}

			if (numVisible == 0) { // Make sure at least one column is visible.
				columnModel.setVisible(columnList.get(0), true);
			}
		}

		setDefaultPreferredColumnSizes();
	}

	/**
	 * Configure the columns in this model with their preferred size.
	 */
	private void setDefaultPreferredColumnSizes() {

		//
		// 					Unusual Code Alert!
		// The table model wants to resize the columns such that they all get an equal share
		// of any available width upon initialization.  This defeats the preferred size of
		// a column if it is specified (which it is usually not).  To override this badness,
		// we will set all preferred sizes AND then for all columns without a preferred size,
		// specify a large value, which causes Java's layout algorithm to have less remaining
		// width to divided amongst all the table columns.  Essentially, we need to make the
		// total width of all columns larger than the table size.  We do this by giving large
		// default width values.
		//
		// FYI, Java's badness happens inside of JTable.doLayout().
		//
		// To easily specify a preferred size for a column, do so in your DynamicTableColumn's
		// getColumnPreferredWidth() method.   If your model is not dynamic, then you have
		// to specify the preferred size manually after you construct your table by grabbing
		// its ColumnModel.
		//

		TableModel model = table.getUnwrappedTableModel();
		if (!(model instanceof AbstractGTableModel<?>)) {
			return;
		}

		AbstractGTableModel<?> gModel = (AbstractGTableModel<?>) model;
		List<TableColumn> columnList = columnModel.getAllColumns();
		for (TableColumn col : columnList) {
			int defaultPreferred = col.getPreferredWidth();
			if (defaultPreferred > 0 && defaultPreferred != 75) {
				// honor any saved preferred size (ignoring the magic default value found
				// inside of TableColumn)
				col.setWidth(defaultPreferred);
				continue;
			}

			int preferred = gModel.getPreferredColumnWidth(col.getModelIndex());
			if (preferred < 15) {
				preferred = LARGE_DEFAULT_COL_WIDTH;
			}
			int size = preferred;
			col.setWidth(size);
			col.setPreferredWidth(size);
		}
	}

	private String getTableModelName() {
		TableModel tableModel = table.getUnwrappedTableModel();
		return tableModel.getClass().getName();
	}

	private TableColumn getColumn(String columnName, List<TableColumn> columnList) {
		for (TableColumn column : columnList) {
			String existingName = getColumnName(column);
			if (columnName.equals(existingName)) {
				return column;
			}
		}
		return null; // possibly removed dynamically discovered column
	}

	void dispose() {
		saveUpdateManager.dispose();
		restoreUpdateManager.dispose();
	}
}
