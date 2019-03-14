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
package docking.widgets.table.columnfilter;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JTable;

import org.jdom.Element;

import docking.DockingWindowManager;
import docking.widgets.table.GTableFilterPanel;
import docking.widgets.table.RowObjectTableModel;
import ghidra.framework.options.PreferenceState;
import ghidra.framework.options.SaveState;
import ghidra.util.Msg;

/**
 * Loads and Save a list of ColumnTableFilters for a specific table to the tool
 *
 * @param <R> the row type of the table.
 */
public class ColumnFilterSaveManager<R> {
	private static final String COLUMN_FILTER_EXTENSION = ".ColumnFilterExtension";
	private static final String COLUMN_FILTER_STATE = "COLUMN_FILTER_STATE";

	private List<ColumnBasedTableFilter<R>> filters = new ArrayList<>();
	private String preferenceKey;

	private DockingWindowManager dockingWindowManager;

	/**
	 * Constructor
	 *
	 * @param panel The GTableFilterPanel for the table.
	 * @param table The JTable that is filterable.
	 * @param model the TableModel that supports filtering.
	 * @param dataSource the table's DataSource object.
	 */
	public ColumnFilterSaveManager(GTableFilterPanel<R> panel, JTable table,
			RowObjectTableModel<R> model, Object dataSource) {
		preferenceKey = panel.getPreferenceKey() + COLUMN_FILTER_EXTENSION;
		loadFromPreferences(table, model, dataSource);
	}

	/**
	 * Adds a new ColumnTableFilter to be saved.
	 *
	 * @param filter The filter to be saved.
	 */
	public void addFilter(ColumnBasedTableFilter<R> filter) {
		filters.add(filter);
	}

	/**
	 * Deletes a ColumnTableFilter from the list of saved filters.
	 *
	 * @param filter the filter to remove from the list of saved filters.
	 */
	public void removeFilter(ColumnBasedTableFilter<R> filter) {
		filters.remove(filter);
	}

	/**
	 * Saves the list of filters to the tool's preference state.
	 */
	public void save() {
		SaveState saveState = new SaveState("COlUMN_FILTERS");
		saveState.putInt("NUM_FILTERS", filters.size());
		for (int i = 0; i < filters.size(); i++) {
			saveState.putXmlElement("FILTER_STATE_" + i, filters.get(i).save().saveToXml());
		}
		PreferenceState preferenceState = new PreferenceState();
		preferenceState.putXmlElement(COLUMN_FILTER_STATE, saveState.saveToXml());
		if (dockingWindowManager == null) {
			return; // can happen in partial environments, like testing
		}

		dockingWindowManager.putPreferenceState(preferenceKey, preferenceState);
	}

	/**
	 * Returns a list of the saved ColumnTableFilters
	 *
	 * @return  a list of the saved ColumnTableFilters
	 */
	public List<ColumnBasedTableFilter<R>> getSavedFilters() {
		return filters;
	}

	private void loadFromPreferences(JTable table, RowObjectTableModel<R> model,
			Object dataSource) {
		dockingWindowManager = DockingWindowManager.getInstance(table);
		if (dockingWindowManager == null) {
			return; // can happen in partial environments, like testing
		}
		PreferenceState preferenceState = dockingWindowManager.getPreferenceState(preferenceKey);
		if (preferenceState != null) {
			Element xmlElement = preferenceState.getXmlElement(COLUMN_FILTER_STATE);
			restoreFromXML(xmlElement, model, dataSource);
		}
	}

	private void restoreFromXML(Element element, RowObjectTableModel<R> model, Object dataSource) {
		SaveState saveState = new SaveState(element);
		int numFilters = saveState.getInt("NUM_FILTERS", 0);
		for (int i = 0; i < numFilters; i++) {
			Element child = saveState.getXmlElement("FILTER_STATE_" + i);
			SaveState childState = new SaveState(child);
			ColumnBasedTableFilter<R> filter = new ColumnBasedTableFilter<>(model);
			try {
				filter.restore(childState, dataSource);
				filters.add(filter);
			}
			catch (Exception e) {
				Msg.warn(this, "Can't load filter");
			}
		}
	}

	/**
	 * Returns true if this save manager contains any filters with the given name.
	 * @param name the name to check for a filter's existence.
	 * @return true if this save manager contains any filters with the given name.
	 */
	public boolean containsFilterWithName(String name) {
		for (ColumnBasedTableFilter<R> columnTableFilter : filters) {
			if (name.equals(columnTableFilter.getName())) {
				return true;
			}
		}
		return false;
	}

}
