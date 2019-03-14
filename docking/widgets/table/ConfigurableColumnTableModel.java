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

import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableModel;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;

/**
 * A model that provides access to table columns that are "configurable," whether by way of 
 * {@link Settings} object, or by the implementations and how they were written (like supplying 
 * custom renderers and such).
 */
public interface ConfigurableColumnTableModel extends TableModel {

	/**
	 * Returns settings for the specified column index.
	 * @param index column index
	 * @return column settings.
	 */
	public Settings getColumnSettings(int index);

	/**
	 * Returns settings definitions for the specified column index.
	 * @param index column index
	 * @return column settings definitions.
	 */
	public SettingsDefinition[] getColumnSettingsDefinitions(int index);

	/**
	 * A convenience method to set bulk column setting information for a group of columns at one
	 * time (this saves repeated rebuilding when settings are changing for multiple columns at
	 * once).
	 * @param index the column index
	 * @param newSettings A list of pair objects that contain the column index of the column to
	 *        which the new settings apply and the new settings object.
	 */
	public void setColumnSettings(int index, Settings newSettings);

	/**
	 * Allows for the bulk setting of Settings.  This prevents excessive event 
	 * notification when all settings need to be changed.  
	 * 
	 * @param settings An array of Settings that contains Settings for each column  
	 *        where the index of the Settings in the array is the index of the column
	 *        in the model.
	 * @see #setColumnSettings(int, Settings)
	 */
	public void setAllColumnSettings(Settings[] settings);

	/**
	 * Gets the maximum number of text display lines needed for any given cell within the 
	 * specified column.
	 * @param index column field index
	 * @return maximum number of lines needed for specified column
	 */
	public int getMaxLines(int index);

	public TableCellRenderer getRenderer(int columnIndex);
}
