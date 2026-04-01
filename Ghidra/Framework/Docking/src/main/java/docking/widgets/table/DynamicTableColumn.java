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

import java.util.Comparator;
import java.util.Date;

import javax.swing.table.TableCellEditor;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.table.column.GColumnRenderer;

/**
 * The root interface for defining columns for {@link DynamicColumnTableModel}s. The class allows
 * you to create objects for tables that know how to give a column value for a given row.
 *
 * @param <ROW_TYPE> The row object class supported by this column
 * @param <COLUMN_TYPE> The column object class supported by this column
 * @param <DATA_SOURCE> The object class type that will be passed to see
 *            <code>getValue(ROW_TYPE, Settings, DATA_SOURCE, ServiceProvider)</code>
 */
public interface DynamicTableColumn<ROW_TYPE, COLUMN_TYPE, DATA_SOURCE> {

	/**
	 * Determines the unique column heading that may be used to identify a column instance.
	 * <p>
	 * This name must be non-changing and is used to save/restore state information.
	 * 
	 * @return the field instance name.
	 */
	public String getColumnName();

	/**
	 * Determines the class of object that is associated with this field (column).
	 * 
	 * @return the column class
	 */
	public Class<COLUMN_TYPE> getColumnClass();

	/**
	 * {@return the preferred width for this column}
	 * <p>
	 * Column should either return a valid positive preferred size or -1
	 */
	public int getColumnPreferredWidth();

	/**
	 * {@return the maximum width for this column}
	 * <p>
	 * Column should either return a valid positive maximum size or -1
	 */
	public int getColumnMaxWidth();

	/**
	 * {@return the minimum width for this column}
	 * <p>
	 * Column should either return a valid positive minimum size or -1
	 */
	public int getColumnMinWidth();

	/**
	 * {@return the single class type of the data that this table field can use to generate columnar
	 * data.}
	 */
	public Class<ROW_TYPE> getSupportedRowType();

	/**
	 * Creates an object that is appropriate for this field (table column) and for the object that
	 * is associated with this row of the table.
	 * 
	 * @param rowObject the object associated with the row in the table.
	 * @param settings field settings
	 * @param data the expected data object, as defined by the DATA_SOURCE type
	 * @param serviceProvider the {@link ServiceProvider} associated with the table.
	 * @return the object for the model to display in the table cell.
	 * @throws IllegalArgumentException if the rowObject is not one supported by this class.
	 */
	public COLUMN_TYPE getValue(ROW_TYPE rowObject, Settings settings, DATA_SOURCE data,
			ServiceProvider serviceProvider) throws IllegalArgumentException;

	/**
	 * {@return the optional cell renderer for this column; null if no renderer is used}
	 * <P>
	 * This method allows columns to define custom rendering. The interface returned here ensures
	 * that the text used for filtering matches what the users sees (via the
	 * {@link GColumnRenderer#getFilterString(Object, Settings)} method).
	 * <P>
	 * Note: some types should not make use of the aforementioned filter string. These types include
	 * the {@link Number} wrapper types, {@link Date} and {@link Enum}s. (This is because the
	 * filtering system works naturally with these types.) See {@link GColumnRenderer}.
	 */
	public GColumnRenderer<COLUMN_TYPE> getColumnRenderer();

	/**
	 * {@return the optional cell editor for this column; null if no custom editor is used}
	 */
	public TableCellEditor getColumnEditor();

	/**
	 * {@return the optional header renderer for this column; null if no renderer is used}
	 * <P>
	 * This method allows columns to define custom header rendering.
	 */
	public GTableHeaderRenderer getHeaderRenderer();

	/**
	 * {@return a list of settings definitions for this field}
	 */
	public SettingsDefinition[] getSettingsDefinitions();

	/**
	 * {@return the maximum number of text display lines needed for any given cell with the
	 * specified settings}
	 * 
	 * @param settings field settings
	 */
	public int getMaxLines(Settings settings);

	/**
	 * Determines the column heading that will be displayed.
	 * 
	 * @param settings the settings
	 * @return the field name to display as the column heading.
	 */
	public String getColumnDisplayName(Settings settings);

	/**
	 * {@return a description of this column. This may be used as a tooltip for the column header}
	 */
	public String getColumnDescription();

	/**
	 * {@return a value that is unique for this table column}
	 * <p>
	 * This is different than getting the display name, which may be shared by different columns.
	 */
	public String getUniqueIdentifier();

	/**
	 * If implemented, will return a comparator that knows how to sort values for this column.
	 * Implementors should return {@code null} if they do not wish to provider a comparator
	 * 
	 * @param model the table model
	 * @param columnIndex the model column index
	 * @return the comparator
	 */
	public Comparator<COLUMN_TYPE> getComparator(DynamicColumnTableModel<?> model,
			int columnIndex);
}
