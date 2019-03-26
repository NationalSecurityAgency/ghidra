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

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.table.column.GColumnRenderer;

/**
 * A class that is an Adapter in order to allow for the use of existing 
 * {@link DynamicTableColumn}s when the actual row type of the table is
 * not the same as the row type that the {@link DynamicTableColumn} supports. 
 *
 * @param <ROW_TYPE> The table's actual row type
 * @param <EXPECTED_ROW_TYPE> The row type expected by the given {@link DynamicTableColumn}
 * @param <COLUMN_TYPE> The column type provided by the given {@link DynamicTableColumn}
 * @param <DATA_SOURCE> the type of the data for each column; can be Object for columns that
 *                      do not have a data source
 */
public class MappedTableColumn<ROW_TYPE, EXPECTED_ROW_TYPE, COLUMN_TYPE, DATA_SOURCE>
		extends AbstractDynamicTableColumn<ROW_TYPE, COLUMN_TYPE, DATA_SOURCE> {

	protected final TableRowMapper<ROW_TYPE, EXPECTED_ROW_TYPE, DATA_SOURCE> mapper;
	protected final DynamicTableColumn<EXPECTED_ROW_TYPE, COLUMN_TYPE, DATA_SOURCE> tableColumn;

	protected MappedTableColumn(TableRowMapper<ROW_TYPE, EXPECTED_ROW_TYPE, DATA_SOURCE> mapper,
			DynamicTableColumn<EXPECTED_ROW_TYPE, COLUMN_TYPE, DATA_SOURCE> tableColumn) {
		this(mapper, tableColumn, tableColumn.getUniqueIdentifier());
	}

	protected MappedTableColumn(TableRowMapper<ROW_TYPE, EXPECTED_ROW_TYPE, DATA_SOURCE> mapper,
			DynamicTableColumn<EXPECTED_ROW_TYPE, COLUMN_TYPE, DATA_SOURCE> tableColumn,
			String uniqueIdentifier) {
		super(uniqueIdentifier);
		this.mapper = mapper;
		this.tableColumn = tableColumn;
	}

	/**
	 * Returns the class of the column that this mapper wraps
	 * 
	 * @return the class of the column that this mapper wraps
	 */
	public Class<?> getMappedColumnClass() {
		if (tableColumn instanceof MappedTableColumn) {
			return ((MappedTableColumn<?, ?, ?, ?>) tableColumn).getMappedColumnClass();
		}
		return tableColumn.getClass();
	}

	@Override
	public Class<COLUMN_TYPE> getColumnClass() {
		return tableColumn.getColumnClass();
	}

	@Override
	public Class<ROW_TYPE> getSupportedRowType() {
		return mapper.getSourceType();
	}

	@Override
	public String getColumnDisplayName(Settings settings) {
		return tableColumn.getColumnDisplayName(settings);
	}

	@Override
	public String getColumnDescription() {
		return tableColumn.getColumnDescription();
	}

	@Override
	public String getColumnName() {
		return tableColumn.getColumnName();
	}

	@Override
	public int getMaxLines(Settings settings) {
		return tableColumn.getMaxLines(settings);
	}

	@Override
	public GColumnRenderer<COLUMN_TYPE> getColumnRenderer() {
		return tableColumn.getColumnRenderer();
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		return tableColumn.getSettingsDefinitions();
	}

	@Override
	public int getColumnPreferredWidth() {
		return tableColumn.getColumnPreferredWidth();
	}

	@Override
	public Comparator<COLUMN_TYPE> getComparator() {
		return tableColumn.getComparator();
	}

	@Override
	public COLUMN_TYPE getValue(ROW_TYPE rowObject, Settings settings, DATA_SOURCE data,
			ServiceProvider serviceProvider) throws IllegalArgumentException {

		if (rowObject == null) {
			// can happen when the model is cleared out from under Swing
			return null;
		}

		EXPECTED_ROW_TYPE mappedObject = mapper.map(rowObject, data, serviceProvider);
		if (mappedObject == null) {
			return null; // some mappers have null data
		}
		return tableColumn.getValue(mappedObject, settings, data, serviceProvider);
	}

	@Override
	public String toString() {
		return "TableColumn: " + getUniqueIdentifier();
	}
}
