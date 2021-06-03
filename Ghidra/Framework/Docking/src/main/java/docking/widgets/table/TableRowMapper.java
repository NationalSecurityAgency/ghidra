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

import java.util.List;

import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.classfinder.ExtensionPoint;
import utilities.util.reflection.ReflectionUtilities;

/**
 * NOTE:  ALL TableRowMapper CLASSES MUST END IN "TableRowMapper".  If not,
 * the ClassSearcher will not find them.
 * 
 * An interface that allows implementors to map an object of one type to another.  This is useful
 * for table models that have row types that are easily converted to other more generic types.
 * <p>
 * This interface is an ExtensionPoint so that once created, they will be ingested automatically
 * by Ghidra.  Once discovered, these mappers will be used to provide dynamic columns to to 
 * tables with row types that match <code>ROW_TYPE</code>.
 *
 * @param <ROW_TYPE> The row type of a given table model
 * @param <EXPECTED_ROW_TYPE> The row type expected by dynamic columns.
 * 
 * @see DynamicTableColumn
 * @see TableUtils                           
 */
public abstract class TableRowMapper<ROW_TYPE, EXPECTED_ROW_TYPE, DATA_SOURCE>
		implements ExtensionPoint {

	@SuppressWarnings({ "unchecked", "rawtypes" })
	// guaranteed by compile constraints
	public final Class<ROW_TYPE> getSourceType() {
		Class<? extends TableRowMapper> implementationClass = getClass();
		List<Class<?>> typeArguments =
			ReflectionUtilities.getTypeArguments(TableRowMapper.class, implementationClass);
		return (Class<ROW_TYPE>) typeArguments.get(0);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	// guaranteed by compile constraints
	public final Class<EXPECTED_ROW_TYPE> getDestinationType() {
		Class<? extends TableRowMapper> implementationClass = getClass();
		List<Class<?>> typeArguments =
			ReflectionUtilities.getTypeArguments(TableRowMapper.class, implementationClass);
		return (Class<EXPECTED_ROW_TYPE>) typeArguments.get(1);
	}

	/**
	 * Creates a table column that will create a table column that knows how to map the 
	 * given <b>ROW_TYPE</b> to the type of the column passed in, the <b>EXPECTED_ROW_TYPE</b>.
	 * 
	 * @param <COLUMN_TYPE> The column type of the given and created columns
	 * @param destinationColumn The existing column, which is based upon EXPECTED_ROW_TYPE,
	 *        that we want to be able to use with the type we have, the ROW_TYPE.
	 */
	public <COLUMN_TYPE> DynamicTableColumn<ROW_TYPE, COLUMN_TYPE, DATA_SOURCE> createMappedTableColumn(
			DynamicTableColumn<EXPECTED_ROW_TYPE, COLUMN_TYPE, DATA_SOURCE> destinationColumn) {
		return new MappedTableColumn<>(this,
			destinationColumn);
	}

	public abstract EXPECTED_ROW_TYPE map(ROW_TYPE rowObject, DATA_SOURCE data,
			ServiceProvider serviceProvider);

}
