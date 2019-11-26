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

import ghidra.docking.settings.Settings;

/**
 * An interface that is meant to take the column type of of a {@link DynamicTableColumn}
 * and convert it to the specified type.   This class is meant to be used when the dynamic 
 * filtering mechanism is not correctly filtering a column, usually because the default filter
 * for the column type does not match what the renderer is displaying in the table.
 *
 * @param <COLUMN_TYPE> the column type
 * @param <FILTER_TYPE> the new type to be used during filter operations
 */
public interface FilterTypeConverter<COLUMN_TYPE, FILTER_TYPE> {

	/**
	 * Returns the destination class of the conversion
	 * 
	 * @return the destination class
	 */
	public Class<FILTER_TYPE> getFilterType();

	/**
	 * Converts in instance of the column type to an instance of the destination type
	 * 
	 * @param t the column type instance
	 * @param settings any settings the converter may need to convert the type
	 * @return the new object
	 */
	public FILTER_TYPE convert(COLUMN_TYPE t, Settings settings);
}
