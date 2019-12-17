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
package ghidra.util.table;

import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.field.ProgramLocationTableColumn;
import docking.widgets.table.*;

/**
 * NOTE:  ALL TableRowMapper CLASSES MUST END IN "TableRowMapper".  If not,
 * the ClassSearcher will not find them.
 * 
 * An interface that allows implementors to map an object of one type to another.  This is useful
 * for table models that have row types that are easily converted to other more generic types.
 * For example, the Bookmarks table model's data is based upon Bookmark objects.  Furthermore, 
 * those objects are easily converted to ProgramLocations and Addresses.  By creating a mapper 
 * for the these types, the table model can now show dynamic columns that work on ProgramLocations
 * and Addresses.  
 * <p>
 * This interface is an ExtensionPoint so that once created, they will be ingested automatically
 * by Ghidra.  Once discovered, these mappers will be used to provide dynamic columns to to 
 * tables with row types that match <code>ROW_TYPE</code>.
 * <p>
 * This column is an extension of {@link TableRowMapper} that has knowledge of 
 * {@link ProgramLocationTableColumn}s, which means that it knows how to generate 
 * {@link ProgramLocation}s.  This is the preferred mapper to use with tables that work on program
 * data, as it means that the column works with navigation.
 *
 * @param <ROW_TYPE> The row type of a given table model
 * @param <EXPECTED_ROW_TYPE> The row type expected by dynamic columns (e.g., ProgramLocations, 
 *                            Addresses, etc).
 * @see AbstractDynamicTableColumn
 * @see TableUtils                           
 */
public abstract class ProgramLocationTableRowMapper<ROW_TYPE, EXPECTED_ROW_TYPE> extends
		TableRowMapper<ROW_TYPE, EXPECTED_ROW_TYPE, Program> {

	/**
	 * Creates a table column that will create a table column that knows how to map the 
	 * given <b>ROW_TYPE</b> to the type of the column passed in, the <b>EXPECTED_ROW_TYPE</b>.
	 * 
	 * @param <COLUMN_TYPE> The column type of the given and created columns
	 * @param destinationColumn The existing column, which is based upon EXPECTED_ROW_TYPE,
	 *        that we want to be able to use with the type we have, the ROW_TYPE.
	 */
	@Override
	public <COLUMN_TYPE> DynamicTableColumn<ROW_TYPE, COLUMN_TYPE, Program> createMappedTableColumn(
			DynamicTableColumn<EXPECTED_ROW_TYPE, COLUMN_TYPE, Program> destinationColumn) {
		if (destinationColumn instanceof ProgramLocationTableColumn<?, ?>) {
			// we just checked
			ProgramLocationTableColumn<EXPECTED_ROW_TYPE, COLUMN_TYPE> programColumn =
				(ProgramLocationTableColumn<EXPECTED_ROW_TYPE, COLUMN_TYPE>) destinationColumn;

			return new MappedProgramLocationTableColumn<ROW_TYPE, EXPECTED_ROW_TYPE, COLUMN_TYPE>(
				this, programColumn);
		}
		return super.createMappedTableColumn(destinationColumn);
	}
}
