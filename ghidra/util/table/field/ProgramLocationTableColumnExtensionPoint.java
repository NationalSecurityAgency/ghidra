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
package ghidra.util.table.field;

import docking.widgets.table.DynamicTableColumnExtensionPoint;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * A convenience class that allows subclasses to signal that they implement 
 * {@link ProgramLocationTableColumn} and that they are {@link ExtensionPoint}s.
 * <p>
 * If you do not wish to be an extension point, but do wish to provide ProgramLocation objects,
 * then you can just implement {@link ProgramLocationTableColumn} or extend 
 * {@link AbstractProgramLocationTableColumn}.
 * 
 * @see ProgramLocationTableColumn
 * @see AbstractProgramLocationTableColumn
 * 
 * @param <ROW_TYPE> The row object class supported by this column
 * @param <COLUMN_TYPE> The column object class supported by this column
 */
public abstract class ProgramLocationTableColumnExtensionPoint<ROW_TYPE, COLUMN_TYPE>
		extends DynamicTableColumnExtensionPoint<ROW_TYPE, COLUMN_TYPE, Program>
		implements ProgramLocationTableColumn<ROW_TYPE, COLUMN_TYPE> {

	// subclasses must implement		
}
