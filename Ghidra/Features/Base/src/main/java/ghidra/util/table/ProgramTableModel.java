/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import ghidra.program.util.ProgramSelection;

/**
 * An interface for translating table rows and columns
 * into program locations and selections.
 */
public interface ProgramTableModel {
    /**
     * Returns a program location corresponding the given row and column.
     * Motivation:
     * Given a table that has a column that contains addresses.
     * If the user clicks on this column, then it would be nice 
     * to have the CodeBrowser navigate to this address.
     * @param row    the row
     * @param column the column
     * @return a program location corresponding the given row and column
     */
	public ProgramLocation getProgramLocation(int row, int column);

	/**
	 * Returns a program selection corresponding to the 
	 * specified row index array. This array will contain
	 * the currently selected rows.
	 * @param rows the currently selected rows.
	 * @return a program selection
	 */
	public ProgramSelection getProgramSelection(int[] rows);
	
	/**
	 * Returns the program associated with this ProgramTableModel.
	 * @return the program associated with this ProgramTableModel.
	 */
	public Program getProgram();
}
