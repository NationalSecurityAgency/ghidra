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
package docking.widgets.table.constraint.dialog;

/**
 * A simple object used to track a component's position in the filter dialog.  This is used to 
 * restore focus when the dialog is rebuilt.
 * <p>
 * This class models the filter dialog as grid.  The dialog has a set of rows, each of which can 
 * have sub-rows within the dialog's row.   The columns values are the same for the dialog as they
 * are for sub-components.
 *  
 * @param dialogRow the row number in the dialog's set of compound rows 
 * @param subRow the row number within a given dialog row
 * @param col the column
 */
record ColumnFilterGridLocation(int dialogRow, int subRow, int col) {

}
