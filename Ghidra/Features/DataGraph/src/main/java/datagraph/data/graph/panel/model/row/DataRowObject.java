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
package datagraph.data.graph.panel.model.row;

import docking.widgets.table.GTable;
import docking.widgets.table.RowObject;
import ghidra.program.model.listing.Data;

/**
 * Abstract class for displaying rows in a Data GTrable model. Similar to a {@link RowObject} in
 * a {@link GTable}. The big difference is that each row maintains its indent level and whether
 * or not is is expanded. GTrables are like tables, but with a tree like structure. Each row that is
 * a child of another row has its indent level set to one more than its parent. The expanded flag is
 * used to indicate if a given row has visible child rows showing or not.
 */

public abstract class DataRowObject {
	private int indentLevel;
	private boolean isExpanded;

	/**
	 * Constructor
	 * @param indentLevel the indent level for this row object
	 * @param isExpanded true if this object has child rows that are being displayed
	 */
	protected DataRowObject(int indentLevel, boolean isExpanded) {
		this.indentLevel = indentLevel;
		this.isExpanded = isExpanded;
	}

	public int getIndentLevel() {
		return indentLevel;
	}

	public boolean isExpanded() {
		return isExpanded;
	}

	/**
	 * {@return the name for this row. Typically this will be the field name, but it could be 
	 * a descriptive title for a group such as array range.}
	 */
	public abstract String getName();

	/**
	 * {@return the interpreted value for the data at this location.}
	 */
	public abstract String getValue();

	/**
	 * {@return the name of the datatype at this location.}
	 */
	public abstract String getDataType();

	/**
	 * {@return true if the row can produce child rows.}
	 */
	public abstract boolean isExpandable();

	/**
	 * {@return true if this location represents a pointer or has outgoing references}
	 */
	public boolean hasOutgoingReferences() {
		return false;
	}

	/**
	 * @{return the Data object associated with this row.}
	 */
	public abstract Data getData();

}
