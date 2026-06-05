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
package docking.widgets.trable;

import java.util.List;

/**
 * Abstract base class for {@link GTrable} row objects. 
 *
 * @param <T> the row object type
 */
public abstract class GTrableRow<T extends GTrableRow<T>> {
	private final int indentLevel;
	private boolean isExpanded = false;

	/**
	 * Constructor
	 * @param indentLevel the indent level of this row
	 */
	protected GTrableRow(int indentLevel) {
		this.indentLevel = indentLevel;
	}

	/**
	 * {@return the indent level for this row}
	 */
	public int getIndentLevel() {
		return indentLevel;
	}

	/**
	 * {@return true if this row is expandable}
	 */
	public abstract boolean isExpandable();

	/**
	 * {@return true if this node is expanded.}
	 */
	public boolean isExpanded() {
		return isExpanded;
	}

	/**
	 * Sets the expanded state.
	 * @param expanded true if this row is expanded
	 */
	void setExpanded(boolean expanded) {
		this.isExpanded = expanded;
	}

	protected abstract List<T> getChildRows();

}
