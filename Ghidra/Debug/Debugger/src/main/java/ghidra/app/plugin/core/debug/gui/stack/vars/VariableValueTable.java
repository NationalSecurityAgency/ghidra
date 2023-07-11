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
package ghidra.app.plugin.core.debug.gui.stack.vars;

import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

import ghidra.app.plugin.core.debug.gui.stack.vars.VariableValueRow.RowKey;

/**
 * A table for display in a variable value hover
 */
public class VariableValueTable {
	private final Map<RowKey, VariableValueRow> rows = new TreeMap<>();

	/**
	 * Add a row to the table
	 * <p>
	 * At most one of each row type can be present. Adding a row whose type already exists will
	 * remove the old row of the same type.
	 * 
	 * @param row
	 */
	public void add(VariableValueRow row) {
		synchronized (rows) {
			rows.put(row.key(), row);
		}
	}

	@Override
	public String toString() {
		synchronized (rows) {
			return String.format("""
					<%s:
					  %s
					>
					""",
				getClass().getSimpleName(),
				rows.values()
						.stream()
						.map(VariableValueRow::toSimpleString)
						.collect(Collectors.joining("\n  ")));
		}
	}

	/**
	 * Render the table as HTML for display in the GUI
	 * 
	 * <p>
	 * The rows are always ordered as in {@link RowKey}.
	 * 
	 * @return the HTML string
	 */
	public String toHtml() {
		synchronized (rows) {
			return String.format("""
					<table>
					  %s
					</table>
					""",
				rows.values()
						.stream()
						.map(VariableValueRow::toHtml)
						.collect(Collectors.joining("\n")));
		}
	}

	/**
	 * Count the number of rows
	 * 
	 * @return the count
	 */
	public int getNumRows() {
		synchronized (rows) {
			return rows.size();
		}
	}

	/**
	 * Get the row of the given type
	 * 
	 * @param key the key / type
	 * @return the row, or null
	 */
	public VariableValueRow get(RowKey key) {
		synchronized (rows) {
			return rows.get(key);
		}
	}

	/**
	 * Remove the row of the given type
	 * 
	 * @param key the key / type
	 */
	public void remove(RowKey key) {
		synchronized (rows) {
			rows.remove(key);
		}
	}

	public void reportDetails() {
		synchronized (rows) {
			for (VariableValueRow row : rows.values()) {
				row.reportDetails();
			}
		}
	}
}
