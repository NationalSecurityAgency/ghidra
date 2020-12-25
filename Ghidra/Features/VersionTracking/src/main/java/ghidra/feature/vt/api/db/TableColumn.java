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
package ghidra.feature.vt.api.db;

import db.Field;

public class TableColumn {

	private final Field columnField;
	private boolean indexed;

	private int ordinal;
	private String name;

	public TableColumn(Field columnField) {
		this(columnField, false);
	}

	public TableColumn(Field columnField, boolean isIndexed) {
		this.columnField = columnField;
		indexed = isIndexed;
	}

	void setName(String name) {
		this.name = name;
	}

	void setOrdinal(int ordinal) {
		this.ordinal = ordinal;
	}

	public boolean isIndexed() {
		return indexed;
	}

	public Field getColumnField() {
		return columnField;
	}

	public String name() {
		return name;
	}

	public int column() {
		return ordinal;
	}

	@Override
	public String toString() {
		return name() + "(" + ordinal + ")";
	}
}
