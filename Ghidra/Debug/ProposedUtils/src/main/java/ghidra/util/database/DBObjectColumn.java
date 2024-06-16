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
package ghidra.util.database;

import java.util.ArrayList;
import java.util.List;

import ghidra.util.database.annot.DBAnnotatedColumn;

/**
 * An opaque handle to the column backing an object field
 * 
 * <p>
 * Each should be declared as a static field of the same class whose field it describes, probably
 * with package-only access. Each must also be annotated with {@link DBAnnotatedColumn}. For an
 * example, see the documentation of {@link DBAnnotatedObject}. The annotated field receives its
 * value the first time a store is created for the containing class. Until then, it is
 * uninitialized.
 */
public class DBObjectColumn {
	static List<DBObjectColumn> instances = new ArrayList<>(20);

	static DBObjectColumn get(int columnNumber) {
		while (instances.size() <= columnNumber) {
			instances.add(null);
		}
		DBObjectColumn column = instances.get(columnNumber);
		if (column == null) {
			column = new DBObjectColumn(columnNumber);
			instances.set(columnNumber, column);
		}
		return column;
	}

	final int columnNumber;

	private DBObjectColumn(int columnNumber) {
		this.columnNumber = columnNumber;
	}
}
