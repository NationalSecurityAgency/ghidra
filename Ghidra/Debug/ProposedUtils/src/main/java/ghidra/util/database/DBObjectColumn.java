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
