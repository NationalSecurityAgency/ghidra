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
package ghidra.program.database.util;

import db.Field;
import db.DBRecord;

/**
 * Query implementation used to test a field in a record to match a given value.
 */
public class FieldMatchQuery implements Query {
	private int column;
	private Field value;

	/**
	 * Constructs a new FieldMatchQuery that tests a records field against a particular value.
	 * @param column the field index in the record to test.
	 * @param value the Field value to test the record's field against.
	 */
	public FieldMatchQuery(int column, Field value) {
		this.column = column;
		this.value = value;
	}

	/**
	 * @see ghidra.program.database.util.Query#matches(db.DBRecord)
	 */
	public boolean matches(DBRecord record) {
		return record.fieldEquals(column, value);
	}

}
