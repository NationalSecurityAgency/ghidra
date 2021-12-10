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

import db.DBRecord;
import db.Field;

/**
 * Query implementation used to test a field in a record to fall within a range of values.
 */
public class FieldRangeQuery implements Query {
	private int column;
	private Field min;
	private Field max;

	/**
	 * Constructs a new FieldRangeQuery that tests a records field against a range of values.
	 * @param column the field index in the record to test.
	 * @param min the minimum field value to test against.
	 * @param max the maximum field value to test against.
	 */

	public FieldRangeQuery(int column, Field min, Field max) {
		this.column = column;
		this.min = min;
		this.max = max;
	}

	/**
	 * @see ghidra.program.database.util.Query#matches(db.DBRecord)
	 */
	public boolean matches(DBRecord record) {
		return (record.compareFieldTo(column, min) > 0) && (record.compareFieldTo(column, max) < 0);
	}

}
