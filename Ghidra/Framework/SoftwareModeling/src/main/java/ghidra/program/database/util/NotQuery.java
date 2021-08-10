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

/**
 * Negates the given query such that this query is the logical "NOT" of the given query.
 */
public class NotQuery implements Query {
	private Query q1;

	/**
	 * Construct a new query that results in the not of the given query.
	 * @param q1 the query to logically negate.
	 */
	public NotQuery(Query q1) {
		this.q1 = q1;
	}

	/**
	 * @see ghidra.program.database.util.Query#matches(db.DBRecord)
	 */
	public boolean matches(DBRecord record) {
		return !q1.matches(record);
	}

}
