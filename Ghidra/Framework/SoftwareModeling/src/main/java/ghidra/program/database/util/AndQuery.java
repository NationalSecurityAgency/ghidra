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
/*
 *
 */
package ghidra.program.database.util;

import db.DBRecord;

/**
 * Combines two queries such that this query is the logical "AND" of the two queries.  If the
 * first query does not match, then the second query is not executed.
 */
public class AndQuery implements Query {
	private Query q1;
	private Query q2;

	/**
	 * Construct a new AndQuery from two other queries.
	 * @param q1 the first query
	 * @param q2 the second query
	 */
	public AndQuery(Query q1, Query q2) {
		this.q1 = q1;
		this.q2 = q2;
	}

	/**
	 * @see ghidra.program.database.util.Query#matches(db.DBRecord)
	 */
	public boolean matches(DBRecord record) {
		return q1.matches(record) && q2.matches(record);
	}

}
