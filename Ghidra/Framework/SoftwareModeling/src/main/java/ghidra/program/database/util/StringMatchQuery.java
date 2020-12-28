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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import db.DBRecord;
import ghidra.util.UserSearchUtils;

/**
 * Query for matching string fields with wildcard string.
 */
public class StringMatchQuery implements Query {

	private int col;
	private Pattern pattern;

	/**
	 * Construct a new StringMatchQuery
	 * @param col column index
	 * @param searchString string to match
	 * @param caseSensitive true if the match should be case sensitive
	 */
	public StringMatchQuery(int col, String searchString, boolean caseSensitive) {
		this.col = col;

		pattern = UserSearchUtils.createSearchPattern(searchString, caseSensitive);
	}

	@Override
	public boolean matches(DBRecord record) {

		String value = record.getString(col);
		Matcher matcher = pattern.matcher(value);
		return matcher.matches();
	}

}
