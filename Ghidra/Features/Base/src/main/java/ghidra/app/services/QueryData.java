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
package ghidra.app.services;

public class QueryData {

	/**
	 * Wildcard char for any string.
	 */
	private static String ANY_STRING_WILDCARD = "*";

	/**
	 * Wildcard char for a single char.
	 */
	private static String ANY_CHAR_WILDCARD = "?";

	private final String queryString;
	private final boolean caseSensitive;
	private final boolean includeDynamicLables;

	public QueryData(String queryString, boolean caseSensitive, boolean includeDynamicLables) {
		super();
		this.queryString = queryString;
		this.caseSensitive = caseSensitive;
		this.includeDynamicLables = includeDynamicLables;
	}

	public QueryData(String queryString, boolean caseSensitive) {
		this(queryString, caseSensitive, true);
	}

	public String getQueryString() {
		return queryString;
	}

	public boolean isCaseSensitive() {
		return caseSensitive;
	}

	public boolean isIncludeDynamicLables() {
		return includeDynamicLables;
	}

	public boolean isWildCard() {
		return hasWildCards(queryString);
	}

	public static boolean hasWildCards(String query) {
		return query.contains(ANY_STRING_WILDCARD) || query.contains(ANY_CHAR_WILDCARD);
	}
}
