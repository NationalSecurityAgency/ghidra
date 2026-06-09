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
package ghidra.features.base.replace;

import java.util.*;

import ghidra.util.classfinder.ClassSearcher;

/**
 * Represents a ghidra program element type that can be individually included or excluded when doing
 * a search and replace operation. The {@link SearchAndReplaceDialog} will include a checkbox for
 * each of these types.
 */
public class SearchType implements Comparable<SearchType> {
	private final SearchAndReplaceHandler handler;
	private final String name;
	private final String description;

	/**
	 * Constructor
	 * @param handler The {@link SearchAndReplaceHandler} that actually has the logic for doing
	 * the search for this program element type.
	 * @param name the name of element type that is searchable
	 * @param description a description of this type which would be suitable to display as a tooltip
	 */
	public SearchType(SearchAndReplaceHandler handler, String name, String description) {
		this.handler = handler;
		this.name = name;
		this.description = description;
	}

	/**
	 * Returns the {@link SearchAndReplaceHandler} that can process this type.
	 * @return the handler for processing this type
	 */
	public SearchAndReplaceHandler getHandler() {
		return handler;
	}

	/**
	 * Returns the name of this search type.
	 * @return the name of this search type
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns a description of this search type.
	 * @return a description of this search type
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Static convenience method for finding all known SearchTypes. It uses the
	 * {@link ClassSearcher} to find all {@link SearchAndReplaceHandler}s and then gathers up
	 * all the SearchTypes that each handler supports.
	 * 
	 * @return The set of all Known SearchTypes
	 */
	public static Set<SearchType> getSearchTypes() {
		List<SearchAndReplaceHandler> handlers =
			ClassSearcher.getInstances(SearchAndReplaceHandler.class);

		Set<SearchType> types = new HashSet<>();

		for (SearchAndReplaceHandler handler : handlers) {
			types.addAll(handler.getSearchAndReplaceTypes());
		}

		return types;
	}

	@Override
	public int compareTo(SearchType o) {
		return name.compareTo(o.name);
	}
}
