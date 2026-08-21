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

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import ghidra.features.base.quickfix.QuickFix;
import ghidra.program.model.listing.Program;
import ghidra.util.UserSearchUtils;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Immutable class for storing all related query information for performing a search and
 * replace operation. It includes the search pattern, the search pattern text, the search lmiit,
 * and the types of program elements to search.
 */
public class SearchAndReplaceQuery {
	private final String searchText;
	private final String replacementText;
	private final Pattern pattern;
	private final int searchLimit;
	private final Set<SearchType> selectedTypes = new HashSet<>();

	/**
	 * Constructor
	 * @param searchText the user entered search pattern text. It will be used to generate the
	 * actual Pattern based on the various options.
	 * @param replacementText the user entered replacement text.
	 * @param searchTypes the types of program elements to search
	 * @param isRegEx true if the given search text is to be interpreted as a regular expression.
	 * @param isCaseSensitive true if the search text should be case sensitive
	 * @param isWholeWord true, the search text should match the enter element in the case of a
	 * rename, or an entire word within a larger sentence in the case of a comment.
	 * @param searchLimit the maximum entries to find before terminating the search.
	 */
	public SearchAndReplaceQuery(String searchText, String replacementText,
			Set<SearchType> searchTypes, boolean isRegEx, boolean isCaseSensitive,
			boolean isWholeWord, int searchLimit) {
		this.searchText = searchText;
		this.replacementText = replacementText;
		this.pattern = createPattern(isRegEx, isCaseSensitive, isWholeWord);
		this.searchLimit = searchLimit;
		selectedTypes.addAll(searchTypes);
	}

	/**
	 * Method to initiate the search.
	 * @param program the program to search 
	 * @param accumulator the accumulator to store the generated {@link QuickFix}s
	 * @param monitor the {@link TaskMonitor}
	 * @throws CancelledException if the search is cancelled.
	 */
	public void findAll(Program program, Accumulator<QuickFix> accumulator,
			TaskMonitor monitor) throws CancelledException {
		Set<SearchAndReplaceHandler> handlers = getHandlers();
		for (SearchAndReplaceHandler handler : handlers) {
			handler.findAll(program, this, accumulator, monitor);
		}
	}

	/**
	 * Returns the search {@link Pattern} used to search program elements.
	 * @return the search {@link Pattern} used to search program elements
	 */
	public Pattern getSearchPattern() {
		return pattern;
	}

	/**
	 * Returns true if the given SearchType is to be included in the search.
	 * @param searchType the SearchType to check if it is included in the search
	 * @return true if the given SearchType is to be included in the search.
	 */
	public boolean containsSearchType(SearchType searchType) {
		return selectedTypes.contains(searchType);
	}

	/**
	 * Returns the search text used to generate the pattern for this query.
	 * @return the search text used to generate the pattern for this query
	 */
	public String getSearchText() {
		return searchText;
	}

	/**
	 * Returns the replacement text that will replace matched elements.
	 * @return the replacement text that will replace matched elements
	 */
	public String getReplacementText() {
		return replacementText;
	}

	/**
	 * Returns a set of all the SearchTypes to be included in this query.
	 * @return a set of all the SearchTypes to be included in this query
	 */
	public Set<SearchType> getSelectedSearchTypes() {
		return selectedTypes;
	}

	/**
	 * Returns the maximum number of search matches to be found before stopping early.
	 * @return the maximum number of search matches to be found before stopping early.
	 */
	public int getSearchLimit() {
		return searchLimit;
	}

	private Pattern createPattern(boolean isRegEx, boolean isCaseSensitive, boolean isWholeWord) {
		int regExFlags = Pattern.DOTALL;
		if (!isCaseSensitive) {
			regExFlags |= Pattern.CASE_INSENSITIVE;
		}

		if (isRegEx) {
			return Pattern.compile(searchText, regExFlags);
		}

		String converted = UserSearchUtils.convertUserInputToRegex(searchText, false);
		if (isWholeWord) {
			converted = "\\b" + converted + "\\b";
		}

		return Pattern.compile(converted, regExFlags);
	}

	private Set<SearchAndReplaceHandler> getHandlers() {
		Set<SearchAndReplaceHandler> handlers = new HashSet<>();
		for (SearchType type : selectedTypes) {
			handlers.add(type.getHandler());
		}
		return handlers;
	}
}
