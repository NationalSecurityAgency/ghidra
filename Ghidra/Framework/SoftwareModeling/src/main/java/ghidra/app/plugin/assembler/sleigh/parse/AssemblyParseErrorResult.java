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
package ghidra.app.plugin.assembler.sleigh.parse;

import java.util.*;

import org.apache.commons.collections4.IterableUtils;

/**
 * An unsuccessful result from parsing
 */
public class AssemblyParseErrorResult extends AssemblyParseResult {
	/**
	 * The maximum number of suggestions to print when describing this error, e.g., when reported in
	 * exception messages.
	 */
	private static final int SUGGESTIONS_THRESHOLD = 10;

	private final String buffer;
	private final Set<String> suggestions;

	/**
	 * @see AssemblyParseResult#error(String, Set)
	 */
	protected AssemblyParseErrorResult(String got, Set<String> suggestions) {
		this.buffer = got;
		this.suggestions = suggestions;
	}

	@Override
	public boolean isError() {
		return true;
	}

	/**
	 * Get a description of the error
	 * 
	 * @return a description
	 */
	public String describeError() {
		Collection<String> truncSuggestions;
		if (suggestions.size() <= SUGGESTIONS_THRESHOLD) {
			truncSuggestions = suggestions;
		}
		else {
			truncSuggestions = new ArrayList<>();
			for (String s : IterableUtils.boundedIterable(suggestions, SUGGESTIONS_THRESHOLD)) {
				truncSuggestions.add(s);
			}
			truncSuggestions.add("...");
		}
		return "Syntax Error: Expected " + truncSuggestions + ". Got " + buffer;
	}

	/**
	 * Get a set of suggested tokens that would have allowed parsing to continue
	 * 
	 * @return the token set
	 */
	public Set<String> getSuggestions() {
		return Collections.unmodifiableSet(suggestions);
	}

	/**
	 * Get the leftover contents of the input buffer when the error occurred
	 * 
	 * @return the remaining buffer contents
	 */
	public String getBuffer() {
		return buffer;
	}

	@Override
	public String toString() {
		return describeError();
	}
}
