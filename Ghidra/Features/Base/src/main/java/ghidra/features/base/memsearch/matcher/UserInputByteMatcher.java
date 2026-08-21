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
package ghidra.features.base.memsearch.matcher;

import java.util.Objects;

import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.util.bytesearch.ExtendedByteSequence;
import ghidra.util.bytesearch.Match;

public abstract class UserInputByteMatcher implements ByteMatcher<SearchData> {

	protected final SearchData searchData;

	protected UserInputByteMatcher(String name, String input, SearchSettings settings) {
		searchData = new SearchData(name, input, settings);
	}

	/**
	 * {@return the name of this byte matcher.}
	 */
	public String getName() {
		return searchData.getName();
	}

	/**
	 * Returns an {@link Iterable} for returning matches within the given byte sequence.
	 * @param bytes the byte sequence to search
	 * @return an iterable for return matches in the given sequence
	 */
	@Override
	public abstract Iterable<Match<SearchData>> match(ExtendedByteSequence bytes);

	/**
	 * Returns a description of what this byte matcher matches. (Typically a sequence of bytes)
	 * @return a description of what this byte matcher matches
	 */
	@Override
	public abstract String getDescription();

	/**
	 * Returns additional information about this byte matcher. (Typically the mask bytes)
	 * @return additional information about this byte matcher
	 */
	public abstract String getToolTip();

	/**
	 * Returns true if this byte matcher is valid and can be used to perform a search. If false,
	 * the description will return an error message explaining why this byte matcher is
	 * invalid.
	 * @return true if this byte matcher is valid and can be used to perform a search.
	 */
	public boolean isValidSearch() {
		return true;
	}

	/**
	 * Returns true if this byte matcher has valid (but possibly incomplete) input text. For 
	 * example, when entering decimal values, the input could be just "-" as the user starts
	 * to enter a negative number. In this case the input is valid, but the {@link #isValidSearch()}
	 * would return false.
	 * @return true if this byte matcher has valid text
	 */
	public boolean isValidInput() {
		return true;
	}

	@Override
	public String toString() {
		return searchData.getInput();
	}

	@Override
	public int hashCode() {
		return searchData.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		UserInputByteMatcher other = (UserInputByteMatcher) obj;
		return Objects.equals(searchData, other.searchData);
	}

	public SearchSettings getSettings() {
		return searchData.getSettings();
	}

	public String getInput() {
		return searchData.getInput();
	}

	public SearchData getSearchData() {
		return searchData;
	}

}
