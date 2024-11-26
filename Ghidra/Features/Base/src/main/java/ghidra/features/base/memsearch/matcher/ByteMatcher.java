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

import ghidra.features.base.memsearch.bytesequence.ExtendedByteSequence;
import ghidra.features.base.memsearch.gui.SearchSettings;

/**
 * ByteMatcher is the base class for an object that be used to scan bytes looking for sequences
 * that match some criteria. As a convenience, it also stores the input string and settings that
 * were used to generated this ByteMatcher.
 */
public abstract class ByteMatcher {

	private final String input;
	private final SearchSettings settings;

	protected ByteMatcher(String input, SearchSettings settings) {
		this.input = input;
		this.settings = settings;
	}

	/**
	 * Returns the original input text that generated this ByteMatacher.
	 * @return the original input text that generated this BytesMatcher
	 */
	public final String getInput() {
		return input == null ? "" : input;
	}

	/**
	 * Returns the settings used to generate this ByteMatcher.
	 * @return the settings used to generate this ByteMatcher
	 */
	public SearchSettings getSettings() {
		return settings;
	}

	/**
	 * Returns an {@link Iterable} for returning matches within the given byte sequence.
	 * @param bytes the byte sequence to search
	 * @return an iterable for return matches in the given sequence
	 */
	public abstract Iterable<ByteMatch> match(ExtendedByteSequence bytes);

	/**
	 * Returns a description of what this byte matcher matches. (Typically a sequence of bytes)
	 * @return a description of what this byte matcher matches
	 */
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
		return input;
	}

	@Override
	public int hashCode() {
		return input.hashCode();
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
		ByteMatcher other = (ByteMatcher) obj;
		return Objects.equals(input, other.input) &&
			settings.getSearchFormat() == other.settings.getSearchFormat();
	}

	/**
	 * Record class to contain a match specification.
	 */
	public record ByteMatch(int start, int length) {}

}
