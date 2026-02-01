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

import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.help.UnsupportedOperationException;

import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.util.bytesearch.ExtendedByteSequence;
import ghidra.util.bytesearch.Match;

/**
 * {@link ByteMatcher} where the user search input has been parsed as a regular expression.
 */
public class RegExByteMatcher extends UserInputByteMatcher {

	private final Pattern pattern;

	public RegExByteMatcher(String input, SearchSettings settings) {
		this("Regex Matcher", input, settings);
	}

	public RegExByteMatcher(String name, String input, SearchSettings settings) {
		super(name, input, settings);
		// without DOTALL mode, bytes that match line terminator characters will cause 
		// the regular expression pattern to not match.
		this.pattern = Pattern.compile(input, Pattern.DOTALL);
	}

	@Override
	public Iterable<Match<SearchData>> match(ExtendedByteSequence byteSequence) {
		return new PatternMatchIterator(byteSequence);
	}

	@Override
	public String getDescription() {
		return "Reg Ex";
	}

	@Override
	public String getToolTip() {
		return null;
	}

//==================================================================================================
// Inner classes
//==================================================================================================

	/**
	 * Class for converting byte sequences into a {@link CharSequence} that can be used by
	 * the java regular expression engine
	 */
	private class ByteCharSequence implements CharSequence {

		private ExtendedByteSequence byteSequence;
		private int preLength;

		ByteCharSequence(ExtendedByteSequence byteSequence) {
			this.byteSequence = byteSequence;
			preLength = byteSequence.getPreLength();
		}

		@Override
		public int length() {
			return byteSequence.getExtendedLength() + preLength;
		}

		@Override
		public char charAt(int index) {
			// Our charSequence starts at the beginning of any pre-bytes.
			// The iterator using this sequence will have to make the opposite translation when
			// interpreting offsets into this sequence as reported by the pattern matcher.
			byte b = byteSequence.getByte(index - preLength);
			return (char) (b & 0xff);
		}

		@Override
		public CharSequence subSequence(int start, int end) {
			throw new UnsupportedOperationException();
		}

	}

	/**
	 * Adapter class for converting java {@link Pattern} matching into an iterator of
	 * {@link Match}s.
	 */
	private class PatternMatchIterator
			implements Iterable<Match<SearchData>>, Iterator<Match<SearchData>> {

		private Matcher matcher;
		private Match<SearchData> nextMatch;
		private ExtendedByteSequence byteSequence;

		public PatternMatchIterator(ExtendedByteSequence byteSequence) {
			this.byteSequence = byteSequence;
			matcher = pattern.matcher(new ByteCharSequence(byteSequence));
			nextMatch = findNextMatch();
		}

		@Override
		public boolean hasNext() {
			return nextMatch != null;
		}

		@Override
		public Match<SearchData> next() {
			if (nextMatch == null) {
				return null;
			}
			Match<SearchData> returnValue = nextMatch;
			nextMatch = findNextMatch();
			return returnValue;

		}

		@Override
		public Iterator<Match<SearchData>> iterator() {
			return this;
		}

		private Match<SearchData> findNextMatch() {
			int preLength = byteSequence.getPreLength();

			// loop until we find a match that starts past the pre-bytes.
			// we are scanning the pre-bytes in case the regEx has any look-behind, but we
			// really only want matches that start in the main range.
			while (matcher.find()) {
				int start = matcher.start() - preLength;
				int end = matcher.end() - preLength;
				if (start >= 0) {
					if (start >= byteSequence.getLength()) {
						return null;	// we are past the end of the main byte sequence, so done
					}
					return new Match<>(searchData, start, end - start);
				}
			}
			return null; // no matches so we are done with this buffer
		}
	}

}
