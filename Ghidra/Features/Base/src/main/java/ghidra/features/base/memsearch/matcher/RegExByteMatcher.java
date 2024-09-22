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

import ghidra.features.base.memsearch.bytesequence.ExtendedByteSequence;
import ghidra.features.base.memsearch.gui.SearchSettings;

/**
 * {@link ByteMatcher} where the user search input has been parsed as a regular expression.
 */
public class RegExByteMatcher extends ByteMatcher {

	private final Pattern pattern;

	public RegExByteMatcher(String input, SearchSettings settings) {
		super(input, settings);
		// without DOTALL mode, bytes that match line terminator characters will cause 
		// the regular expression pattern to not match.
		this.pattern = Pattern.compile(input, Pattern.DOTALL);
	}

	@Override
	public Iterable<ByteMatch> match(ExtendedByteSequence byteSequence) {
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

		ByteCharSequence(ExtendedByteSequence byteSequence) {
			this.byteSequence = byteSequence;
		}

		@Override
		public int length() {
			return byteSequence.getExtendedLength();
		}

		@Override
		public char charAt(int index) {
			byte b = byteSequence.getByte(index);
			return (char) (b & 0xff);
		}

		@Override
		public CharSequence subSequence(int start, int end) {
			throw new UnsupportedOperationException();
		}

	}

	/**
	 * Adapter class for converting java {@link Pattern} matching into an iterator of
	 * {@link ByteMatch}s.
	 */
	private class PatternMatchIterator implements Iterable<ByteMatch>, Iterator<ByteMatch> {

		private Matcher matcher;
		private ByteMatch nextMatch;
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
		public ByteMatch next() {
			if (nextMatch == null) {
				return null;
			}
			ByteMatch returnValue = nextMatch;
			nextMatch = findNextMatch();
			return returnValue;

		}

		@Override
		public Iterator<ByteMatch> iterator() {
			return this;
		}

		private ByteMatch findNextMatch() {
			if (!matcher.find()) {
				return null;
			}
			int start = matcher.start();
			int end = matcher.end();
			if (start >= byteSequence.getLength()) {
				return null;
			}
			return new ByteMatch(start, end - start);
		}
	}

}
