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
import java.util.List;

import ghidra.features.base.memsearch.bytesequence.ExtendedByteSequence;
import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.features.base.memsearch.searcher.MemorySearcher;

/**
 * A ByteMatcher that searches an input sequence for matches from multiple patterns. This is
 * useful for using with the {@link MemorySearcher} so that multiple patterns can be searched with
 * only one pass through memory, thus paying the memory I/O costs only once. The resulting matches
 * will contain the sub ByteMatcher that matched so that it is easy to know which of the multiple
 * patterns matched.
 */
public class CombinedByteMatcher extends ByteMatcher {

	private List<ByteMatcher> matchers;

	public CombinedByteMatcher(List<ByteMatcher> matchers, SearchSettings settings) {
		super("Multi-Pattern Matcher", null, settings);
		this.matchers = matchers;
	}

	@Override
	public Iterable<ByteMatch> match(ExtendedByteSequence bytes) {
		return new MultiMatcherIterator(bytes);
	}

	@Override
	public String getDescription() {
		return getName();
	}

	@Override
	public String getToolTip() {
		return null;
	}

	private class MultiMatcherIterator implements Iterable<ByteMatch>, Iterator<ByteMatch> {

		private Iterator<ByteMatcher> matcherIterator;
		private Iterator<ByteMatch> currentMatchIterator;
		private ExtendedByteSequence bytes;

		MultiMatcherIterator(ExtendedByteSequence bytes) {
			this.bytes = bytes;
			matcherIterator = matchers.iterator();
			currentMatchIterator = getNextMatchIterator();
		}

		@Override
		public boolean hasNext() {
			while (currentMatchIterator != null && !currentMatchIterator.hasNext()) {
				currentMatchIterator = getNextMatchIterator();
			}
			return currentMatchIterator != null;
		}

		private Iterator<ByteMatch> getNextMatchIterator() {
			if (matcherIterator.hasNext()) {
				ByteMatcher matcher = matcherIterator.next();
				return matcher.match(bytes).iterator();
			}
			return null;
		}

		@Override
		public ByteMatch next() {
			if (hasNext()) {
				return currentMatchIterator.next();
			}
			return null;
		}

		@Override
		public Iterator<ByteMatch> iterator() {
			return this;
		}

	}
}
