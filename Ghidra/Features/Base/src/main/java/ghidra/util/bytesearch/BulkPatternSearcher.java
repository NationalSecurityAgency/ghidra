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
package ghidra.util.bytesearch;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.util.*;

import ghidra.util.task.TaskMonitor;

/** 
 * State machine for searching for a list of {@link BytePattern}s simultaneously in a byte
 * sequence. Once this BulkPatternMatcher is constructed from a list of patterns, it can
 * be used any number of times to search byte sequences. There are an assortment of search methods
 * to meet various client needs.
 * <P>
 * The search methods break down into the following categories:
 * 1) Searching a byte buffer with the result being an iterator over matches.
 * 2) Searching a byte buffer with the results being added to a given list.
 * 3) Searching an input stream with the results being added to a given list.
 * 4) Searching an {@link ExtendedByteSequence} with the results being added to a given list
 * <P>
 * In addition, the byte buffer methods all have a variation that takes an additional parameter
 * stating how many of the bytes in the buffer are searchable. (The buffer is not full).
 * Also, the input stream method has a variation where the max bytes to read from the stream
 * is given.
 *
 * @param <T> The specific pattern type
 */
public class BulkPatternSearcher<T extends BytePattern> {
	private static final int DEFAULT_BUFFER_SIZE = 4096;

	private List<T> patterns;
	private SearchState<T> startState;
	private int bufferSize = DEFAULT_BUFFER_SIZE;
	private int uniqueStateCount;
	private int maxPatternLength;

	/**
	 * Constructor
	 * @param patterns the list of patterns that can be search simultaneously using an internal
	 * finite state machine
	 */
	public BulkPatternSearcher(List<T> patterns) {
		this.patterns = patterns;
		maxPatternLength = computeMaxPatternLength();
		startState = buildStateMachine();
	}

	private int computeMaxPatternLength() {
		int max = 0;
		for (T pattern : patterns) {
			max = Math.max(max, pattern.getSize());
		}
		return max;
	}

	/**
	 * Search the given byte buffer for any of this searcher's patterns.
	 * @param input the byte buffer to search
	 * @return An iterator that will return pattern matches one at a time.
	 */
	public Iterator<Match<T>> search(byte[] input) {
		return new ByteArrayMatchIterator(input);
	}

	/**
	 * Search the given byte buffer up the specified length for any of this searcher's patterns.
	 * @param input the byte buffer to search
	 * @param length the actual number of the bytes in the buffer to search.
	 * @return An iterator that will return pattern matches one at a time.
	 */
	public Iterator<Match<T>> search(byte[] input, int length) {
		return new ByteArrayMatchIterator(input, length);
	}

	/**
	 * Searches for the patterns in the given byte array, adding match results to the given list
	 * of results.
	 * @param input the byte array to search for patterns
	 * @param results the list of match results to populate
	 */
	public void search(byte[] input, List<Match<T>> results) {
		search(input, input.length, results);
	}

	/**
	 * Searches for the patterns in the given byte array, adding match results to the given list
	 * of results.
	 * @param input the byte array to search for patterns
	 * @param numBytes the number of valid bytes in the input buffer to search
	 * @param results the list of match results to populate
	 */
	public void search(byte[] input, int numBytes, List<Match<T>> results) {
		for (int patternStart = 0; patternStart < numBytes; patternStart++) {
			SearchState<T> state = startState;
			for (int i = patternStart; i < numBytes; i++) {
				int index = input[i] & 0xff;	// turn byte value into unsigned int (0-255)
				SearchState<T> nextState = state.nextStates[index];
				if (nextState == null) {
					break;
				}
				nextState.addMatches(results, patternStart);
				state = nextState;
			}
		}
	}

	/**
	 * Searches for the patterns in the given byte array that start at the first byte in the array.
	 * Resulting matches are added to the given results list.
	 * @param input the byte array to search for patterns
	 * @param numBytes the number of bytes to use from the given byte array. (The byte array might
	 * not be fully populated with valid data.)
	 * @param results the list of match results to populate
	 */
	public void matches(byte[] input, int numBytes, List<Match<T>> results) {
		SearchState<T> state = startState;
		for (int i = 0; i < numBytes; i++) {
			int index = input[i] & 0xff;	// turn byte value into unsigned int (0-255)
			SearchState<T> nextState = state.nextStates[index];
			if (nextState == null) {
				break;
			}
			nextState.addMatches(results, 0);
			state = nextState;
		}
	}

	/**
	 * Searches for the patterns in the given {@link ExtendedByteSequence}, adding match results
	 * to the given list of results.
	 * @param bytes the extended byte sequence to search
	 * @param results the list of match results to populate
	 * Users of this method may have split a larger byte sequence into chunks and the final match
	 * position needs to be the sum of the chunk offset plus the offset within this chunk.
	 */
	public void search(ExtendedByteSequence bytes, List<Match<T>> results) {
		search(bytes, results, 0);
	}

	private void search(ExtendedByteSequence bytes, List<Match<T>> results, long streamOffset) {
		for (int start = -bytes.getPreLength(); start < bytes.getLength(); start++) {
			SearchState<T> state = startState;
			for (int j = start; j < bytes.getExtendedLength(); j++) {
				int index = bytes.getByte(j) & 0xff;
				SearchState<T> nextState = state.nextStates[index];
				if (nextState == null) {
					break;
				}
				nextState.addMatchesFilteredByEffectiveStart(results, start, 0,
					bytes.getLength() - 1, streamOffset);
				state = nextState;
			}
		}
	}

	/**
	 * Searches for the patterns in the given input stream, adding match results to the given list
	 * of results. 
	 * @param is the input stream of bytes to scan for patterns
	 * @param results the list of match results to populate
	 * @param monitor the task monitor
	 * @throws IOException if an exception occurs reading the input stream 
	 */
	public void search(InputStream is, List<Match<T>> results, TaskMonitor monitor)
			throws IOException {
		search(is, -1, results, monitor);
	}

	/**
	 * Searches for the patterns in the given input stream, adding match results to the given
	 * list of results. 
	 *
	 * @param inputStream the input stream of bytes to scan for patterns
	 * @param maxRead the maximum offset into the input stream where a match can start. Additional
	 * bytes can be read from the stream to complete patterns
	 * @param results the list of match results to populate
	 * @param monitor the task monitor
	 * @throws IOException if an exception occurs reading the input stream 
	 */
	public void search(InputStream inputStream, long maxRead, List<Match<T>> results,
			TaskMonitor monitor) throws IOException {
		RestrictedStream restrictedStream = new RestrictedStream(inputStream, maxRead);
		int bufSize = Math.max(maxPatternLength, bufferSize);
		long streamOffset = 0;

		// The basic strategy is to use two byte buffers and create a virtual buffer with those two
		// buffers. The first pass will look for patterns that start in the 1st buffer but can 
		// extend into the second buffer. This is to ensure that we find patterns that span
		// buffers.
		//
		// Then the second buffer is swapped to be the 1st buffer and new data is read
		// into the what was the 1st buffer, but is now the 2nd buffer. This pattern is repeated
		// until all the data is processed up to the number of bytes specified by the maxRead. No
		// patterns will matched in any data in the stream past that point, but data past that point
		// may be used to complete a pattern.

		InputStreamBufferByteSequence pre = new InputStreamBufferByteSequence(bufSize);
		InputStreamBufferByteSequence main = new InputStreamBufferByteSequence(bufSize);
		InputStreamBufferByteSequence post = new InputStreamBufferByteSequence(bufSize);
		main.load(restrictedStream, bufSize);
		post.load(restrictedStream, bufSize);

		while (main.getLength() > 0 && post.getLength() > 0) {
			if (monitor.isCancelled()) {
				return;
			}

			ExtendedByteSequence combined =
				new ExtendedByteSequence(main, pre, post, maxPatternLength);
			search(combined, results, streamOffset);
			monitor.incrementProgress(main.getLength());
			streamOffset += main.getLength();

			// rotate buffers and load data into second buffer
			InputStreamBufferByteSequence tmp = pre;
			pre = main;
			main = post;
			post = tmp;
			post.load(restrictedStream, bufSize);
		}
		// just have to read a bit more to finish last pattern and we go beyond restricted maxRead
		// so use unrestricted stream
		post.load(inputStream, maxPatternLength);
		ExtendedByteSequence combined =
			new ExtendedByteSequence(main, pre, post, maxPatternLength);
		search(combined, results, streamOffset);
		monitor.incrementProgress(main.getLength());
	}

	/**
	 * Sets the buffer size used when using one of the search methods that takes an input stream.
	 * Mostly used for testing.
	 * @param bufferSize the size of the buffers to use when searching input streams.
	 */
	public void setBufferSize(int bufferSize) {
		this.bufferSize = bufferSize;
	}

	/**
	 * {@return the length of the longest pattern}
	 */
	public int getMaxPatternLength() {
		return maxPatternLength;
	}

	private SearchState<T> buildStateMachine() {
		Queue<SearchState<T>> unprocessed = new ArrayDeque<>();

		// We use a map that uses the same unique state as the key and the value.
		// This way, if you create a new state that is equal to an existing state in the cache,
		// you can use the new state instance as a key to get the existing equivalent state.
		Map<SearchState<T>, SearchState<T>> dedupCache = new HashMap<>();
		SearchState<T> start = new SearchState<T>(patterns, 0);
		unprocessed.add(start);
		while (!unprocessed.isEmpty()) {
			SearchState<T> next = unprocessed.remove();
			next.computeTransitions(unprocessed, dedupCache);
		}
		uniqueStateCount = dedupCache.size() + 1; // add 1 for the root state which wasn't cached
		dedupCache.clear();
		return start;
	}

	/**
	 * {@return the number of unique states generated. Used for testing.}
	 */
	public int getUniqueStateCount() {
		return uniqueStateCount;
	}

	private class ByteArrayMatchIterator implements Iterator<Match<T>> {
		private byte[] bytes;
		private int length;
		private int patternStart = 0;
		private Queue<Match<T>> resultBuffer = new ArrayDeque<>();

		ByteArrayMatchIterator(byte[] input) {
			this(input, input.length);
		}

		ByteArrayMatchIterator(byte[] input, int length) {
			this.bytes = input;
			this.length = Math.min(length, bytes.length);
			findNext();
		}

		private void findNext() {
			while (patternStart < length && resultBuffer.isEmpty()) {
				SearchState<T> state = startState;
				for (int i = patternStart; i < length; i++) {
					int index = bytes[i] & 0xff;	// turn byte value into unsigned int (0-255)
					state = state.nextStates[index];
					if (state == null) {
						break;
					}
					state.addMatches(resultBuffer, patternStart);
				}
				patternStart++;
			}
		}

		@Override
		public boolean hasNext() {
			return !resultBuffer.isEmpty();
		}

		@Override
		public Match<T> next() {
			Match<T> nextResult = resultBuffer.poll();
			if (resultBuffer.isEmpty()) {
				findNext();
			}

			return nextResult;
		}
	}

	/**
	 * A single state in the state machine that represents one or more active patterns that have
	 * matched the sequence of bytes so far.
	 * 
	 * @param <T> the specific type of patterns being search for
	 */
	private static class SearchState<T extends BytePattern> {
		private List<T> activePatterns;      // patterns that have matched the input bytes so far
		private List<T> completedPatterns;   // the active patterns that have completely matched 
		private SearchState<T>[] nextStates; // next state (transition) for each possible input byte
		private int level;					 // the number of bytes that have been matched so far	
		private int hash;

		SearchState(List<T> activePatterns, int level) {
			this.activePatterns = activePatterns;
			this.level = level;
			hash = Objects.hash(activePatterns, level);
		}

		void computeTransitions(Queue<SearchState<T>> unresolved,
				Map<SearchState<T>, SearchState<T>> cache) {
			completedPatterns = buildFullyMatchedPatternsList();
			nextStates = createTransitionArray();
			if (completedPatterns != null && completedPatterns.size() == activePatterns.size()) {
				return; // we are a terminal state
			}
			for (int inputValue = 0; inputValue < 256; inputValue++) {
				List<T> matchedPatterns = getMatchingPatternsForTransitionValue(inputValue);
				if (!matchedPatterns.isEmpty()) {
					nextStates[inputValue] = getSearchState(matchedPatterns, cache, unresolved);
				}
			}
		}

		@Override
		public int hashCode() {
			return hash;
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
			SearchState<?> other = (SearchState<?>) obj;
			if (hash != other.hash) {
				return false;
			}
			return level == other.level && Objects.equals(activePatterns, other.activePatterns);
		}

		@SuppressWarnings("unchecked")
		private SearchState<T>[] createTransitionArray() {
			return (SearchState<T>[]) Array.newInstance(getClass(), 256);
		}

		private SearchState<T> getSearchState(List<T> patterns,
				Map<SearchState<T>, SearchState<T>> cache, Queue<SearchState<T>> unresolved) {
			SearchState<T> newState = new SearchState<T>(patterns, level + 1);
			SearchState<T> existing = cache.get(newState);
			if (existing != null) {
				return existing;
			}
			cache.put(newState, newState);
			unresolved.add(newState);
			return newState;
		}

		private List<T> getMatchingPatternsForTransitionValue(int inputValue) {
			List<T> matchedPatterns = new ArrayList<>();
			for (T pattern : activePatterns) {
				if (pattern.isMatch(level, inputValue)) {
					matchedPatterns.add(pattern);
				}
			}
			return matchedPatterns;
		}

		private void addMatches(Collection<Match<T>> results, int start) {
			if (completedPatterns == null) {
				return;
			}
			for (T pattern : completedPatterns) {
				results.add(new Match<T>(pattern, start, pattern.getSize()));
			}
		}

		private void addMatchesFilteredByEffectiveStart(Collection<Match<T>> results, int start,
				int min, int max, long streamOffset) {
			if (completedPatterns == null) {
				return;
			}
			for (T pattern : completedPatterns) {
				int actualStart = start + pattern.getPreSequenceLength();
				if (actualStart >= min && actualStart <= max) {
					results.add(new Match<T>(pattern, streamOffset + start, pattern.getSize()));
				}
			}

		}

		private List<T> buildFullyMatchedPatternsList() {
			List<T> list = new ArrayList<>();
			for (T pattern : activePatterns) {
				if (pattern.getSize() == level) {
					list.add(pattern);
				}
			}
			return list.isEmpty() ? null : list;
		}
	}

	private static class RestrictedStream extends InputStream {
		private long maxRead;
		private long totalRead;
		private InputStream is;

		RestrictedStream(InputStream is, long maxRead) {
			this.is = is;
			this.maxRead = maxRead;
		}

		@Override
		public int read(byte[] buf) throws IOException {
			return read(buf, 0, buf.length);
		}

		@Override
		public int read(byte[] buf, int offset, int amount) throws IOException {
			int amountToRead = amount;
			if (maxRead >= 0) {
				long remaining = maxRead - totalRead;
				amountToRead = (int) Math.min(remaining, amount);
			}
			int n = is.read(buf, offset, amountToRead);
			n = n > 0 ? n : 0;
			totalRead += n;
			return n;
		}

		@Override
		public int read() throws IOException {
			if (totalRead >= maxRead) {
				return -1;
			}
			int value = is.read();
			if (value < 0) {
				return -1;
			}
			totalRead++;
			return value;
		}
	}
}
