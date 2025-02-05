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
package ghidra.features.base.memsearch.searcher;

import java.util.function.Predicate;

import ghidra.features.base.memsearch.bytesequence.*;
import ghidra.features.base.memsearch.bytesource.AddressableByteSource;
import ghidra.features.base.memsearch.matcher.ByteMatcher;
import ghidra.features.base.memsearch.matcher.ByteMatcher.ByteMatch;
import ghidra.program.model.address.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.task.TaskMonitor;

/**
 * Class for searching bytes from a byteSource (memory) using a {@link ByteMatcher}. It handles
 * breaking the search down into a series of searches, handling gaps in the address set and
 * breaking large address ranges down into manageable sizes.
 * <P>
 * It is created with a specific byte source, matcher, address set, and search limit. Clients can
 * then either call the {@link #findAll(Accumulator, TaskMonitor)} method or use it to incrementally
 * search using {@link #findNext(Address, TaskMonitor)}, 
 * {@link #findPrevious(Address, TaskMonitor)}, or {@link #findOnce(Address, boolean, TaskMonitor)}.
 */

public class MemorySearcher {
	private static final int DEFAULT_CHUNK_SIZE = 16 * 1024;
	private static final int OVERLAP_SIZE = 100;
	private final AddressableByteSequence bytes1;
	private final AddressableByteSequence bytes2;
	private final ByteMatcher matcher;
	private final int chunkSize;

	private Predicate<MemoryMatch> filter = r -> true;
	private final int searchLimit;
	private final AddressSetView searchSet;

	/**
	 * Constructor
	 * @param byteSource the source of the bytes to be searched
	 * @param matcher the matcher that can find matches in a byte sequence
	 * @param addresses the address in the byte source to search
	 * @param searchLimit the max number of hits before stopping
	 */
	public MemorySearcher(AddressableByteSource byteSource, ByteMatcher matcher,
			AddressSetView addresses, int searchLimit) {
		this(byteSource, matcher, addresses, searchLimit, DEFAULT_CHUNK_SIZE);
	}

	/**
	 * Constructor
	 * @param byteSource the source of the bytes to be searched
	 * @param matcher the matcher that can find matches in a byte sequence
	 * @param addresses the address in the byte source to search
	 * @param searchLimit the max number of hits before stopping
	 * @param chunkSize the maximum number of bytes to feed to the matcher at any one time. 
	 */
	public MemorySearcher(AddressableByteSource byteSource, ByteMatcher matcher,
			AddressSetView addresses, int searchLimit, int chunkSize) {
		this.matcher = matcher;
		this.searchSet = addresses;
		this.searchLimit = searchLimit;
		this.chunkSize = chunkSize;

		bytes1 = new AddressableByteSequence(byteSource, chunkSize);
		bytes2 = new AddressableByteSequence(byteSource, chunkSize);
	}

	/**
	 * Sets any match filters. The filter can be used to exclude matches that don't meet some
	 * criteria that is not captured in the byte matcher such as alignment and code unit type.
	 * @param filter the predicate to use to filter search results
	 */
	public void setMatchFilter(Predicate<MemoryMatch> filter) {
		this.filter = filter;
	}

	/**
	 * Searches all the addresses in this search's {@link AddressSetView} using the byte matcher to
	 * find matches. As each match is found (and passes any filters), the match is given to the 
	 * accumulator. The search continues until either the entire address set has been search or
	 * the search limit has been reached.
	 * @param accumulator the accumulator for found matches
	 * @param monitor the task monitor
	 * @return true if the search completed searching through the entire address set.
	 */
	public boolean findAll(Accumulator<MemoryMatch> accumulator, TaskMonitor monitor) {
		monitor.initialize(searchSet.getNumAddresses(), "Searching...");

		for (AddressRange range : searchSet.getAddressRanges()) {
			if (!findAll(accumulator, range, monitor)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Searches forwards or backwards starting at the given address until a match is found or
	 * the start or end of the address set is reached. It does not currently wrap the search.
	 * @param start the address to start searching
	 * @param forward if true, search forward, otherwise, search backwards.
	 * @param monitor the task monitor
	 * @return the first match found or null if no match found.
	 */
	public MemoryMatch findOnce(Address start, boolean forward, TaskMonitor monitor) {
		if (forward) {
			return findNext(start, monitor);
		}
		return findPrevious(start, monitor);
	}

	/**
	 * Searches forwards starting at the given address until a match is found or
	 * the end of the address set is reached. It does not currently wrap the search.
	 * @param start the address to start searching
	 * @param monitor the task monitor
	 * @return the first match found or null if no match found.
	 */
	public MemoryMatch findNext(Address start, TaskMonitor monitor) {

		long numAddresses = searchSet.getNumAddresses() - searchSet.getAddressCountBefore(start);
		monitor.initialize(numAddresses, "Searching....");

		for (AddressRange range : searchSet.getAddressRanges(start, true)) {
			range = range.intersectRange(start, range.getMaxAddress());
			MemoryMatch match = findFirst(range, monitor);
			if (match != null) {
				return match;
			}
			if (monitor.isCancelled()) {
				break;
			}
		}
		return null;
	}

	/**
	 * Searches backwards starting at the given address until a match is found or
	 * the beginning of the address set is reached. It does not currently wrap the search.
	 * @param start the address to start searching
	 * @param monitor the task monitor
	 * @return the first match found or null if no match found.
	 */
	public MemoryMatch findPrevious(Address start, TaskMonitor monitor) {

		monitor.initialize(searchSet.getAddressCountBefore(start) + 1, "Searching....");

		for (AddressRange range : searchSet.getAddressRanges(start, false)) {
			MemoryMatch match = findLast(range, start, monitor);
			if (match != null) {
				return match;
			}
			if (monitor.isCancelled()) {
				break;
			}
		}
		return null;
	}

	private MemoryMatch findFirst(AddressRange range, TaskMonitor monitor) {
		AddressableByteSequence searchBytes = bytes1;
		AddressableByteSequence extra = bytes2;

		AddressRangeIterator it = new AddressRangeSplitter(range, chunkSize, true);
		AddressRange first = it.next();

		searchBytes.setRange(first);
		while (it.hasNext()) {
			AddressRange next = it.next();
			extra.setRange(next);

			MemoryMatch match = findFirst(searchBytes, extra, monitor);
			if (match != null) {
				return match;
			}
			if (monitor.isCancelled()) {
				break;
			}

			// Flip flop the byte buffers, making the extended buffer become primary and preparing
			// the primary buffer to be used to read the next chunk. See the
			// ExtendedByteSequence class for an explanation of this approach.
			searchBytes = extra;
			extra = searchBytes == bytes1 ? bytes2 : bytes1;
		}
		// last segment, no extra bytes to overlap, so just search the primary buffer
		extra.clear();
		return findFirst(searchBytes, extra, monitor);
	}

	private MemoryMatch findLast(AddressRange range, Address start, TaskMonitor monitor) {
		AddressableByteSequence searchBytes = bytes1;
		AddressableByteSequence extra = bytes2;
		extra.clear();

		if (range.contains(start)) {
			Address min = range.getMinAddress();
			Address max = range.getMaxAddress();
			range = new AddressRangeImpl(min, start);
			AddressRange remaining = new AddressRangeImpl(start.next(), max);
			AddressRange extraRange = new AddressRangeSplitter(remaining, chunkSize, true).next();
			extra.setRange(extraRange);
		}

		AddressRangeIterator it = new AddressRangeSplitter(range, chunkSize, false);

		while (it.hasNext()) {
			AddressRange next = it.next();
			searchBytes.setRange(next);
			MemoryMatch match = findLast(searchBytes, extra, monitor);
			if (match != null) {
				return match;
			}
			if (monitor.isCancelled()) {
				break;
			}

			// Flip flop the byte buffers, making the primary buffer the new extended buffer
			// and refilling the primary buffer with new data going backwards.
			extra = searchBytes;
			searchBytes = extra == bytes1 ? bytes2 : bytes1;
		}
		return null;
	}

	private MemoryMatch findFirst(AddressableByteSequence searchBytes, ByteSequence extra,
			TaskMonitor monitor) {

		ExtendedByteSequence searchSequence =
			new ExtendedByteSequence(searchBytes, extra, OVERLAP_SIZE);

		for (ByteMatch byteMatch : matcher.match(searchSequence)) {
			Address address = searchBytes.getAddress(byteMatch.start());
			byte[] bytes = searchSequence.getBytes(byteMatch.start(), byteMatch.length());
			MemoryMatch match = new MemoryMatch(address, bytes, matcher);
			if (filter.test(match)) {
				return match;
			}
			if (monitor.isCancelled()) {
				break;
			}
		}
		monitor.incrementProgress(searchBytes.getLength());
		return null;
	}

	private MemoryMatch findLast(AddressableByteSequence searchBytes, ByteSequence extra,
			TaskMonitor monitor) {

		MemoryMatch last = null;

		ExtendedByteSequence searchSequence =
			new ExtendedByteSequence(searchBytes, extra, OVERLAP_SIZE);

		for (ByteMatch byteMatch : matcher.match(searchSequence)) {
			Address address = searchBytes.getAddress(byteMatch.start());
			byte[] bytes = searchSequence.getBytes(byteMatch.start(), byteMatch.length());
			MemoryMatch match = new MemoryMatch(address, bytes, matcher);
			if (filter.test(match)) {
				last = match;
			}
			if (monitor.isCancelled()) {
				return null;
			}
		}
		monitor.incrementProgress(searchBytes.getLength());
		return last;
	}

	private boolean findAll(Accumulator<MemoryMatch> accumulator, AddressRange range,
			TaskMonitor monitor) {
		AddressableByteSequence searchBytes = bytes1;
		AddressableByteSequence extra = bytes2;

		AddressRangeIterator it = new AddressRangeSplitter(range, chunkSize, true);
		AddressRange first = it.next();

		searchBytes.setRange(first);
		while (it.hasNext()) {
			AddressRange next = it.next();
			extra.setRange(next);
			if (!findAll(accumulator, searchBytes, extra, monitor)) {
				return false;
			}
			searchBytes = extra;
			extra = searchBytes == bytes1 ? bytes2 : bytes1;
		}
		extra.clear();
		return findAll(accumulator, searchBytes, extra, monitor);
	}

	private boolean findAll(Accumulator<MemoryMatch> accumulator,
			AddressableByteSequence searchBytes, ByteSequence extra, TaskMonitor monitor) {

		if (monitor.isCancelled()) {
			return false;
		}

		ExtendedByteSequence searchSequence =
			new ExtendedByteSequence(searchBytes, extra, OVERLAP_SIZE);

		for (ByteMatch byteMatch : matcher.match(searchSequence)) {
			Address address = searchBytes.getAddress(byteMatch.start());
			byte[] bytes = searchSequence.getBytes(byteMatch.start(), byteMatch.length());
			MemoryMatch match = new MemoryMatch(address, bytes, matcher);
			if (filter.test(match)) {
				if (accumulator.size() >= searchLimit) {
					return false;
				}
				accumulator.add(match);
			}
			if (monitor.isCancelled()) {
				return false;
			}

		}
		// Reset the monitor message, since clients may change the message (such as the 
		// incremental table loader)
		monitor.setMessage("Searching...");
		monitor.incrementProgress(searchBytes.getLength());
		return true;
	}
}
