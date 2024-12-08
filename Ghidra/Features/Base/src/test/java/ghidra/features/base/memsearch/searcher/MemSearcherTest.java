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

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.features.base.memsearch.bytesource.AddressableByteSource;
import ghidra.features.base.memsearch.bytesource.SearchRegion;
import ghidra.features.base.memsearch.matcher.ByteMatcher;
import ghidra.features.base.memsearch.matcher.RegExByteMatcher;
import ghidra.program.model.address.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.task.TaskMonitor;

public class MemSearcherTest {
	private static final int SEARCH_LIMIT = 10;
	private static final int TINY_CHUNK_SIZE = 4;
	private TestByteSource bytes;
	private AddressSpace space;
	private TaskMonitor monitor = TaskMonitor.DUMMY;
	private ByteMatcher bobMatcher = new RegExByteMatcher("bob", null);
	private Accumulator<MemoryMatch> accumulator = new ListAccumulator<>();

	@Before
	public void setUp() {
		space = new GenericAddressSpace("test", 64, AddressSpace.TYPE_RAM, 0);
	}

	@Test
	public void testFindNext() {
		bytes = new TestByteSource(addr(0), "xxbobxxx");
		MemorySearcher searcher = new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT);

		MemoryMatch match = searcher.findNext(addr(0), monitor);
		assertMatch(2, "bob", match);
	}

	@Test
	public void testFindNextStartingAtMatch() {
		bytes = new TestByteSource(addr(0), "xxbobxxx");
		MemorySearcher searcher = new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT);

		MemoryMatch match = searcher.findNext(addr(2), monitor);
		assertMatch(2, "bob", match);
	}

	@Test
	public void testFindNextNoMatch() {
		bytes = new TestByteSource(addr(0), "xxjoexxx");
		MemorySearcher searcher = new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT);

		MemoryMatch match = searcher.findNext(addr(0), monitor);
		assertNull(match);
	}

	@Test
	public void testFindNextInSecondChunk() {
		bytes = new TestByteSource(addr(0), "xxxx xbob x");	// spaces are removed by bytes call
		AddressSet addresses = bytes.getAddressSet();
		MemorySearcher searcher =
			new MemorySearcher(bytes, bobMatcher, addresses, SEARCH_LIMIT, TINY_CHUNK_SIZE);

		MemoryMatch match = searcher.findNext(addr(0), monitor);
		assertMatch(5, "bob", match);
	}

	@Test
	public void testFindNextInLaterChunk() {
		bytes = new TestByteSource(addr(0), "xxxx xxxx xxxx xxxx xbob x");
		MemorySearcher searcher =
			new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT, TINY_CHUNK_SIZE);

		MemoryMatch match = searcher.findNext(addr(0), monitor);
		assertMatch(17, "bob", match);
	}

	@Test
	public void testFindNextMatchSpansChunks() {
		bytes = new TestByteSource(addr(0), "xxxb obxx");
		MemorySearcher searcher =
			new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT, TINY_CHUNK_SIZE);

		MemoryMatch match = searcher.findNext(addr(0), monitor);
		assertMatch(3, "bob", match);
	}

	@Test
	public void testFindNextMultipleRanges() {
		bytes = new TestByteSource(addr(0), "xxxxx");
		bytes.addBytes(addr(100), "xxxxxboxxbxx");
		bytes.addBytes(addr(200), "xxxbobxxxxbobxxxx");
		MemorySearcher searcher = new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT);

		MemoryMatch match = searcher.findNext(addr(0), monitor);
		assertMatch(203, "bob", match);
	}

	@Test
	public void testFindPrevious() {
		bytes = new TestByteSource(addr(0), "xxbobxxx");
		MemorySearcher searcher = new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT);

		MemoryMatch match = searcher.findPrevious(addr(100), monitor);
		assertMatch(2, "bob", match);
	}

	@Test
	public void testFindPreviousNoMatch() {
		bytes = new TestByteSource(addr(0), "xxjoexxx");
		MemorySearcher searcher = new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT);

		MemoryMatch match = searcher.findPrevious(addr(100), monitor);
		assertNull(match);
	}

	@Test
	public void testFindPreviousStartingAtMatch() {
		bytes = new TestByteSource(addr(0), "xxbobxxx");
		MemorySearcher searcher = new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT);

		MemoryMatch match = searcher.findPrevious(addr(2), monitor);
		assertMatch(2, "bob", match);
	}

	@Test
	public void testFindPreviousInFirstChunk() {
		bytes = new TestByteSource(addr(0), "xxxx xbob");
		MemorySearcher searcher =
			new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT, TINY_CHUNK_SIZE);

		MemoryMatch match = searcher.findPrevious(addr(100), monitor);
		assertMatch(5, "bob", match);
	}

	@Test
	public void testFindPreviousInSecondChunk() {
		bytes = new TestByteSource(addr(0), "xbob xxxx");
		MemorySearcher searcher =
			new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT, TINY_CHUNK_SIZE);

		MemoryMatch match = searcher.findPrevious(addr(100), monitor);
		assertMatch(1, "bob", match);
	}

	@Test
	public void testFindPreviousInLaterChunk() {
		bytes = new TestByteSource(addr(0), "xbob xxxx xxxx xxxx xxxx xxxx x");
		MemorySearcher searcher =
			new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT, TINY_CHUNK_SIZE);

		MemoryMatch match = searcher.findPrevious(addr(100), monitor);
		assertMatch(1, "bob", match);
	}

	@Test
	public void testFindPreviousSpansChunk() {
		bytes = new TestByteSource(addr(0), "xxbo bxxx");
		MemorySearcher searcher =
			new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT, TINY_CHUNK_SIZE);

		MemoryMatch match = searcher.findPrevious(addr(100), monitor);
		assertMatch(2, "bob", match);
	}

	@Test
	public void testFindPrevioustMultipleRanges() {
		bytes = new TestByteSource(addr(0), "xxbobxxx");
		bytes.addBytes(addr(100), "xxxxxboxxbxx");
		bytes.addBytes(addr(200), "xxxxxxxbbxxxx");
		MemorySearcher searcher = new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT);

		MemoryMatch match = searcher.findNext(addr(0), monitor);
		assertMatch(2, "bob", match);
	}

	@Test
	public void testFindAll() {
		bytes = new TestByteSource(addr(0), "xbob xxxb obxx xxxx xxbo b");
		MemorySearcher searcher =
			new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT, TINY_CHUNK_SIZE);
		searcher.findAll(accumulator, monitor);
		assertEquals(3, accumulator.size());
		Iterator<MemoryMatch> it = accumulator.iterator();
		assertMatch(1, "bob", it.next());
		assertMatch(7, "bob", it.next());
		assertMatch(18, "bob", it.next());
	}

	@Test
	public void testFindAllMultipleRanges() {
		bytes = new TestByteSource(addr(0), "xbobxxxx");
		bytes.addBytes(addr(100), "bobxxxxxx");
		bytes.addBytes(addr(200), "xxxxxx");
		bytes.addBytes(addr(300), "xxxx xxbo bxxx bob");
		MemorySearcher searcher =
			new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT, TINY_CHUNK_SIZE);
		searcher.findAll(accumulator, monitor);
		assertEquals(4, accumulator.size());
		Iterator<MemoryMatch> it = accumulator.iterator();
		assertMatch(1, "bob", it.next());
		assertMatch(100, "bob", it.next());
		assertMatch(306, "bob", it.next());
		assertMatch(312, "bob", it.next());
	}

	@Test
	public void testNextWithFilter() {
		bytes = new TestByteSource(addr(0), "xxbobxxxbob");
		MemorySearcher searcher = new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT);
		searcher.setMatchFilter(r -> r.getAddress().getOffset() != 2);

		MemoryMatch match = searcher.findNext(addr(0), monitor);
		assertMatch(8, "bob", match);

	}

	@Test
	public void testPreviousWithFilter() {
		bytes = new TestByteSource(addr(0), "xxbobxxxbob");
		MemorySearcher searcher = new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT);
		searcher.setMatchFilter(r -> r.getAddress().getOffset() != 8);

		MemoryMatch match = searcher.findNext(addr(0), monitor);
		assertMatch(2, "bob", match);

	}

	@Test
	public void testAllWithFilter() {
		bytes = new TestByteSource(addr(0), "bobx xxbo bxxx xxxx xbob xxxx bobx");
		MemorySearcher searcher = new MemorySearcher(bytes, bobMatcher, addrs(), SEARCH_LIMIT);
		searcher.setMatchFilter(r -> r.getAddress().getOffset() % 2 == 0); // only even addresses

		searcher.findAll(accumulator, monitor);

		assertEquals(3, accumulator.size());
		Iterator<MemoryMatch> it = accumulator.iterator();
		assertMatch(0, "bob", it.next());
		assertMatch(6, "bob", it.next());
		assertMatch(24, "bob", it.next());
	}

	private AddressSet addrs() {
		return bytes.getAddressSet();
	}

	private void assertMatch(int address, String matchString, MemoryMatch match) {
		assertNotNull(match);
		assertEquals(addr(address), match.getAddress());
		assertEquals(matchString.length(), match.getLength());
		assertEqualBytes(bytes(matchString), match.getBytes());
	}

	private void assertEqualBytes(byte[] bytes1, byte[] bytes2) {
		assertEquals(bytes1.length, bytes2.length);
		for (int i = 0; i < bytes1.length; i++) {
			assertEquals(bytes1[i], bytes2[i]);
		}
	}

	private byte[] bytes(String string) {
		// remove spaces as they are there for formatting purposes
		string = string.replaceAll(" ", "");
		return string.getBytes();
	}

	private class TestByteSource implements AddressableByteSource {
		private AddressSet set = new AddressSet();
		private Map<Address, byte[]> map = new HashMap<>();

		TestByteSource(Address address, String data) {
			addBytes(address, data);
		}

		public AddressSet getAddressSet() {
			return set;
		}

		void addBytes(Address address, String data) {
			byte[] dataBytes = bytes(data);
			Address end = address.add(dataBytes.length - 1);
			int beforeNumAddressRanges = set.getNumAddressRanges();
			set.addRange(address, end);
			int afterNumAddressRanges = set.getNumAddressRanges();
			// this simplistic test implementation can't handle ranges that coalesce so make
			// sure our address set has an addition range in case we mess up writing a test
			assertEquals(beforeNumAddressRanges + 1, afterNumAddressRanges);
			map.put(address, dataBytes);
		}

		@Override
		public int getBytes(Address address, byte[] byteData, int length) {
			AddressRange range = set.getRangeContaining(address);
			if (range == null) {
				return 0;
			}
			Address minAddress = range.getMinAddress();
			int index = (int) address.subtract(minAddress);
			byte[] sourceBytes = map.get(minAddress);
			System.arraycopy(sourceBytes, index, byteData, 0, length);
			return length;
		}

		@Override
		public List<SearchRegion> getSearchableRegions() {
			return null;
		}

		@Override
		public void invalidate() {
			// ignore
		}
	}

	private Address addr(long offset) {
		return space.getAddress(offset);
	}
}
