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
package ghidra.util.search.trie;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.*;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

public class ByteTrieTest {

	ByteTrieIfc<String> trie;

	@Before
	public void setUp() throws Exception {
		trie = new ByteTrie<String>();
	}

	@Test
    public void testIsEmpty() throws Exception {
		assertTrue("failed empty on creation", trie.isEmpty());
		add(trie, "1", true);
		assertTrue("failed !empty after add", !trie.isEmpty());
	}

	@Test
    public void testExists() throws Exception {
		assertTrue("failed empty exists", !exists(trie, "1"));
		add(trie, "1", true);
		assertTrue("failed !empty exists", exists(trie, "1"));
		add(trie, "10101", true);
		assertTrue("failed 10101 exists", exists(trie, "10101"));
		add(trie, "10111", true);
		assertTrue("failed 10111 exists", exists(trie, "10111"));
	}

	@Test
    public void testFindAndGetValue() throws Exception {
		add(trie, "10101", true);
		ByteTrieNodeIfc<String> trieNode = find(trie, "101");
		assertNotNull("failed to find prefix 101", trieNode);
		assertEquals("wrong prefix for 101", "101", cvt(trieNode.getValue()));
		assertEquals("wrong length for 101", 3, trieNode.length());

		trieNode = find(trie, "10101");
		assertNotNull("failed to find prefix 10101", trieNode);
		assertEquals("wrong prefix for 10101", "10101", cvt(trieNode.getValue()));
		assertEquals("wrong length for 10101", 5, trieNode.length());

		trieNode = find(trie, "");
		assertNotNull("failed to find prefix ''", trieNode);
		assertEquals("wrong prefix for ''", "", cvt(trieNode.getValue()));
		assertEquals("wrong length for ''", 0, trieNode.length());
	}

	private String cvt(byte[] value) {
		return new String(value);
	}

	@Test
    public void testEmptyIterator() throws Exception {
		assertTrue("failed empty iterator", !iterator(trie).hasNext());
	}

	@Test
    public void testIterator() throws Exception {
		String[] values = new String[] { "1000", "0010", "0100", "0001", "0000", "1100", "0110" };
		TreeSet<String> expected = new TreeSet<String>();
		for (String value : values) {
			add(trie, value, true);
			expected.add(value);
		}
		int pos = 0;
		Iterator<String> expecteds = expected.iterator();
		Iterator<String> actuals = iterator(trie);
		while (expecteds.hasNext() && actuals.hasNext()) {
			String ex = expecteds.next();
			String ac = actuals.next();
			assertEquals("wrong value at position " + pos, ex, ac);
			++pos;
		}
		assertTrue("too few values in trie", !expecteds.hasNext());
		assertTrue("too many values in trie", !actuals.hasNext());
	}

	@Test
    public void testIterator2() throws Exception {
		String[] values =
			new String[] { "10000", "00010", "0100", "0000001", "", "0000", "1100", "0110", "0" };
		TreeSet<String> expected = new TreeSet<String>();
		for (String value : values) {
			add(trie, value, true);
			expected.add(value);
		}
		int pos = 0;
		Iterator<String> expecteds = expected.iterator();
		Iterator<String> actuals = iterator(trie);
		while (expecteds.hasNext() && actuals.hasNext()) {
			String ex = expecteds.next();
			String ac = actuals.next();
			assertEquals("wrong value at position " + pos, ex, ac);
			++pos;
		}
		assertTrue("too few values in trie", !expecteds.hasNext());
		assertTrue("too many values in trie", !actuals.hasNext());
	}

	@Test
    public void testIterator3() throws Exception {
		String[] values = new String[] { "1000", "0010", "0100", "0001", "0000", "1100", "0110" };
		TreeSet<String> expected = new TreeSet<String>();
		for (String value : values) {
			add(trie, value, true);
			expected.add(value);
		}
		int pos = 0;
		Iterator<String> expecteds = expected.iterator();
		Iterator<String> actuals = iterator2(trie);
		while (expecteds.hasNext() && actuals.hasNext()) {
			String ex = expecteds.next();
			String ac = actuals.next();
			assertEquals("wrong value at position " + pos, ex, ac);
			++pos;
		}
		assertTrue("too few values in trie", !expecteds.hasNext());
		assertTrue("too many values in trie", !actuals.hasNext());
	}

	@Test
    public void testIterator4() throws Exception {
		String[] values =
			new String[] { "10000", "00010", "0100", "0000001", "", "0000", "1100", "0110", "0" };
		TreeSet<String> expected = new TreeSet<String>();
		for (String value : values) {
			add(trie, value, true);
			expected.add(value);
		}
		int pos = 0;
		Iterator<String> expecteds = expected.iterator();
		Iterator<String> actuals = iterator2(trie);
		while (expecteds.hasNext() && actuals.hasNext()) {
			String ex = expecteds.next();
			String ac = actuals.next();
			assertEquals("wrong value at position " + pos, ex, ac);
			++pos;
		}
		assertTrue("too few values in trie", !expecteds.hasNext());
		assertTrue("too many values in trie", !actuals.hasNext());
	}

	@Test
    public void testSize() throws Exception {
		assertEquals("wrong size for empty", 0, trie.size());
		add(trie, "foo", true);
		assertEquals("wrong size for add foo", 1, trie.size());
		add(trie, "foo", false);
		assertEquals("wrong size for add foo (again)", 1, trie.size());
		add(trie, "bar", true);
		assertEquals("wrong size for add bar", 2, trie.size());
		add(trie, "", true);
		assertEquals("wrong size for add ''", 3, trie.size());
	}

	@Test
    public void testNumberOfNodes() throws Exception {
		assertEquals("wrong size for empty", 1, trie.numberOfNodes());
		add(trie, "00", true);
		assertEquals("wrong size for '00'", 3, trie.numberOfNodes());
		add(trie, "01", true);
		assertEquals("wrong size for '01'", 4, trie.numberOfNodes());
		add(trie, "0", true);
		assertEquals("wrong size for '0'", 4, trie.numberOfNodes());
		add(trie, "000", true);
		assertEquals("wrong size for '000'", 5, trie.numberOfNodes());
	}

	@Test
    public void testSearch1() throws Exception {
		add(trie, "a", true);
		add(trie, "ab", true);
		add(trie, "bc", true);
		add(trie, "bca", true);
		add(trie, "c", true);
		add(trie, "caa", true);

		List<SearchResult<Integer, String>> result =
			trie.search("abccab".getBytes(), TaskMonitorAdapter.DUMMY_MONITOR);

		assertEquals("wrong size result list", 7, result.size());
		expect(result, 0, "a");
		expect(result, 0, "ab");
		expect(result, 1, "bc");
		expect(result, 2, "c");
		expect(result, 3, "c");
		expect(result, 4, "a");
		expect(result, 4, "ab");
	}

	@Test
    public void testSearch2() throws Exception {
		add(trie, "he", true);
		add(trie, "she", true);
		add(trie, "his", true);
		add(trie, "hers", true);

		List<SearchResult<Integer, String>> result =
			trie.search("they shelled this hershey".getBytes(), TaskMonitorAdapter.DUMMY_MONITOR);

		assertEquals("wrong size result list", 8, result.size());
		expect(result, 1, "he");
		expect(result, 5, "she");
		expect(result, 6, "he");
		expect(result, 14, "his");
		expect(result, 18, "he");
		expect(result, 18, "hers");
		expect(result, 21, "she");
		expect(result, 22, "he");
	}

	@Test
    public void testSearch3() throws Exception {
		add(trie, "unstoppable", true);
		add(trie, "stop", true);
		add(trie, "top", true);
		add(trie, "to", true);
		add(trie, "stoppable", true);
		add(trie, "able", true);
		add(trie, "tables", true);

		List<SearchResult<Integer, String>> result =
			trie.search("unstoppable tables".getBytes(), TaskMonitorAdapter.DUMMY_MONITOR);

		assertEquals("wrong size result list", 8, result.size());
		expect(result, 0, "unstoppable");
		expect(result, 2, "stop");
		expect(result, 2, "stoppable");
		expect(result, 3, "to");
		expect(result, 3, "top");
		expect(result, 7, "able");
		expect(result, 12, "tables");
		expect(result, 13, "able");
	}

	private static void add(ByteTrieIfc<String> trie, String value, boolean shouldBeAdded) {
		boolean added = trie.add(value.getBytes(), value);
		assertEquals("added wrong", shouldBeAdded, added);
	}

	private static boolean exists(ByteTrieIfc<String> trie, String value) {
		return trie.find(value.getBytes()) != null;
	}

	private static ByteTrieNodeIfc<String> find(ByteTrieIfc<String> trie, String value) {
		return trie.find(value.getBytes());
	}

	private static void expect(List<SearchResult<Integer, String>> result, int position,
			String value) {
		for (SearchResult<Integer, String> searchResult : result) {
			if (searchResult.position == position && searchResult.item.equals(value)) {
				return;
			}
		}
		Assert.fail("did not find '" + value + "' at position " + position);
	}

	/**
	 * For testing only!
	 * @return iterator over manufactured Strings of byte[] in trie
	 * @throws CancelledException 
	 */
	private static Iterator<String> iterator(ByteTrieIfc<String> trie) throws CancelledException {
		final ArrayList<String> list = new ArrayList<String>();
		trie.inorder(TaskMonitorAdapter.DUMMY_MONITOR, new Op<String>() {
			@Override
			public void op(ByteTrieNodeIfc<String> node) {
				if (node.isTerminal()) {
					assertEquals("wrong node length", node.getValue().length, node.length());
					list.add(new String(node.getValue()));
				}
			}
		});
		return list.iterator();
	}

	/**
	 * For testing only!
	 * @return iterator over manufactured Strings of byte[] in trie
	 * @throws CancelledException 
	 */
	private static Iterator<String> iterator2(ByteTrieIfc<String> trie) throws CancelledException {
		final ArrayList<String> list = new ArrayList<String>();
		trie.inorder(TaskMonitorAdapter.DUMMY_MONITOR, new Op<String>() {
			@Override
			public void op(ByteTrieNodeIfc<String> node) {
				if (node.isTerminal()) {
					assertEquals("wrong node length", node.getValue().length, node.length());
					list.add(node.getItem());
				}
			}
		});
		return list.iterator();
	}
}
