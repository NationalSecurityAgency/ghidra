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

public class CaseInsensitiveByteTrieTest {

	private final class CaseInsensitiveStringComparator implements Comparator<String> {
		@Override
		public int compare(String arg0, String arg1) {
			return arg0.compareToIgnoreCase(arg1);
		}
	}

	ByteTrieIfc<String> trie;

	@Before
	public void setUp() throws Exception {
		trie = new CaseInsensitiveByteTrie<String>();
	}

	@Test
	public void testIsEmpty() throws Exception {
		assertTrue("failed empty on creation", trie.isEmpty());
		add(trie, "a", true);
		assertTrue("failed !empty after add", !trie.isEmpty());
	}

	@Test
	public void testExists() throws Exception {
		assertTrue("failed empty exists", !exists(trie, "a"));
		assertTrue("failed empty exists", !exists(trie, "A"));
		add(trie, "a", true);
		assertTrue("failed !empty exists", exists(trie, "a"));
		assertTrue("failed !empty exists", exists(trie, "A"));
		add(trie, "ab", true);
		assertTrue("failed ab exists", exists(trie, "ab"));
		assertTrue("failed AB exists", exists(trie, "AB"));
		add(trie, "ac", true);
		assertTrue("failed ac exists", exists(trie, "ac"));
		assertTrue("failed AC exists", exists(trie, "AC"));
	}

	@Test
	public void testFindAndGetValue() throws Exception {
		add(trie, "aBcde", true);
		ByteTrieNodeIfc<String> trieNode = find(trie, "abc");
		assertNotNull("failed to find prefix abc", trieNode);
		assertEquals("wrong prefix for abc", "aBc", cvt(trieNode.getValue()));
		assertEquals("wrong length for abc", 3, trieNode.length());

		trieNode = find(trie, "ABC");
		assertNotNull("failed to find prefix ABC", trieNode);
		assertEquals("wrong prefix for ABC", "aBc", cvt(trieNode.getValue()));
		assertEquals("wrong length for ABC", 3, trieNode.length());

		trieNode = find(trie, "abcDE");
		assertNotNull("failed to find prefix abcDE", trieNode);
		assertEquals("wrong prefix for abcDE", "aBcde", cvt(trieNode.getValue()));
		assertEquals("wrong length for abcDE", 5, trieNode.length());

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
		String[] values = new String[] { "baAa", "AabA", "aBaA", "aAab", "AaAA", "Bbaa", "aBBa" };
		TreeSet<String> expected = new TreeSet<String>(new CaseInsensitiveStringComparator());
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
			assertTrue("wrong value at position " + pos, ex.equalsIgnoreCase(ac));
			++pos;
		}
		assertTrue("too few values in trie", !expecteds.hasNext());
		assertTrue("too many values in trie", !actuals.hasNext());
	}

	@Test
	public void testIterator2() throws Exception {
		String[] values =
			new String[] { "baaAA", "aAaBa", "ABaa", "AaaaaAb", "", "aaAA", "BBAA", "AbbA", "a" };
		TreeSet<String> expected = new TreeSet<String>(new CaseInsensitiveStringComparator());
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
			assertTrue("wrong value at position " + pos, ex.equalsIgnoreCase(ac));
			++pos;
		}
		assertTrue("too few values in trie", !expecteds.hasNext());
		assertTrue("too many values in trie", !actuals.hasNext());
	}

	@Test
	public void testIterator3() throws Exception {
		String[] values = new String[] { "baAa", "AabA", "aBaA", "aAab", "AaAA", "Bbaa", "aBBa" };
		TreeSet<String> expected = new TreeSet<String>(new CaseInsensitiveStringComparator());
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
			new String[] { "baaAA", "aAaBa", "ABaa", "AaaaaAb", "", "aaAA", "BBAA", "AbbA", "a" };
		TreeSet<String> expected = new TreeSet<String>(new CaseInsensitiveStringComparator());
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
		add(trie, "fOo", false);
		assertEquals("wrong size for add fOo (again)", 1, trie.size());
		add(trie, "bar", true);
		assertEquals("wrong size for add bar", 2, trie.size());
		add(trie, "", true);
		assertEquals("wrong size for add ''", 3, trie.size());
	}

	@Test
	public void testNumberOfNodes() throws Exception {
		assertEquals("wrong size for empty", 1, trie.numberOfNodes());
		add(trie, "aa", true);
		assertEquals("wrong size for 'aa'", 3, trie.numberOfNodes());
		add(trie, "Ab", true);
		assertEquals("wrong size for 'Ab'", 4, trie.numberOfNodes());
		add(trie, "A", true);
		assertEquals("wrong size for 'A'", 4, trie.numberOfNodes());
		add(trie, "aAa", true);
		assertEquals("wrong size for 'aAa'", 5, trie.numberOfNodes());
	}

	@Test
	public void testSearch1() throws Exception {
		add(trie, "a", true);
		add(trie, "Ab", true);
		add(trie, "bc", true);
		add(trie, "BCa", true);
		add(trie, "C", true);
		add(trie, "cAa", true);

		List<SearchResult<Integer, String>> result =
			trie.search("abccab".getBytes(), TaskMonitorAdapter.DUMMY_MONITOR);

		assertEquals("wrong size result list", 7, result.size());
		expect(result, 0, "a");
		expect(result, 0, "Ab");
		expect(result, 1, "bc");
		expect(result, 2, "C");
		expect(result, 3, "C");
		expect(result, 4, "a");
		expect(result, 4, "Ab");
	}

	@Test
	public void testSearch2() throws Exception {
		add(trie, "hE", true);
		add(trie, "sHe", true);
		add(trie, "hiS", true);
		add(trie, "Hers", true);

		List<SearchResult<Integer, String>> result =
			trie.search("they shelled this hershey".getBytes(), TaskMonitorAdapter.DUMMY_MONITOR);

		assertEquals("wrong size result list", 8, result.size());
		expect(result, 1, "hE");
		expect(result, 5, "sHe");
		expect(result, 6, "hE");
		expect(result, 14, "hiS");
		expect(result, 18, "hE");
		expect(result, 18, "Hers");
		expect(result, 21, "sHe");
		expect(result, 22, "hE");
	}

	@Test
	public void testSearch3() throws Exception {
		add(trie, "unStoppable", true);
		add(trie, "sTop", true);
		add(trie, "toP", true);
		add(trie, "To", true);
		add(trie, "stoppAble", true);
		add(trie, "abLE", true);
		add(trie, "tAblEs", true);

		List<SearchResult<Integer, String>> result =
			trie.search("unstoppable tables".getBytes(), TaskMonitorAdapter.DUMMY_MONITOR);

		assertEquals("wrong size result list", 8, result.size());
		expect(result, 0, "unStoppable");
		expect(result, 2, "sTop");
		expect(result, 2, "stoppAble");
		expect(result, 3, "To");
		expect(result, 3, "toP");
		expect(result, 7, "abLE");
		expect(result, 12, "tAblEs");
		expect(result, 13, "abLE");
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
