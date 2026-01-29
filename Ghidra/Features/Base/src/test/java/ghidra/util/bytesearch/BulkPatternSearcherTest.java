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

import static org.junit.Assert.*;

import java.io.*;
import java.util.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.features.base.memsearch.bytesequence.ByteArrayByteSequence;
import ghidra.util.task.TaskMonitor;

public class BulkPatternSearcherTest {
	String data = "abbcabaaabbbcccba";

	private TestPattern a = new TestPattern("a");
	private TestPattern ab = new TestPattern("ab");
	private TestPattern abc = new TestPattern("abc");
	private TestPattern cab = new TestPattern("cab");
	private TestPattern bcc = new TestPattern("bcc");

	private BulkPatternSearcher<TestPattern> searcher;
	private List<Match<TestPattern>> results = new ArrayList<Match<TestPattern>>();

	@Before
	public void setUp() {
		List<TestPattern> patterns = List.of(a, ab, abc, cab, bcc);
		searcher = new BulkPatternSearcher<TestPattern>(patterns);
	}

	@Test
	public void testMatchWithIntoList() {
		searcher.search(data.getBytes(), results);
		Iterator<Match<TestPattern>> it = results.iterator();
		assertTrue(it.hasNext());
		assertMatch(it.next(), a, 0);
		assertMatch(it.next(), ab, 0);
		assertMatch(it.next(), cab, 3);
		assertMatch(it.next(), a, 4);
		assertMatch(it.next(), ab, 4);
		assertMatch(it.next(), a, 6);
		assertMatch(it.next(), a, 7);
		assertMatch(it.next(), a, 8);
		assertMatch(it.next(), ab, 8);
		assertMatch(it.next(), bcc, 11);
		assertMatch(it.next(), a, 16);
		assertFalse(it.hasNext());
	}

	@Test
	public void testMatchWithIntoListWithBufferLimit() {
		searcher.search(data.getBytes(), 5, results);
		Iterator<Match<TestPattern>> it = results.iterator();
		assertTrue(it.hasNext());
		assertMatch(it.next(), a, 0);
		assertMatch(it.next(), ab, 0);
		assertMatch(it.next(), a, 4);
		assertFalse(it.hasNext());
	}

	@Test
	public void testMatchWithIterator() {
		Iterator<Match<TestPattern>> it = searcher.search(data.getBytes());
		assertTrue(it.hasNext());
		assertMatch(it.next(), a, 0);
		assertMatch(it.next(), ab, 0);
		assertMatch(it.next(), cab, 3);
		assertMatch(it.next(), a, 4);
		assertMatch(it.next(), ab, 4);
		assertMatch(it.next(), a, 6);
		assertMatch(it.next(), a, 7);
		assertMatch(it.next(), a, 8);
		assertMatch(it.next(), ab, 8);
		assertMatch(it.next(), bcc, 11);
		assertMatch(it.next(), a, 16);
		assertFalse(it.hasNext());

	}

	@Test
	public void testMatchWithIteratorAndBufferLimit() {
		Iterator<Match<TestPattern>> it = searcher.search(data.getBytes(), 5);
		assertTrue(it.hasNext());
		assertMatch(it.next(), a, 0);
		assertMatch(it.next(), ab, 0);
		assertMatch(it.next(), a, 4);
		assertFalse(it.hasNext());
	}

	@Test
	public void testInputStream() throws IOException {
		TestPattern t = new TestPattern("test");
		TestPattern i = new TestPattern("input stream");
		TestPattern s = new TestPattern("stream");
		BulkPatternSearcher<TestPattern> Matcher = new BulkPatternSearcher<>(List.of(t, i, s));

		String input = "This is a test of the input stream";
		InputStream is = new ByteArrayInputStream(input.getBytes());

		Matcher.search(is, results, TaskMonitor.DUMMY);

		assertEquals(3, results.size());
		assertMatch(results.get(0), t, 10);
		assertMatch(results.get(1), i, 22);
		assertMatch(results.get(2), s, 28);
	}

	@Test
	public void testInputStreamWithMatchThatSpansBuffer() throws IOException {
		TestPattern p1 = new TestPattern("test");
		TestPattern p2 = new TestPattern("test of the");
		TestPattern p3 = new TestPattern("stream");
		BulkPatternSearcher<TestPattern> matcher = new BulkPatternSearcher<>(List.of(p1, p2, p3));
		matcher.setBufferSize(15);	// test with buffer so that a pattern crosses buffer boundary
		String input = "This is a test of the input stream";
		InputStream is = new ByteArrayInputStream(input.getBytes());

		matcher.search(is, -1, results, TaskMonitor.DUMMY);

		assertEquals(3, results.size());
		assertMatch(results.get(0), p1, 10);
		assertMatch(results.get(1), p2, 10);
		assertMatch(results.get(2), p3, 28);

	}

	@Test
	public void testInputStreamWithMaxReadSet() throws IOException {
		TestPattern t = new TestPattern("test");
		TestPattern i = new TestPattern("input stream");
		TestPattern s = new TestPattern("stream");
		BulkPatternSearcher<TestPattern> matcher = new BulkPatternSearcher<>(List.of(t, i, s));

		String input = "This is a test of the input stream";
		InputStream is = new ByteArrayInputStream(input.getBytes());

		matcher.search(is, 24, results, TaskMonitor.DUMMY);

		assertEquals(2, results.size());
		assertMatch(results.get(0), t, 10);
		assertMatch(results.get(1), i, 22);
	}

	@Test
	public void testDittedPattern() {
		TestPattern p1 = new TestPattern("b.t");
		TestPattern p2 = new TestPattern("t..t");
		TestPattern p3 = new TestPattern(".ba.");
		searcher = new BulkPatternSearcher<>(List.of(p1, p2, p3));

		String input = "bat baat bt abbt";
		Iterator<Match<TestPattern>> it = searcher.search(input.getBytes());
		assertTrue(it.hasNext());
		assertMatch(it.next(), p1, 0);
		assertMatch(it.next(), p3, 3);
		assertMatch(it.next(), p2, 7);
		assertMatch(it.next(), p1, 13);
		assertFalse(it.hasNext());
	}

	@Test
	public void testStatesFullyDedup() {
		TestPattern p1 = new TestPattern("..ab");
		TestPattern p2 = new TestPattern("..ac");
		TestPattern p3 = new TestPattern("axad");
		searcher = new BulkPatternSearcher<>(List.of(p1, p2, p3));

		/**
			This should produce the following search state graph. Each state indicates the 
			active patterns and the level (the # input bytes matched) and is shown as:
				  	
				(pattern, ..., level)
						
				                                    (p1,p2,p3,0)
				                                   /           \
				                                  a             !a (any input other than a)
				                                 /               \
				                                /                 \
				                         (p1,p2,p3,1)           (p1,p2,1)
				                        /           \                \                               
				                       x             !x              (any input)                            
				                      /               \                \                           
				                     /                 \                \                            
				                    /                   \                \                            
				                   /                     \                \                 
				            (p1,p2,p3,2)              (p1,p2,2)        (p1,p2,2) dup
				            /          \              /        \
		                   a            !a           a          !a
				          /              \          /            \
				   (p1,p2,p3,3)         null    (p1,p2,3)       null
		           /     |    \                /         \
		          b      c     d              b           c
		         /       |      \            /             \
		      (p1,4)  (p2,4)   (p3,4)    (p1,4) dup      (p2,4) dup
		*/

		assertEquals(10, searcher.getUniqueStateCount());

	}

	@Test
	public void testSearchBeginningOnly() {
		searcher.matches(data.getBytes(), data.length(), results);
		Iterator<Match<TestPattern>> it = results.iterator();
		assertTrue(it.hasNext());
		assertMatch(it.next(), a, 0);
		assertMatch(it.next(), ab, 0);
		assertFalse(it.hasNext());
	}

	@Test
	public void testByteSequenceStartsInMainEndsInPost() {
		TestPattern p = new TestPattern("joebob");
		search("xxxxjoexbob", "xxxjoe", "bob", p);
		assertEquals(1, results.size());
		assertMatch(results.get(0), p, 3);
	}

	@Test
	public void testPreSequencePatterns_patternStartsInPre_effectivelyStartInPre() {
		TestPattern p = new TestPattern("joe", "bob");

		// pre-pattern and effective start are both in pre sequence, so no match
		search("xxjoeb", "obxxx", "xxxx", p);
		assertTrue(results.isEmpty());
	}

	@Test
	public void testPreSequencePatterns_patternStartInPre_effectivelyStartsInMain() {
		TestPattern p = new TestPattern("joe", "bob");

		// pre-patterns starts in pre sequence, effective match start is in main, so this
		// is a match
		search("xxxxjoe", "bobxxx", "xxxx", p);
		assertEquals(1, results.size());
		assertMatch(results.get(0), p, -3);
	}

	@Test
	public void testPreSequencePatterns_patternStartsInMainEndsInPost() {
		TestPattern p = new TestPattern("joe", "bob");

		// create input such that pre-sequence and main sequence start in main, but pattern
		// ends in post sequence, so this is a match
		search("xxx", "xxjoeb", "obxx", p);
		assertEquals(1, results.size());
		assertMatch(results.get(0), p, 2);
	}

	@Test
	public void testPreSequencePattern_patternStartsInMain_effectStartInPost() {
		TestPattern p = new TestPattern("joe", "bob");

		// create input such that the pre-sequence starts in the main, but the actual pattern
		// match start is in the post sequence, so this in not a match

		search("xxx", "xxxjoe", "bob", p);
		assertTrue(results.isEmpty());
	}

	private void search(String preData, String mainData, String postData, TestPattern p) {
		ByteSequence pre = new ByteArrayByteSequence(preData);
		ByteSequence main = new ByteArrayByteSequence(mainData);
		ByteSequence post = new ByteArrayByteSequence(postData);
		ExtendedByteSequence sequence = new ExtendedByteSequence(main, pre, post, 10);

		BulkPatternSearcher<TestPattern> patternSearcher =
			new BulkPatternSearcher<TestPattern>(List.of(p));
		patternSearcher.search(sequence, results);

	}

	private void assertMatch(Match<TestPattern> match, TestPattern expectedPattern, int start) {
		assertEquals(new Match<>(expectedPattern, start, expectedPattern.getSize()), match);
	}

	private class TestPattern extends DittedBitSequence {

		private String inputString;
		private int preSequenceLength;

		public TestPattern(String inputString) {
			this("", inputString);
		}

		public TestPattern(String preSequence, String matchSequence) {
			super(getBytes(preSequence + matchSequence), getMask(preSequence + matchSequence));
			this.inputString = preSequence + matchSequence;
			this.preSequenceLength = preSequence.length();
		}

		private static byte[] getMask(String inputString) {
			byte[] mask = new byte[inputString.length()];
			for (int i = 0; i < inputString.length(); i++) {
				if (inputString.charAt(i) == '.') {
					mask[i] = 0;
				}
				else {
					mask[i] = (byte) 0xff;
				}
			}
			return mask;
		}

		private static byte[] getBytes(String inputString) {
			byte[] bytes = inputString.getBytes();
			for (int i = 0; i < inputString.length(); i++) {
				if (inputString.charAt(i) == '.') {
					bytes[i] = 0;
				}
			}
			return bytes;
		}

		@Override
		public String toString() {
			return inputString;
		}

		@Override
		public int getPreSequenceLength() {
			return preSequenceLength;
		}

	}
}
