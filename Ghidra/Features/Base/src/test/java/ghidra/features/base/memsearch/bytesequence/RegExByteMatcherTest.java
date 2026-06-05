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
package ghidra.features.base.memsearch.bytesequence;

import static org.junit.Assert.*;

import java.util.Iterator;

import org.junit.Before;
import org.junit.Test;

import ghidra.features.base.memsearch.matcher.*;
import ghidra.util.bytesearch.*;

public class RegExByteMatcherTest {
	private ExtendedByteSequence byteSequence;

	@Before
	public void setUp() {
		ByteSequence pre = new ByteArrayByteSequence(makeBytes(""));
		ByteSequence main = new ByteArrayByteSequence(makeBytes("one two three tw"));
		ByteSequence extra = new ByteArrayByteSequence(makeBytes("o four two five"));
		byteSequence = new ExtendedByteSequence(main, pre, extra, 100);

	}

	@Test
	public void testSimplePatternWithOneMatchCrossingBoundary() {

		RegExByteMatcher byteMatcher = new RegExByteMatcher("two", null);
		SearchData searchData = byteMatcher.getSearchData();

		Iterator<Match<SearchData>> it = byteMatcher.match(byteSequence).iterator();

		assertTrue(it.hasNext());
		assertEquals(new Match<>(searchData, 4, 3), it.next());

		assertTrue(it.hasNext());
		assertEquals(new Match<>(searchData, 14, 3), it.next());

		assertFalse(it.hasNext());

	}

	@Test
	public void testSimplePatternWithOneMatchCrossingBoundaryNoHasNextCalls() {

		RegExByteMatcher byteMatcher = new RegExByteMatcher("two", null);
		SearchData searchData = byteMatcher.getSearchData();

		Iterator<Match<SearchData>> it = byteMatcher.match(byteSequence).iterator();

		assertEquals(new Match<>(searchData, 4, 3), it.next());
		assertEquals(new Match<>(searchData, 14, 3), it.next());
		assertNull(it.next());
	}

	@Test
	public void testNoMatch() {

		ByteMatcher<SearchData> byteMatcher = new RegExByteMatcher("apple", null);

		Iterator<Match<SearchData>> it = byteMatcher.match(byteSequence).iterator();
		assertFalse(it.hasNext());
	}

	@Test
	public void testPositiveLookBehindAcrossBuffers() {
		ByteSequence pre = new ByteArrayByteSequence(makeBytes("bbb bob bob aaa"));
		ByteSequence main = new ByteArrayByteSequence(makeBytes(" bob bob aaa bob"));
		ByteSequence post = null;

		byteSequence = new ExtendedByteSequence(main, pre, post, 100);
		RegExByteMatcher byteMatcher = new RegExByteMatcher("(?<=aaa )bob", null);
		SearchData searchData = byteMatcher.getSearchData();

		Iterator<Match<SearchData>> it = byteMatcher.match(byteSequence).iterator();
		assertTrue(it.hasNext());
		assertEquals(new Match<>(searchData, 1, 3), it.next());
		assertEquals(new Match<>(searchData, 13, 3), it.next());
		assertFalse(it.hasNext());

	}

	@Test
	public void testPositiveLookBehindAcrossBuffers_ThatStartBeforeMainAreIgnored() {
		ByteSequence pre = new ByteArrayByteSequence(makeBytes("aaa joe aaa bo"));
		ByteSequence main = new ByteArrayByteSequence(makeBytes("b bob bob bob"));
		ByteSequence post = null;

		byteSequence = new ExtendedByteSequence(main, pre, post, 100);
		RegExByteMatcher byteMatcher = new RegExByteMatcher("(?<=aaa )bob", null);

		Iterator<Match<SearchData>> it = byteMatcher.match(byteSequence).iterator();
		assertFalse(it.hasNext());
	}

	@Test
	public void testPositiveLookBehindAcrossBuffers_ThatStartInPostAreIgnored() {
		ByteSequence pre = null;
		ByteSequence main = new ByteArrayByteSequence(makeBytes("bbb bob bob aaa "));
		ByteSequence post = new ByteArrayByteSequence(makeBytes("bob bob aaa bob"));

		byteSequence = new ExtendedByteSequence(main, pre, post, 100);
		RegExByteMatcher byteMatcher = new RegExByteMatcher("(?<=aaa )bob", null);

		Iterator<Match<SearchData>> it = byteMatcher.match(byteSequence).iterator();
		assertFalse(it.hasNext());
	}

	@Test
	public void testNegativeLookBehindAcrossBuffers() {
		ByteSequence pre = new ByteArrayByteSequence(makeBytes("aaa bob bob aaa"));
		ByteSequence main = new ByteArrayByteSequence(makeBytes(" bob bob aaa bob"));
		ByteSequence post = null;

		byteSequence = new ExtendedByteSequence(main, pre, post, 100);
		RegExByteMatcher byteMatcher = new RegExByteMatcher("(?<!aaa )bob", null);
		SearchData searchData = byteMatcher.getSearchData();

		Iterator<Match<SearchData>> it = byteMatcher.match(byteSequence).iterator();
		assertTrue(it.hasNext());
		assertEquals(new Match<>(searchData, 5, 3), it.next());
		assertFalse(it.hasNext());
	}

	private byte[] makeBytes(String string) {
		byte[] bytes = new byte[string.length()];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) string.charAt(i);
		}
		return bytes;
	}

}
