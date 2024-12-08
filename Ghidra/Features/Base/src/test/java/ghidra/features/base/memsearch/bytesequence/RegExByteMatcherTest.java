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

import ghidra.features.base.memsearch.matcher.ByteMatcher;
import ghidra.features.base.memsearch.matcher.ByteMatcher.ByteMatch;
import ghidra.features.base.memsearch.matcher.RegExByteMatcher;

public class RegExByteMatcherTest {
	private ExtendedByteSequence byteSequence;

	@Before
	public void setUp() {
		ByteSequence main = new ByteArrayByteSequence(makeBytes("one two three tw"));
		ByteSequence extra = new ByteArrayByteSequence(makeBytes("o four two five"));
		byteSequence = new ExtendedByteSequence(main, extra, 100);

	}

	@Test
	public void testSimplePatternWithOneMatchCrossingBoundary() {

		ByteMatcher byteMatcher = new RegExByteMatcher("two", null);

		Iterator<ByteMatch> it = byteMatcher.match(byteSequence).iterator();

		assertTrue(it.hasNext());
		assertEquals(new ByteMatch(4, 3), it.next());

		assertTrue(it.hasNext());
		assertEquals(new ByteMatch(14, 3), it.next());

		assertFalse(it.hasNext());

	}

	@Test
	public void testSimplePatternWithOneMatchCrossingBoundaryNoHasNextCalls() {

		ByteMatcher byteMatcher = new RegExByteMatcher("two", null);

		Iterator<ByteMatch> it = byteMatcher.match(byteSequence).iterator();

		assertEquals(new ByteMatch(4, 3), it.next());
		assertEquals(new ByteMatch(14, 3), it.next());
		assertNull(it.next());
	}

	@Test
	public void testNoMatch() {

		ByteMatcher byteMatcher = new RegExByteMatcher("apple", null);

		Iterator<ByteMatch> it = byteMatcher.match(byteSequence).iterator();
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
