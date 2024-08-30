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
import ghidra.features.base.memsearch.matcher.MaskedByteSequenceByteMatcher;

public class MaskedBytesSequenceByteMatcherTest {

	private ExtendedByteSequence byteSequence;

	@Before
	public void setUp() {

		ByteSequence main = new ByteArrayByteSequence(makeBytes(1, 2, 3, 2, 4, 5, 2, 6, 2, 3, 2));
		ByteSequence extra = new ByteArrayByteSequence(makeBytes(4, 1, 1, 3, 2, 4));

		byteSequence = new ExtendedByteSequence(main, extra, 100);

	}

	@Test
	public void testSimplePatterWithOneMatchCrossingBoundary() {

		byte[] searchBytes = makeBytes(3, 2, 4);
		ByteMatcher byteMatcher = new MaskedByteSequenceByteMatcher("", searchBytes, null);

		Iterator<ByteMatch> it = byteMatcher.match(byteSequence).iterator();

		assertTrue(it.hasNext());
		assertEquals(new ByteMatch(2, 3), it.next());

		assertTrue(it.hasNext());
		assertEquals(new ByteMatch(9, 3), it.next());

		assertFalse(it.hasNext());

	}

	@Test
	public void testSimplePatterWithOneMatchCrossingBoundaryNoHasNextCalls() {

		byte[] searchBytes = makeBytes(3, 2, 4);
		ByteMatcher byteMatcher = new MaskedByteSequenceByteMatcher("", searchBytes, null);

		Iterator<ByteMatch> it = byteMatcher.match(byteSequence).iterator();

		assertEquals(new ByteMatch(2, 3), it.next());
		assertEquals(new ByteMatch(9, 3), it.next());
		assertNull(it.next());
	}

	@Test
	public void testMaskPattern() {

		byte[] searchBytes = makeBytes(2, 0, 2);
		byte[] masks = makeBytes(0xff, 0x00, 0xff);
		ByteMatcher byteMatcher =
			new MaskedByteSequenceByteMatcher("", searchBytes, masks, null);

		Iterator<ByteMatch> it = byteMatcher.match(byteSequence).iterator();

		assertEquals(new ByteMatch(1, 3), it.next());
		assertEquals(new ByteMatch(6, 3), it.next());
		assertEquals(new ByteMatch(8, 3), it.next());
		assertNull(it.next());
	}

	@Test
	public void testPatternStartButNotEnoughExtraBytes() {
		byte[] searchBytes = makeBytes(6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
		byte[] masks = makeBytes(0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
		ByteMatcher byteMatcher =
			new MaskedByteSequenceByteMatcher("", searchBytes, masks, null);

		Iterator<ByteMatch> it = byteMatcher.match(byteSequence).iterator();
		assertFalse(it.hasNext());
	}

	@Test
	public void testGetDescription() {
		byte[] searchBytes = makeBytes(1, 2, 3, 0xaa);
		ByteMatcher byteMatcher = new MaskedByteSequenceByteMatcher("", searchBytes, null);

		assertEquals("01 02 03 aa", byteMatcher.getDescription());
	}

	private static byte[] makeBytes(int... byteValues) {
		byte[] bytes = new byte[byteValues.length];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) byteValues[i];
		}
		return bytes;
	}
}
