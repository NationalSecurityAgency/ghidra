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

import org.junit.Test;

public class ByteArrayByteSequenceTest {
	private ByteSequence main = new ByteArrayByteSequence((byte) 0, (byte) 1, (byte) 2, (byte) 3);
	private ByteSequence extra = new ByteArrayByteSequence((byte) 4, (byte) 5);
	private ByteSequence extended = new ExtendedByteSequence(main, extra, 100);

	@Test
	public void testSimpleByteSeqeunce() {
		assertEquals(4, main.getLength());
		assertEquals(0, main.getByte(0));
		assertEquals(1, main.getByte(1));
		assertEquals(2, main.getByte(2));
		assertEquals(3, main.getByte(3));
		try {
			main.getByte(4);
			fail("Expected index out of bounds exception");
		}
		catch (IndexOutOfBoundsException e) {
			// expected
		}
	}

	@Test
	public void testSimpleGetAvailableBytes() {
		assertTrue(main.hasAvailableBytes(0, 1));
		assertTrue(main.hasAvailableBytes(0, 2));
		assertTrue(main.hasAvailableBytes(0, 3));
		assertTrue(main.hasAvailableBytes(0, 4));
		assertFalse(main.hasAvailableBytes(0, 5));

		assertTrue(main.hasAvailableBytes(1, 1));
		assertTrue(main.hasAvailableBytes(1, 2));
		assertTrue(main.hasAvailableBytes(1, 3));
		assertFalse(main.hasAvailableBytes(1, 4));
		assertFalse(main.hasAvailableBytes(1, 5));

		assertTrue(main.hasAvailableBytes(2, 1));
		assertTrue(main.hasAvailableBytes(2, 2));
		assertFalse(main.hasAvailableBytes(2, 3));
		assertFalse(main.hasAvailableBytes(2, 4));

		assertTrue(main.hasAvailableBytes(3, 1));
		assertFalse(main.hasAvailableBytes(3, 2));
		assertFalse(main.hasAvailableBytes(3, 3));

		assertFalse(main.hasAvailableBytes(4, 1));
		assertFalse(main.hasAvailableBytes(4, 2));

	}

	@Test
	public void testExtendedByteSeqeunce() {
		assertEquals(4, extended.getLength());
		assertEquals(0, extended.getByte(0));
		assertEquals(1, extended.getByte(1));
		assertEquals(2, extended.getByte(2));
		assertEquals(3, extended.getByte(3));
		assertEquals(4, extended.getByte(4));
		assertEquals(5, extended.getByte(5));
		try {
			extended.getByte(6);
			fail("Expected index out of bounds exception");
		}
		catch (IndexOutOfBoundsException e) {
			// expected
		}
	}

	@Test
	public void testExtendedGetAvailableBytes() {

		assertTrue(extended.hasAvailableBytes(0, 1));
		assertTrue(extended.hasAvailableBytes(0, 2));
		assertTrue(extended.hasAvailableBytes(0, 3));
		assertTrue(extended.hasAvailableBytes(0, 4));
		assertTrue(extended.hasAvailableBytes(0, 5));
		assertTrue(extended.hasAvailableBytes(0, 6));
		assertFalse(extended.hasAvailableBytes(0, 7));

		assertTrue(extended.hasAvailableBytes(1, 1));
		assertTrue(extended.hasAvailableBytes(1, 2));
		assertTrue(extended.hasAvailableBytes(1, 3));
		assertTrue(extended.hasAvailableBytes(1, 4));
		assertTrue(extended.hasAvailableBytes(1, 5));
		assertFalse(extended.hasAvailableBytes(1, 6));
		assertFalse(extended.hasAvailableBytes(1, 7));

		assertTrue(extended.hasAvailableBytes(2, 1));
		assertTrue(extended.hasAvailableBytes(2, 2));
		assertTrue(extended.hasAvailableBytes(2, 3));
		assertTrue(extended.hasAvailableBytes(2, 4));
		assertFalse(extended.hasAvailableBytes(2, 5));
		assertFalse(extended.hasAvailableBytes(2, 6));

		assertTrue(extended.hasAvailableBytes(3, 1));
		assertTrue(extended.hasAvailableBytes(3, 2));
		assertTrue(extended.hasAvailableBytes(3, 3));
		assertFalse(extended.hasAvailableBytes(3, 4));
		assertFalse(extended.hasAvailableBytes(3, 5));

		assertTrue(extended.hasAvailableBytes(4, 1));
		assertTrue(extended.hasAvailableBytes(4, 2));
		assertFalse(extended.hasAvailableBytes(4, 3));
		assertFalse(extended.hasAvailableBytes(4, 4));

		assertTrue(extended.hasAvailableBytes(5, 1));
		assertFalse(extended.hasAvailableBytes(5, 2));
		assertFalse(extended.hasAvailableBytes(5, 3));

		assertFalse(extended.hasAvailableBytes(6, 1));

	}

}
