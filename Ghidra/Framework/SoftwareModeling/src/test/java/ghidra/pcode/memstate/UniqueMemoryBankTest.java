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
package ghidra.pcode.memstate;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.memstate.UniqueMemoryBank.WordInfo;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;

public class UniqueMemoryBankTest extends AbstractGenericTest {

	private AddressSpace uniqueSpace;
	private UniqueMemoryBank uniqueBank;
	private byte[] eightTestBytes = new byte[] { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7 };
	private byte[] eightZeroBytes = new byte[8];
	private byte[] sixteenTestBytes = new byte[] { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9,
		0xa, 0xb, 0xc, 0xd, 0xe, 0xf };

	@Before
	public void setUp() {
		uniqueSpace = new GenericAddressSpace("unique", 64, AddressSpace.TYPE_UNIQUE, 0);
		uniqueBank = new UniqueMemoryBank(uniqueSpace, false);
	}

	public UniqueMemoryBankTest() {
		super();
	}

	@Test
	public void WordInfoBasicTest() {
		WordInfo info = new WordInfo();
		assertFalse(info.isEntireWordInitialized());
		info.setByte((byte) 0x0, 0);
		assertFalse(info.isEntireWordInitialized());
		info.setByte((byte) 0x1, 1);
		assertFalse(info.isEntireWordInitialized());
		info.setByte((byte) 0x2, 2);
		assertFalse(info.isEntireWordInitialized());
		info.setByte((byte) 0x3, 3);
		assertFalse(info.isEntireWordInitialized());
		info.setByte((byte) 0x4, 4);
		assertFalse(info.isEntireWordInitialized());
		info.setByte((byte) 0x5, 5);
		assertFalse(info.isEntireWordInitialized());
		info.setByte((byte) 0x6, 6);
		assertFalse(info.isEntireWordInitialized());
		info.setByte((byte) 0x7, 7);
		assertTrue(info.isEntireWordInitialized());
		for (int i = 0; i < 8; ++i) {
			assertEquals((byte) i, info.getByte(i));
		}
	}

	@Test(expected = LowlevelError.class)
	public void testGetUnitializedByte() {
		WordInfo info = new WordInfo();
		info.setByte((byte) 0, 0);
		info.setByte((byte) 1, 1);
		info.setByte((byte) 3, 3);
		info.setByte((byte) 4, 4);
		info.setByte((byte) 5, 5);
		info.setByte((byte) 6, 6);
		info.setByte((byte) 7, 7);
		@SuppressWarnings("unused")
		byte val = info.getByte(2);
	}

	@Test
	public void testSimpleRead() {
		uniqueBank.setChunk(0x1000, 8, eightTestBytes);
		byte[] dest = new byte[8];
		int numBytes = uniqueBank.getChunk(0x1000, 8, dest, true);
		assertEquals(8, numBytes);
		assertTrue(Arrays.equals(dest, eightTestBytes));
	}

	@Test
	public void testDifferentlySizedReads() {
		uniqueBank.setChunk(0x1000, 8, eightTestBytes);
		byte[] dest = new byte[4];
		int numBytes = uniqueBank.getChunk(0x1000, 4, dest, true);
		assertEquals(4, numBytes);
		assertTrue(Arrays.equals(dest, new byte[] { 0x0, 0x1, 0x2, 0x3 }));
		numBytes = uniqueBank.getChunk(0x1004, 4, dest, true);
		assertEquals(4, numBytes);
		assertTrue(Arrays.equals(dest, new byte[] { 0x4, 0x5, 0x6, 0x7 }));
	}

	@Test
	public void testLargeReadWrite() {
		uniqueBank.setChunk(0x1004, 16, sixteenTestBytes);
		byte[] dest = new byte[16];
		int numBytes = uniqueBank.getChunk(0x1004, 16, dest, true);
		assertEquals(16, numBytes);
		assertTrue(Arrays.equals(dest, sixteenTestBytes));

		byte[] largeSrc = new byte[64];
		for (int i = 0; i < 64; ++i) {
			largeSrc[i] = (byte) (i + 1);
		}
		uniqueBank.setChunk(0x1007, 64, largeSrc);
		dest = new byte[64];
		numBytes = uniqueBank.getChunk(0x1007, 64, dest, true);
		assertEquals(64, numBytes);
		assertTrue(Arrays.equals(dest, largeSrc));
	}

	@Test
	public void testReadAcrossUndefined() {
		byte[] fourBytes = new byte[] { 0x11, 0x22, 0x33, 0x44 };
		uniqueBank.setChunk(0x1007, 4, fourBytes);
		uniqueBank.setChunk(0x100c, 4, fourBytes);
		byte[] dest = new byte[9];
		int numBytes = uniqueBank.getChunk(0x1007, 9, dest, true);
		assertEquals(4, numBytes);
		assertEquals(0x11, dest[0]);
		assertEquals(0x22, dest[1]);
		assertEquals(0x33, dest[2]);
		assertEquals(0x44, dest[3]);
	}

	@Test
	public void testNonAlignedReadWrite() {
		byte[] fourBytes = new byte[] { 0x11, 0x22, 0x33, 0x44 };
		uniqueBank.setChunk(0x1004, 4, fourBytes);
		byte[] dest = new byte[4];
		int numBytes = uniqueBank.getChunk(0x1004, 4, dest, true);
		assertEquals(4, numBytes);
		assertTrue(Arrays.equals(fourBytes, dest));
	}

	@Test
	public void testOverlappingReadWrite() {
		uniqueBank.setChunk(0x1000, 16, sixteenTestBytes);
		uniqueBank.setChunk(0x1004, 8, eightZeroBytes);
		byte[] dest = new byte[16];
		int numBytes = uniqueBank.getChunk(0x1000, 16, dest, true);
		assertEquals(16, numBytes);
		for (int i = 0; i < 16; ++i) {
			if (i > 3 && i < 12) {
				assertEquals(0, dest[i]);
			}
			else {
				assertEquals(i, dest[i]);
			}
		}
	}

	@Test
	public void testOneByteRead() {
		byte[] one = new byte[] { (byte) 0x7f };
		uniqueBank.setChunk(0x1000, 1, one);
		byte[] dest = new byte[16];
		int numBytes = uniqueBank.getChunk(0x1000, 1, dest, false);
		assertEquals(1, numBytes);
		assertEquals(dest[0], (byte) 0x7f);

	}

	@Test
	public void testClear() {
		uniqueBank.setChunk(0x1000, 8, eightTestBytes);
		byte[] dest = new byte[8];
		uniqueBank.clear();
		int numBytes = uniqueBank.getChunk(0x1000, 8, dest, true);
		assertEquals(0, numBytes);
		numBytes = uniqueBank.getChunk(0x1000, 7, dest, true);
		assertEquals(0, numBytes);
		numBytes = uniqueBank.getChunk(0x1000, 6, dest, true);
		assertEquals(0, numBytes);
		numBytes = uniqueBank.getChunk(0x1000, 5, dest, true);
		assertEquals(0, numBytes);
		numBytes = uniqueBank.getChunk(0x1000, 4, dest, true);
		assertEquals(0, numBytes);
		numBytes = uniqueBank.getChunk(0x1000, 3, dest, true);
		assertEquals(0, numBytes);
		numBytes = uniqueBank.getChunk(0x1000, 2, dest, true);
		assertEquals(0, numBytes);
		numBytes = uniqueBank.getChunk(0x1000, 1, dest, true);
		assertEquals(0, numBytes);
		numBytes = uniqueBank.getChunk(0x1000, 0, dest, true);
		assertEquals(0, numBytes);
	}

	@Test
	public void testSimpleOverwrite() {
		uniqueBank.setChunk(0x1000, 8, eightTestBytes);
		byte[] dest = new byte[8];
		int numBytes = uniqueBank.getChunk(0x1000, 8, dest, true);
		assertEquals(8, numBytes);
		assertTrue(Arrays.equals(dest, eightTestBytes));
		uniqueBank.setChunk(0x1000, 8, eightZeroBytes);
		numBytes = uniqueBank.getChunk(0x1000, 8, dest, true);
		assertEquals(8, numBytes);
		assertTrue(Arrays.equals(dest, eightZeroBytes));
	}

	@Test(expected = LowlevelError.class)
	public void testUnitializedReadStop() {
		byte[] dest = new byte[16];
		uniqueBank.getChunk(0x1000, 0x10, dest, false);
	}

	@Test
	public void testUnitializedReadContinue() {
		byte[] dest = new byte[16];
		int bytesRead = uniqueBank.getChunk(0x1000, 0x10, dest, true);
		assertEquals(0, bytesRead);
	}

	@SuppressWarnings("unused")
	@Test(expected = UnsupportedOperationException.class)
	public void testGetPageException() {
		MemoryPage page = uniqueBank.getPage(0);
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testSetPageException() {
		uniqueBank.setPage(0, new byte[0], 0, 4096, 0);
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testSetPageInitializedException() {
		uniqueBank.setPageInitialized(0, true, 0, 4096, 0);
	}

	//possibly add:
	//zero-byte read/write
	//try to write more bytes than the array has
	//try to read more bytes into the array than it has

}
