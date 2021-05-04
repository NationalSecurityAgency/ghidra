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
package ghidra.app.util.bin;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.Arrays;

import org.junit.Test;

public class ExtentsByteProviderTest {
	private ByteArrayProvider bap(int... values) {
		byte[] bytes = new byte[values.length];
		for (int i = 0; i < values.length; i++) {
			bytes[i] = (byte) values[i];
		}
		return new ByteArrayProvider(bytes);
	}

	/*
	 * "NN 01 NN 03 NN 05 NN 07 NN 09"... (NN = blockNumber, 00-FF = offset in block)
	 */
	private ByteArrayProvider patternedBAP(int bs, int count) {
		byte[] bytes = new byte[bs * count];
		for (int blockNum = 0; blockNum < count; blockNum++) {
			int blockStart = blockNum * bs;
			Arrays.fill(bytes, blockStart, blockStart + bs, (byte) blockNum);
			for (int i = 1; i < bs; i += 2) {
				bytes[i + blockStart] = (byte) (i % 256);
			}
		}
		return new ByteArrayProvider(bytes);
	}

	@Test(expected = IOException.class)
	public void testEmptyExtentBP() throws IOException {
		try (ExtentsByteProvider ebp = new ExtentsByteProvider(bap(55), null)) {
			ebp.readByte(0);
		}
	}

	@Test
	public void testExtentBP_SingleByteRead() throws IOException {
		try (ExtentsByteProvider ebp = new ExtentsByteProvider(patternedBAP(10, 10), null)) {
			ebp.addExtent(10, 10);
			ebp.addExtent(0, 1);
			ebp.addExtent(0, 10);

			assertEquals(21, ebp.length());

			assertEquals(0x01, ebp.readByte(0));
			assertEquals(0x01, ebp.readByte(1));
			assertEquals(0x01, ebp.readByte(2));
			assertEquals(0x03, ebp.readByte(3));
			assertEquals(0x09, ebp.readByte(9));

			assertEquals(0x00, ebp.readByte(11));
			assertEquals(0x01, ebp.readByte(12));
			assertEquals(0x00, ebp.readByte(13));
			assertEquals(0x03, ebp.readByte(14));
			assertEquals(0x09, ebp.readByte(20));

			try {
				ebp.readByte(21);
				fail();
			}
			catch (IOException e) {
				// good
			}
		}
	}

	@Test
	public void testExtentBP_MultiByteRead() throws IOException {
		try (ExtentsByteProvider ebp = new ExtentsByteProvider(patternedBAP(10, 10), null)) {
			ebp.addExtent(10, 10);
			ebp.addExtent(0, 1);
			ebp.addExtent(0, 10);

			assertEquals(21, ebp.length());

			byte[] bytes = ebp.readBytes(0, 21);
			assertEquals(0x01, bytes[0]);
			assertEquals(0x01, bytes[1]);
			assertEquals(0x01, bytes[2]);
			assertEquals(0x03, bytes[3]);
			assertEquals(0x09, bytes[9]);

			assertEquals(0x00, bytes[11]);
			assertEquals(0x01, bytes[12]);
			assertEquals(0x00, bytes[13]);
			assertEquals(0x03, bytes[14]);
			assertEquals(0x09, bytes[20]);
		}
	}

	@Test
	public void testExtentBP_MisalignedMultiByteRead() throws IOException {
		try (ExtentsByteProvider ebp = new ExtentsByteProvider(patternedBAP(10, 10), null)) {
			ebp.addExtent(10, 10);
			ebp.addExtent(0, 10);

			assertEquals(20, ebp.length());

			byte[] bytes = ebp.readBytes(5, 10);
			assertEquals(0x05, bytes[0]);
			assertEquals(0x01, bytes[1]);
			assertEquals(0x07, bytes[2]);
			assertEquals(0x01, bytes[3]);
			assertEquals(0x09, bytes[4]);
			assertEquals(0x00, bytes[5]);
			assertEquals(0x01, bytes[6]);
			assertEquals(0x00, bytes[7]);
			assertEquals(0x03, bytes[8]);
			assertEquals(0x00, bytes[9]);
		}
	}

	@Test
	public void testSmallExtentBP() throws IOException {
		try (ExtentsByteProvider ebp = new ExtentsByteProvider(patternedBAP(10, 10), null)) {
			ebp.addExtent(10, 1);
			ebp.addExtent(0, 1);

			assertEquals(2, ebp.length());

			assertEquals(0x01, ebp.readByte(0));
			assertEquals(0x00, ebp.readByte(1));

			try {
				ebp.readByte(3);
				fail();
			}
			catch (IOException e) {
				// good
			}
		}
	}

	@Test
	public void testExtentBP_SparseMultiByteRead() throws IOException {
		try (ExtentsByteProvider ebp = new ExtentsByteProvider(patternedBAP(10, 10), null)) {
			ebp.addExtent(-1, 5);

			assertEquals(5, ebp.length());

			byte[] bytes = ebp.readBytes(0, 5);
			assertEquals(0x00, bytes[0]);
			assertEquals(0x00, bytes[1]);
			assertEquals(0x00, bytes[2]);
			assertEquals(0x00, bytes[3]);
			assertEquals(0x00, bytes[4]);
		}
	}

	@Test
	public void testExtentBP_SparseSingleByteRead() throws IOException {
		try (ExtentsByteProvider ebp = new ExtentsByteProvider(patternedBAP(10, 10), null)) {
			ebp.addExtent(-1, 5);

			assertEquals(5, ebp.length());

			assertEquals(0x00, ebp.readByte(0));
			assertEquals(0x00, ebp.readByte(1));
			assertEquals(0x00, ebp.readByte(2));
			assertEquals(0x00, ebp.readByte(3));
			assertEquals(0x00, ebp.readByte(4));
		}
	}

	@Test
	public void testExtentBP_MixedSparseMultiByteRead() throws IOException {
		try (ExtentsByteProvider ebp = new ExtentsByteProvider(patternedBAP(10, 10), null)) {
			ebp.addExtent(10, 10);
			ebp.addExtent(-1, 5);
			ebp.addExtent(0, 10);

			assertEquals(25, ebp.length());

			byte[] bytes = ebp.readBytes(0, 25);
			assertEquals(0x01, bytes[0]);
			assertEquals(0x01, bytes[1]);
			assertEquals(0x01, bytes[2]);
			assertEquals(0x03, bytes[3]);
			assertEquals(0x09, bytes[9]);

			assertEquals(0x00, bytes[10]);
			assertEquals(0x00, bytes[11]);
			assertEquals(0x00, bytes[12]);
			assertEquals(0x00, bytes[13]);
			assertEquals(0x00, bytes[14]);

			assertEquals(0x00, bytes[15]);
			assertEquals(0x01, bytes[16]);
			assertEquals(0x00, bytes[17]);
			assertEquals(0x03, bytes[18]);
			assertEquals(0x09, bytes[24]);
		}
	}
}
