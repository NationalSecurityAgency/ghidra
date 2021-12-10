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

import java.io.File;
import java.io.IOException;
import java.nio.file.AccessMode;
import java.util.Arrays;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class FileByteProviderTest extends AbstractGenericTest {

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

	@Test
	public void testSmallRead() throws IOException {
		File file1 = createTempFileForTest("file1");
		FileUtilities.writeStringToFile(file1, "testing\nsecond line");
		try (FileByteProvider fbp = new FileByteProvider(file1, null, AccessMode.READ)) {
			BinaryReader br = new BinaryReader(fbp, true);
			assertEquals("testing", br.readAsciiString(0));
			assertEquals("second line", br.readAsciiString(8));
		}
	}

	@Test
	public void testReadAtBuffersBoundaries() throws IOException, CancelledException {
		File file1 = createTempFileForTest("file1");
		int bs = FileByteProvider.BUFFER_SIZE;
		FSUtilities.copyByteProviderToFile(patternedBAP(bs, 5), file1, TaskMonitor.DUMMY);
		try (FileByteProvider fbp = new FileByteProvider(file1, null, AccessMode.READ)) {
			BinaryReader br = new BinaryReader(fbp, false /*BE*/);
			assertEquals(5 * bs, fbp.length());

			assertEquals(0x0001, br.readUnsignedShort(0));
			assertEquals(0x00ff, br.readUnsignedShort(bs - 2));
			assertEquals(0x0101, br.readUnsignedShort(bs));
			assertEquals(0x01ff, br.readUnsignedShort(bs + bs - 2));
			assertEquals(0x0401, br.readUnsignedShort(bs * 4));
		}

	}

	@Test
	public void testReadStraddleBuffersBoundaries() throws IOException, CancelledException {
		File file1 = createTempFileForTest("file1");
		int bs = FileByteProvider.BUFFER_SIZE;
		FSUtilities.copyByteProviderToFile(patternedBAP(bs, 5), file1, TaskMonitor.DUMMY);
		try (FileByteProvider fbp = new FileByteProvider(file1, null, AccessMode.READ)) {
			BinaryReader br = new BinaryReader(fbp, false /*BE*/);
			assertEquals(5 * bs, fbp.length());

			assertEquals(0x00ff0101, br.readUnsignedInt(bs - 2));
			assertEquals(0x01ff0201, br.readUnsignedInt(bs + bs - 2));
		}

	}

	@Test
	public void testReadMultiStraddleBuffersBoundaries() throws IOException, CancelledException {
		File file1 = createTempFileForTest("file1");
		int bs = FileByteProvider.BUFFER_SIZE;
		FSUtilities.copyByteProviderToFile(patternedBAP(bs, 5), file1, TaskMonitor.DUMMY);
		try (FileByteProvider fbp = new FileByteProvider(file1, null, AccessMode.READ)) {
			assertEquals(5 * bs, fbp.length());

			byte[] bytes = fbp.readBytes(bs - 2, bs + 4); // read from 3 adjacent blocks, 2+bs+2
			BinaryReader br = new BinaryReader(new ByteArrayProvider(bytes), false /*BE*/);

			assertEquals(0x00ff0101, br.readUnsignedInt(0));
			assertEquals(0x01ff0201, br.readUnsignedInt(bs));
		}

	}
}
