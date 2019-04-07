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
package db.buffers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.*;
import java.util.Arrays;

import org.junit.*;

import generic.test.AbstractGenericTest;
import utilities.util.FileUtilities;

public class LocalBufferFileTest extends AbstractGenericTest {

	private static final int BUFFER_SIZE = 1024;

	private File testDir = new File(AbstractGenericTest.getTestDirectoryPath(), "LocalBufferFileTest");

	public LocalBufferFileTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		FileUtilities.deleteDir(testDir);
		testDir.mkdir();
	}

	@After
	public void tearDown() throws Exception {
		FileUtilities.deleteDir(testDir);

	}

	@Test
	public void testTempFile() throws Exception {
		File file = null;
		LocalBufferFile bf = null;
		try {
			bf = new LocalBufferFile(BUFFER_SIZE, "test", ".tmp");
			file = bf.getFile();
			assertTrue(file.exists());
			assertEquals(BUFFER_SIZE, bf.getBufferSize());

			assertEquals("Free list should be empty", 0, bf.getFreeIndexes().length);
			assertEquals(0, bf.getIndexCount());

			doWriteReadTest(bf);

			bf.close();
			bf = null;

			assertTrue(!file.exists());
			file = null;
		}
		finally {
			if (bf != null) {
				try {
					bf.close();
				}
				catch (IOException e) {
				}
			}
			if (file != null) {
				file.delete();
			}
		}
	}

	@Test
	public void testFileSave() throws Exception {
		File file = new File(testDir, "test.bf");
		LocalBufferFile bf = null;
		try {
			bf = new LocalBufferFile(file, BUFFER_SIZE);
			assertTrue(file.exists());
			assertEquals(BUFFER_SIZE, bf.getBufferSize());

			assertEquals("Free list should be empty", 0, bf.getFreeIndexes().length);
			assertEquals(0, bf.getIndexCount());

			int[] freeList = doWriteReadTest(bf);

			int indexCnt = bf.getIndexCount();
			bf.setFreeIndexes(freeList);// causes corresponding buffer ID's to become -1
			long fileID = bf.getFileId();
			assertTrue(fileID != 0);
			bf.setParameter("TestParm1", 0x321);
			bf.setParameter("TestParm2", 0x543);

			bf.close();
			bf = null;

			assertTrue(file.exists());

			// Reopen buffer file for reading
			bf = new LocalBufferFile(file, true);
			assertEquals(indexCnt, bf.getIndexCount());
			assertTrue(Arrays.equals(freeList, bf.getFreeIndexes()));
			assertEquals(fileID, bf.getFileId());
			assertEquals(0x321, bf.getParameter("TestParm1"));
			assertEquals(0x543, bf.getParameter("TestParm2"));

			doReadTest2(bf);

			bf.close();
			bf = null;

			assertTrue(file.exists());

		}
		finally {
			if (bf != null) {
				try {
					bf.close();
				}
				catch (IOException e) {
				}
			}
			file.delete();
		}
	}

	@Test
	public void testFileModify() throws Exception {
		File file = new File(testDir, "test.bf");
		LocalBufferFile bf = null;
		try {
			bf = new LocalBufferFile(file, BUFFER_SIZE);
			assertTrue(file.exists());
			assertEquals(BUFFER_SIZE, bf.getBufferSize());

			assertEquals("Free list should be empty", 0, bf.getFreeIndexes().length);
			assertEquals(0, bf.getIndexCount());

			int[] freeList = doWriteReadTest(bf);

			int indexCnt = bf.getIndexCount();
			bf.setFreeIndexes(freeList);// causes corresponding buffer ID's to become -1
			long fileID = bf.getFileId();
			assertTrue(fileID != 0);
			bf.setParameter("TestParm1", 0x321);
			bf.setParameter("TestParm2", 0x543);

			bf.close();
			bf = null;

			assertTrue(file.exists());

			// Reopen buffer file for modification
			bf = new LocalBufferFile(file, false);
			assertEquals(indexCnt, bf.getIndexCount());
			assertTrue(Arrays.equals(freeList, bf.getFreeIndexes()));
			assertEquals(fileID, bf.getFileId());
			assertEquals(0x321, bf.getParameter("TestParm1"));
			assertEquals(0x543, bf.getParameter("TestParm2"));

			doReadTest2(bf);

			bf.setParameter("TestParm1", 0x322);
			bf.setParameter("TestParm2", 0x544);

			byte[] data = new byte[BUFFER_SIZE];
			DataBuffer buf = new DataBuffer(data);

			Arrays.fill(data, (byte) 0xf2);
			buf.setId(12);
			bf.put(buf, 2);

			doReadTest1(bf);

			bf.setFreeIndexes(new int[0]);

			bf.close();
			bf = null;

			assertTrue(file.exists());

			// Reopen buffer file for reading
			bf = new LocalBufferFile(file, true);
			assertEquals(indexCnt, bf.getIndexCount());
			assertEquals("Free list should be empty", 0, bf.getFreeIndexes().length);
			assertEquals(fileID, bf.getFileId());
			assertEquals(0x322, bf.getParameter("TestParm1"));
			assertEquals(0x544, bf.getParameter("TestParm2"));

			doReadTest1(bf);

			bf.close();
			bf = null;

			assertTrue(file.exists());

		}
		finally {
			if (bf != null) {
				try {
					bf.close();
				}
				catch (IOException e) {
				}
			}
			file.delete();
		}
	}

	private int[] doWriteReadTest(LocalBufferFile bf) throws IOException {

		DataBuffer buf = new DataBuffer(BUFFER_SIZE - 1);

		try {
			bf.get(buf, 0);
			Assert.fail("Expected EOFException getting non-exting buffer");
		}
		catch (EOFException e) {
			// expected
		}

		try {
			bf.put(buf, 0);
			Assert.fail("Expected IllegalArgumentException putting small buffer");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		byte[] data = new byte[BUFFER_SIZE];
		buf = new DataBuffer(data);

		Arrays.fill(data, (byte) 0xf0);
		buf.setId(10);
		bf.put(buf, 0);

		Arrays.fill(data, (byte) 0xf1);
		buf.setId(11);
		bf.put(buf, 1);

		Arrays.fill(data, (byte) 0xf2);
		buf.setId(12);
		bf.put(buf, 2);

		doReadTest1(bf);

		buf.setId(12);
		buf.setEmpty(true);
		bf.put(buf, 2);

		doReadTest2(bf);

		// Return static free list
		return new int[] { 2 };
	}

	private void doReadTest1(LocalBufferFile bf) throws IOException {

		DataBuffer buf = new DataBuffer();

		bf.get(buf, 0);
		assertEquals(10, buf.getId());
		assertTrue(!buf.isEmpty());
		checkData(buf.data, (byte) 0xf0);

		bf.get(buf, 2);
		assertEquals(12, buf.getId());
		assertTrue(!buf.isEmpty());
		checkData(buf.data, (byte) 0xf2);

		bf.get(buf, 1);
		assertEquals(11, buf.getId());
		assertTrue(!buf.isEmpty());
		checkData(buf.data, (byte) 0xf1);
	}

	private void doReadTest2(LocalBufferFile bf) throws IOException {

		DataBuffer buf = new DataBuffer();

		bf.get(buf, 0);
		assertEquals(10, buf.getId());
		assertTrue(!buf.isEmpty());
		checkData(buf.data, (byte) 0xf0);

		bf.get(buf, 2);
		assertEquals(-1, buf.getId());
		assertTrue(buf.isEmpty());

		bf.get(buf, 1);
		assertEquals(11, buf.getId());
		assertTrue(!buf.isEmpty());
		checkData(buf.data, (byte) 0xf1);
	}

	private void checkData(byte[] data, byte b) {
		assertEquals(BUFFER_SIZE, data.length);

	}

}
