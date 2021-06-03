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
package ghidra.app.plugin.core.byteviewer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.*;
import java.math.BigInteger;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.util.*;

/**
 * Tests for the file implementation of a ByteBlockSet and ByteBlock.
 * 
 * 
 *
 */
public class FileByteBlockTest extends AbstractGenericTest {

	private FileByteBlockSet blockSet;
	private FileByteBlock block;
	private File file;
	private byte[] buf;

	/*
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {
		createFile();
		blockSet = new FileByteBlockSet(file);
		block = (FileByteBlock) blockSet.getBlocks()[0];
	}

	/*
	 * @see TestCase#tearDown()
	 */
	@After
	public void tearDown() throws Exception {
		file.delete();
		blockSet.dispose();
	}

	@Test
	public void testGetByte() throws Exception {
		for (int i = 0; i < 100; i++) {
			assertEquals((byte) i, block.getByte(BigInteger.valueOf(i)));
		}
	}

	@Test
	public void testGetInt() throws Exception {
		block.setBigEndian(true);
		DataConverter conv = BigEndianDataConverter.INSTANCE;

		for (int i = 0; i < 20; i++) {
			byte[] b = new byte[4];
			System.arraycopy(buf, i + 4, b, 0, b.length);
			assertEquals(conv.getInt(b), block.getInt(BigInteger.valueOf(i + 4)));

		}
		block.setBigEndian(false);
		conv = LittleEndianDataConverter.INSTANCE;
		for (int i = 0; i < 12; i++) {
			byte[] b = new byte[4];
			System.arraycopy(buf, i + 4, b, 0, b.length);
			assertEquals(conv.getInt(b), block.getInt(BigInteger.valueOf(i + 4)));
		}

	}

	@Test
	public void testGetLong() throws Exception {
		block.setBigEndian(true);
		DataConverter conv = BigEndianDataConverter.INSTANCE;

		for (int i = 0; i < 10; i++) {
			byte[] b = new byte[8];
			System.arraycopy(buf, i + 8, b, 0, b.length);
			assertEquals(conv.getLong(b), block.getLong(BigInteger.valueOf(i + 8)));
		}

		for (int i = 0; i < 10; i++) {
			byte[] b = new byte[8];
			System.arraycopy(buf, i + 12, b, 0, b.length);
			assertEquals(conv.getLong(b), block.getLong(BigInteger.valueOf(i + 12)));
		}

		block.setBigEndian(false);
		conv = LittleEndianDataConverter.INSTANCE;
		for (int i = 0; i < 10; i++) {
			byte[] b = new byte[8];
			System.arraycopy(buf, i + 8, b, 0, b.length);
			assertEquals(conv.getLong(b), block.getLong(BigInteger.valueOf(i + 8)));
		}
		for (int i = 0; i < 10; i++) {
			byte[] b = new byte[8];
			System.arraycopy(buf, i + 12, b, 0, b.length);
			assertEquals(conv.getLong(b), block.getLong(BigInteger.valueOf(i + 12)));
		}

	}

	@Test
	public void testSetByte() throws Exception {
		block.setByte(BigInteger.ZERO, (byte) 33);
		assertEquals((byte) 33, block.getByte(BigInteger.ZERO));

		blockSet.notifyByteEditing(block, BigInteger.ZERO, new byte[] { (byte) 0 },
			new byte[] { (byte) 33 });

		assertTrue(blockSet.isChanged(block, BigInteger.ZERO, 1));

		block.setByte(BigInteger.valueOf(99), (byte) 33);
		assertEquals((byte) 33, block.getByte(BigInteger.valueOf(99)));

		blockSet.notifyByteEditing(block, BigInteger.valueOf(99), new byte[] { (byte) 99 },
			new byte[] { (byte) 33 });

		assertTrue(blockSet.isChanged(block, BigInteger.valueOf(99), 1));

	}

	@Test
	public void testSetInt() throws Exception {
		block.setBigEndian(true);
		DataConverter conv = BigEndianDataConverter.INSTANCE;

		byte[] b = new byte[4];
		System.arraycopy(buf, 35, b, 0, b.length);
		conv.getInt(b);

		byte[] newb = new byte[4];
		conv.putInt(newb, 0, 425);

		block.setInt(BigInteger.valueOf(35), 425);

		blockSet.notifyByteEditing(block, BigInteger.valueOf(35), b, newb);
		for (int i = 0; i < 4; i++) {
			assertTrue(blockSet.isChanged(block, BigInteger.valueOf(35 + i), b.length));
		}

		block.setBigEndian(false);
		conv = LittleEndianDataConverter.INSTANCE;

		b = new byte[4];
		System.arraycopy(buf, 35, b, 0, b.length);
		conv.getInt(b);

		newb = new byte[4];
		conv.putInt(newb, 0, 425);

		block.setInt(BigInteger.valueOf(35), 425);

		blockSet.notifyByteEditing(block, BigInteger.valueOf(35), b, newb);
		for (int i = 0; i < 4; i++) {
			assertTrue(blockSet.isChanged(block, BigInteger.valueOf(35 + i), b.length));
		}

	}

	@Test
	public void testSetLong() throws Exception {
		block.setBigEndian(true);
		DataConverter conv = BigEndianDataConverter.INSTANCE;

		byte[] b = new byte[8];
		System.arraycopy(buf, 35, b, 0, b.length);
		conv.getLong(b);

		byte[] newb = new byte[8];
		conv.putLong(newb, 0, 12425);

		block.setLong(BigInteger.valueOf(35), 12425);

		blockSet.notifyByteEditing(block, BigInteger.valueOf(35), b, newb);
		for (int i = 0; i < 8; i++) {
			assertTrue(blockSet.isChanged(block, BigInteger.valueOf(35 + i), b.length));
		}

		block.setBigEndian(false);
		conv = LittleEndianDataConverter.INSTANCE;

		b = new byte[8];
		System.arraycopy(buf, 35, b, 0, b.length);
		conv.getLong(b);

		newb = new byte[8];
		conv.putLong(newb, 0, 12425);

		block.setLong(BigInteger.valueOf(35), 12425);

		blockSet.notifyByteEditing(block, BigInteger.valueOf(35), b, newb);
		for (int i = 0; i < 8; i++) {
			assertTrue(blockSet.isChanged(block, BigInteger.valueOf(35 + i), b.length));
		}

	}

	@Test
	public void testSave() throws Exception {
		for (int i = 0; i < 20; i++) {
			block.setByte(BigInteger.valueOf(i), (byte) (10 + i));
		}
		File f = createTempFile("updated", ".bin");
		blockSet.save(f.getAbsolutePath());

		assertTrue(f.exists());

		assertEquals(100, f.length());

		FileInputStream fis = new FileInputStream(f);
		byte[] b = new byte[100];
		fis.read(b);
		fis.close();
		f.delete();

		for (int i = 0; i < 20; i++) {
			assertEquals((byte) (10 + i), b[i]);
			assertTrue(!blockSet.isChanged(block, BigInteger.valueOf(i), 1));
		}
	}

	private void createFile() throws IOException {

		file = createTempFileForTest(".bin");

		FileOutputStream fos = new FileOutputStream(file);
		buf = new byte[100];
		for (int i = 0; i < buf.length; i++) {
			buf[i] = (byte) i;
		}
		fos.write(buf);
		fos.close();
	}

}
