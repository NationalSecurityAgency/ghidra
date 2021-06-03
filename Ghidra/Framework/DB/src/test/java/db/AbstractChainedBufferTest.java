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
package db;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.Arrays;
import java.util.Random;

import org.junit.*;

import db.buffers.BufferMgr;
import generic.test.AbstractGenericTest;

public abstract class AbstractChainedBufferTest extends AbstractGenericTest {

	private static final int BUFFER_SIZE = 256;
	private static final int CACHE_SIZE = 4 * 1024 * 1024;

	private static final int BIG_DATA_SIZE = BUFFER_SIZE * BUFFER_SIZE;

	private BufferMgr mgr;

	private static final Random random = new Random(1);

	private final boolean obfuscated;
	private final Buffer sourceData;
	private final int sourceDataOffset;

	/**
	 * Constructor for DatabaseTest.
	 * @param arg0
	 */
	AbstractChainedBufferTest(boolean obfuscated, Buffer sourceData, int sourceDataOffset) {
		super();
		this.obfuscated = obfuscated;
		this.sourceData = sourceData;
		this.sourceDataOffset = sourceDataOffset;
	}

	@Before
	public void setUp() throws Exception {
		mgr = new BufferMgr(BUFFER_SIZE, CACHE_SIZE, BufferMgr.DEFAULT_CHECKPOINT_COUNT);
	}

	@After
	public void tearDown() throws Exception {

		mgr.dispose();
	}

	@Test
	public void testCreateChainedBuffer() throws IOException {
		ChainedBuffer cb =
			new ChainedBuffer(128 * 1024, obfuscated, sourceData, sourceDataOffset, mgr);
		byte[] origBytes = new byte[cb.length()];
		if (sourceData != null) {
			sourceData.get(sourceDataOffset, origBytes);
		}
		assertArrayEquals(origBytes, cb.get(0, origBytes.length));

		cb = new ChainedBuffer(BUFFER_SIZE / 2, obfuscated, sourceData, sourceDataOffset, mgr);
		origBytes = new byte[cb.length()];
		if (sourceData != null) {
			sourceData.get(sourceDataOffset, origBytes);
		}
		assertArrayEquals(origBytes, cb.get(0, origBytes.length));
	}

	@Test
	public void testReadOnlyChainedBuffer() throws IOException {
		ChainedBuffer cb =
			new ChainedBuffer(128 * 1024, obfuscated, sourceData, sourceDataOffset, mgr);
		byte[] origBytes = new byte[128 * 1024];
		Arrays.fill(origBytes, (byte) '1');
		assertEquals(origBytes.length, cb.put(0, origBytes));
		cb.setReadOnly();

		try {
			assertEquals(origBytes.length, cb.put(0, origBytes));
			Assert.fail("Expected exception when read-only");
		}
		catch (UnsupportedOperationException e) {
			// expected
		}
	}

	@Test
	public void testFillChainnedBuffer() throws IOException {

		ChainedBuffer cb =
			new ChainedBuffer(BIG_DATA_SIZE, obfuscated, sourceData, sourceDataOffset, mgr);

		// Fill
		cb.fill(0, BIG_DATA_SIZE - 1, (byte) 0x12);

		// Verify data
		byte[] data = cb.get(0, BIG_DATA_SIZE);
		for (int i = 0; i < BIG_DATA_SIZE; i++) {
			assertEquals(data[i], (byte) 0x12);
		}

		// Re-instantiate buffer
		int id = cb.getId();
		cb = new ChainedBuffer(mgr, id);

		// Re-verify data
		data = cb.get(0, BIG_DATA_SIZE);
		for (int i = 0; i < BIG_DATA_SIZE; i++) {
			assertEquals(data[i], (byte) 0x12);
		}
	}

	@Test
	public void testBigChainnedBuffer() throws IOException {

		ChainedBuffer cb =
			new ChainedBuffer(BIG_DATA_SIZE, obfuscated, sourceData, sourceDataOffset, mgr);

		// Fill
		int cnt = BIG_DATA_SIZE / 4;
		int offset = 0;
		for (int i = 0; i < cnt; i++) {
			assertEquals(offset + 4, cb.putInt(offset, i));
			offset += 4;
		}

		// Verify data
		offset = 0;
		for (int i = 0; i < cnt; i++) {
			assertEquals(i, cb.getInt(offset));
			offset += 4;
		}

		// Reinstatiate buffer
		int id = cb.getId();
		cb = new ChainedBuffer(mgr, id);

		// Verify data
		offset = 0;
		for (int i = 0; i < cnt; i++) {
			assertEquals(i, cb.getInt(offset));
			offset += 4;
		}

	}

	@Test
	public void testPutAndGet() throws IOException {
		int size = 32768;
		byte[] bytes0 = new byte[size];
		Arrays.fill(bytes0, (byte) '0');
		byte[] bytes1 = new byte[size];
		Arrays.fill(bytes1, (byte) '1');
		byte[] bytes2 = new byte[256];
		Arrays.fill(bytes2, (byte) '2');
		byte[] resultBytes = new byte[size];
		byte[] checkBytes = new byte[size];
		int nextIndex;

		ChainedBuffer cb = new ChainedBuffer(size, obfuscated, sourceData, sourceDataOffset, mgr);

		// Write to entire buffer.
		nextIndex = cb.put(0, bytes0);
		assertEquals(nextIndex, size);
		Arrays.fill(resultBytes, 0, size, (byte) '0');
		cb.get(0, checkBytes);
		assertTrue(Arrays.equals(resultBytes, checkBytes));
		assertEquals(cb.length(), size);

		// Write a few bytes into buffer.
		cb.put(0, bytes0);
		nextIndex = cb.put(128, bytes1, 128, 3);
		assertEquals(nextIndex, 128 + 3);
		Arrays.fill(resultBytes, 0, size, (byte) '0');
		Arrays.fill(resultBytes, 128, 128 + 3, (byte) '1');
		cb.get(0, checkBytes);
		assertTrue(Arrays.equals(resultBytes, checkBytes));
		assertEquals(cb.length(), size);

		// Write up to end of buffer.
		cb.put(0, bytes0);
		nextIndex = cb.put(128, bytes1, 128, size - 128);
		assertEquals(nextIndex, size);
		Arrays.fill(resultBytes, 0, 128, (byte) '0');
		Arrays.fill(resultBytes, 128, size, (byte) '1');
		cb.get(0, checkBytes);
		assertTrue(Arrays.equals(resultBytes, checkBytes));
		assertEquals(cb.length(), size);

		try {
			cb.put(-1, bytes2);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.put(size - 1, bytes2);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.put(size + 1, bytes2);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.get(-1, bytes2);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.get(size - 1, bytes2);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.get(size + 1, bytes2);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}
	}

	@Test
	public void testSetByte() throws IOException {
		int size = 400;
		byte[] origBytes = new byte[size];
		byte[] newBytes = new byte[size];
		byte[] resultBytes = new byte[size];
		Arrays.fill(origBytes, (byte) 'a');
		System.arraycopy(origBytes, 0, newBytes, 0, size);

		ChainedBuffer cb =
			new ChainedBuffer(origBytes.length, obfuscated, sourceData, sourceDataOffset, mgr);
		cb.put(0, origBytes);

		newBytes[100] = (byte) 'B';
		assertEquals(101, cb.putByte(100, (byte) 'B'));
		cb.get(0, resultBytes);
		assertTrue(Arrays.equals(resultBytes, newBytes));

		newBytes[350] = (byte) 'L';
		assertEquals(351, cb.putByte(350, (byte) 'L'));
		cb.get(0, resultBytes);
		assertTrue(Arrays.equals(resultBytes, newBytes));

		try {
			cb.putByte(-1, (byte) 0);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.putByte(size + 1, (byte) 0);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}
	}

	@Test
	public void testGetByte() throws IOException {
		int size = 800;
		byte[] bytes = new byte[size / 2];
		Arrays.fill(bytes, (byte) 'a');
		bytes[120] = (byte) 'W';
		bytes[299] = (byte) 0x02;
		bytes[360] = (byte) 'x';

		ChainedBuffer cb = new ChainedBuffer(size, obfuscated, sourceData, sourceDataOffset, mgr);

		assertEquals(sourceData != null ? sourceData.getByte(sourceDataOffset) : 0, cb.getByte(0));// uninitialized data
		assertEquals(sourceData != null ? sourceData.getByte(sourceDataOffset + (size - 1)) : 0,
			cb.getByte(size - 1));// uninitialized data

		int baseIndex = 50;
		cb.put(baseIndex, bytes);

		assertEquals(cb.getByte(baseIndex + 0), (byte) 'a');
		assertEquals(cb.getByte(baseIndex + 120), (byte) 'W');
		assertEquals(cb.getByte(baseIndex + 299), (byte) 0x02);
		assertEquals(cb.getByte(baseIndex + 360), (byte) 'x');
		assertEquals(cb.getByte(baseIndex + 399), (byte) 'a');

		assertEquals(sourceData != null ? sourceData.getByte(sourceDataOffset + 20) : 0,
			cb.getByte(20));
		assertEquals(sourceData != null ? sourceData.getByte(sourceDataOffset + 450) : 0,
			cb.getByte(450));
		assertEquals(sourceData != null ? sourceData.getByte(sourceDataOffset + 700) : 0,
			cb.getByte(700));

		try {
			cb.getByte(-1);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.getByte(size + 1);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}
	}

	@Test
	public void testSetInt() throws IOException {
		int size = 400;
		byte[] origBytes = new byte[size];
		byte[] newBytes = new byte[size];
		byte[] resultBytes = new byte[size];
		Arrays.fill(origBytes, (byte) 'a');
		System.arraycopy(origBytes, 0, newBytes, 0, size);

		ChainedBuffer cb =
			new ChainedBuffer(origBytes.length, obfuscated, sourceData, sourceDataOffset, mgr);
		cb.put(0, origBytes);

		newBytes[100] = (byte) 0x12;
		newBytes[101] = (byte) 0x34;
		newBytes[102] = (byte) 0x56;
		newBytes[103] = (byte) 0x78;
		int value1 = 0x12345678;
		assertEquals(104, cb.putInt(100, value1));
		cb.get(0, resultBytes);
		assertTrue(Arrays.equals(resultBytes, newBytes));

		newBytes[248] = (byte) 0x33;
		newBytes[249] = (byte) 0x33;
		newBytes[250] = (byte) 0x33;
		newBytes[251] = (byte) 0x33;
		int value2 = 0x33333333;
		assertEquals(252, cb.putInt(248, value2));
		cb.get(0, resultBytes);
		assertTrue(Arrays.equals(resultBytes, newBytes));

		newBytes[350] = (byte) 0x77;
		newBytes[351] = (byte) 0x77;
		newBytes[352] = (byte) 0x77;
		newBytes[353] = (byte) 0x77;
		int value3 = 0x77777777;
		assertEquals(354, cb.putInt(350, value3));
		cb.get(0, resultBytes);
		assertTrue(Arrays.equals(resultBytes, newBytes));

		try {
			cb.putInt(-1, 0);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.putInt(size - 1, 0);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.putInt(size + 1, 0);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}
	}

	@Test
	public void testGetInt() throws IOException {
		int size = 400;
		byte[] origBytes = new byte[size];
		byte[] newBytes = new byte[size];
		Arrays.fill(origBytes, (byte) 0x47);
		System.arraycopy(origBytes, 0, newBytes, 0, size);
		newBytes[100] = (byte) 0x12;
		newBytes[101] = (byte) 0x34;
		newBytes[102] = (byte) 0x56;
		newBytes[103] = (byte) 0x78;
		int value1 = 0x12345678;
		newBytes[248] = (byte) 0x33;
		newBytes[249] = (byte) 0x33;
		newBytes[250] = (byte) 0x33;
		newBytes[251] = (byte) 0x33;
		int value2 = 0x33333333;
		newBytes[350] = (byte) 0x77;
		newBytes[351] = (byte) 0x77;
		newBytes[352] = (byte) 0x77;
		newBytes[353] = (byte) 0x77;
		int value3 = 0x77777777;
		int value = 0x47474747;

		ChainedBuffer cb =
			new ChainedBuffer(newBytes.length, obfuscated, sourceData, sourceDataOffset, mgr);

		cb.getInt(0);// uninitialized data
		cb.getInt(size - 4);// uninitialized data

		cb.put(0, newBytes);

		assertEquals(value, cb.getInt(0));
		assertEquals(value1, cb.getInt(100));
		assertEquals(value2, cb.getInt(248));
		assertEquals(value, cb.getInt(260));
		assertEquals(value3, cb.getInt(350));
		assertEquals(value, cb.getInt(396));

		try {
			cb.getInt(-1);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.getInt(size - 1);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.getInt(size + 1);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}
	}

	@Test
	public void testSetLong() throws IOException {
		int size = 16000;
		byte[] origBytes = new byte[size];
		byte[] newBytes = new byte[size];
		byte[] resultBytes = new byte[size];
		Arrays.fill(origBytes, (byte) 'b');
		System.arraycopy(origBytes, 0, newBytes, 0, size);

		ChainedBuffer cb =
			new ChainedBuffer(origBytes.length, obfuscated, sourceData, sourceDataOffset, mgr);
		cb.put(0, origBytes);

		newBytes[100] = (byte) 0x12;
		newBytes[101] = (byte) 0x34;
		newBytes[102] = (byte) 0x56;
		newBytes[103] = (byte) 0x78;
		newBytes[104] = (byte) 0xa1;
		newBytes[105] = (byte) 0xa2;
		newBytes[106] = (byte) 0xa3;
		newBytes[107] = (byte) 0xa4;
		long value1 = 0x12345678a1a2a3a4L;
		assertEquals(108, cb.putLong(100, value1));
		cb.get(0, resultBytes);
		assertTrue(Arrays.equals(resultBytes, newBytes));

		newBytes[247] = (byte) 0x33;
		newBytes[248] = (byte) 0x33;
		newBytes[249] = (byte) 0x33;
		newBytes[250] = (byte) 0x33;
		newBytes[251] = (byte) 0x33;
		newBytes[252] = (byte) 0x33;
		newBytes[253] = (byte) 0x33;
		newBytes[254] = (byte) 0x33;
		long value2 = 0x3333333333333333L;
		assertEquals(255, cb.putLong(247, value2));
		cb.get(0, resultBytes);
		assertTrue(Arrays.equals(resultBytes, newBytes));

		newBytes[1350] = (byte) 0x77;
		newBytes[1351] = (byte) 0x77;
		newBytes[1352] = (byte) 0x77;
		newBytes[1353] = (byte) 0x77;
		newBytes[1354] = (byte) 0x77;
		newBytes[1355] = (byte) 0x77;
		newBytes[1356] = (byte) 0x77;
		newBytes[1357] = (byte) 0x77;
		long value3 = 0x7777777777777777L;
		assertEquals(1358, cb.putLong(1350, value3));
		cb.get(0, resultBytes);
		assertTrue(Arrays.equals(resultBytes, newBytes));

		try {
			cb.putLong(-1, 0);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.putLong(size - 1, 0);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.putLong(size + 1, 0);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}
	}

	@Test
	public void testGetLong() throws IOException {
		int size = 1504;
		byte[] origBytes = new byte[size];
		byte[] newBytes = new byte[size];
		Arrays.fill(origBytes, (byte) 0x47);
		System.arraycopy(origBytes, 0, newBytes, 0, size);
		newBytes[100] = (byte) 0x12;
		newBytes[101] = (byte) 0x34;
		newBytes[102] = (byte) 0x56;
		newBytes[103] = (byte) 0x78;
		newBytes[104] = (byte) 0xa1;
		newBytes[105] = (byte) 0xa2;
		newBytes[106] = (byte) 0xa3;
		newBytes[107] = (byte) 0xa4;
		long value1 = 0x12345678a1a2a3a4L;
		newBytes[247] = (byte) 0x33;
		newBytes[248] = (byte) 0x33;
		newBytes[249] = (byte) 0x33;
		newBytes[250] = (byte) 0x33;
		newBytes[251] = (byte) 0x33;
		newBytes[252] = (byte) 0x33;
		newBytes[253] = (byte) 0x33;
		newBytes[254] = (byte) 0x33;
		long value2 = 0x3333333333333333L;
		newBytes[1350] = (byte) 0x77;
		newBytes[1351] = (byte) 0x77;
		newBytes[1352] = (byte) 0x77;
		newBytes[1353] = (byte) 0x77;
		newBytes[1354] = (byte) 0x77;
		newBytes[1355] = (byte) 0x77;
		newBytes[1356] = (byte) 0x77;
		newBytes[1357] = (byte) 0x77;
		long value3 = 0x7777777777777777L;
		long value = 0x4747474747474747L;

		ChainedBuffer cb =
			new ChainedBuffer(newBytes.length, obfuscated, sourceData, sourceDataOffset, mgr);

		cb.getLong(0);// uninitialized data
		cb.getLong(size - 8);// uninitialized data

		cb.put(0, newBytes);

		assertEquals(value, cb.getLong(0));
		assertEquals(value1, cb.getLong(100));
		assertEquals(value2, cb.getLong(247));
		assertEquals(value, cb.getLong(260));
		assertEquals(value3, cb.getLong(1350));
		assertEquals(value, cb.getLong(1496));

		try {
			cb.getLong(-1);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.getLong(size - 1);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.getLong(size + 1);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}
	}

	@Test
	public void testSetShort() throws IOException {
		int size = 400;
		byte[] origBytes = new byte[size];
		byte[] newBytes = new byte[size];
		byte[] resultBytes = new byte[size];
		Arrays.fill(origBytes, (byte) 'a');
		System.arraycopy(origBytes, 0, newBytes, 0, size);

		ChainedBuffer cb =
			new ChainedBuffer(origBytes.length, obfuscated, sourceData, sourceDataOffset, mgr);
		cb.put(0, origBytes);

		newBytes[100] = (byte) 0x12;
		newBytes[101] = (byte) 0x34;
		short value1 = 0x1234;
		assertEquals(102, cb.putShort(100, value1));
		cb.get(0, resultBytes);
		assertTrue(Arrays.equals(resultBytes, newBytes));

		newBytes[249] = (byte) 0x33;
		newBytes[250] = (byte) 0x33;
		short value2 = 0x3333;
		assertEquals(251, cb.putShort(249, value2));
		cb.get(0, resultBytes);
		assertTrue(Arrays.equals(resultBytes, newBytes));

		newBytes[350] = (byte) 0x77;
		newBytes[351] = (byte) 0x77;
		short value3 = 0x7777;
		assertEquals(352, cb.putShort(350, value3));
		cb.get(0, resultBytes);
		assertTrue(Arrays.equals(resultBytes, newBytes));

		try {
			cb.putShort(-1, (short) 0);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.putShort(size - 1, (short) 0);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.putShort(size + 1, (short) 0);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}
	}

	@Test
	public void testGetShort() throws IOException {
		int size = 400;
		byte[] origBytes = new byte[size];
		byte[] newBytes = new byte[size];
		Arrays.fill(origBytes, (byte) 0x47);
		System.arraycopy(origBytes, 0, newBytes, 0, size);
		newBytes[100] = (byte) 0x12;
		newBytes[101] = (byte) 0x34;
		short value1 = 0x1234;
		newBytes[249] = (byte) 0x33;
		newBytes[250] = (byte) 0x33;
		short value2 = 0x3333;
		newBytes[350] = (byte) 0x77;
		newBytes[351] = (byte) 0x77;
		short value3 = 0x7777;
		short value = 0x4747;

		ChainedBuffer cb =
			new ChainedBuffer(newBytes.length, obfuscated, sourceData, sourceDataOffset, mgr);

		cb.getShort(0);// uninitialized data
		cb.getShort(size - 2);// uninitialized data

		cb.put(0, newBytes);

		assertEquals(value, cb.getShort(0));
		assertEquals(value1, cb.getShort(100));
		assertEquals(value2, cb.getShort(249));
		assertEquals(value, cb.getShort(260));
		assertEquals(value3, cb.getShort(350));
		assertEquals(value, cb.getShort(396));

		try {
			cb.getShort(-1);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.getShort(size - 1);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}

		try {
			cb.getShort(size + 1);
			Assert.fail();
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// good
		}
	}

	@Test
	public void testGetId() throws IOException {

		int size = 400;
		ChainedBuffer cb = new ChainedBuffer(32768, obfuscated, sourceData, sourceDataOffset, mgr);
		byte[] bytes = new byte[size];
		random.nextBytes(bytes);
		cb.put(0, bytes);
		int id = cb.getId();

		cb = new ChainedBuffer(mgr, id);
		assertTrue(Arrays.equals(bytes, cb.get(0, size)));
	}

	@Test
	public void testDelete() throws IOException {

		ChainedBuffer cb = new ChainedBuffer(32768, obfuscated, sourceData, sourceDataOffset, mgr);
		int id = cb.getId();
		cb.delete();
		assertEquals(-1, cb.getId());

		try {
			cb = new ChainedBuffer(mgr, id);
			Assert.fail();
		}
		catch (IOException e) {
			// good
		}

	}

	private void doSplitTest(int size) throws IOException {
		ChainedBuffer cb = new ChainedBuffer(size, obfuscated, sourceData, sourceDataOffset, mgr);
		byte[] bytes = new byte[size];
		random.nextBytes(bytes);
		cb.put(0, bytes);
		assertTrue(Arrays.equals(bytes, cb.get(0, size)));
		assertEquals(0, mgr.getLockCount());
		int splitOffset = size / 2;
		int size2 = size - splitOffset;
		ChainedBuffer cb2 = cb.split(splitOffset);
		assertEquals(splitOffset, cb.length());
		assertEquals(size2, cb2.length());
		assertTrue(equals(cb.get(0, splitOffset), 0, bytes, 0, splitOffset));
		assertTrue(equals(cb2.get(0, size2), 0, bytes, splitOffset, size2));
		assertEquals(0, mgr.getLockCount());
	}

	@Test
	public void testSplit() throws IOException {

		doSplitTest(BUFFER_SIZE / 2);// single to single
		doSplitTest((int) (BUFFER_SIZE * 1.5));// indexed to single
		doSplitTest(BUFFER_SIZE * 4);// indexed to indexed

	}

	private void doAppendTest(int size1, int size2) throws IOException {

		ChainedBuffer cb1 = new ChainedBuffer(size1, obfuscated, sourceData, sourceDataOffset, mgr);
		byte[] bytes1 = new byte[size1];
		random.nextBytes(bytes1);
		cb1.put(0, bytes1);

		ChainedBuffer cb2 = new ChainedBuffer(size2, obfuscated, sourceData, sourceDataOffset, mgr);
		byte[] bytes2 = new byte[size2];
		random.nextBytes(bytes2);
		cb2.put(0, bytes2);

		try {
			cb1.append(cb2);
			if (sourceData != null) {
				fail("Buffers with source data should have thrown exception");
			}
		}
		catch (UnsupportedOperationException e) {
			if (sourceData == null) {
				e.printStackTrace();
				fail("unexpected exception");
			}
			return;
		}

		assertEquals(size1 + size2, cb1.length());

		// Make sure cb2 no longer exists
		assertEquals(-1, cb2.getId());

		assertTrue(Arrays.equals(bytes1, cb1.get(0, size1)));
		assertTrue(Arrays.equals(bytes2, cb1.get(size1, size2)));
		assertEquals(0, mgr.getLockCount());

	}

	@Test
	public void testAppend() throws IOException {

		doAppendTest(BUFFER_SIZE / 3, BUFFER_SIZE / 3);// single + single = single
		doAppendTest(BUFFER_SIZE / 3, 2 * BUFFER_SIZE);// single + indexed
		doAppendTest(2 * BUFFER_SIZE, BUFFER_SIZE / 3);// indexed + single
		doAppendTest(2 * BUFFER_SIZE, 2 * BUFFER_SIZE);// indexed + indexed
		doAppendTest(8 * BUFFER_SIZE, 8 * BUFFER_SIZE);// large indexed + large indexed

	}

	private boolean equals(byte[] bytes1, int offset1, byte[] bytes2, int offset2, int cnt) {
		for (int i = 0; i < cnt; i++) {
			if (bytes1[offset1++] != bytes2[offset2++]) {
				return false;
			}
		}
		return true;
	}

	private boolean doSetSize(ChainedBuffer cb, int newSize, boolean preserveData)
			throws IOException {
		try {
			cb.setSize(newSize, preserveData);
			if (sourceData != null) {
				fail("Buffers with source data should have thrown exception");
			}
			return true;
		}
		catch (UnsupportedOperationException e) {
			if (sourceData == null) {
				e.printStackTrace();
				fail("unexpected exception");
			}
		}
		return false;
	}

	@Test
	public void testSetSize() throws IOException {

		// start with small buffer
		int size = BUFFER_SIZE / 2;
		ChainedBuffer cb = new ChainedBuffer(size, obfuscated, sourceData, sourceDataOffset, mgr);
		byte[] bytes = new byte[size];
		random.nextBytes(bytes);
		cb.put(0, bytes);
		assertTrue(Arrays.equals(bytes, cb.get(0, size)));
		assertEquals(0, mgr.getLockCount());

		// Grow buffer (single index buffer)
		int newSize = (int) (2.3 * BUFFER_SIZE);
		if (doSetSize(cb, newSize, true)) {
			assertTrue(Arrays.equals(bytes, cb.get(0, size)));
			int addSize = newSize - size;
			byte[] addBytes = new byte[addSize];
			assertTrue(Arrays.equals(addBytes, cb.get(size, addBytes.length)));
			random.nextBytes(addBytes);
			cb.put(size, addBytes);
			assertTrue(Arrays.equals(bytes, cb.get(0, size)));
			assertTrue(Arrays.equals(addBytes, cb.get(size, addSize)));
			bytes = cb.get(0, newSize);
			size = newSize;
			assertEquals(cb.length(), size);
			assertEquals(bytes.length, size);
			assertEquals(0, mgr.getLockCount());
		}

		// Grow buffer (multiple index buffers)
		newSize = (BUFFER_SIZE / 8) * BUFFER_SIZE;
		if (doSetSize(cb, newSize, true)) {
			int addSize = newSize - size;
			byte[] addBytes = new byte[addSize];
			random.nextBytes(addBytes);
			cb.put(size, addBytes);
			assertTrue(Arrays.equals(bytes, cb.get(0, size)));
			assertTrue(Arrays.equals(addBytes, cb.get(size, addSize)));
			bytes = cb.get(0, newSize);
			size = newSize;
			assertEquals(cb.length(), size);
			assertEquals(bytes.length, size);
			assertEquals(0, mgr.getLockCount());
		}

		// Shrink buffer (single index buffer)
		newSize = 2 * BUFFER_SIZE;
		if (doSetSize(cb, newSize, true)) {
			assertTrue(equals(bytes, 0, cb.get(0, newSize), 0, newSize));
			bytes = new byte[newSize];
			random.nextBytes(bytes);
			cb.put(0, bytes);
			assertTrue(equals(bytes, 0, cb.get(0, newSize), 0, newSize));
			size = newSize;
			assertEquals(cb.length(), size);
			assertEquals(0, mgr.getLockCount());
		}

		// Shrink to small buffer
		newSize = BUFFER_SIZE / 2;
		if (doSetSize(cb, newSize, true)) {
			assertTrue(equals(bytes, 0, cb.get(0, newSize), 0, newSize));
			bytes = new byte[newSize];
			random.nextBytes(bytes);
			cb.put(0, bytes);
			assertTrue(equals(bytes, 0, cb.get(0, newSize), 0, newSize));
			size = newSize;
			assertEquals(cb.length(), size);
			assertEquals(0, mgr.getLockCount());
		}
	}
}
