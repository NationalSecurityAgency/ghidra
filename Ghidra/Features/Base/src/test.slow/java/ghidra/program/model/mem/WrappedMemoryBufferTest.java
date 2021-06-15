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
package ghidra.program.model.mem;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitorAdapter;

public class WrappedMemoryBufferTest extends AbstractGhidraHeadedIntegrationTest {
	private Program program;
	private MemBuffer memBuf;

	public WrappedMemoryBufferTest() {
		super();
	}

	private void loadProgram(String name) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(name, ProgramBuilder._TOY);
		builder.createMemory("ram", "0x0", 100000);
		program = builder.getProgram();
		memBuf = new MemoryBufferImpl(program.getMemory(), program.getMinAddress());
		memBuf = new WrappedMemBuffer(memBuf, 20, 0);
	}

	@Test
	public void testGetBytes() throws Exception {
		loadProgram("notepad");

		Address minAddr = program.getMinAddress();
		Address maxAddr = program.getMaxAddress();
		setBytes(minAddr, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
		setBytes(maxAddr.subtract(7), new byte[] { 11, 12, 13, 14, 15, 16, 17, 18 });

		memBuf = new MemoryBufferImpl(program.getMemory(), minAddr);
		memBuf = new WrappedMemBuffer(memBuf, 5, 0);
		byte[] bytes = new byte[4];
		assertEquals(4, memBuf.getBytes(bytes, 0));
		Assert.assertArrayEquals("Unexpected bytes read from memBuf", new byte[] { 1, 2, 3, 4 },
			bytes);
		assertEquals(4, memBuf.getBytes(bytes, 4));
		Assert.assertArrayEquals("Unexpected bytes read from memBuf", new byte[] { 5, 6, 7, 8 },
			bytes);

		Arrays.fill(bytes, (byte) 0);
		assertEquals(2, memBuf.getBytes(bytes, 99998));
		Assert.assertArrayEquals("Unexpected bytes read from memBuf", new byte[] { 17, 18, 0, 0 },
			bytes);
		assertEquals(4, memBuf.getBytes(bytes, 99996));
		Assert.assertArrayEquals("Unexpected bytes read from memBuf", new byte[] { 15, 16, 17, 18 },
			bytes);
		assertEquals(4, memBuf.getBytes(bytes, 99995));
		Assert.assertArrayEquals("Unexpected bytes read from memBuf", new byte[] { 14, 15, 16, 17 },
			bytes);
		Arrays.fill(bytes, (byte) 0);
		assertEquals(0, memBuf.getBytes(bytes, 100000));
		Assert.assertArrayEquals("Unexpected bytes read from memBuf", new byte[] { 0, 0, 0, 0 },
			bytes);
	}

	@Test
	public void testGetBytesBuffered() throws Exception {
		loadProgram("notepad");

		Address minAddr = program.getMinAddress();
		Address maxAddr = program.getMaxAddress();
		setBytes(minAddr,
			new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 });

		memBuf = new MemoryBufferImpl(program.getMemory(), minAddr);
		memBuf = new WrappedMemBuffer(memBuf, 4, 0);
		byte[] bytes = new byte[6];
		// test get too many for cache
		assertEquals(6, memBuf.getBytes(bytes, 2));
		Assert.assertArrayEquals("Unexpected bytes read from memBuf",
			new byte[] { 2, 3, 4, 5, 6, 7 }, bytes);

		// test not in buffer
		memBuf = new WrappedMemBuffer(memBuf, 6, 0);
		assertEquals(6, memBuf.getBytes(bytes, 0));
		Assert.assertArrayEquals("Unexpected bytes read from memBuf",
			new byte[] { 0, 1, 2, 3, 4, 5 }, bytes);
		assertEquals(6, memBuf.getBytes(bytes, 2));
		Assert.assertArrayEquals("Unexpected bytes read from memBuf",
			new byte[] { 2, 3, 4, 5, 6, 7 }, bytes);
		assertEquals(6, memBuf.getBytes(bytes, 8));
		Assert.assertArrayEquals("Unexpected bytes read from memBuf",
			new byte[] { 8, 9, 10, 11, 12, 13 }, bytes);
		assertEquals(6, memBuf.getBytes(bytes, 1));
		Assert.assertArrayEquals("Unexpected bytes read from memBuf",
			new byte[] { 1, 2, 3, 4, 5, 6 }, bytes);

		assertEquals(10, memBuf.getByte(10));
		assertEquals(0, memBuf.getByte(0));
		assertEquals(5, memBuf.getByte(5));
		assertEquals(6, memBuf.getByte(6));
	}

	@Test
	public void testGetBytesNoBuffered() throws Exception {
		loadProgram("notepad");

		Address minAddr = program.getMinAddress();
		Address maxAddr = program.getMaxAddress();
		setBytes(minAddr,
			new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 });

		memBuf = new MemoryBufferImpl(program.getMemory(), minAddr);
		memBuf = new WrappedMemBuffer(memBuf, 0, 0);
		byte[] bytes = new byte[6];
		// test get too many for cache
		assertEquals(6, memBuf.getBytes(bytes, 2));
		Assert.assertArrayEquals("Unexpected bytes read from memBuf",
			new byte[] { 2, 3, 4, 5, 6, 7 }, bytes);

		// test not in buffer
		memBuf = new WrappedMemBuffer(memBuf, 0, 0);
		assertEquals(6, memBuf.getBytes(bytes, 0));
		Assert.assertArrayEquals("Unexpected bytes read from memBuf",
			new byte[] { 0, 1, 2, 3, 4, 5 }, bytes);
		assertEquals(6, memBuf.getBytes(bytes, 2));
		Assert.assertArrayEquals("Unexpected bytes read from memBuf",
			new byte[] { 2, 3, 4, 5, 6, 7 }, bytes);
		assertEquals(6, memBuf.getBytes(bytes, 8));
		Assert.assertArrayEquals("Unexpected bytes read from memBuf",
			new byte[] { 8, 9, 10, 11, 12, 13 }, bytes);
		assertEquals(6, memBuf.getBytes(bytes, 1));
		Assert.assertArrayEquals("Unexpected bytes read from memBuf",
			new byte[] { 1, 2, 3, 4, 5, 6 }, bytes);

		assertEquals(10, memBuf.getByte(10));
		assertEquals(0, memBuf.getByte(0));
		assertEquals(5, memBuf.getByte(5));
		assertEquals(6, memBuf.getByte(6));
	}

	@Test
	public void testGetIntBuffered() throws Exception {
		loadProgram("notepad");
		int value;

		Address minAddr = program.getMinAddress();
		Address maxAddr = program.getMaxAddress();
		setBytes(minAddr, new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
			18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 });

		memBuf = new DumbMemBufferImpl(program.getMemory(), minAddr);
		memBuf = new WrappedMemBuffer(memBuf, 3, 0);

		value = memBuf.getInt(0);
		assertEquals(value, 0x00010203);
		value = memBuf.getInt(1);
		assertEquals(value, 0x01020304);
		value = memBuf.getInt(3);
		assertEquals(value, 0x03040506);
		value = memBuf.getInt(8);
		assertEquals(value, 0x08090A0B);

		memBuf = new DumbMemBufferImpl(program.getMemory(), minAddr);
		memBuf = new WrappedMemBuffer(memBuf, 4, 0);
		value = memBuf.getInt(0);
		assertEquals(value, 0x00010203);
		value = memBuf.getInt(1);
		assertEquals(value, 0x01020304);
		value = memBuf.getInt(3);
		assertEquals(value, 0x03040506);
		value = memBuf.getInt(8);
		assertEquals(value, 0x08090A0B);

		memBuf = new DumbMemBufferImpl(program.getMemory(), minAddr);
		memBuf = new WrappedMemBuffer(memBuf, 5, 0);
		value = memBuf.getInt(0);
		assertEquals(value, 0x00010203);
		value = memBuf.getInt(1);
		assertEquals(value, 0x01020304);
		value = memBuf.getInt(3);
		assertEquals(value, 0x03040506);
		value = memBuf.getInt(8);
		assertEquals(value, 0x08090A0B);

		memBuf = new MemoryBufferImpl(program.getMemory(), minAddr);
		memBuf = new WrappedMemBuffer(memBuf, 3, 4);
		value = memBuf.getInt(0);
		assertEquals(value, 0x04050607);
		value = memBuf.getInt(1);
		assertEquals(value, 0x05060708);
		value = memBuf.getInt(3);
		assertEquals(value, 0x0708090A);
		value = memBuf.getInt(8);
		assertEquals(value, 0x0C0D0E0F);

		memBuf = new MemoryBufferImpl(program.getMemory(), minAddr);
		memBuf = new WrappedMemBuffer(memBuf, 4, 4);
		value = memBuf.getInt(0);
		assertEquals(value, 0x04050607);
		value = memBuf.getInt(1);
		assertEquals(value, 0x05060708);
		value = memBuf.getInt(3);
		assertEquals(value, 0x0708090A);
		value = memBuf.getInt(8);
		assertEquals(value, 0x0C0D0E0F);

		memBuf = new DumbMemBufferImpl(program.getMemory(), minAddr);
		memBuf = new WrappedMemBuffer(memBuf, 5, 4);
		value = memBuf.getInt(0);
		assertEquals(value, 0x04050607);
		value = memBuf.getInt(1);
		assertEquals(value, 0x05060708);
		value = memBuf.getInt(3);
		assertEquals(value, 0x0708090A);
		value = memBuf.getInt(8);
		assertEquals(value, 0x0C0D0E0F);
	}

	@Test
	public void testGetShortBuffered() throws Exception {
		loadProgram("notepad");
		int value;

		Address minAddr = program.getMinAddress();
		Address maxAddr = program.getMaxAddress();
		setBytes(minAddr, new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
			18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 });

		memBuf = new DumbMemBufferImpl(program.getMemory(), minAddr);
		memBuf = new WrappedMemBuffer(memBuf, 3, 0);

		value = memBuf.getShort(0);
		assertEquals(value, 0x0001);
		value = memBuf.getShort(1);
		assertEquals(value, 0x0102);
		value = memBuf.getShort(3);
		assertEquals(value, 0x0304);
		value = memBuf.getShort(8);
		assertEquals(value, 0x0809);

		memBuf = new DumbMemBufferImpl(program.getMemory(), minAddr);
		memBuf = new WrappedMemBuffer(memBuf, 5, 4);
		value = memBuf.getShort(0);
		assertEquals(value, 0x0405);
		value = memBuf.getShort(1);
		assertEquals(value, 0x0506);
		value = memBuf.getShort(3);
		assertEquals(value, 0x0708);
		value = memBuf.getShort(8);
		assertEquals(value, 0x0C0D);
	}

	@Test
	public void testGetLongBuffered() throws Exception {
		loadProgram("notepad");
		long value;

		Address minAddr = program.getMinAddress();
		Address maxAddr = program.getMaxAddress();
		setBytes(minAddr, new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 });

		memBuf = new DumbMemBufferImpl(program.getMemory(), minAddr);
		memBuf = new WrappedMemBuffer(memBuf, 7, 0);

		value = memBuf.getLong(0);
		assertEquals(value, 0x0001020304050607L);
		value = memBuf.getLong(1);
		assertEquals(value, 0x0102030405060708L);
		value = memBuf.getLong(3);
		assertEquals(value, 0x030405060708090AL);
		value = memBuf.getLong(8);
		assertEquals(value, 0x08090A0B0C0D0E0FL);

		memBuf = new DumbMemBufferImpl(program.getMemory(), minAddr);
		memBuf = new WrappedMemBuffer(memBuf, 9, 4);
		value = memBuf.getLong(0);
		assertEquals(value, 0x0405060708090A0BL);
		value = memBuf.getLong(1);
		assertEquals(value, 0x05060708090A0B0CL);
		value = memBuf.getLong(3);
		assertEquals(value, 0x0708090A0B0C0D0EL);
		value = memBuf.getLong(0);
		assertEquals(value, 0x0405060708090A0BL);
	}

	private void setBytes(Address addr, byte[] bytes) throws MemoryAccessException {

		Memory mem = program.getMemory();
		int txId = program.startTransaction("Test");
		try {
			mem.setBytes(addr, bytes);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testProgram20bit() throws Exception {
		program =
			createDefaultProgram(testName.getMethodName(), ProgramBuilder._X86_16_REAL_MODE, this);

		Address start = program.getAddressFactory().getAddress("0000:0000");

		InputStream is = new InputStream() {
			private int pos = 0;

			@Override
			public int read() throws IOException {
				if (pos < 0x10000) {
					++pos;
					return 0xaa;
				}
				if (pos < 0x20000) {
					++pos;
					return 0xbb;
				}
				if (pos < 0x30000) {
					++pos;
					return 0xcc;
				}
				return 0;
			}
		};

		int id = program.startTransaction("add block");
		try {
			program.getMemory().createInitializedBlock(".test", start, is, 0x30000,
				TaskMonitorAdapter.DUMMY_MONITOR, false);
		}
		finally {
			program.endTransaction(id, true);
		}

		MemoryBufferImpl buf = new MemoryBufferImpl(program.getMemory(), start);

		WrappedMemBuffer wrapBuf = new WrappedMemBuffer(buf, 0);
		for (int i = 0; i < 0x30000; i++) {
			int b = 0xff & wrapBuf.getByte(i);
			if (i < 0x10000) {
				assertEquals(0xaa, b);
				continue;
			}
			if (i < 0x20000) {
				assertEquals(0xbb, b);
				continue;
			}
			if (i < 0x30000) {
				assertEquals(0xcc, b);
				continue;
			}
		}

		wrapBuf = new WrappedMemBuffer(buf, 10, 0);
		for (int i = 0; i < 0x30000; i++) {
			int b = 0xff & wrapBuf.getByte(i);
			if (i < 0x10000) {
				assertEquals(0xaa, b);
				continue;
			}
			if (i < 0x20000) {
				assertEquals(0xbb, b);
				continue;
			}
			if (i < 0x30000) {
				assertEquals(0xcc, b);
				continue;
			}
		}
	}

	@Test
	public void testBoundary() throws Exception {
		loadProgram("notepad");

		Memory mem = program.getMemory();
		Address addr = program.getMaxAddress();
		memBuf = new MemoryBufferImpl(mem, program.getMaxAddress());
		WrappedMemBuffer wrapBuf = new WrappedMemBuffer(memBuf, 0);

		assertEquals(mem.getByte(addr), wrapBuf.getByte(0));

		try {
			wrapBuf.getByte(1);
			Assert.fail("Should not have been able to get byte");
		}
		catch (MemoryAccessException e) {
			// good
		}

		wrapBuf = new WrappedMemBuffer(memBuf, 20, 0);

		assertEquals(mem.getByte(addr), wrapBuf.getByte(0));

		try {
			wrapBuf.getByte(1);
			Assert.fail("Should not have been able to get byte");
		}
		catch (MemoryAccessException e) {
			// good
		}
	}

	@Test
	public void testBoundary1() throws Exception {
		loadProgram("notepad");

		Memory mem = program.getMemory();
		Address addr = program.getMaxAddress();
		memBuf = new MemoryBufferImpl(mem, program.getMaxAddress());
		WrappedMemBuffer wrapBuf = new WrappedMemBuffer(memBuf, 0);

		assertEquals(mem.getByte(addr), wrapBuf.getByte(0));
		try {
			wrapBuf.getByte(1);
			Assert.fail("Should not have been able to get byte");
		}
		catch (MemoryAccessException e) {
			// good
		}

		wrapBuf = new WrappedMemBuffer(memBuf, 20, 0);

		assertEquals(mem.getByte(addr), wrapBuf.getByte(0));
		try {
			wrapBuf.getByte(1);
			Assert.fail("Should not have been able to get byte");
		}
		catch (MemoryAccessException e) {
			// good
		}
	}

}
