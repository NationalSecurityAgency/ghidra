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

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitorAdapter;

public class MemoryBufferImplTest extends AbstractGhidraHeadedIntegrationTest {
	private Program program;
	private MemoryBufferImpl memBuf;

	public MemoryBufferImplTest() {
		super();
	}

	private void loadProgram(String name) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(name, ProgramBuilder._TOY);
		builder.createMemory("ram", "0x0", 100000);
		program = builder.getProgram();
		memBuf = new MemoryBufferImpl(program.getMemory(), program.getMinAddress());
	}

	@Test
	public void testGetBytes() throws Exception {
		loadProgram("notepad");

		Address minAddr = program.getMinAddress();
		Address maxAddr = program.getMaxAddress();
		setBytes(minAddr, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
		setBytes(maxAddr.subtract(7), new byte[] { 11, 12, 13, 14, 15, 16, 17, 18 });

		memBuf = new MemoryBufferImpl(program.getMemory(), minAddr);
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
	public void testAdvance() throws Exception {
		loadProgram("notepad");

		Memory mem = program.getMemory();
		Address addr = program.getMinAddress();
		memBuf = new MemoryBufferImpl(mem, program.getMinAddress());
		for (int i = 0; i < 5000; i++) {
			assertEquals(mem.getByte(addr), memBuf.getByte(0));
			assertEquals(mem.getByte(addr.add(1)), memBuf.getByte(1));
			assertEquals(mem.getByte(addr.add(2)), memBuf.getByte(2));
			assertEquals(mem.getByte(addr.add(3)), memBuf.getByte(3));
			assertEquals(mem.getShort(addr), memBuf.getShort(0));
			assertEquals(mem.getInt(addr), memBuf.getInt(0));
			assertEquals(BigInteger.valueOf(mem.getLong(addr)), memBuf.getBigInteger(0, 8, true));
			memBuf.advance(1);
			addr = addr.next();
		}

		addr = program.getMinAddress();
		memBuf = new MemoryBufferImpl(mem, program.getMinAddress());
		for (int i = 0; i < 5000; i++) {
			assertEquals(mem.getByte(addr), memBuf.getByte(0));
			assertEquals(mem.getByte(addr.add(1)), memBuf.getByte(1));
			assertEquals(mem.getByte(addr.add(2)), memBuf.getByte(2));
			assertEquals(mem.getByte(addr.add(3)), memBuf.getByte(3));
			memBuf.advance(3);
			addr = addr.add(3);
		}
	}

	@Test
	public void testSetPosition() throws Exception {
		loadProgram("notepad");

		Memory mem = program.getMemory();
		Address addr = program.getMinAddress();
		memBuf = new MemoryBufferImpl(mem, program.getMinAddress());
		for (int i = 0; i < 5000; i++) {
			assertEquals(mem.getByte(addr), memBuf.getByte(0));
			assertEquals(mem.getByte(addr.add(1)), memBuf.getByte(1));
			assertEquals(mem.getByte(addr.add(2)), memBuf.getByte(2));
			assertEquals(mem.getByte(addr.add(3)), memBuf.getByte(3));
			addr = addr.add(5);
			memBuf.setPosition(addr);
		}

		addr = program.getMinAddress();
		memBuf = new MemoryBufferImpl(mem, program.getMinAddress());
		for (int i = 0; i < 500; i++) {
			assertEquals(mem.getByte(addr), memBuf.getByte(0));
			assertEquals(mem.getByte(addr.add(1)), memBuf.getByte(1));
			assertEquals(mem.getByte(addr.add(2)), memBuf.getByte(2));
			assertEquals(mem.getByte(addr.add(3)), memBuf.getByte(3));
			addr = addr.add(50);
			memBuf.setPosition(addr);
		}

		addr = program.getMinAddress();
		memBuf = new MemoryBufferImpl(mem, program.getMinAddress());
		for (int i = 0; i < 10; i++) {
			assertEquals(mem.getByte(addr), memBuf.getByte(0));
			assertEquals(mem.getByte(addr.add(1)), memBuf.getByte(1));
			assertEquals(mem.getByte(addr.add(2)), memBuf.getByte(2));
			assertEquals(mem.getByte(addr.add(3)), memBuf.getByte(3));
			addr = addr.add(2000);
			memBuf.setPosition(addr);
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

		for (int i = 0; i < 0x30000; i++) {
			int b = 0xff & buf.getByte(i);
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

		assertEquals(mem.getByte(addr), memBuf.getByte(0));
		memBuf.advance(1);
		addr = addr.next();

		try {
			memBuf.getByte(0);
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

		assertEquals(mem.getByte(addr), memBuf.getByte(0));
		try {
			memBuf.getByte(1);
			Assert.fail("Should not have been able to get byte");
		}
		catch (MemoryAccessException e) {
			// good
		}
	}

}
