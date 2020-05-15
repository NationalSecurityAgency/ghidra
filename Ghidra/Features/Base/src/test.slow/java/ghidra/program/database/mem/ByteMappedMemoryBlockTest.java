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
package ghidra.program.database.mem;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class ByteMappedMemoryBlockTest extends AbstractGhidraHeadedIntegrationTest {

	private AddressSpace space;
	private MemoryBlock block;
	private Memory memory;
	private Program program;
	private int transactionID;

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY64_LE, this);
		memory = program.getMemory();

		byte[] bytes = new byte[0x100];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) i;
		}
		space = program.getAddressFactory().getDefaultAddressSpace();
		transactionID = program.startTransaction("Test");

		block = memory.createInitializedBlock("BYTE_BLOCK", space.getAddress(0),
			bytes.length, (byte) 0, TaskMonitor.DUMMY, false);
		memory.setBytes(block.getStart(), bytes);
	}

	@After
	public void tearDown() {
		program.endTransaction(transactionID, true);
		program.release(this);
	}

	private Address addr(long offset) {
		return space.getAddress(offset);
	}

	@Test
	public void testCreateNewBlock1to1() throws Exception {
		MemoryBlock byteMappedBlock =
			memory.createByteMappedBlock("test", addr(0x1000), addr(0x80), 0x100, false);
		assertEquals(0x100, byteMappedBlock.getSize());
		assertEquals(addr(0x1000), byteMappedBlock.getStart());
		assertEquals(addr(0x10FF), byteMappedBlock.getEnd());

		AddressSet set = new AddressSet(addr(0), addr(0xFF));
		set.add(addr(0x1000), addr(0x107F));
		assertEquals(set, memory.getAllInitializedAddressSet());
		assertEquals(set, memory.getLoadedAndInitializedAddressSet());

		MemoryBlockSourceInfo info = byteMappedBlock.getSourceInfos().get(0);
		ByteMappingScheme scheme = info.getByteMappingScheme().get();
		assertEquals(1, scheme.getMappedByteCount());
		assertEquals(1, scheme.getMappedSourceByteCount());
		assertEquals(addr(0x80), scheme.getMappedSourceAddress(addr(0), 0x80));

		for (int i = 0; i < 0x80; i++) {
			byte b = byteMappedBlock.getByte(addr(0x1000 + i));
			assertEquals(0x80 + i, b & 0xff);
		}

		try {
			byteMappedBlock.getByte(addr(0x1100));
			fail("expected MemoryAccessException");
		}
		catch (MemoryAccessException e) {
			// expected
		}

		byte[] bytes = new byte[0x100];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) ~i;
		}

		MemoryBlock block2 = memory.createInitializedBlock("BYTE_BLOCK2", space.getAddress(0x100),
			bytes.length,
			(byte) 0, TaskMonitor.DUMMY, false);

		set.add(addr(0x100), addr(0x1FF));
		set.add(addr(0x1080), addr(0x10FF));
		assertEquals(set, memory.getAllInitializedAddressSet());
		assertEquals(set, memory.getLoadedAndInitializedAddressSet());

		assertEquals(0, byteMappedBlock.getByte(addr(0x1080)));

		memory.setBytes(block2.getStart(), bytes);

		for (int i = 0; i < 0x80; i++) {
			byte b = byteMappedBlock.getByte(addr(0x1000 + i));
			assertEquals(0x80 + i, b & 0xff);
		}

		for (int i = 0; i < 0x7F; i++) {
			byte b = byteMappedBlock.getByte(addr(0x1080 + i));
			assertEquals(~i & 0xff, b & 0xff);
		}

		byte[] data1 = new byte[] { 1, 2, 3 };
		byteMappedBlock.putBytes(addr(0x1080), data1);

		byte[] data2 = new byte[3];
		assertEquals(3, byteMappedBlock.getBytes(addr(0x1080), data2));
		assertTrue(Arrays.equals(data1, data2));
		assertEquals(3, block2.getBytes(addr(0x100), data2));
		assertTrue(Arrays.equals(data1, data2));
	}

	@Test
	public void testCreateNewBlock1to2() throws Exception {
		MemoryBlock byteMappedBlock = memory.createByteMappedBlock("test", addr(0x1000), addr(0x80),
			0x100, new ByteMappingScheme(1, 2), false);
		assertEquals(0x100, byteMappedBlock.getSize());
		assertEquals(addr(0x1000), byteMappedBlock.getStart());
		assertEquals(addr(0x10FF), byteMappedBlock.getEnd());

		AddressSet set = new AddressSet(addr(0), addr(0xFF));
		set.add(addr(0x1000), addr(0x103F));
		assertEquals(set, memory.getAllInitializedAddressSet());
		assertEquals(set, memory.getLoadedAndInitializedAddressSet());

		MemoryBlockSourceInfo info = byteMappedBlock.getSourceInfos().get(0);
		ByteMappingScheme scheme = info.getByteMappingScheme().get();
		assertEquals(1, scheme.getMappedByteCount());
		assertEquals(2, scheme.getMappedSourceByteCount());
		assertEquals(addr(0x100), scheme.getMappedSourceAddress(addr(0), 0x80));

		for (int i = 0; i < 0x40; i++) {
			byte b = byteMappedBlock.getByte(addr(0x1000 + i));
			assertEquals(0x80 + (2 * i), b & 0xff);
		}

		try {
			byteMappedBlock.getByte(addr(0x1100));
			fail("expected MemoryAccessException");
		}
		catch (MemoryAccessException e) {
			// expected
		}

		byte[] bytes = new byte[0x100];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) ~i;
		}

		MemoryBlock block2 = memory.createInitializedBlock("BYTE_BLOCK2", space.getAddress(0x100),
			bytes.length, (byte) 0, TaskMonitor.DUMMY, false);

		set.add(addr(0x100), addr(0x1FF));
		set.add(addr(0x1040), addr(0x10BF));
		assertEquals(set, memory.getAllInitializedAddressSet());
		assertEquals(set, memory.getLoadedAndInitializedAddressSet());

		assertEquals(0, byteMappedBlock.getByte(addr(0x1080)));

		memory.setBytes(block2.getStart(), bytes);

		for (int i = 0; i < 0x40; i++) {
			byte b = byteMappedBlock.getByte(addr(0x1000 + i));
			assertEquals(0x80 + (2 * i), b & 0xff);
		}

		for (int i = 0; i < 0x7F; i++) {
			byte b = byteMappedBlock.getByte(addr(0x1040 + i));
			assertEquals(~(2 * i) & 0xff, b & 0xff);
		}

		byte[] data1 = new byte[] { 1, 2, 3, 4 };
		byteMappedBlock.putBytes(addr(0x1040), data1);

		byte[] data2 = new byte[4];
		assertEquals(4, byteMappedBlock.getBytes(addr(0x1040), data2));
		assertTrue(Arrays.equals(data1, data2));
		assertEquals(4, block2.getBytes(addr(0x100), data2));
		assertTrue(Arrays.equals(new byte[] { 1, -2, 2, -4 }, data2));
	}

	@Test
	public void testCreateNewBlock2to4() throws Exception {
		MemoryBlock byteMappedBlock = memory.createByteMappedBlock("test", addr(0x1000), addr(0x80),
			0x100, new ByteMappingScheme(2, 4), false);
		assertEquals(0x100, byteMappedBlock.getSize());
		assertEquals(addr(0x1000), byteMappedBlock.getStart());
		assertEquals(addr(0x10FF), byteMappedBlock.getEnd());

		AddressSet set = new AddressSet(addr(0), addr(0xFF));
		set.add(addr(0x1000), addr(0x103E));
		assertEquals(set, memory.getAllInitializedAddressSet());
		assertEquals(set, memory.getLoadedAndInitializedAddressSet());

		MemoryBlockSourceInfo info = byteMappedBlock.getSourceInfos().get(0);
		ByteMappingScheme scheme = info.getByteMappingScheme().get();
		assertEquals(2, scheme.getMappedByteCount());
		assertEquals(4, scheme.getMappedSourceByteCount());
		assertEquals(addr(0x100), scheme.getMappedSourceAddress(addr(0), 0x80));

		for (int i = 0; i < 0x40; i++) {
			byte b = byteMappedBlock.getByte(addr(0x1000 + i));
			int val = 0x80 + (4 * (i / 2) + (i % 2));
			assertEquals(val & 0xff, b & 0xff);
		}

		try {
			byteMappedBlock.getByte(addr(0x1100));
			fail("expected MemoryAccessException");
		}
		catch (MemoryAccessException e) {
			// expected
		}

		byte[] bytes = new byte[0x100];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) ~i;
		}

		MemoryBlock block2 = memory.createInitializedBlock("BYTE_BLOCK2", space.getAddress(0x100),
			bytes.length, (byte) 0, TaskMonitor.DUMMY, false);

		set.add(addr(0x100), addr(0x1FF));
		set.add(addr(0x103F), addr(0x10BE));
		assertEquals(set, memory.getAllInitializedAddressSet());
		assertEquals(set, memory.getLoadedAndInitializedAddressSet());

		assertEquals(0, byteMappedBlock.getByte(addr(0x1080)));

		memory.setBytes(block2.getStart(), bytes);

		for (int i = 0; i < 0x40; i++) {
			byte b = byteMappedBlock.getByte(addr(0x1000 + i));
			int val = 0x80 + (4 * (i / 2) + (i % 2));
			assertEquals(val & 0xff, b & 0xff);
		}

		for (int i = 0; i < 0x7F; i++) {
			byte b = byteMappedBlock.getByte(addr(0x1040 + i));
			int val = ~(4 * (i / 2) + (i % 2));
			assertEquals(val & 0xff, b & 0xff);
		}

		byte[] data1 = new byte[] { 1, 2, 3, 4 };
		byteMappedBlock.putBytes(addr(0x1040), data1);

		byte[] data2 = new byte[4];
		assertEquals(4, byteMappedBlock.getBytes(addr(0x1040), data2));
		assertTrue(Arrays.equals(data1, data2));
		assertEquals(4, block2.getBytes(addr(0x100), data2));
		assertTrue(Arrays.equals(new byte[] { 1, 2, -3, -4 }, data2));
	}

	@Test
	public void testCreateNewBlock2to4Overlay() throws Exception {
		MemoryBlock byteMappedBlock = memory.createByteMappedBlock("test", addr(0x1000), addr(0x80),
			0x100, new ByteMappingScheme(2, 4), true);
		assertTrue(byteMappedBlock.isOverlay());
		AddressSpace testSpace = program.getAddressFactory().getAddressSpace("test");
		assertNotNull(testSpace);
		assertEquals(space, testSpace.getPhysicalSpace());
		assertEquals(testSpace.getAddress(0x1000), testSpace.getMinAddress());
		assertEquals(testSpace.getAddress(0x10FF), testSpace.getMaxAddress());
		assertEquals(0x100, byteMappedBlock.getSize());
		assertEquals(testSpace.getAddress(0x1000), byteMappedBlock.getStart());
		assertEquals(testSpace.getAddress(0x10FF), byteMappedBlock.getEnd());

		AddressSet set = new AddressSet(addr(0), addr(0xFF));
		set.add(testSpace.getAddress(0x1000), testSpace.getAddress(0x103E));
		assertEquals(set, memory.getAllInitializedAddressSet());
		assertEquals(set, memory.getLoadedAndInitializedAddressSet());

		MemoryBlockSourceInfo info = byteMappedBlock.getSourceInfos().get(0);
		ByteMappingScheme scheme = info.getByteMappingScheme().get();
		assertEquals(2, scheme.getMappedByteCount());
		assertEquals(4, scheme.getMappedSourceByteCount());
		assertEquals(addr(0x100), scheme.getMappedSourceAddress(addr(0), 0x80));

		for (int i = 0; i < 0x40; i++) {
			byte b = byteMappedBlock.getByte(testSpace.getAddress(0x1000 + i));
			int val = 0x80 + (4 * (i / 2) + (i % 2));
			assertEquals(val & 0xff, b & 0xff);
		}

		try {
			byteMappedBlock.getByte(testSpace.getAddress(0x1100));
			fail("expected MemoryAccessException");
		}
		catch (MemoryAccessException e) {
			// expected
		}

		byte[] bytes = new byte[0x100];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) ~i;
		}

		MemoryBlock block2 = memory.createInitializedBlock("BYTE_BLOCK2", space.getAddress(0x100),
			bytes.length, (byte) 0, TaskMonitor.DUMMY, false);

		set.add(addr(0x100), addr(0x1FF));
		set.add(testSpace.getAddress(0x103F), testSpace.getAddress(0x10BE));
		assertEquals(set, memory.getAllInitializedAddressSet());
		assertEquals(set, memory.getLoadedAndInitializedAddressSet());

		assertEquals(0, byteMappedBlock.getByte(testSpace.getAddress(0x1080)));

		memory.setBytes(block2.getStart(), bytes);

		for (int i = 0; i < 0x40; i++) {
			byte b = byteMappedBlock.getByte(testSpace.getAddress(0x1000 + i));
			int val = 0x80 + (4 * (i / 2) + (i % 2));
			assertEquals(val & 0xff, b & 0xff);
		}

		for (int i = 0; i < 0x7F; i++) {
			byte b = byteMappedBlock.getByte(testSpace.getAddress(0x1040 + i));
			int val = ~(4 * (i / 2) + (i % 2));
			assertEquals(val & 0xff, b & 0xff);
		}

		byte[] data1 = new byte[] { 1, 2, 3, 4 };
		byteMappedBlock.putBytes(testSpace.getAddress(0x1040), data1);

		byte[] data2 = new byte[4];
		assertEquals(4, byteMappedBlock.getBytes(testSpace.getAddress(0x1040), data2));
		assertTrue(Arrays.equals(data1, data2));
		assertEquals(4, block2.getBytes(addr(0x100), data2));
		assertTrue(Arrays.equals(new byte[] { 1, 2, -3, -4 }, data2));
	}

	@Test
	public void testNoUnderlyingMemory() throws Exception {

		MemoryBlock byteMappedBlock = memory.createByteMappedBlock("BYTE_BLOCK", addr(0x1000),
			addr(0x1020), 0x10, new ByteMappingScheme(1, 1), false);

		Address addr = addr(0x1040);
		MemoryBlock newblock = memory.createBlock(byteMappedBlock, "Test", addr, 0x20);
		try {
			newblock.getByte(addr);
			Assert.fail("Should not have gotten a byte");
		}
		catch (MemoryAccessException e) {
			// expected
		}
	}
}
