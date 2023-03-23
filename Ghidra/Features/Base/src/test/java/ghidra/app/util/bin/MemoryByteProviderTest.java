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

import static org.junit.Assert.assertEquals;

import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class MemoryByteProviderTest extends AbstractGhidraHeadedIntegrationTest {
	protected ProgramDB program;
	protected AddressSpace space;
	protected Memory memory;
	protected TaskMonitor monitor = TaskMonitor.DUMMY;
	private ProgramBuilder builder;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder(testName.getMethodName(), ProgramBuilder._X64, this);
		program = builder.getProgram();
		memory = program.getMemory();
		space = program.getAddressFactory().getDefaultAddressSpace();
	}

	protected Address addr(long l) {
		return space.getAddress(l);
	}

	private void setBlockStartEndBytes(MemoryBlock memblk, String start, String end)
			throws Exception {
		builder.setBytes(memblk.getStart().toString(true),
			start.getBytes(StandardCharsets.US_ASCII));
		byte[] endBytes = end.getBytes(StandardCharsets.US_ASCII);
		builder.setBytes(memblk.getEnd().subtract(endBytes.length - 1).toString(true), endBytes);
	}

	private MemoryBlock addRam0() throws Exception {
		MemoryBlock memblk = builder.createMemory(space.getName(), "0", 0x50);
		setBlockStartEndBytes(memblk, "startram0\0", "endram0\0");
		return memblk;
	}

	private MemoryBlock addRam1() throws Exception {
		MemoryBlock memblk = builder.createMemory(space.getName(), "50", 0x50);
		setBlockStartEndBytes(memblk, "startram1\0", "endram1\0");
		return memblk;
	}

	private MemoryBlock addRam2() throws Exception {
		MemoryBlock memblk = builder.createMemory(space.getName(), "a0", 0x50);
		setBlockStartEndBytes(memblk, "startram2\0", "endram2\0");
		return memblk;
	}

	private MemoryBlock addRamEnd() throws Exception {
		MemoryBlock memblk = builder.createMemory(space.getName(), "ffffffffffffffb0", 0x50);
		setBlockStartEndBytes(memblk, "highstart\0", "highend\0");
		return memblk;
	}

	@After
	public void tearDown() throws Exception {
		builder.dispose();
	}

	@Test
	public void testNoMemory() throws IOException {
		MemoryByteProvider mbp = MemoryByteProvider.createProgramHeaderByteProvider(program, false);
		assertEquals(0, mbp.length());

		mbp = MemoryByteProvider.createDefaultAddressSpaceByteProvider(program, false);
		assertEquals(0, mbp.length());
	}

	@Test
	public void testCreateProgramHeader_Offset() throws Exception {
		addRam1();
		MemoryByteProvider mbp = MemoryByteProvider.createProgramHeaderByteProvider(program, false);
		BinaryReader reader = new BinaryReader(mbp, true);

		assertEquals(0x50, mbp.length());
		assertEquals("startram1", reader.readAsciiString(0));
	}

	@Test
	public void testCreateDefaultAddressSpace_Offset() throws Exception {
		addRam1();
		MemoryByteProvider mbp =
			MemoryByteProvider.createDefaultAddressSpaceByteProvider(program, false);
		BinaryReader reader = new BinaryReader(mbp, true);

		assertEquals(0x50 + 0x50, mbp.length());
		assertEquals("startram1", reader.readAsciiString(0x50));
	}

	@Test
	public void testMinAddrNotInBlock() throws Exception {
		addRam1();
		MemoryByteProvider mbp = new MemoryByteProvider(memory, addr(1));
		BinaryReader reader = new BinaryReader(mbp, true);

		assertEquals(0x50 + 0x50 - 1, mbp.length());
		assertEquals("startram1", reader.readAsciiString(0x50 - 1));
	}

	@Test
	public void testMinAddrInBlock() throws Exception {
		addRam1();
		MemoryByteProvider mbp = new MemoryByteProvider(memory, addr(0x51));
		BinaryReader reader = new BinaryReader(mbp, true);

		assertEquals(0x50 - 1, mbp.length());
		assertEquals(/* missing 's' */ "tartram1", reader.readAsciiString(0));
	}

	@Test
	public void testMinAddrAfterBlock() throws Exception {
		addRam1();
		MemoryByteProvider mbp = new MemoryByteProvider(memory, addr(0x5000));

		assertEquals(0, mbp.length());
	}

	@Test
	public void testMultiblock_adjacent() throws Exception {
		MemoryBlock blk1 = addRam1();
		MemoryBlock blk2 = addRam2();
		setBlockStartEndBytes(blk1, "blah", "aaaa");
		setBlockStartEndBytes(blk2, "bbbb", "blah");
		MemoryByteProvider mbp =
			MemoryByteProvider.createProgramHeaderByteProvider(program, false);
		BinaryReader reader = new BinaryReader(mbp, true);

		assertEquals(blk2.getEnd().getOffset() - blk1.getStart().getOffset() + 1, mbp.length());
		assertEquals(0x61616161, reader.readInt(0x50 - 4));
		assertEquals(0x62626262, reader.readInt(0x50));
		assertEquals(0x62626161, reader.readInt(0x50 - 2));
	}

	@Test
	public void testMultiblockLength_disjoint() throws Exception {
		MemoryBlock blk0 = addRam0();
		MemoryBlock blk2 = addRam2();
		MemoryByteProvider mbp =
			MemoryByteProvider.createProgramHeaderByteProvider(program, false);

		assertEquals(blk2.getEnd().getOffset() - blk0.getStart().getOffset() + 1, mbp.length());
	}

	@Test
	public void testLength_block_at_end_of_64bits() throws Exception {
		MemoryBlock blk = addRamEnd();
		MemoryByteProvider mbp =
			MemoryByteProvider.createProgramHeaderByteProvider(program, false);

		assertEquals(blk.getEnd().getOffset() - blk.getStart().getOffset() + 1, mbp.length());
	}

	@Test
	public void testLength_all64bits() throws Exception {
		addRam0();
		addRamEnd();
		MemoryByteProvider mbp =
			MemoryByteProvider.createProgramHeaderByteProvider(program, false);

		assertEquals(Long.MAX_VALUE, mbp.length());
	}

	@Test
	public void testFull64bitAddressSpace() throws Exception {
		addRamEnd();
		MemoryByteProvider mbp =
			MemoryByteProvider.createDefaultAddressSpaceByteProvider(program, false);
		BinaryReader reader = new BinaryReader(mbp, true);

		assertEquals(Long.MAX_VALUE, mbp.length());
		assertEquals("highstart", reader.readAsciiString(0xffffffffffffffb0L));
		assertEquals("end", reader.readAsciiString(0xfffffffffffffffcL));
	}

	@Test(expected = EOFException.class)
	public void testFull64bitAddressSpace_fail_when_wrap_string() throws Exception {
		MemoryBlock blk = addRamEnd();
		setBlockStartEndBytes(blk, "blah", "fail");
		MemoryByteProvider mbp =
			MemoryByteProvider.createDefaultAddressSpaceByteProvider(program, false);
		BinaryReader reader = new BinaryReader(mbp, true);

		reader.readAsciiString(0xfffffffffffffffcL);
	}

	@Test(expected = EOFException.class)
	public void testFull64bitAddressSpace_fail_when_wrap_int() throws Exception {
		addRamEnd();
		MemoryByteProvider mbp =
			MemoryByteProvider.createDefaultAddressSpaceByteProvider(program, false);
		BinaryReader reader = new BinaryReader(mbp, true);

		reader.readInt(0xfffffffffffffffeL);
	}

	@Test(expected = EOFException.class)
	public void testEOFExceptionWhenCrossingMemBlockBoundary() throws Exception {
		MemoryBlock blk1 = addRam1();
		addRamEnd();
		MemoryByteProvider mbp =
			MemoryByteProvider.createDefaultAddressSpaceByteProvider(program, false);
		BinaryReader reader = new BinaryReader(mbp, true);

		assertEquals("endram1", reader.readAsciiString(blk1.getEnd().getOffset() - 7));

		setBlockStartEndBytes(blk1, "blah", "fail");
		reader.readAsciiString(blk1.getEnd().getOffset() - 3);
	}
}
