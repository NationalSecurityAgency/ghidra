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
package sarif;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.program.util.ProgramDiff;
import ghidra.util.task.TaskMonitor;

public class MemoryMapSarifTest extends AbstractSarifTest {

	public MemoryMapSarifTest() {
		super();
	}

	@Test
	public void testCreateBlock() throws Exception {
		Memory mem = program.getMemory();

		MemoryBlock block = createBlock("Test", addr(0x4000), 100);
		addrSet.add(block.getAddressRange());

		// need to create a buffer with junk and free it
		// to verify that clean buffer is later produced
		MemoryBlock block2 = createBlock("Test2", addr(0x6000), 0x1000);
		mem.removeBlock(block2, TaskMonitor.DUMMY);
		addrSet.add(block2.getAddressRange());

		// Verify buffer
		block2 = mem.createBlock(block, "Test2", addr(0x6000), 0x1000);

		ProgramDiff programDiff = readWriteCompare();

		AddressSetView differences = programDiff.getDifferences(monitor);
		assert (differences.isEmpty());
	}

	@Test
	public void testCreateUninitializedBlock() throws Exception {
		Memory mem = program.getMemory();

		MemoryBlock ablock = mem.createUninitializedBlock("A", addr(0x4000), 10, false);
		addrSet.add(ablock.getAddressRange());

		ProgramDiff programDiff = readWriteCompare();

		AddressSetView differences = programDiff.getDifferences(monitor);
		assert (differences.isEmpty());
	}

	@Test
	public void testCreateOverlayBlock() throws Exception {
		Memory mem = program.getMemory();
		MemoryBlock oblock = mem.createInitializedBlock(".overlay", addr(0), 0x1000, (byte) 0xa, TaskMonitor.DUMMY,
				true);
		addrSet.add(oblock.getAddressRange());
		assertEquals(MemoryBlockType.DEFAULT, oblock.getType());
		assertTrue(oblock.isOverlay());

		ProgramDiff programDiff = readWriteCompare();

		AddressSetView differences = programDiff.getDifferences(monitor);
		assert (differences.isEmpty());
	}

	@Test
	public void testCreateBitMappedBlock() throws Exception {
		Memory mem = program.getMemory();
		MemoryBlock bitBlock = mem.createBitMappedBlock("bit", addr(0x4000), addr(0xf00), 0x1000, false);
		addrSet.add(bitBlock.getAddressRange());

		assertEquals(MemoryBlockType.BIT_MAPPED, bitBlock.getType());

		ProgramDiff programDiff = readWriteCompare();

		AddressSetView differences = programDiff.getDifferences(monitor);
		assert (differences.isEmpty());
	}

	@Test
	public void testCreateByteMappedBlock() throws Exception {
		Memory mem = program.getMemory();
		MemoryBlock byteBlock = mem.createByteMappedBlock("byte", addr(0x4000), addr(0xf00), 0x200, false);
		addrSet.add(byteBlock.getAddressRange());

		assertEquals(MemoryBlockType.BYTE_MAPPED, byteBlock.getType());

		ProgramDiff programDiff = readWriteCompare();

		AddressSetView differences = programDiff.getDifferences(monitor);
		assert (differences.isEmpty());
	}
	

	private MemoryBlock createBlock(String name, Address start, long size) throws Exception {
		return createBlock(name, start, size, 0);
	}

	private MemoryBlock createBlock(String name, Address start, long size, int initialValue) throws Exception {
		return program.getMemory().createInitializedBlock(name, start, size, (byte) initialValue, TaskMonitor.DUMMY,
				false);
	}
}
