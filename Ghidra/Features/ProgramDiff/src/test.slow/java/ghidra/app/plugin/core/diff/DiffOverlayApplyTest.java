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
package ghidra.app.plugin.core.diff;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.program.database.ProgramAddressFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.DiffUtility;
import ghidra.test.ClassicSampleX86ProgramBuilder;
import ghidra.util.task.TaskMonitorAdapter;

public class DiffOverlayApplyTest extends DiffApplyTestAdapter {

	public DiffOverlayApplyTest() {
		super();
	}

@Test
    public void testShowHideDiffApplySettings() throws Exception {
		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		builder.createMemory(".data", "0x2001000", 1000);

		Program p1 = builder.getProgram();
		assertTrue(p1.getAddressFactory() instanceof ProgramAddressFactory);
		assertEquals(2, p1.getAddressFactory().getNumAddressSpaces()); // ram, OTHER

		int id1 = p1.startTransaction("");
		Memory memory1 = p1.getMemory();
		MemoryBlock dataBlock1 = memory1.getBlock(".data");
		MemoryBlock overlayBlock1 =
			memory1.createInitializedBlock("OVL1", dataBlock1.getStart(), 0x20L, (byte) 0,
				TaskMonitorAdapter.DUMMY_MONITOR, true);
		assertEquals(3, p1.getAddressFactory().getNumAddressSpaces()); // ram, OTHER, OVL1

		AddressSet addressSet1 = new AddressSet(overlayBlock1.getStart(), overlayBlock1.getEnd());
		byte[] bytes1 =
			{ 'a', 'p', 'p', 'l', 'e', (byte) 0, 'o', 'r', 'a', 'n', 'g', 'e', (byte) 0 };
		memory1.setBytes(overlayBlock1.getStart(), bytes1);

		Listing listing1 = p1.getListing();
		Address overlayAddress1 = overlayBlock1.getStart();
		listing1.createData(overlayAddress1, new TerminatedStringDataType());
		overlayAddress1 = overlayAddress1.add(6);
		listing1.createData(overlayAddress1, new TerminatedStringDataType());

		p1.endTransaction(id1, true);

		ClassicSampleX86ProgramBuilder builder2 = new ClassicSampleX86ProgramBuilder();
		builder2.createMemory(".data", "0x2001000", 1000);
		Program p2 = builder2.getProgram();
		assertTrue(p2.getAddressFactory() instanceof ProgramAddressFactory);
		assertEquals(2, p2.getAddressFactory().getNumAddressSpaces());

		int id2 = p2.startTransaction("");
		Memory memory2 = p2.getMemory();
		MemoryBlock dataBlock2 = memory2.getBlock(".data");
		MemoryBlock overlayBlock2 =
			memory2.createInitializedBlock("OVL1", dataBlock2.getStart(), 0x20L, (byte) 0,
				TaskMonitorAdapter.DUMMY_MONITOR, true);
		assertEquals(3, p2.getAddressFactory().getNumAddressSpaces());

		AddressSet addressSet2 = DiffUtility.getCompatibleAddressSet(addressSet1, p2);
		byte[] bytes2 =
			{ 'd', 'o', 'b', 'e', 'r', 'm', 'a', 'n', (byte) 0, 'p', 'o', 'o', 'd', 'l', 'e',
				(byte) 0 };
		memory2.setBytes(overlayBlock2.getStart(), bytes2);

		Listing listing2 = p2.getListing();
		Address overlayAddress2 = overlayBlock2.getStart();
		listing2.createData(overlayAddress2, new TerminatedStringDataType());
		overlayAddress2 = overlayAddress2.add(9);
		listing2.createData(overlayAddress2, new TerminatedStringDataType());

		p2.endTransaction(id2, true);

		openProgram(p1);

		openDiff(p2);
		setDiffSelection(addressSet2);
		apply();

		Listing listing = p1.getListing();
		MemoryBlock overlayBlock = p1.getMemory().getBlock("OVL1");
		Address overlayAddress = overlayBlock.getStart();
		Data dataAt = listing.getDataAt(overlayAddress);
		assertNotNull(dataAt);
		assertEquals("doberman", dataAt.getValue());

		overlayAddress = overlayBlock.getStart().add(9);
		dataAt = listing.getDataAt(overlayAddress);
		assertNotNull(dataAt);
		assertEquals("poodle", dataAt.getValue());
	}
}
