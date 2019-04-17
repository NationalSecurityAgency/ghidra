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
package ghidra.app.merge.listing;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.database.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Test the versioned merge of equate changes and conflicts.
 */
public class EquateMergeManager2Test extends AbstractListingMergeManagerTest {

	// 0 = nothing @ 010019a4
	// 0 = zero @ 010019a2, 010019f8
	// 0 @ 01001eba, 01001ec6, 010024bb OP(1)
	// 1 = 01 @ 01001d0b
	// 1 = 1 @ 01001da6 OP(1)
	// 1 = ein @ 01001cea
	// 1 = one @ 01001b5d
	// 1 = uno @ 01001bc9
	// 1 @ 01002533 OP(1), 01002623
	// 2 @ 01001ed2, 0100253a OP(1), 01002591
	// 3 = 0x3 @ 01001dd5
	// 3 = tres @ 01001dd8

	/**
	 * 
	 * @param arg0
	 */
	public EquateMergeManager2Test() {
		super();
	}

	@Test
	public void testAddDiffPickLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
	
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					EquateTable equateTab = program.getEquateTable();
					Address addr = addr(program, "0x1002d18");
					try {
						equateTab.createEquate("TWO", 2).addReference(addr, 1);
						equateTab.createEquate("ONE", 1).addReference(addr, 1);
					}
					catch (DuplicateNameException | InvalidInputException e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
	
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					EquateTable equateTab = program.getEquateTable();
					Address addr = addr(program, "0x1002d18");
					equateTab.getEquate("uno").addReference(addr, 1);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});
	
		executeMerge(ASK_USER);
		chooseEquate("0x1002d18", 1, KEEP_MY);
		waitForMergeCompletion();
	
		EquateTable equateTab = resultProgram.getEquateTable();
		List<Equate> equates = equateTab.getEquates(addr("0x1002d18"), 1);
		assertEquals(2, equates.size());
		Equate eq;
		eq = equates.get(0);
		assertEquals("TWO", eq.getName());
		assertEquals(2L, eq.getValue());
		eq = equates.get(1);
		assertEquals("uno", eq.getName());
		assertEquals(1L, eq.getValue());
	}

	@Test
	    public void testAddDiffPickMy() throws Exception {
			mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
	
				/* (non-Javadoc)
				 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
				 */
				@Override
				public void modifyLatest(ProgramDB program) {
					int txId = program.startTransaction("Modify Latest Program");
					boolean commit = false;
					try {
						EquateTable equateTab = program.getEquateTable();
						Address addr = addr(program, "0x1002533");
	//					equateTab.getEquate("one").addReference(addr, 1);
						try {
							equateTab.createEquate("0x1", 1).addReference(addr, 1);
						}
						catch (DuplicateNameException | InvalidInputException e) {
							Assert.fail(e.getMessage());
						}
						commit = true;
					}
					finally {
						program.endTransaction(txId, commit);
					}
				}
	
				/* (non-Javadoc)
				 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
				 */
				@Override
				public void modifyPrivate(ProgramDB program) {
					int txId = program.startTransaction("Modify My Program");
					boolean commit = false;
					try {
						EquateTable equateTab = program.getEquateTable();
						Address addr = addr(program, "0x1002533");
						equateTab.getEquate("uno").addReference(addr, 1);
						commit = true;
					}
					finally {
						program.endTransaction(txId, commit);
					}
				}
			});
	
			executeMerge(ASK_USER);
		waitForPrompting();
			chooseEquate("0x1002533", 1, KEEP_MY);
			waitForMergeCompletion();
	
			EquateTable equateTab = resultProgram.getEquateTable();
			List<Equate> equates = equateTab.getEquates(addr("0x1002533"), 1);
			assertEquals(1, equates.size());
			Equate eq = equates.get(0);
			assertEquals("uno", eq.getName());
			assertEquals(1L, eq.getValue());
		}

	@Test
	public void testAddNameDiffOnByteDataUpperBit0PickLatest() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new ByteDataType(),
			new byte[] { (byte) 0x5f }, 0x5f, false);
	}

	@Test
	public void testAddNameDiffOnByteDataUpperBit0PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new ByteDataType(),
			new byte[] { (byte) 0x5f }, 0x5f, true);
	}

	@Test
	public void testAddNameDiffOnByteDataUpperBit1PickLatest() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new ByteDataType(),
			new byte[] { (byte) 0xad }, 0xad, false);
	}

	@Test
	public void testAddNameDiffOnByteDataUpperBit1PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new ByteDataType(),
			new byte[] { (byte) 0xad }, 0xad, true);
	}

	@Test
	public void testAddNameDiffOnDWordDataUpperBit0PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new DWordDataType(), new byte[] { (byte) 0x5f,
			(byte) 0x5f, (byte) 0x5f, (byte) 0x5f }, 0x5f5f5f5f, true);
	}

	@Test
	public void testAddNameDiffOnDWordDataUpperBit1PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new DWordDataType(), new byte[] { (byte) 0xad,
			(byte) 0xad, (byte) 0xad, (byte) 0xad }, 0xadadadadL, true);
	}

	@Test
	public void testAddNameDiffOnInt3DataUpperBit0PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new Integer3DataType(), new byte[] {
			(byte) 0x5f, (byte) 0x5f, (byte) 0x5f }, 0x5f5f5fL, true);
	}

	@Test
	public void testAddNameDiffOnInt3DataUpperBit1PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new UnsignedInteger3DataType(), new byte[] {
			(byte) 0xad, (byte) 0xad, (byte) 0xad }, 0xadadadL, true);
	}

	@Test
	public void testAddNameDiffOnInt5DataUpperBit0PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new UnsignedInteger5DataType(), new byte[] {
			(byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f }, 0x5f5f5f5f5fL, true);
	}

	@Test
	public void testAddNameDiffOnInt5DataUpperBit1PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new UnsignedInteger5DataType(), new byte[] {
			(byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad }, 0xadadadadadL, true);
	}

	@Test
	public void testAddNameDiffOnInt6DataUpperBit0PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new UnsignedInteger6DataType(), new byte[] {
			(byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f },
			0x5f5f5f5f5f5fL, true);
	}

	@Test
	public void testAddNameDiffOnInt6DataUpperBit1PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new UnsignedInteger6DataType(), new byte[] {
			(byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad },
			0xadadadadadadL, true);
	}

	@Test
	public void testAddNameDiffOnInt7DataUpperBit0PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new UnsignedInteger7DataType(), new byte[] {
			(byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f,
			(byte) 0x5f }, 0x5f5f5f5f5f5f5fL, true);
	}

	@Test
	public void testAddNameDiffOnInt7DataUpperBit1PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new UnsignedInteger7DataType(), new byte[] {
			(byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad,
			(byte) 0xad }, 0xadadadadadadadL, true);
	}

	@Test
	public void testAddNameDiffOnNegativeOperand() throws Exception {
		// 0x1002d20   LEA  ECX,[ESI + -0x20]
		mtf.initialize("NotepadMergeListingTest_X86", new OriginalProgramModifierListener() {
	
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Setup Original Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					Address startAddr = addr(program, "0x1002d20");
					program.getMemory().setBytes(startAddr,
						new byte[] { (byte) 0x8d, (byte) 0x4e, (byte) 0xe0 }); // LEA  ECX,[ESI + -0x20]
					createInstruction(program, startAddr);
					Instruction instruction = listing.getInstructionAt(startAddr);
					Assert.assertTrue(instruction != null);
					Assert.assertEquals(2, instruction.getNumOperands());
					commit = true;
				}
				catch (MemoryAccessException e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
	
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					EquateTable equateTab = program.getEquateTable();
					Address addr = addr(program, "0x1002d20");
					try {
						equateTab.createEquate("FOO", -0x20).addReference(addr, 1);
					}
					catch (DuplicateNameException | InvalidInputException e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
	
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					EquateTable equateTab = program.getEquateTable();
					Address addr = addr(program, "0x1002d20");
					try {
						equateTab.createEquate("BAR", -0x20).addReference(addr, 1);
					}
					catch (DuplicateNameException | InvalidInputException e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});
	
		executeMerge(ASK_USER);
		chooseEquate("0x1002d20", 1, KEEP_MY); // -0x20
		waitForMergeCompletion();
	
		EquateTable equateTab = resultProgram.getEquateTable();
		List<Equate> equates = equateTab.getEquates(addr("0x1002d20"), 1);
		assertEquals(1, equates.size());
		Equate eq = equates.get(0);
		assertEquals("BAR", eq.getName());
		assertEquals(-0x20L, eq.getValue());
	}

	@Test
	public void testAddNameDiffOnQWordDataUpperBit0PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new QWordDataType(), new byte[] { (byte) 0x5f,
			(byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f,
			(byte) 0x5f }, 0x5f5f5f5f5f5f5f5fL, true);
	}

	@Test
	public void testAddNameDiffOnQWordDataUpperBit1PickLatest() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new QWordDataType(), new byte[] { (byte) 0xad,
			(byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad,
			(byte) 0xad }, 0xadadadadadadadadL, false);
	}

	@Test
	public void testAddNameDiffOnQWordDataUpperBit1PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new QWordDataType(), new byte[] { (byte) 0xad,
			(byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad,
			(byte) 0xad }, 0xadadadadadadadadL, true);
	}

	@Test
	public void testAddNameDiffOnSignedByteDataUpperBit0PickLatest() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new SignedByteDataType(),
			new byte[] { (byte) 0x5f }, 0x5fL, false);
	}

	@Test
	public void testAddNameDiffOnSignedByteDataUpperBit0PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new SignedByteDataType(),
			new byte[] { (byte) 0x5f }, 0x5fL, true);
	}

	@Test
	public void testAddNameDiffOnSignedByteDataUpperBit1PickLatest() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new SignedByteDataType(),
			new byte[] { (byte) 0xad }, 0xffffffffffffffadL, false);
	}

	@Test
	public void testAddNameDiffOnSignedByteDataUpperBit1PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new SignedByteDataType(),
			new byte[] { (byte) 0xad }, 0xffffffffffffffadL, true);
	}

	@Test
	public void testAddNameDiffOnSignedDWordDataUpperBit0PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new SignedDWordDataType(), new byte[] {
			(byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f }, 0x5f5f5f5fL, true);
	}

	@Test
	public void testAddNameDiffOnSignedDWordDataUpperBit1PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new SignedDWordDataType(), new byte[] {
			(byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad }, 0xffffffffadadadadL, true);
	}

	@Test
	public void testAddNameDiffOnSignedInt3DataUpperBit0PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new Integer3DataType(), new byte[] {
			(byte) 0x5f, (byte) 0x5f, (byte) 0x5f }, 0x5f5f5fL, true);
	}

	@Test
	public void testAddNameDiffOnSignedInt3DataUpperBit1PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new Integer3DataType(), new byte[] {
			(byte) 0xad, (byte) 0xad, (byte) 0xad }, 0xffffffffffadadadL, true);
	}

	@Test
	public void testAddNameDiffOnSignedInt5DataUpperBit0PickLatest() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new Integer5DataType(), new byte[] {
			(byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f }, 0x5f5f5f5f5fL, false);
	}
}
