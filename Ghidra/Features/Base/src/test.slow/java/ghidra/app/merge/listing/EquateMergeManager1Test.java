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

import static org.junit.Assert.*;

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
public class EquateMergeManager1Test extends AbstractListingMergeManagerTest {

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
	public EquateMergeManager1Test() {
		super();
	}

	@Test
	public void testRemoveEquate() throws Exception {
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
					equateTab.removeEquate("uno"); // 01001bc9
					equateTab.removeEquate("ein"); // 01001cea
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
					equateTab.removeEquate("one"); // 01001b5d
					equateTab.removeEquate("ein"); // 01001cea
					equateTab.removeEquate("zero"); // 010019a2, 010019f8
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		originalProgram = mtf.getOriginalProgram();
		EquateTable originalEquateTab = originalProgram.getEquateTable();
		List<Equate> equates = originalEquateTab.getEquates(addr(originalProgram, "0x1001b5d"), 1);
		assertEquals(1, equates.size());
		assertEquals("one", equates.get(0).getName());

		equates = originalEquateTab.getEquates(addr(originalProgram, "0x1001bc9"), 1);
		assertEquals(1, equates.size());
		assertEquals("uno", equates.get(0).getName());

		equates = originalEquateTab.getEquates(addr(originalProgram, "0x1001cea"), 1);
		assertEquals(1, equates.size());
		assertEquals("ein", equates.get(0).getName());

		equates = originalEquateTab.getEquates(addr(originalProgram, "0x10019a2"), 1);
		assertEquals(1, equates.size());
		assertEquals("zero", equates.get(0).getName());

		equates = originalEquateTab.getEquates(addr(originalProgram, "0x10019f8"), 1);
		assertEquals(1, equates.size());
		assertEquals("zero", equates.get(0).getName());

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		EquateTable equateTab = resultProgram.getEquateTable();
		equates = equateTab.getEquates(addr("0x1001b5d"), 0);
		assertEquals(0, equates.size());
		equates = equateTab.getEquates(addr("0x1001bc9"), 0);
		assertEquals(0, equates.size());
		equates = equateTab.getEquates(addr("0x1001cea"), 0);
		assertEquals(0, equates.size());
		equates = equateTab.getEquates(addr("0x10019a2"), 0);
		assertEquals(0, equates.size());
		equates = equateTab.getEquates(addr("0x10019f8"), 0);
		assertEquals(0, equates.size());
	}

	@Test
	public void testChangeEquate() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					changeEquate(program, "0x1001b5d", 1, 1L, "SINGLE");
					changeEquate(program, "0x1001bc9", 1, 1L, "first");
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
					changeEquate(program, "0x1001b5d", 1, 1L, "ONE");
					changeEquate(program, "0x1001bc9", 1, 1L, "INITIAL");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON_NAME);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		Equate eq;
		EquateTable equateTab = resultProgram.getEquateTable();
		List<Equate> equates = equateTab.getEquates(addr("0x1001b5d"), 1);
		assertEquals(1, equates.size());
		eq = equates.get(0);
		assertEquals("SINGLE", eq.getName());
		assertEquals(1L, eq.getValue());

		equates = equateTab.getEquates(addr("0x1001bc9"), 1);
		assertEquals(1, equates.size());
		eq = equates.get(0);
		assertEquals("INITIAL", eq.getName());
		assertEquals(1L, eq.getValue());
	}

	/**
	 * 
	 * @param program
	 * @param address
	 * @param opIndex
	 * @param value
	 */
	protected void changeEquate(ProgramDB program, String address, int opIndex, long value,
			String newName) {
		EquateTable equateTab = program.getEquateTable();
		Address addr = addr(program, address);
		Equate oldEquate = equateTab.getEquate(addr, opIndex, value);
		if (oldEquate.getName().equals(newName)) {
			Assert.fail(
				"Equate '" + oldEquate.getName() + "' already exists with value=" + value + ".");
		}
		oldEquate.removeReference(addr, opIndex);
		try {
			Equate newEquate = equateTab.getEquate(newName);
			if (newEquate == null) {
				newEquate = equateTab.createEquate(newName, value);
			}
			if (newEquate.getValue() != value) {
				Assert.fail("Can't create equate '" + newEquate.getName() + "' with value=" +
					value + ". It already exists with value=" + newEquate.getValue() + ".");
			}
			newEquate.addReference(addr, opIndex);
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
	}

	@Test
	public void testRemoveVsChangeEquate() throws Exception {
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
					equateTab.removeEquate("uno"); // 01001bc9
					equateTab.removeEquate("ein"); // 01001cea
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
					changeEquate(program, "0x1001bc9", 1, 1L, "dog");
					changeEquate(program, "0x1001cea", 1, 1L, "cat");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON_NAME);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		EquateTable equateTab = resultProgram.getEquateTable();
		List<Equate> equates = equateTab.getEquates(addr("0x1001bc9"), 1);
		assertEquals(0, equates.size());
		equates = equateTab.getEquates(addr("0x1001cea"), 1);
		assertEquals(1, equates.size());
		Equate eq = equates.get(0);
		assertEquals("cat", eq.getName());
		assertEquals(1L, eq.getValue());
	}

	@Test
	public void testAddNameDiffPickMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					EquateTable equateTab = program.getEquateTable();
					Address addr = addr(program, "0x1002d18");
					try {
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

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					EquateTable equateTab = program.getEquateTable();
					Address addr = addr(program, "0x1002d18");
					try {
						equateTab.createEquate("SINGLE", 1).addReference(addr, 1);
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
		chooseEquate("0x1002d18", 1, KEEP_MY);
		waitForMergeCompletion();

		EquateTable equateTab = resultProgram.getEquateTable();
		List<Equate> equates = equateTab.getEquates(addr("0x1002d18"), 1);
		assertEquals(1, equates.size());
		Equate eq = equates.get(0);
		assertEquals("SINGLE", eq.getName());
		assertEquals(1L, eq.getValue());
	}

	@Test
	public void testAddNameDiffOnWordDataUpperBit0PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new WordDataType(),
			new byte[] { (byte) 0x5f, (byte) 0x5f }, 0x5f5f, true);
	}

	@Test
	public void testAddNameDiffOnWordDataUpperBit1PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new WordDataType(),
			new byte[] { (byte) 0xad, (byte) 0xad }, 0xadad, true);
	}

	@Test
	public void testAddNameDiffOnSignedWordDataUpperBit0PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new SignedWordDataType(),
			new byte[] { (byte) 0x5f, (byte) 0x5f }, 0x5f5fL, true);
	}

	@Test
	public void testAddNameDiffOnSignedWordDataUpperBit1PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new SignedWordDataType(),
			new byte[] { (byte) 0xad, (byte) 0xad }, 0xffffffffffffadadL, true);
	}

	@Test
	public void testAddNameDiffOnSignedQWordDataUpperBit0PickMy() throws Exception {
		runTestAddNameDiffPickIndicated(
			"0x1002d24", new SignedQWordDataType(), new byte[] { (byte) 0x5f, (byte) 0x5f,
				(byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f },
			0x5f5f5f5f5f5f5f5fL, true);
	}

	@Test
	public void testAddNameDiffOnSignedQWordDataUpperBit1PickMy() throws Exception {
		runTestAddNameDiffPickIndicated(
			"0x1002d24", new SignedQWordDataType(), new byte[] { (byte) 0xad, (byte) 0xad,
				(byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad },
			0xadadadadadadadadL, true);
	}

	@Test
	public void testAddNameDiffOnSignedInt5DataUpperBit0PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new Integer5DataType(),
			new byte[] { (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f },
			0x5f5f5f5f5fL, true);
	}

	@Test
	public void testAddNameDiffOnSignedInt5DataUpperBit1PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new Integer5DataType(),
			new byte[] { (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad },
			0xffffffadadadadadL, true);
	}

	@Test
	public void testAddNameDiffOnSignedInt6DataUpperBit0PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new Integer6DataType(), new byte[] {
			(byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f },
			0x5f5f5f5f5f5fL, true);
	}

	@Test
	public void testAddNameDiffOnSignedInt6DataUpperBit1PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new Integer6DataType(), new byte[] {
			(byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad },
			0xffffadadadadadadL, true);
	}

	@Test
	public void testAddNameDiffOnSignedInt7DataUpperBit0PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new Integer7DataType(),
			new byte[] { (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f,
				(byte) 0x5f, (byte) 0x5f },
			0x5f5f5f5f5f5f5fL, true);
	}

	@Test
	public void testAddNameDiffOnSignedInt7DataUpperBit1PickMy() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new Integer7DataType(),
			new byte[] { (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad,
				(byte) 0xad, (byte) 0xad },
			0xffadadadadadadadL, true);
	}

	@Test
	public void testAddNameDiffOnSignedWordDataUpperBit0PickLatest() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new SignedWordDataType(),
			new byte[] { (byte) 0x5f, (byte) 0x5f }, 0x5f5fL, false);
	}

	@Test
	public void testAddNameDiffOnSignedQWordDataUpperBit0PickLatest() throws Exception {
		runTestAddNameDiffPickIndicated(
			"0x1002d24", new SignedQWordDataType(), new byte[] { (byte) 0x5f, (byte) 0x5f,
				(byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f },
			0x5f5f5f5f5f5f5f5fL, false);
	}

	@Test
	public void testAddNameDiffOnSignedQWordDataUpperBit1PickLatest() throws Exception {
		runTestAddNameDiffPickIndicated(
			"0x1002d24", new SignedQWordDataType(), new byte[] { (byte) 0xad, (byte) 0xad,
				(byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad },
			0xadadadadadadadadL, false);
	}

	@Test
	public void testAddNameDiffOnSignedInt5DataUpperBit1PickLatest() throws Exception {
		runTestAddNameDiffPickIndicated(
			"0x1002d24", new Integer5DataType(), new byte[] { (byte) 0xad, (byte) 0xad, (byte) 0xad,
				(byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad },
			0xffffffadadadadadL, false);
	}

	@Test
	public void testAddNameDiffOnSignedInt6DataUpperBit0PickLatest() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new Integer6DataType(), new byte[] {
			(byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f, (byte) 0x5f },
			0x5f5f5f5f5f5fL, false);
	}

	@Test
	public void testAddNameDiffOnSignedInt6DataUpperBit1PickLatest() throws Exception {
		runTestAddNameDiffPickIndicated("0x1002d24", new Integer6DataType(), new byte[] {
			(byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad, (byte) 0xad },
			0xffffadadadadadadL, false);
	}

	private void setupAddNameDiffOnSubOperand() throws Exception {
		// 0x1002d20   LEA EAX,[0x0 + ECX*0x4]
		//
		// LATEST   0x0=NADA  0x4=FOUR
		// MY       0x0=ZERO  0x4=QUAD
		mtf.initialize("NotepadMergeListingTest_X86", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Setup Original Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					Address startAddr = addr(program, "0x1002d20");
					program.getMemory().setBytes(startAddr, new byte[] { (byte) 0x8d, (byte) 0x04,
						(byte) 0x8d, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0 }); //LEA EAX,[0x0 + ECX*0x4]
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
						equateTab.createEquate("NADA", 0).addReference(addr, 1);
						equateTab.createEquate("FOUR", 4).addReference(addr, 1);
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
						equateTab.createEquate("ZERO", 0).addReference(addr, 1);
						equateTab.createEquate("QUAD", 4).addReference(addr, 1);
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
	}

	@Test
	public void testAddNameDiffOnSubOperandPickLatestLatest() throws Exception {
		// 0x1002d20   LEA EAX,[0x0 + ECX*0x4]
		//
		// LATEST   0x0=NADA  0x4=FOUR
		// MY       0x0=ZERO  0x4=QUAD
		setupAddNameDiffOnSubOperand();

		executeMerge(ASK_USER);
		chooseEquate("0x1002d20", 1, KEEP_LATEST); // 0x0
		chooseEquate("0x1002d20", 1, KEEP_LATEST); // 0x4
		waitForMergeCompletion();

		EquateTable equateTab = resultProgram.getEquateTable();
		List<Equate> equates = equateTab.getEquates(addr("0x1002d20"), 1);
		assertEquals(2, equates.size());
		Equate eq = equates.get(0);
		assertEquals("NADA", eq.getName());
		assertEquals(0L, eq.getValue());
		eq = equates.get(1);
		assertEquals("FOUR", eq.getName());
		assertEquals(4L, eq.getValue());
	}

	@Test
	public void testAddNameDiffOnSubOperandPickMyMy() throws Exception {
		// 0x1002d20   LEA EAX,[0x0 + ECX*0x4]
		//
		// LATEST   0x0=NADA  0x4=FOUR
		// MY       0x0=ZERO  0x4=QUAD
		setupAddNameDiffOnSubOperand();

		executeMerge(ASK_USER);
		chooseEquate("0x1002d20", 1, KEEP_MY); // 0x0
		chooseEquate("0x1002d20", 1, KEEP_MY); // 0x4
		waitForMergeCompletion();

		EquateTable equateTab = resultProgram.getEquateTable();
		List<Equate> equates = equateTab.getEquates(addr("0x1002d20"), 1);
		assertEquals(2, equates.size());
		Equate eq = equates.get(0);
		assertEquals("QUAD", eq.getName());
		assertEquals(4L, eq.getValue());
		eq = equates.get(1);
		assertEquals("ZERO", eq.getName());
		assertEquals(0L, eq.getValue());
	}

	@Test
	public void testAddNameDiffOnSubOperandPickLatestMy() throws Exception {
		// 0x1002d20   LEA EAX,[0x0 + ECX*0x4]
		//
		// LATEST   0x0=NADA  0x4=FOUR
		// MY       0x0=ZERO  0x4=QUAD
		setupAddNameDiffOnSubOperand();

		executeMerge(ASK_USER);
		chooseEquate("0x1002d20", 1, KEEP_MY); // 0x4
		chooseEquate("0x1002d20", 1, KEEP_LATEST); // 0x0
		waitForMergeCompletion();

		EquateTable equateTab = resultProgram.getEquateTable();
		List<Equate> equates = equateTab.getEquates(addr("0x1002d20"), 1);
		assertEquals(2, equates.size());
		Equate eq;
		eq = equates.get(0);
		assertEquals("NADA", eq.getName());
		assertEquals(0L, eq.getValue());
		eq = equates.get(1);
		assertEquals("QUAD", eq.getName());
		assertEquals(4L, eq.getValue());
	}

	@Test
	public void testAddNameDiffOnSubOperandPickMyLatest() throws Exception {
		// 0x1002d20   LEA EAX,[0x0 + ECX*0x4]
		//
		// LATEST   0x0=NADA  0x4=FOUR
		// MY       0x0=ZERO  0x4=QUAD
		setupAddNameDiffOnSubOperand();

		executeMerge(ASK_USER);
		chooseEquate("0x1002d20", 1, KEEP_LATEST); // 0x4
		chooseEquate("0x1002d20", 1, KEEP_MY); // 0x0
		waitForMergeCompletion();

		EquateTable equateTab = resultProgram.getEquateTable();
		List<Equate> equates = equateTab.getEquates(addr("0x1002d20"), 1);
		assertEquals(2, equates.size());
		Equate eq;
		eq = equates.get(0);
		assertEquals("FOUR", eq.getName());
		assertEquals(4L, eq.getValue());
		eq = equates.get(1);
		assertEquals("ZERO", eq.getName());
		assertEquals(0L, eq.getValue());
	}

	@Test
	public void testAddSameNameDiffValue() throws Exception {
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
						equateTab.createEquate("apple", 2).addReference(addr, 1);
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
					try {
						equateTab.createEquate("apple", 1).addReference(addr, 1);
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
		waitForMergeCompletion();

		Equate eq;
		EquateTable equateTab = resultProgram.getEquateTable();

		List<Equate> equates = equateTab.getEquates(addr("0x1002d18"), 1);
		assertEquals(2, equates.size());
		eq = equates.get(0);
		assertEquals("apple", eq.getName());
		assertEquals(2L, eq.getValue());
		eq = equates.get(1);
		assertEquals("apple_conflict", eq.getName());
		assertEquals(1L, eq.getValue());
	}

	@Test
	public void testAddSameNameDiffValueWithResolve() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					changeEquate(program, "0x10019f8", 1, 0, "ORANGE");
					changeEquate(program, "0x1001d0b", 1, 1, "PEAR");
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
					changeEquate(program, "0x1001bc9", 1, 1, "ORANGE");
					changeEquate(program, "0x1001d0b", 1, 1, "ORANGE");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		Equate eq;
		EquateTable equateTab = resultProgram.getEquateTable();

		List<Equate> equates = equateTab.getEquates(addr("0x10019f8"), 1);
		assertEquals(1, equates.size());
		eq = equates.get(0);
		assertEquals("ORANGE", eq.getName());
		assertEquals(0L, eq.getValue());

		equates = equateTab.getEquates(addr("0x1001bc9"), 1);
		assertEquals(1, equates.size());
		eq = equates.get(0);
		assertEquals("ORANGE_conflict", eq.getName());
		assertEquals(1L, eq.getValue());

		equates = equateTab.getEquates(addr("0x1001d0b"), 1);
		assertEquals(1, equates.size());
		eq = equates.get(0);
		assertEquals("ORANGE_conflict", eq.getName());
		assertEquals(1L, eq.getValue());

	}

	private void setupUseForAll() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					changeEquate(program, "0x1001b5d", 1, 1L, "SINGLE");
					changeEquate(program, "0x1001bc9", 1, 1L, "first");
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
					changeEquate(program, "0x1001b5d", 1, 1L, "ONE");
					changeEquate(program, "0x1001bc9", 1, 1L, "INITIAL");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});
	}

	@Test
	public void testChangeEquateUseForAllPickLatest() throws Exception {
		setupUseForAll();

		executeMerge(ASK_USER);
		chooseEquate("0x1001b5d", 0, KEEP_LATEST, true);
//		chooseRadioButton("0x1001bc9", 0, KEEP_LATEST, true); // Handled by Use For All.
		waitForMergeCompletion();

		Equate eq;
		EquateTable equateTab = resultProgram.getEquateTable();
		List<Equate> equates = equateTab.getEquates(addr("0x1001b5d"), 1);
		assertEquals(1, equates.size());
		eq = equates.get(0);
		assertEquals("SINGLE", eq.getName());
		assertEquals(1L, eq.getValue());

		equates = equateTab.getEquates(addr("0x1001bc9"), 1);
		assertEquals(1, equates.size());
		eq = equates.get(0);
		assertEquals("first", eq.getName());
		assertEquals(1L, eq.getValue());
	}

	@Test
	public void testChangeEquateUseForAllPickMy() throws Exception {
		setupUseForAll();

		executeMerge(ASK_USER);
		chooseEquate("0x1001b5d", 0, KEEP_MY, true);
//		chooseRadioButton("0x1001bc9", 0, KEEP_MY, true); // Handled by Use For All.
		waitForMergeCompletion();

		Equate eq;
		EquateTable equateTab = resultProgram.getEquateTable();
		List<Equate> equates = equateTab.getEquates(addr("0x1001b5d"), 1);
		assertEquals(1, equates.size());
		eq = equates.get(0);
		assertEquals("ONE", eq.getName());
		assertEquals(1L, eq.getValue());

		equates = equateTab.getEquates(addr("0x1001bc9"), 1);
		assertEquals(1, equates.size());
		eq = equates.get(0);
		assertEquals("INITIAL", eq.getName());
		assertEquals(1L, eq.getValue());
	}

}
