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

import org.junit.Test;

import ghidra.program.database.OriginalProgramModifierListener;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;

/**
 * Test the merge of the versioned program's listing.
 * Provides tests that create instructions with overrides in various combinations.
 * For tests with conflicts, checks selection of latest, my, or original code unit(s).
 */
public class CodeUnitMergeManager6Test extends AbstractListingMergeManagerTest {

	public CodeUnitMergeManager6Test() {
		super();
	}

	@Test
	public void testAddLengthOverrideMyInstrPickMyInstr() throws Exception {
		mtf.initialize("DiffTestPgm1", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					// nop #0x3       11011001 00110001 00000000
					// imm r1,#0x300           00110001 00000000
					// imm r0,#0x0                               00000000 00000000
					setBytes(program, "0x10013d9", new byte[] { (byte) 0xd9, 0x31, 0, 0, 0 });
					commit = true;
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
					disassemble(program, "0x10013d9", "0x10013dc");
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
					disassemble(program, "0x10013d9", "0x10013dc");
					Listing listing = program.getListing();
					Instruction instr = listing.getInstructionAt(addr(program, "0x10013d9"));
					try {
						instr.setLengthOverride(1);
					}
					catch (CodeUnitInsertionException e) {
						failWithException("Unexpected exception", e);
					}
					disassemble(program, "0x10013da", "0x10013db");
					instr = listing.getInstructionAt(addr(program, "0x10013da"));
					assertNotNull("Failed to create overlapped instruction", instr);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x10013d9", "0x10013db", KEEP_MY);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013db")));

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs = refMgr.getReferencesFrom(addr("0x10013d9"));
		assertEquals(1, refs.length);
		assertEquals(RefType.FALL_THROUGH, refs[0].getReferenceType());
		assertEquals(addr("0x10013dc"), refs[0].getToAddress());
	}

	@Test
	public void testModifyLengthOverrideMyInstrPickOriginalInstr() throws Exception {
		mtf.initialize("DiffTestPgm1", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					// nop #0x3       11011001 00110001 00000000
					// imm r1,#0x300           00110001 00000000
					// imm r0,#0x0                               00000000 00000000
					setBytes(program, "0x10013d9", new byte[] { (byte) 0xd9, 0x31, 0, 0, 0 });
					disassemble(program, "0x10013d9", "0x10013dc");
					Listing listing = program.getListing();
					Instruction instr = listing.getInstructionAt(addr(program, "0x10013d9"));
					try {
						instr.setLengthOverride(1);
					}
					catch (CodeUnitInsertionException e) {
						failWithException("Unexpected exception", e);
					}
					commit = true;
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
					disassemble(program, "0x10013da", "0x10013db");
					Listing listing = program.getListing();
					Instruction instr = listing.getInstructionAt(addr(program, "0x10013da"));
					assertNotNull("Failed to create overlapped instruction", instr);
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
					clear(program, "0x10013d9", "0x10013d9");
					disassemble(program, "0x10013d9", "0x10013dc");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x10013d9", "0x10013db", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013db")));

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs = refMgr.getReferencesFrom(addr("0x10013d9"));
		assertEquals(1, refs.length);
		assertEquals(RefType.FALL_THROUGH, refs[0].getReferenceType());
		assertEquals(addr("0x10013dc"), refs[0].getToAddress());
	}

	@Test
	public void testAddLengthAndFallthroughOverrideMyInstrPickMyInstr() throws Exception {
		mtf.initialize("DiffTestPgm1", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					// nop #0x3       11011001 00110001 00000000
					// imm r1,#0x300           00110001 00000000
					// imm r0,#0x0                               00000000 00000000
					setBytes(program, "0x10013d9", new byte[] { (byte) 0xd9, 0x31, 0, 0, 0 });
					commit = true;
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
					disassemble(program, "0x10013d9", "0x10013dc");
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
					disassemble(program, "0x10013d9", "0x10013dc");
					Listing listing = program.getListing();
					Instruction instr = listing.getInstructionAt(addr(program, "0x10013d9"));
					try {
						instr.setLengthOverride(1);
					}
					catch (CodeUnitInsertionException e) {
						failWithException("Unexpected exception", e);
					}
					instr.setFallThrough(addr(program, "0x10013de"));

					disassemble(program, "0x10013da", "0x10013db");
					instr = listing.getInstructionAt(addr(program, "0x10013da"));
					assertNotNull("Failed to create overlapped instruction", instr);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x10013d9", "0x10013db", KEEP_MY);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013db")));

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs = refMgr.getReferencesFrom(addr("0x10013d9"));
		assertEquals(1, refs.length);
		assertEquals(RefType.FALL_THROUGH, refs[0].getReferenceType());
		assertEquals(addr("0x10013de"), refs[0].getToAddress());
	}

}
