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

import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Listing;

public class DelaySlotCodeUnitMergeManagerTest extends AbstractListingMergeManagerTest {

	private final byte[] delaySlotPair1 = new byte[] { 0x54, 0x40, 0x00, 0x01, 0x24, 0x16, 0x00,
		0x40 };

	private final byte[] delaySlotPair2 = new byte[] { 0x0c, 0x10, (byte) 0xcf, (byte) 0xe7, 0x02,
		0x20, 0x28, 0x21 };

	/**
	 * 
	 * @param arg0
	 */
	public DelaySlotCodeUnitMergeManagerTest() {
		super();
	}

@Test
    public void testAddLatestDelaySlot() throws Exception {

		mtf.initialize("r4000", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					listing.clearCodeUnits(addr(program, "80b4"), addr(program, "80bb"), false);
					program.getMemory().setBytes(addr(program, "80b4"), delaySlotPair1);
					Disassembler disassembler =
						Disassembler.getDisassembler(program, monitor, null);
					disassembler.disassemble(addr(program, "80b4"), null);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Checked-out Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					listing.clearCodeUnits(addr(program, "80b0"), addr(program, "80bf"), false);
					program.getMemory().setBytes(addr(program, "80b0"), delaySlotPair2);
					program.getMemory().setBytes(addr(program, "80b8"), delaySlotPair2);
					Disassembler disassembler =
						Disassembler.getDisassembler(program, monitor, null);
					disassembler.disassemble(addr(program, "80b0"), null);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x80b0", "0x80bf", KEEP_LATEST);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram,
			new AddressSet(addr("80a0"), addr("80cb")));
	}

@Test
    public void testAddLatestDelaySlot2() throws Exception {

		mtf.initialize("r4000", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					listing.clearCodeUnits(addr(program, "80b4"), addr(program, "80bb"), false);
					program.getMemory().setBytes(addr(program, "80b4"), delaySlotPair1);
					Disassembler disassembler =
						Disassembler.getDisassembler(program, monitor, null);
					disassembler.disassemble(addr(program, "80b4"), null);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Checked-out Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					listing.clearCodeUnits(addr(program, "80b0"), addr(program, "80bf"), false);
					program.getMemory().setBytes(addr(program, "80b0"), delaySlotPair2);
					program.getMemory().setBytes(addr(program, "80b8"), delaySlotPair2);
					Disassembler disassembler =
						Disassembler.getDisassembler(program, monitor, null);
					disassembler.disassemble(addr(program, "80b0"), null);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x80b0", "0x80bf", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("80a0"),
			addr("80cb")));
	}

@Test
    public void testAddLatestDelaySlot3() throws Exception {

		mtf.initialize("r4000", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					listing.clearCodeUnits(addr(program, "80b4"), addr(program, "80bb"), false);
					program.getMemory().setBytes(addr(program, "80b4"), delaySlotPair1);
					Disassembler disassembler =
						Disassembler.getDisassembler(program, monitor, null);
					disassembler.disassemble(addr(program, "80b4"), null);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Checked-out Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					listing.clearCodeUnits(addr(program, "80b0"), addr(program, "80bf"), false);
					program.getMemory().setBytes(addr(program, "80b0"), delaySlotPair2);
					program.getMemory().setBytes(addr(program, "80b8"), delaySlotPair2);
					Disassembler disassembler =
						Disassembler.getDisassembler(program, monitor, null);
					disassembler.disassemble(addr(program, "80b0"), null);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x80b0", "0x80bf", KEEP_MY);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("80a0"), addr("80cb")));
	}
}
