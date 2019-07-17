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

import ghidra.program.database.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;

import org.junit.Test;

/**
 * Test the merge of the versioned program's code units when starting as Instruction.
 */
public class CodeUnitMergeManager5Test extends AbstractListingMergeManagerTest {
	// Byte Tests
	// 0x10074ae is a "ds" of "GetClientRect",00
	// 0x1007530 is a "ds" of "CharLowerW",00
	// 0x100753c is a "dw" of 296h
	// 0x100753e - 0x100754a is a "ds" of "UpdateWindow",00

	/**
	 * 
	 * @param arg0
	 */
	public CodeUnitMergeManager5Test() {
		super();
	}

@Test
    public void testByteCuDiff() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					setBytes(program, "0x100753c", getHexByteArray("96 02"));
					createData(program, "0x100753c", new WordDataType()); // Add word

					setBytes(program, "0x100754e",
						getHexByteArray("53 65 74 59 6f 75 72 53 74 75 66 66 00"));
					createData(program, "0x100754e", new StringDataType()); // Add string "SetYourStuff"

					setBytes(program, "0x1007568", getHexByteArray("12 00"));
					createData(program, "0x1007568", new WordDataType()); // Add word

					setBytes(program, "0x1007578",
						getHexByteArray("4c 6f 74 73 4f 66 53 74 75 66 66 54 6f 44 6f 00"));
					createData(program, "0x1007578", new StringDataType()); // Add string "LotsOfStuffToDo"

					setBytes(program, "0x1007598", getHexByteArray("78 00"));
					createData(program, "0x1007598", new WordDataType()); // Add word

					setBytes(program, "0x100759a",
						getHexByteArray("59 65 74 41 6e 6f 74 68 65 72 53 74 72 69 6e 67 3f 00"));
					createData(program, "0x100759a", new StringDataType()); // Add string "YetAnotherString?"

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					setBytes(program, "0x100753c", new byte[] { (byte) 0x95 });
					clear(program, "0x100754e", "0x100755a");
					setBytes(program, "0x1007569", new byte[] { (byte) 0x95 });
					clear(program, "0x1007578", "0x1007587");
					setBytes(program, "0x1007598", new byte[] { (byte) 0x95 });
					clear(program, "0x100759a", "0x10075ab");
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
					clear(program, "0x100753c", "0x100753d");
					setBytes(program, "0x100754f", new byte[] { (byte) 0x95 });
					clear(program, "0x1007568", "0x1007569");
					setBytes(program, "0x100757a", new byte[] { (byte) 0x95 });
					clear(program, "0x1007598", "0x1007599");
					setBytes(program, "0x100759a", new byte[] { (byte) 0x95 });
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER, true);
		chooseCodeUnit("0x100753c", "0x100753d", KEEP_LATEST);
		chooseCodeUnit("0x100754e", "0x100755a", KEEP_LATEST);
		chooseCodeUnit("0x1007568", "0x1007569", KEEP_MY);
		chooseCodeUnit("0x1007578", "0x1007587", KEEP_MY);
		chooseCodeUnit("0x1007598", "0x1007599", KEEP_ORIGINAL);
		chooseCodeUnit("0x100759a", "0x10075ab", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x100753c"),
			addr("0x100753d")));
		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x100754e"),
			addr("0x100755a")));
		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x1007568"),
			addr("0x1007569")));
		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x1007578"),
			addr("0x1007587")));
		assertSameBytes(resultProgram, originalProgram, new AddressSet(addr("0x1007598"),
			addr("0x1007599")));
		assertSameBytes(resultProgram, originalProgram, new AddressSet(addr("0x100759a"),
			addr("0x10075ab")));

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x100753c"),
			addr("0x100753d")));
		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x100754e"),
			addr("0x100755a")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1007568"),
			addr("0x1007569")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1007578"),
			addr("0x1007587")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1007598"),
			addr("0x1007599")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x100759a"),
			addr("0x10075ab")));
	}

@Test
    public void testByteEquateDiff() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					setBytes(program, "0x100d1ec", new byte[] { (byte) 0x54 });
					setBytes(program, "0x100d1f8", new byte[] { (byte) 0x2a });
					setBytes(program, "0x100d208", new byte[] { (byte) 0x60 });
					setEquate(program, "C", 0x43L, "0x100d214", 0);
					setEquate(program, "r", 0x72, "0x100d218", 0);
					setEquate(program, "+", 0x2b, "0x100d21c", 0);
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
					setEquate(program, "t", 0x74L, "0x100d1ec", 0);
					setEquate(program, ".", 0x2eL, "0x100d1f8", 0);
					setEquate(program, "n", 0x6eL, "0x100d208", 0);
					setBytes(program, "0x100d214", new byte[] { (byte) 0x51 });
					setBytes(program, "0x100d218", new byte[] { (byte) 0x62 });
					setBytes(program, "0x100d21c", new byte[] { (byte) 0x2a });
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x100d1ec", "0x100d1ec", KEEP_LATEST);
		chooseCodeUnit("0x100d1f8", "0x100d1f8", KEEP_MY);
		chooseCodeUnit("0x100d208", "0x100d208", KEEP_ORIGINAL);
		chooseCodeUnit("0x100d214", "0x100d214", KEEP_LATEST);
		chooseCodeUnit("0x100d218", "0x100d218", KEEP_MY);
		chooseCodeUnit("0x100d21c", "0x100d21c", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x100d1ec"),
			addr("0x100d1ec")));
		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x100d1f8"),
			addr("0x100d1f8")));
		assertSameBytes(resultProgram, originalProgram, new AddressSet(addr("0x100d208"),
			addr("0x100d208")));
		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x100d214"),
			addr("0x100d214")));
		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x100d218"),
			addr("0x100d218")));
		assertSameBytes(resultProgram, originalProgram, new AddressSet(addr("0x100d21c"),
			addr("0x100d21c")));

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x100d1ec"),
			addr("0x100d1ec")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x100d1f8"),
			addr("0x100d1f8")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x100d208"),
			addr("0x100d208")));
		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x100d214"),
			addr("0x100d214")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x100d218"),
			addr("0x100d218")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x100d21c"),
			addr("0x100d21c")));
	}

@Test
    public void testCodeUnitEquateDiff() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					clear(program, "0x1001bbd", "0x1001bc2");
					disassemble(program, "0x1001bbe", "0x1001bc2");

					clear(program, "0x1001c2b", "0x1001c33");

					clear(program, "0x1006654", "0x1006657");
					createData(program, "0x1006654", new FloatDataType());

					setEquate(program, "stuff", 0x1194L, "0x1006674", 0);

					setEquate(program, "1A7", 0x1a7L, "0x1006be2", 0);

					setEquate(program, "1B0", 0x1b0L, "0x1007446", 0);

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
					setEquate(program, "b7", 0xb7L, "0x1001bbd", 0);

					setEquate(program, "80", 0x80L, "0x1001c2b", 1);

					setEquate(program, "NegativeOne", 0xffffffffL, "0x1006654", 0);

					clear(program, "0x1006674", "0x1006677");
					createData(program, "0x1006674", new FloatDataType());

					clear(program, "0x1006be2", "0x1006be3");
					createData(program, "0x1006be2", new ArrayDataType(new ByteDataType(), 2, 1));

					clear(program, "0x1007446", "0x1007447");
					disassemble(program, "0x1007446", "0x1007447");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x1001bbd", "0x1001bc3", KEEP_LATEST);
		chooseCodeUnit("0x1001c2b", "0x1001c33", KEEP_MY);
		chooseCodeUnit("0x1006654", "0x1006657", KEEP_ORIGINAL);
		chooseCodeUnit("0x1006674", "0x1006677", KEEP_LATEST);
		chooseCodeUnit("0x1006be2", "0x1006be3", KEEP_MY);
		chooseCodeUnit("0x1007446", "0x1007447", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x1001bb8"),
			addr("0x1001bbc")));
		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x1001c2b"),
			addr("0x1001c33")));
		assertSameBytes(resultProgram, originalProgram, new AddressSet(addr("0x1006654"),
			addr("0x1006657")));
		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x1006674"),
			addr("0x1006677")));
		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x1006be2"),
			addr("0x1006be3")));
		assertSameBytes(resultProgram, originalProgram, new AddressSet(addr("0x1007446"),
			addr("0x1007447")));

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1001bb8"),
			addr("0x1001bbc")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1001c2b"),
			addr("0x1001c33")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1006654"),
			addr("0x1006657")));
		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1006674"),
			addr("0x1006677")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1006be2"),
			addr("0x1006be3")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1007446"),
			addr("0x1007447")));
	}

@Test
    public void testCodeUnitFunctionDiff() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// TODO
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// TODO
			}
		});

		executeMerge(ASK_USER);
		// TODO
//		chooseCodeUnit("0x1001bb8", "0x1001bbc", KEEP_LATEST);
//		chooseCodeUnit("0x1001c2b", "0x1001c33", KEEP_MY);
//		chooseCodeUnit("0x1006654", "0x1006657", KEEP_ORIGINAL);
//		chooseCodeUnit("0x1006674", "0x1006677", KEEP_LATEST);
//		chooseCodeUnit("0x1006be2", "0x1006be3", KEEP_MY);
//		chooseCodeUnit("0x1007446", "0x1007447", KEEP_ORIGINAL);
		waitForMergeCompletion();

		// TODO
//		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x1001bb8"), addr("0x1001bbc")));
//		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x1001c2b"), addr("0x1001c33")));
//		assertSameBytes(resultProgram, originalProgram, new AddressSet(addr("0x1006654"), addr("0x1006657")));
//		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x1006674"), addr("0x1006677")));
//		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x1006be2"), addr("0x1006be3")));
//		assertSameBytes(resultProgram, originalProgram, new AddressSet(addr("0x1007446"), addr("0x1007447")));
//		
//		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1001bb8"), addr("0x1001bbc")));
//		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1001c2b"), addr("0x1001c33")));
//		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1006654"), addr("0x1006657")));
//		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1006674"), addr("0x1006677")));
//		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1006be2"), addr("0x1006be3")));
//		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1007446"), addr("0x1007447")));
	}

@Test
    public void testCodeUnitReferenceDiff() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// TODO
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// TODO
			}
		});

		executeMerge(ASK_USER);
		// TODO
//		chooseCodeUnit("0x1001bb8", "0x1001bbc", KEEP_LATEST);
//		chooseCodeUnit("0x1001c2b", "0x1001c33", KEEP_MY);
//		chooseCodeUnit("0x1006654", "0x1006657", KEEP_ORIGINAL);
//		chooseCodeUnit("0x1006674", "0x1006677", KEEP_LATEST);
//		chooseCodeUnit("0x1006be2", "0x1006be3", KEEP_MY);
//		chooseCodeUnit("0x1007446", "0x1007447", KEEP_ORIGINAL);
		waitForMergeCompletion();

		// TODO
//		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x1001bb8"), addr("0x1001bbc")));
//		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x1001c2b"), addr("0x1001c33")));
//		assertSameBytes(resultProgram, originalProgram, new AddressSet(addr("0x1006654"), addr("0x1006657")));
//		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x1006674"), addr("0x1006677")));
//		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x1006be2"), addr("0x1006be3")));
//		assertSameBytes(resultProgram, originalProgram, new AddressSet(addr("0x1007446"), addr("0x1007447")));
//		
//		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1001bb8"), addr("0x1001bbc")));
//		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1001c2b"), addr("0x1001c33")));
//		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1006654"), addr("0x1006657")));
//		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1006674"), addr("0x1006677")));
//		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1006be2"), addr("0x1006be3")));
//		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1007446"), addr("0x1007447")));
	}

}
