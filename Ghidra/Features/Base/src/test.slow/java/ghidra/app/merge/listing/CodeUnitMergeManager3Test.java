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

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;

/**
 * Test the merge of the versioned program's code units when starting as Data.
 */
public class CodeUnitMergeManager3Test extends AbstractListingMergeManagerTest {

	/**
	 * 
	 * @param arg0
	 */
	public CodeUnitMergeManager3Test() {
		super();
	}

@Test
    public void testDataAddLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 100a2c5 initially is "dw" -> ADD
					clear(program, "0x100a2c5", "0x100a2c6");
					disassemble(program, "0x100a2c5", "0x100a2c6");

					// 100a2d8 initially is "ds" string -> OR
					clear(program, "0x100a2d8", "0x100a2da");

					// 100a2f4 initially is "ddw" -> TEST and ADD
					clear(program, "0x100a2f4", "0x100a2f7");
					createData(program, "0x100a2f7", new FloatDataType());

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
				// No changes.
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		AddressSet addrSet = new AddressSet(addr("0x100a2c5"), addr("0x100a2c6"));
		addrSet.addRange(addr("0x100a2d8"), addr("0x100a2da"));
		addrSet.addRange(addr("0x100a2f4"), addr("0x100a2f7"));
		assertSameCodeUnits(resultProgram, latestProgram, addrSet);
	}

@Test
    public void testDataAddMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes.
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// 100a2c5 initially is "dw" -> ADD
					clear(program, "0x100a2c5", "0x100a2c6");
					disassemble(program, "0x100a2c5", "0x100a2c6");

					// 100a2d8 initially is "ds" string -> OR
					clear(program, "0x100a2d8", "0x100a2da");

					// 100a2f4 initially is "ddw" -> TEST and ADD
					clear(program, "0x100a2f4", "0x100a2f7");
					createData(program, "0x100a2f4", new FloatDataType());

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		AddressSet addrSet = new AddressSet(addr("0x100a2c5"), addr("0x100a2c6"));
		addrSet.addRange(addr("0x100a2d8"), addr("0x100a2da"));
		addrSet.addRange(addr("0x100a2f4"), addr("0x100a2f7"));
		assertSameCodeUnits(resultProgram, myProgram, addrSet);
	}

@Test
    public void testDataLatestInstrMyUndef() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 100a2c5 initially is "dw" -> ADD
					clear(program, "0x100a2c5", "0x100a2c6");
					disassemble(program, "0x100a2c5", "0x100a2c6");

					// 100a2d8 initially is "ds" string -> OR
					clear(program, "0x100a2d8", "0x100a2da");
					disassemble(program, "0x100a2d8", "0x100a2da");

					// 100a2f4 initially is "ddw" -> TEST and ADD
					clear(program, "0x100a2f4", "0x100a2f7");
					disassemble(program, "0x100a2f4", "0x100a2f7");

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
					// 100a2c5 initially is "dw" -> ADD
					clear(program, "0x100a2c5", "0x100a2c6");

					// 100a2d8 initially is "ds" string -> OR
					clear(program, "0x100a2d8", "0x100a2da");

					// 100a2f4 initially is "ddw" -> TEST and ADD
					clear(program, "0x100a2f4", "0x100a2f7");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x100a2c5", "0x100a2c6", KEEP_LATEST);
		chooseCodeUnit("0x100a2d8", "0x100a2db", KEEP_MY);
		chooseCodeUnit("0x100a2f4", "0x100a2f7", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x100a2c5"),
			addr("0x100a2c6")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x100a2d8"),
			addr("0x100a2da")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x100a2f4"),
			addr("0x100a2f7")));
	}

@Test
    public void testDataLatestUndefMyInstr() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 100a2c5 initially is "dw" -> ADD
					clear(program, "0x100a2c5", "0x100a2c6");

					// 100a2d8 initially is "ds" string -> OR
					clear(program, "0x100a2d8", "0x100a2da");

					// 100a2f4 initially is "ddw" -> TEST and ADD
					clear(program, "0x100a2f4", "0x100a2f7");

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
					// 100a2c5 initially is "dw" -> ADD
					clear(program, "0x100a2c5", "0x100a2c6");
					disassemble(program, "0x100a2c5", "0x100a2c6");

					// 100a2d8 initially is "ds" string -> OR
					clear(program, "0x100a2d8", "0x100a2da");
					disassemble(program, "0x100a2d8", "0x100a2da");

					// 100a2f4 initially is "ddw" -> TEST and ADD
					clear(program, "0x100a2f4", "0x100a2f7");
					disassemble(program, "0x100a2f4", "0x100a2f7");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x100a2c5", "0x100a2c6", KEEP_LATEST);
		chooseCodeUnit("0x100a2d8", "0x100a2db", KEEP_MY);
		chooseCodeUnit("0x100a2f4", "0x100a2f7", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x100a2c5"),
			addr("0x100a2c6")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x100a2d8"),
			addr("0x100a2da")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x100a2f4"),
			addr("0x100a2f7")));
	}

@Test
    public void testDataLatestUndefMyDataX() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 100a2c5 initially is "dw" -> ADD
					clear(program, "0x100a2c5", "0x100a2c6");

					// 100a2d8 initially is "ds" string -> OR
					clear(program, "0x100a2d8", "0x100a2da");

					// 100a2f4 initially is "ddw" -> TEST and ADD
					clear(program, "0x100a2f4", "0x100a2f7");

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
					// 100a2c5 initially is "dw" -> ADD
					clear(program, "0x100a2c5", "0x100a2c6");
					createData(program, "0x100a2c5", new ArrayDataType(new ByteDataType(), 2, 1));

					// 100a2d8 initially is "ds" string -> OR
					clear(program, "0x100a2d8", "0x100a2da");
					DataType dt =
						program.getDataTypeManager().getDataType(new CategoryPath("/"),
							"ThreeBytes");
					assertNotNull(dt);
					createData(program, "0x100a2d8", dt);

					// 100a2f4 initially is "ddw" -> TEST and ADD
					clear(program, "0x100a2f4", "0x100a2f7");
					createData(program, "0x100a2f4", new FloatDataType());

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x100a2c5", "0x100a2c6", KEEP_LATEST);
		chooseCodeUnit("0x100a2d8", "0x100a2da", KEEP_MY);
		chooseCodeUnit("0x100a2f4", "0x100a2f7", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x100a2c5"),
			addr("0x100a2c6")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x100a2d8"),
			addr("0x100a2da")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x100a2f4"),
			addr("0x100a2f7")));
	}

@Test
    public void testDataLatestDataXMyUndef() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 100a2c5 initially is "dw" -> ADD
					clear(program, "0x100a2c5", "0x100a2c6");
					createData(program, "0x100a2c5", new ArrayDataType(new ByteDataType(), 2, 1));

					// 100a2d8 initially is "ds" string -> OR
					clear(program, "0x100a2d8", "0x100a2da");
					DataType dt =
						program.getDataTypeManager().getDataType(new CategoryPath("/"),
							"ThreeBytes");
					assertNotNull(dt);
					createData(program, "0x100a2d8", dt);

					// 100a2f4 initially is "ddw" -> TEST and ADD
					clear(program, "0x100a2f4", "0x100a2f7");
					createData(program, "0x100a2f4", new FloatDataType());

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
					// 100a2c5 initially is "dw" -> ADD
					clear(program, "0x100a2c5", "0x100a2c6");

					// 100a2d8 initially is "ds" string -> OR
					clear(program, "0x100a2d8", "0x100a2da");

					// 100a2f4 initially is "ddw" -> TEST and ADD
					clear(program, "0x100a2f4", "0x100a2f7");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x100a2c5", "0x100a2c6", KEEP_LATEST);
		chooseCodeUnit("0x100a2d8", "0x100a2da", KEEP_MY);
		chooseCodeUnit("0x100a2f4", "0x100a2f7", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x100a2c5"),
			addr("0x100a2c6")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x100a2d8"),
			addr("0x100a2da")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x100a2f4"),
			addr("0x100a2f7")));
	}

@Test
    public void testDataAddDiffData() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 100a2c5 initially is "dw" -> ADD
					clear(program, "0x100a2c5", "0x100a2c6");
					createData(program, "0x100a2c5", new ArrayDataType(new ByteDataType(), 2, 1));

					// 100a2d8 initially is "ds" string -> OR
					clear(program, "0x100a2d8", "0x100a2da");
					DataType dt =
						program.getDataTypeManager().getDataType(new CategoryPath("/"),
							"ThreeBytes");
					assertNotNull(dt);
					createData(program, "0x100a2d8", dt);

					// 100a2f4 initially is "ddw" -> TEST and ADD
					clear(program, "0x100a2f4", "0x100a2f7");
					createData(program, "0x100a2f4", new FloatDataType());

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
					// 100a2c5 initially is "dw" -> ADD
					clear(program, "0x100a2c5", "0x100a2c6");
					createData(program, "0x100a2c5", new ArrayDataType(new CharDataType(), 2, 1));

					// 100a2d8 initially is "ds" string -> OR
					clear(program, "0x100a2d8", "0x100a2da");
					createData(program, "0x100a2d8", new ArrayDataType(new CharDataType(), 3, 1));

					// 100a2f4 initially is "ddw" -> TEST and ADD
					clear(program, "0x100a2f4", "0x100a2f7");
					createData(program, "0x100a2f4", new TypedefDataType("FloatTypeDef",
						new FloatDataType()));

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x100a2c5", "0x100a2c6", KEEP_LATEST);
		chooseCodeUnit("0x100a2d8", "0x100a2da", KEEP_MY);
		chooseCodeUnit("0x100a2f4", "0x100a2f7", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x100a2c5"),
			addr("0x100a2c6")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x100a2d8"),
			addr("0x100a2da")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x100a2f4"),
			addr("0x100a2f7")));
	}

@Test
    public void testDataAddSame() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 100a2c5 initially is "dw" -> ADD
					clear(program, "0x100a2c5", "0x100a2c6");
					disassemble(program, "0x100a2c5", "0x100a2c6");

					// 100a2d8 initially is "ds" string -> OR
					clear(program, "0x100a2d8", "0x100a2da");

					// 100a2f4 initially is "ddw" -> TEST and ADD
					clear(program, "0x100a2f4", "0x100a2f7");
					createData(program, "0x100a2f4", new FloatDataType());

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
					// 100a2c5 initially is "dw" -> ADD
					clear(program, "0x100a2c5", "0x100a2c6");
					disassemble(program, "0x100a2c5", "0x100a2c6");

					// 100a2d8 initially is "ds" string -> OR
					clear(program, "0x100a2d8", "0x100a2da");

					// 100a2f4 initially is "ddw" -> TEST and ADD
					clear(program, "0x100a2f4", "0x100a2f7");
					createData(program, "0x100a2f4", new FloatDataType());

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x100a2c5"),
			addr("0x100a2c6")));
		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x100a2d8"),
			addr("0x100a2da")));
		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x100a2f4"),
			addr("0x100a2f7")));
	}

@Test
    public void testDataAddOnUninitializedNoConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Structure struct = new StructureDataType("FooStruct", 0);
					struct.add(new DWordDataType());
					struct.add(new CharDataType());
					struct.add(new CharDataType());
					createData(program, "0x10085f0", struct); // 10085f0 - 10085f5

					struct = new StructureDataType("struct1", 0);
					struct.add(new ByteDataType());
					struct.add(new CharDataType());
					struct.add(new ByteDataType());
					createData(program, "0x1008600", struct); // 1008600 - 1008602

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
					Structure struct = new StructureDataType("FooStruct", 0);
					struct.add(new DWordDataType());
					struct.add(new CharDataType());
					struct.add(new CharDataType());
					createData(program, "0x10085f0", struct); // 10085f0 - 10085f5

					struct = new StructureDataType("struct2", 0);
					struct.add(new CharDataType());
					struct.add(new CharDataType());
					struct.add(new CharDataType());
					createData(program, "0x1008606", struct); // 1008606 - 1008608

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x10085f0"),
			addr("0x10085f5")));
		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1008600"),
			addr("0x1008602")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1008606"),
			addr("0x1008608")));
	}

@Test
    public void testDataAddOnUninitializedConflicts() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createData(program, "0x10085e8", new CharDataType());  // 10085e8 - 10085e8

					Structure struct = new StructureDataType("FooStruct", 0);
					struct.add(new DWordDataType());
					struct.add(new CharDataType());
					struct.add(new CharDataType());
					createData(program, "0x10085f0", struct); // 10085f0 - 10085f5

					createData(program, "0x10085fb", new FloatDataType()); // 10085fb - 10085fe

					struct = new StructureDataType("struct", 0);
					struct.add(new ByteDataType());
					struct.add(new CharDataType());
					struct.add(new ByteDataType());
					createData(program, "0x1008600", struct); // 1008600 - 1008602

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
					createData(program, "0x10085e8", new ByteDataType());  // 10085e8 - 10085e8

					Structure struct = new StructureDataType("BarStruct", 0);
					struct.add(new ByteDataType());
					struct.add(new FloatDataType());
					createData(program, "0x10085f0", struct); // 10085f0 - 10085f4

					createData(program, "0x10085fc", new ByteDataType());  // 10085fc - 10085fc
					createData(program, "0x10085fd", new CharDataType()); // 10085fd - 10085fd

					struct = new StructureDataType("struct", 0);
					struct.add(new CharDataType());
					struct.add(new CharDataType());
					struct.add(new CharDataType());
					createData(program, "0x1008606", struct); // 1008606 - 1008608

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x10085e8", "0x10085e8", KEEP_LATEST);
		chooseCodeUnit("0x10085f0", "0x10085f5", KEEP_MY);
		chooseCodeUnit("0x10085fb", "0x10085fe", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x10085e8"),
			addr("0x10085e8")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x10085f0"),
			addr("0x10085f5")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x10085fb"),
			addr("0x10085fe")));
		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1008600"),
			addr("0x1008602")));
		DataType resultDt =
			((Data) resultProgram.getListing().getCodeUnitAt(addr("0x1008606"))).getDataType();
		DataType myDt =
			((Data) myProgram.getListing().getCodeUnitAt(addr("0x1008606"))).getDataType();
		assertSameDataType(resultDt, myDt);
	}

}
