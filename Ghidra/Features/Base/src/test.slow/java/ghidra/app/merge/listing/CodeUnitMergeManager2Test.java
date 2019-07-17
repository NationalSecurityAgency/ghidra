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
import ghidra.program.model.listing.ContextChangeException;

/**
 * Test the merge of the versioned program's code units when starting as Instruction.
 */
public class CodeUnitMergeManager2Test extends AbstractListingMergeManagerTest {

	/**
	 * 
	 * @param arg0
	 */
	public CodeUnitMergeManager2Test() {
		super();
	}

@Test
    public void testInstrMyDataUndef() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004aba");

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					createData(program, "0x1004adb", new ArrayDataType(new ByteDataType(), 3, 1));

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1004ab5"),
			addr("0x1004aba")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1004adb"),
			addr("0x1004add")));
	}

@Test
    public void testInstrMyDataUndefContextRegChg() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004aba");

					setContextReg(program, "0x1004ab5", "0x1004ab6", 2);

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
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004aba");

					setContextReg(program, "0x1004ab5", "0x1004aba6", 1);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		chooseCodeUnit("0x1004ab5", "0x1004ab6", KEEP_MY);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1004ab5"),
			addr("0x1004ab6")));
	}

@Test
    public void testInstrLatestDataUndef() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004aba");

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					createData(program, "0x1004adb", new ArrayDataType(new ByteDataType(), 3, 1));

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
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004ab5"),
			addr("0x1004aba")));
		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004adb"),
			addr("0x1004add")));
	}

@Test
    public void testInstrLatestDataMyUndef() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004aba");
					createData(program, "0x1004ab5", new WordDataType());
					createData(program, "0x1004ab7", new FloatDataType());

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					DataType dt =
						program.getDataTypeManager().getDataType(new CategoryPath("/"),
							"ThreeBytes");
					assertNotNull(dt);
					createData(program, "0x1004adb", dt);

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");
					createData(program, "0x1004b19", new ArrayDataType(new ByteDataType(), 3, 1));

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
					// single instruction
					clear(program, "0x1004ab5", "0x1004aba");

					// single instruction
					clear(program, "0x1004adb", "0x1004add");

					// single instruction
					clear(program, "0x1004b19", "0x1004b1b");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});
		executeMerge(ASK_USER);

		chooseCodeUnit("0x1004ab5", "0x1004ab6", KEEP_LATEST);
		chooseCodeUnit("0x1004adb", "0x1004add", KEEP_MY);
		chooseCodeUnit("0x1004b19", "0x1004b1e", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004ab5"),
			addr("0x1004aba")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1004adb"),
			addr("0x1004add")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1004b19"),
			addr("0x1004b1b")));
	}

@Test
    public void testInstrLatestUndefMyData() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004aba");

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");

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
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004ab6");
					createData(program, "0x1004ab5", new ByteDataType());
					createData(program, "0x1004ab6", new ByteDataType());

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					DataType dt =
						program.getDataTypeManager().getDataType(new CategoryPath("/"),
							"ThreeBytes");
					assertNotNull(dt);
					createData(program, "0x1004adb", dt);

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");
					createData(program, "0x1004b19", new ArrayDataType(new ByteDataType(), 3, 1));

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		chooseCodeUnit("0x1004ab5", "0x1004ab6", KEEP_LATEST);
		chooseCodeUnit("0x1004adb", "0x1004add", KEEP_MY);
		chooseCodeUnit("0x1004b19", "0x1004b1e", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004ab5"),
			addr("0x1004aba")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1004adb"),
			addr("0x1004add")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1004b19"),
			addr("0x1004b1b")));
	}

@Test
    public void testInstrLatestInstrA() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004aba");
					disassemble(program, "0x1004ab6", "0x1004ab9");

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					disassemble(program, "0x1004adc", "0x1004add");

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");
					disassemble(program, "0x1004b1a", "0x1004b1b");

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
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004ab5"),
			addr("0x1004aba")));
		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004adb"),
			addr("0x1004add")));
		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004b19"),
			addr("0x1004b1b")));
	}

@Test
    public void testInstrMyInstrA() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004aba");
					disassemble(program, "0x1004ab6", "0x1004ab9");

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					disassemble(program, "0x1004adc", "0x1004add");

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");
					disassemble(program, "0x1004b1a", "0x1004b1b");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1004ab5"),
			addr("0x1004aba")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1004adb"),
			addr("0x1004add")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1004b19"),
			addr("0x1004b1b")));
	}

@Test
    public void testInstrLatestInstrAMyData() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004aba");
					disassemble(program, "0x1004ab6", "0x1004ab9");

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					disassemble(program, "0x1004adc", "0x1004add");

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");
					disassemble(program, "0x1004b1a", "0x1004b1b");

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
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004aba");
					createData(program, "0x1004ab5", new WordDataType());
					createData(program, "0x1004ab7", new FloatDataType());

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					DataType dt =
						program.getDataTypeManager().getDataType(new CategoryPath("/"),
							"ThreeBytes");
					assertNotNull(dt);
					createData(program, "0x1004adb", dt);

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");
					createData(program, "0x1004b19", new ArrayDataType(new ByteDataType(), 3, 1));

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		chooseCodeUnit("0x1004ab5", "0x1004aba", KEEP_LATEST);
		chooseCodeUnit("0x1004adb", "0x1004add", KEEP_MY);
		chooseCodeUnit("0x1004b19", "0x1004b1e", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004ab5"),
			addr("0x1004aba")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1004adb"),
			addr("0x1004add")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1004b19"),
			addr("0x1004b1b")));
	}

@Test
    public void testInstrLatestInstrAMyUndef() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004aba");
					disassemble(program, "0x1004ab6", "0x1004ab9");

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					disassemble(program, "0x1004adc", "0x1004add");

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");
					createData(program, "0x1004b19", new ByteDataType());
					disassemble(program, "0x1004b1a", "0x1004b1b");

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
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004aba");

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");
					createData(program, "0x1004b19", new ByteDataType());

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		chooseCodeUnit("0x1004ab5", "0x1004ab7", KEEP_LATEST);
		chooseCodeUnit("0x1004adb", "0x1004add", KEEP_MY);
		chooseCodeUnit("0x1004b19", "0x1004b1e", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004ab5"),
			addr("0x1004aba")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1004adb"),
			addr("0x1004add")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1004b19"),
			addr("0x1004b1b")));
	}

@Test
    public void testInstrLatestDataMyInstrA() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004aba");
					createData(program, "0x1004ab5", new WordDataType());
					createData(program, "0x1004ab7", new FloatDataType());

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					DataType dt =
						program.getDataTypeManager().getDataType(new CategoryPath("/"),
							"ThreeBytes");
					assertNotNull(dt);
					createData(program, "0x1004adb", dt);

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");
					createData(program, "0x1004b19", new ArrayDataType(new ByteDataType(), 3, 1));

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
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004aba");
					disassemble(program, "0x1004ab6", "0x1004ab9");

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					disassemble(program, "0x1004adc", "0x1004add");

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");
					disassemble(program, "0x1004b1a", "0x1004b1b");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		chooseCodeUnit("0x1004ab5", "0x1004aba", KEEP_LATEST);
		chooseCodeUnit("0x1004adb", "0x1004add", KEEP_MY);
		chooseCodeUnit("0x1004b19", "0x1004b1e", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004ab5"),
			addr("0x1004aba")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1004adb"),
			addr("0x1004add")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1004b19"),
			addr("0x1004b1b")));
	}

@Test
    public void testInstrLatestUndefMyInstrA() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");

					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004aba");

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
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004ab6");
					disassemble(program, "0x1004ab6", "0x1004ab9");

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					disassemble(program, "0x1004adc", "0x1004add");

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");
					disassemble(program, "0x1004b1a", "0x1004b1b");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		chooseCodeUnit("0x1004ab5", "0x1004ab7", KEEP_LATEST);
		chooseCodeUnit("0x1004adb", "0x1004add", KEEP_MY);
		chooseCodeUnit("0x1004b19", "0x1004b1e", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x1004ab5"),
			addr("0x1004ab6")));
		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004ab5"),
			addr("0x1004ab6")));
		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x1004adb"),
			addr("0x1004add")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1004adb"),
			addr("0x1004add")));
		assertSameBytes(resultProgram, originalProgram, new AddressSet(addr("0x1004b19"),
			addr("0x1004b1b")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1004b19"),
			addr("0x1004b1b")));
	}

@Test
    public void testInstrAddDiffInstr() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004aba");
					setContextReg(program, "0x1004ab5", "0x1004aba", 0x1000);
					disassemble(program, "0x1004ab6", "0x1004ab7");

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					setContextReg(program, "0x1004adb", "0x1004add", 0x1000);
					disassemble(program, "0x1004adc", "0x1004adc");

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");
					disassemble(program, "0x1004b1a", "0x1004b1b");

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
					// TODO
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004ab9");
					disassemble(program, "0x1004ab7", "0x1004ab8");

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					disassemble(program, "0x1004add", "0x1004add");

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");
					setBytes(program, "0x1004b19", new byte[] { (byte) 0x40 });
					disassemble(program, "0x1004b19", "0x1004b1b");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		chooseCodeUnit("0x1004ab5", "0x1004ab8", KEEP_LATEST);
		chooseCodeUnit("0x1004adb", "0x1004ade", KEEP_MY);
		chooseCodeUnit("0x1004b19", "0x1004b1e", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004ab5"),
			addr("0x1004ab6")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1004adb"),
			addr("0x1004add")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1004b19"),
			addr("0x1004b1b")));
	}

@Test
    public void testInstrAddSameInstr() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004aba");
					disassemble(program, "0x1004ab6", "0x1004ab9");

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					disassemble(program, "0x1004adc", "0x1004add");

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");
					disassemble(program, "0x1004b1a", "0x1004b1b");

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
					// 1004ab5-1004aba initially is JZ LAB01004bb7
					// 1004ab6-1004ab7 initially is TEST AH,BH
					// 1004ab8-1004ab9 initially is ADD [EAX],AL
					clear(program, "0x1004ab5", "0x1004aba");
					disassemble(program, "0x1004ab6", "0x1004ab9");

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					disassemble(program, "0x1004adc", "0x1004add");

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");
					disassemble(program, "0x1004b1a", "0x1004b1b");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x1004ab5"),
			addr("0x1004aba")));
		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004ab5"),
			addr("0x1004aba")));
		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x1004adb"),
			addr("0x1004add")));
		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004adb"),
			addr("0x1004add")));
		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x1004b19"),
			addr("0x1004b1b")));
		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004b19"),
			addr("0x1004b1b")));
	}

}
