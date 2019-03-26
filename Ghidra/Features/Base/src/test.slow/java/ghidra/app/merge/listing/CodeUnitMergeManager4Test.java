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

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Test the merge of the versioned program's code units when bytes
 * have been modified.
 */
public class CodeUnitMergeManager4Test extends AbstractListingMergeManagerTest {
	// Byte Tests
	// 0x10074ae is a "ds" of "GetClientRect",00
	// 0x1007530 is a "ds" of "CharLowerW",00
	// 0x100753c is a "dw" of 296h
	// 0x100753e - 0x100754a is a "ds" of "UpdateWindow",00

	// NotepadMergeListingTest original byte values are:
	// Address   Byte
	// --------- ----
	// 0x100753c 0x96
	// 0x100753d 0x02
	// 0x100753e 0x55
	// 0x100753f 0x70
	// 0x1007540 0x64
	// 0x1007541 0x61
	// 0x1007542 0x74
	// 0x1007543 0x65
	// 0x1007544 0x57

	/**
	 * 
	 * @param arg0
	 */
	public CodeUnitMergeManager4Test() {
		super();
	}

@Test
    public void testLatestByteDiff() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					setBytes(program, "0x100753c", new byte[] { (byte) 0x95 });
					setBytes(program, "0x100753f", new byte[] { (byte) 0x68 });
					setBytes(program, "0x1007544", new byte[] { (byte) 0x67 });
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

		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x100753c"),
			addr("0x100754a")));
	}

@Test
    public void testMyByteDiff() throws Exception {
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
					setBytes(program, "0x100753c", new byte[] { (byte) 0x95 });
					setBytes(program, "0x100753f", new byte[] { (byte) 0x68 });
					setBytes(program, "0x1007544", new byte[] { (byte) 0x67 });
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x1007530"),
			addr("0x100754f")));
	}

@Test
    public void testChangeSameBytes() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					setBytes(program, "0x100753c", new byte[] { (byte) 0x95 });
					setBytes(program, "0x100753f", new byte[] { (byte) 0x68 });
					setBytes(program, "0x1007544", new byte[] { (byte) 0x67 });
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
					setBytes(program, "0x100753c", new byte[] { (byte) 0x95 });
					setBytes(program, "0x100753f", new byte[] { (byte) 0x68 });
					setBytes(program, "0x1007544", new byte[] { (byte) 0x67 });
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x1007530"),
			addr("0x100754f")));
	}

@Test
    public void testChangeDiffBytes() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					setBytes(program, "0x100753c", new byte[] { (byte) 0x95 }); // Previously 0x96
					setBytes(program, "0x100753f", new byte[] { (byte) 0x68 }); // Previously 0x70
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
					setBytes(program, "0x100753d", new byte[] { (byte) 0x03 }); // Previously 0x02
					setBytes(program, "0x1007544", new byte[] { (byte) 0x67 }); // Previously 0x57
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameBytes(resultProgram, originalProgram, new AddressSet(addr("0x1007530"),
			addr("0x100753b")));
		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x100753c"),
			addr("0x100753c")));
		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x100753d"),
			addr("0x100753d")));
		assertSameBytes(resultProgram, originalProgram, new AddressSet(addr("0x100753e"),
			addr("0x100753e")));
		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x100753f"),
			addr("0x100753f")));
		assertSameBytes(resultProgram, originalProgram, new AddressSet(addr("0x1007540"),
			addr("0x1007543")));
		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x1007544"),
			addr("0x1007544")));
		assertSameBytes(resultProgram, originalProgram, new AddressSet(addr("0x1007545"),
			addr("0x100754f")));
	}

@Test
    public void testByteConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					setBytes(program, "0x100753c", new byte[] { (byte) 0x95 });
					setBytes(program, "0x100753f", new byte[] { (byte) 0x68 });
					setBytes(program, "0x1007544", new byte[] { (byte) 0x67 });
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
					setBytes(program, "0x100753c", new byte[] { (byte) 0x94 });
					setBytes(program, "0x100753f", new byte[] { (byte) 0x68 });
					setBytes(program, "0x1007544", new byte[] { (byte) 0x68 });
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x100753c", "0x100753c", KEEP_LATEST);
		chooseCodeUnit("0x1007544", "0x1007544", KEEP_MY);
		waitForMergeCompletion();

		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x100753c"),
			addr("0x100753c")));
		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x100753f"),
			addr("0x100753f")));
		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x1007544"),
			addr("0x1007544")));
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
					setBytes(program, "0x1004ab5", new byte[] { (byte) 0x0d });
					setBytes(program, "0x1004aba", new byte[] { (byte) 0x0e });
					disassemble(program, "0x1004ab5", "0x1004aba");

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					setBytes(program, "0x1004adb", new byte[] { (byte) 0x29 });
					disassemble(program, "0x1004adb", "0x1004add");

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");
					setBytes(program, "0x1004b19", new byte[] { (byte) 0x56 });
					disassemble(program, "0x1004b19", "0x1004b1b");

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
					setBytes(program, "0x1004ab5", new byte[] { (byte) 0x0d });
					setBytes(program, "0x1004aba", new byte[] { (byte) 0x0e });
					disassemble(program, "0x1004ab5", "0x1004aba");

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					setBytes(program, "0x1004adb", new byte[] { (byte) 0x29 });
					disassemble(program, "0x1004adb", "0x1004add");

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");
					setBytes(program, "0x1004b19", new byte[] { (byte) 0x56 });
					disassemble(program, "0x1004b19", "0x1004b1b");

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
    public void testInstrLatestInstrAMyInstrB() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// 1004ab5-1004aba disassembles to OR EAX,0xfc84
					clear(program, "0x1004aa5", "0x1004aaa");
					setBytes(program, "0x1004aa5", new byte[] { (byte) 0x0d });
					setBytes(program, "0x1004aaa", new byte[] { (byte) 0x0e });
					disassemble(program, "0x1004aa5", "0x1004aaa");

					// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
					// 1004adc-1004adc disassembles to POP EBP
					// 1004add-1004add disassembles to CLC
					clear(program, "0x1004adb", "0x1004add");
					setBytes(program, "0x1004adb", new byte[] { (byte) 0x29 });
					disassemble(program, "0x1004adb", "0x1004add");

					// 1004b19-1004b1b initially is MOV CX,[EAX]
					// 1004b1a-1004b1b initially is MOV ECX,[EAX]
					clear(program, "0x1004b19", "0x1004b1b");
					setBytes(program, "0x1004b19", new byte[] { (byte) 0x56 });
					disassemble(program, "0x1004b19", "0x1004b1b");

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
					// 1004ab5-1004ab6 disassembles to OR EAX,0xfc84
					// 1004ab7-1004ab7 disassembles to CLD
					// 1004ab8-1004ab9 disassembles to ADD [EAX],AL
					// 1004aba-1004aba disassembles to POP DS
					clear(program, "0x1004aa5", "0x1004aaa");
					setBytes(program, "0x1004aa5", new byte[] { (byte) 0x0c });
					setBytes(program, "0x1004aaa", new byte[] { (byte) 0x1f });
					disassemble(program, "0x1004aa5", "0x1004aaa");

					// 1004adb-1004add disassembles to SBB 0xfffffff8[EBP],EBX
					clear(program, "0x1004adb", "0x1004add");
					setBytes(program, "0x1004adb", new byte[] { (byte) 0x19 });
					disassemble(program, "0x1004adb", "0x1004add");

					// 1004b19-1004b19 disassembles to INC EBP
					// 1004b1a-1004b1b disassembles to JNP 0x1004b24
					clear(program, "0x1004b19", "0x1004b1b");
					setBytes(program, "0x1004b19", new byte[] { (byte) 0x45 });
//					setBytes(program, "0x1004b1a", new byte[] {(byte)0x7b});
					disassemble(program, "0x1004b19", "0x1004b1b");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		chooseCodeUnit("0x1004aa5", "0x1004aaa", KEEP_LATEST);
		chooseCodeUnit("0x1004adb", "0x1004adc", KEEP_MY);
		chooseCodeUnit("0x1004b19", "0x1004b1e", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004aa5"),
			addr("0x1004aaa")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1004adb"),
			addr("0x1004add")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1004b19"),
			addr("0x1004b1e")));
	}

//	public void testInstrLatestInstrAMyUndef() throws Exception {
//		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
//	        /* (non-Javadoc)
//	         * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//	         */
//	        public void modifyLatest(ProgramDB program) {
//	            int txId = program.startTransaction("Modify Latest Program");
//	            boolean commit = false;
//	            try {
//	            	// 1004ab5-1004aba initially is JZ LAB01004bb7
//	            	// 1004ab6-1004ab7 initially is TEST AH,BH
//	            	// 1004ab8-1004ab9 initially is ADD [EAX],AL
//					clear(program, "0x1004ab5", "0x1004aba");
//					disassemble(program, "0x1004ab6", "0x1004ab9");
//					
//	            	// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
//	            	// 1004adc-1004adc disassembles to POP EBP
//	            	// 1004add-1004add disassembles to CLC
//					clear(program, "0x1004adb", "0x1004add");
//					disassemble(program, "0x1004adc", "0x1004add");
//					
//	            	// 1004b19-1004b1b initially is MOV CX,[EAX]
//	            	// 1004b1a-1004b1b initially is MOV ECX,[EAX]
//					clear(program, "0x1004b19", "0x1004b1b");
//					createData(program, "0x1004b19", new ByteDataType());
//					disassemble(program, "0x1004b1a", "0x1004b1b");
//					
//	                commit = true;
//				} finally {
//	                program.endTransaction(txId, commit);
//	            }
//	        }
//
//	        /* (non-Javadoc)
//	         * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
//	         */
//	        public void modifyPrivate(ProgramDB program) {
//	            int txId = program.startTransaction("Modify My Program");
//	            boolean commit = false;
//	            try {
//	            	// 1004ab5-1004aba initially is JZ LAB01004bb7
//	            	// 1004ab6-1004ab7 initially is TEST AH,BH
//	            	// 1004ab8-1004ab9 initially is ADD [EAX],AL
//					clear(program, "0x1004ab5", "0x1004aba");
//					
//	            	// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
//	            	// 1004adc-1004adc disassembles to POP EBP
//	            	// 1004add-1004add disassembles to CLC
//					clear(program, "0x1004adb", "0x1004add");
//					
//	            	// 1004b19-1004b1b initially is MOV CX,[EAX]
//	            	// 1004b1a-1004b1b initially is MOV ECX,[EAX]
//					clear(program, "0x1004b19", "0x1004b1b");
//					createData(program, "0x1004b19", new ByteDataType());
//					
//	                commit = true;
//				} finally {
//	                program.endTransaction(txId, commit);
//	            }
//	        }
//		});
//		
//		executeMerge(ASK_USER);
//		Thread.sleep(250);
//		chooseCodeUnit("0x1004ab5", "0x1004aba", KEEP_LATEST);
//		chooseCodeUnit("0x1004adb", "0x1004add", KEEP_MY);
//		chooseCodeUnit("0x1004b19", "0x1004b1b", KEEP_ORIGINAL);
//		waitWhileFocusWindow("Merge Programs", 5000);
//		
//		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004ab5"), addr("0x1004aba")));
//		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1004adb"), addr("0x1004add")));
//		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1004b19"), addr("0x1004b1b")));
//	}
//	
//	public void testInstrLatestDataMyInstrA() throws Exception {
//		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
//	        /* (non-Javadoc)
//	         * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//	         */
//	        public void modifyLatest(ProgramDB program) {
//	            int txId = program.startTransaction("Modify Latest Program");
//	            boolean commit = false;
//	            try {
//	            	// 1004ab5-1004aba initially is JZ LAB01004bb7
//	            	// 1004ab6-1004ab7 initially is TEST AH,BH
//	            	// 1004ab8-1004ab9 initially is ADD [EAX],AL
//					clear(program, "0x1004ab5", "0x1004aba");
//					createData(program, "0x1004ab5", new WordDataType());
//					createData(program, "0x1004ab7", new FloatDataType());
//					
//	            	// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
//	            	// 1004adc-1004adc disassembles to POP EBP
//	            	// 1004add-1004add disassembles to CLC
//					clear(program, "0x1004adb", "0x1004add");
//					DataType dt = program.getDataTypeManager().getDataType(new CategoryPath("/"),  "ThreeBytes");
//					assertNotNull(dt);
//					createData(program, "0x1004adb", dt);
//					
//	            	// 1004b19-1004b1b initially is MOV CX,[EAX]
//	            	// 1004b1a-1004b1b initially is MOV ECX,[EAX]
//					clear(program, "0x1004b19", "0x1004b1b");
//					createData(program, "0x1004b19", new ArrayDataType(new ByteDataType(), 3, 1));
//					
//	                commit = true;
//				} finally {
//	                program.endTransaction(txId, commit);
//	            }
//	        }
//
//	        /* (non-Javadoc)
//	         * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
//	         */
//	        public void modifyPrivate(ProgramDB program) {
//	            int txId = program.startTransaction("Modify My Program");
//	            boolean commit = false;
//	            try {
//	            	// 1004ab5-1004aba initially is JZ LAB01004bb7
//	            	// 1004ab6-1004ab7 initially is TEST AH,BH
//	            	// 1004ab8-1004ab9 initially is ADD [EAX],AL
//					clear(program, "0x1004ab5", "0x1004aba");
//					disassemble(program, "0x1004ab6", "0x1004ab9");
//					
//	            	// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
//	            	// 1004adc-1004adc disassembles to POP EBP
//	            	// 1004add-1004add disassembles to CLC
//					clear(program, "0x1004adb", "0x1004add");
//					disassemble(program, "0x1004adc", "0x1004add");
//					
//	            	// 1004b19-1004b1b initially is MOV CX,[EAX]
//	            	// 1004b1a-1004b1b initially is MOV ECX,[EAX]
//					clear(program, "0x1004b19", "0x1004b1b");
//					disassemble(program, "0x1004b1a", "0x1004b1b");
//					
//	                commit = true;
//				} finally {
//	                program.endTransaction(txId, commit);
//	            }
//	        }
//		});
//		
//		executeMerge(ASK_USER);
//		Thread.sleep(250);
//		chooseCodeUnit("0x1004ab5", "0x1004aba", KEEP_LATEST);
//		chooseCodeUnit("0x1004adb", "0x1004add", KEEP_MY);
//		chooseCodeUnit("0x1004b19", "0x1004b1b", KEEP_ORIGINAL);
//		waitWhileFocusWindow("Merge Programs", 5000);
//		
//		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004ab5"), addr("0x1004aba")));
//		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1004adb"), addr("0x1004add")));
//		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1004b19"), addr("0x1004b1b")));
//	}
//	
//	public void testInstrLatestUndefMyInstrA() throws Exception {
//		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
//	        /* (non-Javadoc)
//	         * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//	         */
//	        public void modifyLatest(ProgramDB program) {
//	            int txId = program.startTransaction("Modify Latest Program");
//	            boolean commit = false;
//	            try {
//	            	// 1004b19-1004b1b initially is MOV CX,[EAX]
//	            	// 1004b1a-1004b1b initially is MOV ECX,[EAX]
//					clear(program, "0x1004b19", "0x1004b1b");
//					
//	            	// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
//	            	// 1004adc-1004adc disassembles to POP EBP
//	            	// 1004add-1004add disassembles to CLC
//					clear(program, "0x1004adb", "0x1004add");
//					
//	            	// 1004ab5-1004aba initially is JZ LAB01004bb7
//	            	// 1004ab6-1004ab7 initially is TEST AH,BH
//	            	// 1004ab8-1004ab9 initially is ADD [EAX],AL
//					clear(program, "0x1004ab5", "0x1004aba");
//					
//	                commit = true;
//				} finally {
//	                program.endTransaction(txId, commit);
//	            }
//	        }
//
//	        /* (non-Javadoc)
//	         * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
//	         */
//	        public void modifyPrivate(ProgramDB program) {
//	            int txId = program.startTransaction("Modify My Program");
//	            boolean commit = false;
//	            try {
//	            	// 1004ab5-1004aba initially is JZ LAB01004bb7
//	            	// 1004ab6-1004ab7 initially is TEST AH,BH
//	            	// 1004ab8-1004ab9 initially is ADD [EAX],AL
//					clear(program, "0x1004ab5", "0x1004aba");
//					disassemble(program, "0x1004ab6", "0x1004ab9");
//					
//	            	// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
//	            	// 1004adc-1004adc disassembles to POP EBP
//	            	// 1004add-1004add disassembles to CLC
//					clear(program, "0x1004adb", "0x1004add");
//					disassemble(program, "0x1004adc", "0x1004add");
//					
//	            	// 1004b19-1004b1b initially is MOV CX,[EAX]
//	            	// 1004b1a-1004b1b initially is MOV ECX,[EAX]
//					clear(program, "0x1004b19", "0x1004b1b");
//					disassemble(program, "0x1004b1a", "0x1004b1b");
//					
//	                commit = true;
//				} finally {
//	                program.endTransaction(txId, commit);
//	            }
//	        }
//		});
//		
//		executeMerge(ASK_USER);
//		Thread.sleep(250);
//		chooseCodeUnit("0x1004ab5", "0x1004aba", KEEP_LATEST);
//		chooseCodeUnit("0x1004adb", "0x1004add", KEEP_MY);
//		chooseCodeUnit("0x1004b19", "0x1004b1b", KEEP_ORIGINAL);
//		waitWhileFocusWindow("Merge Programs", 5000);
//		
//		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004ab5"), addr("0x1004aba")));
//		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1004adb"), addr("0x1004add")));
//		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1004b19"), addr("0x1004b1b")));
//	}
//	
//	public void testInstrAddDiffInstr() throws Exception {
//		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
//	        /* (non-Javadoc)
//	         * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//	         */
//	        public void modifyLatest(ProgramDB program) {
//	            int txId = program.startTransaction("Modify Latest Program");
//	            boolean commit = false;
//	            try {
//	            	// 1004ab5-1004aba initially is JZ LAB01004bb7
//	            	// 1004ab6-1004ab7 initially is TEST AH,BH
//	            	// 1004ab8-1004ab9 initially is ADD [EAX],AL
//					clear(program, "0x1004ab5", "0x1004aba");
//					disassemble(program, "0x1004ab6", "0x1004ab7");
//					
//	            	// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
//	            	// 1004adc-1004adc disassembles to POP EBP
//	            	// 1004add-1004add disassembles to CLC
//					clear(program, "0x1004adb", "0x1004add");
//					disassemble(program, "0x1004adc", "0x1004adc");
//					
//	            	// 1004b19-1004b1b initially is MOV CX,[EAX]
//	            	// 1004b1a-1004b1b initially is MOV ECX,[EAX]
//					clear(program, "0x1004b19", "0x1004b1b");
//					disassemble(program, "0x1004b1a", "0x1004b1b");
//					
//	                commit = true;
//				} finally {
//	                program.endTransaction(txId, commit);
//	            }
//	        }
//
//	        /* (non-Javadoc)
//	         * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
//	         */
//	        public void modifyPrivate(ProgramDB program) {
//	            int txId = program.startTransaction("Modify My Program");
//	            boolean commit = false;
//	            try {
//	            	// TODO
//	            	// 1004ab5-1004aba initially is JZ LAB01004bb7
//	            	// 1004ab6-1004ab7 initially is TEST AH,BH
//	            	// 1004ab8-1004ab9 initially is ADD [EAX],AL
//					clear(program, "0x1004ab5", "0x1004aba");
//					disassemble(program, "0x1004ab8", "0x1004ab9");
//					
//	            	// 1004adb-1004add disassembles to CMP local_c[EBP],EBX
//	            	// 1004adc-1004adc disassembles to POP EBP
//	            	// 1004add-1004add disassembles to CLC
//					clear(program, "0x1004adb", "0x1004add");
//					disassemble(program, "0x1004add", "0x1004add");
//					
//	            	// 1004b19-1004b1b initially is MOV CX,[EAX]
//	            	// 1004b1a-1004b1b initially is MOV ECX,[EAX]
//					clear(program, "0x1004b19", "0x1004b1b");
//					disassemble(program, "0x1004b1b", "0x1004b1b");
//					
//	                commit = true;
//				} finally {
//	                program.endTransaction(txId, commit);
//	            }
//	        }
//		});
//		
//		executeMerge(ASK_USER);
//		Thread.sleep(250);
//		chooseCodeUnit("0x1004ab5", "0x1004aba", KEEP_LATEST);
//		chooseCodeUnit("0x1004adb", "0x1004add", KEEP_MY);
//		chooseCodeUnit("0x1004b19", "0x1004b1b", KEEP_ORIGINAL);
//		waitWhileFocusWindow("Merge Programs", 5000);
//		
//		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x1004ab5"), addr("0x1004aba")));
//		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x1004adb"), addr("0x1004add")));
//		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x1004b19"), addr("0x1004b1b")));
//	}

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
    public void testSameDataDiffBytes() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
//	            	// 100a2c5 initially is "dw" -> ADD
//					clear(program, "0x100a2c5", "0x100a2c6");
//					setBytes(program, "0x100a2c5", new byte[] {});
//					disassemble(program, "0x100a2c5", "0x100a2c6");

					// 100a2d8 initially is "ds" string -> OR
					clear(program, "0x100a2d8", "0x100a2da");
					setBytes(program, "0x100a2da", new byte[] { (byte) 0x56 });

					// 100a2f4 initially is "ddw" -> TEST and ADD
					clear(program, "0x100a2f4", "0x100a2f7");
					setBytes(program, "0x100a2f4", new byte[] { (byte) 0x11 });
					createData(program, "0x100a2f4", new FloatDataType());

					// 100a0ac
					setBytes(program, "0x100a0ad", new byte[] { (byte) 0x03 });
					DataType dt =
						program.getDataTypeManager().getDataType(new CategoryPath("/"),
							"ThreeBytes");
					assertNotNull(dt);
					createData(program, "0x100a0ac", dt);

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
//	            	// 100a2c5 initially is "dw" -> ADD
//					clear(program, "0x100a2c5", "0x100a2c6");
//					disassemble(program, "0x100a2c5", "0x100a2c6");

					// 100a2d8 initially is "ds" string -> OR
					clear(program, "0x100a2d8", "0x100a2da");
					setBytes(program, "0x100a2da", new byte[] { (byte) 0x34 });

					// 100a2f4 initially is "ddw" -> TEST and ADD
					clear(program, "0x100a2f4", "0x100a2f7");
					setBytes(program, "0x100a2f4", new byte[] { (byte) 0x12 });
					createData(program, "0x100a2f4", new FloatDataType());

					// 100a0ac
					setBytes(program, "0x100a0ad", new byte[] { (byte) 0x04 });
					DataType dt =
						program.getDataTypeManager().getDataType(new CategoryPath("/"),
							"UnionSize4");
					assertNotNull(dt);
					createData(program, "0x100a0ac", dt);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x100a0ac", "0x100a0af", KEEP_ORIGINAL);
		chooseCodeUnit("0x100a2d8", "0x100a2da", KEEP_LATEST);
		chooseCodeUnit("0x100a2f4", "0x100a2f7", KEEP_MY);
		waitForMergeCompletion();

		assertSameBytes(resultProgram, originalProgram, new AddressSet(addr("0x100a0ac"),
			addr("0x100a0af")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x100a0ac"),
			addr("0x100a0af")));
		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x100a2d8"),
			addr("0x100a2da")));
		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x100a2d8"),
			addr("0x100a2da")));
		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x100a2f4"),
			addr("0x100a2f7")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x100a2f4"),
			addr("0x100a2f7")));
	}

@Test
    public void testLatestByteXMyDataA() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					setBytes(program, "0x100a0ad", new byte[] { (byte) 0x03 });
					setBytes(program, "0x100a0bb", new byte[] { (byte) 0x22 });
					setBytes(program, "0x100a0c2", new byte[] { (byte) 0x10 });
					setBytes(program, "0x100a0c4", new byte[] { (byte) 0x56 });
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
					DataType dt =
						program.getDataTypeManager().getDataType(new CategoryPath("/"),
							"UnionSize4");
					assertNotNull(dt);
					createData(program, "0x100a0ac", dt);

					dt =
						program.getDataTypeManager().getDataType(new CategoryPath("/"),
							"ThreeBytes");
					assertNotNull(dt);
					createData(program, "0x100a0bb", dt);

					dt = new ArrayDataType(new CharDataType(), 5, 1);
					assertNotNull(dt);
					createData(program, "0x100a0c0", dt);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x100a0ac", "0x100a0af", KEEP_LATEST);
		chooseCodeUnit("0x100a0bb", "0x100a0bd", KEEP_MY);
		chooseCodeUnit("0x100a0c0", "0x100a0c4", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x100a0ac"),
			addr("0x100a0af")));
		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x100a0ac"),
			addr("0x100a0af")));
		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x100a0bb"),
			addr("0x100a0bd")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x100a0bb"),
			addr("0x100a0bd")));
		assertSameBytes(resultProgram, originalProgram, new AddressSet(addr("0x100a0c0"),
			addr("0x100a0c4")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x100a0c0"),
			addr("0x100a0c4")));
	}

@Test
    public void testLatestByteXDiffData() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					setBytes(program, "0x100a0ad", new byte[] { (byte) 0x03 });
					setBytes(program, "0x100a0bb", new byte[] { (byte) 0x22 });
					setBytes(program, "0x100a0c2", new byte[] { (byte) 0x10 });
					setBytes(program, "0x100a0c4", new byte[] { (byte) 0x56 });

					DataType dt =
						program.getDataTypeManager().getDataType(new CategoryPath("/"),
							"ThreeBytes");
					assertNotNull(dt);
					createData(program, "0x100a0ac", dt);

					createData(program, "0x100a0bb", new DWordDataType());

					dt = new ArrayDataType(new CharDataType(), 5, 1);
					assertNotNull(dt);
					createData(program, "0x100a0c0", dt);

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
					DataType dt =
						program.getDataTypeManager().getDataType(new CategoryPath("/"),
							"UnionSize4");
					assertNotNull(dt);
					createData(program, "0x100a0ac", dt);

					dt =
						program.getDataTypeManager().getDataType(new CategoryPath("/"),
							"ThreeBytes");
					assertNotNull(dt);
					createData(program, "0x100a0bb", dt);

					createData(program, "0x100a0c0", new FloatDataType());

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x100a0ac", "0x100a0af", KEEP_LATEST);
		chooseCodeUnit("0x100a0bb", "0x100a0be", KEEP_MY);
		chooseCodeUnit("0x100a0c0", "0x100a0c4", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x100a0ac"),
			addr("0x100a0af")));
		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x100a0ac"),
			addr("0x100a0af")));
		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x100a0bb"),
			addr("0x100a0bd")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x100a0bb"),
			addr("0x100a0bd")));
		assertSameBytes(resultProgram, originalProgram, new AddressSet(addr("0x100a0c0"),
			addr("0x100a0c4")));
		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x100a0c0"),
			addr("0x100a0c4")));
	}

	/**
	 * test that automerge happens correctly when you:
	 *   Delete category "cat1"
	 *   Recreate category "cat1"
	 *   Add "Dt1" to category "cat1"
	 *   Apply "Dt1" to the program as defined data.
	 * Should end up with Dt1 applied in the program.
	 * @throws Exception
	 */
@Test
    public void testDeleteCatAddDtApplyDt() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Create a data that won't conflict with MY program.
					createData(program, "0x100a0bb", new DWordDataType());

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
					CategoryPath catPath = new CategoryPath("/cat1");
					DataTypeManager dtm = program.getDataTypeManager();
					Category root = dtm.getCategory(CategoryPath.ROOT);
					Category cat = dtm.getCategory(catPath);
					assertNotNull(cat);
					// Delete category "cat1".
					root.removeCategory("cat1", TaskMonitorAdapter.DUMMY_MONITOR);
					cat = dtm.getCategory(catPath);
					assertNull(cat);
					//Add "cat1" category back
					cat = dtm.createCategory(catPath);
					assertNotNull(cat);
					// Create the Dt1 in MY program to be tested.
					StructureDataType dt1 = new StructureDataType("Dt1", 0);
					dt1.add(new ByteDataType());
					dt1.add(new WordDataType());
					DataType newDt = cat.addDataType(dt1, DataTypeConflictHandler.DEFAULT_HANDLER);
					DataType dt = dtm.getDataType(new CategoryPath("/cat1"), "Dt1");
					assertNotNull(dt);
					assertEquals(dt, newDt);
					// Apply "Dt1" to the program.
					createData(program, "0x100a0ac", dt);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameBytes(resultProgram, myProgram, new AddressSet(addr("0x100a0ac"),
			addr("0x100a0af")));
		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x100a0ac"),
			addr("0x100a0af")));
		assertSameBytes(resultProgram, latestProgram, new AddressSet(addr("0x100a0bb"),
			addr("0x100a0bd")));
		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x100a0bb"),
			addr("0x100a0bd")));
	}

}
