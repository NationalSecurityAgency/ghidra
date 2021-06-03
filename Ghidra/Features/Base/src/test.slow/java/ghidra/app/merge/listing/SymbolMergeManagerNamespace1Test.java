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

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

/**
 * Test the merge of the versioned program's symbols in the listing.
 */
public class SymbolMergeManagerNamespace1Test extends AbstractListingMergeManagerTest {

	// *** NotepadMergeListingTest ***
	// Global
	//		FirstClass
	//			FUN_01005887
	//			FUN_010058b8
	//		SecondClass
	//			FUN_01005320
	//			FUN_010062f0
	//		EmptyClass
	//		FirstNamespace
	//			FUN_0100194b
	//			FUN_01004bc0
	//		SecondNamespace
	//			FUN_01002239
	//			SubClass
	//				FUN_01004a5e
	//				FUN_01004c30
	//			SubNamespace
	//				FUN_010053c6
	//		EmptyNamespace

	// *** NotepadMergeListingTest ***
	// 010018b3: one default symbol from ref
	// 010018bf: one default symbol from ref
	// 01001b97: no symbol
	// 01001bde: one default symbol from ref
	// 01002691: primary local "AAA" scope=FUN_0100248f
	// 01002721: primary global "XXX"
	// 010028eb: no symbol
	// 01003075: primary global "YYY"
	// 01003075: non-primary global "ZZZ"
	// 01003075: non-primary global "QQQ"
	// 010032a7: no symbol
	// 01003439: primary local "BBB" scope=FUN_010033f6
	// 01003e25: primary local "CCC" scope=FUN_01003bed
	// 010044d0: primary global "DDD"
	// 010044d0: non-primary local "DDD6" scope=FUN_01004444
	// 01004bdc: primary local "EEE4" scope=FUN_01004bc0
	// 01004bdc: non-primary global "EEE"
	// 01004bf4: no symbol
	// 01004cf9: one default symbol
	// 01005c2f: no symbol
	// 01005c6f: one function symbol "FUN_01005c6f" scope=global
	// 01006420: primary global "entry" (entry point)
	// 01006420: local "ABC"
	// 01006420: global "DEF"
	// 0100e483: primary global "AAA"

	// *** NotepadMergeListingTest ***
	// 01001978     no function
	// 0100299e		no function
	// 01002a91		FUN_01002a91	body:1002a91-1002b43
	// 01002b44		FUN_01002b44	body:1002b44-1002b7c
	// 01002b7d		FUN_01002b7d	body:1002b7d-1002c92
	// 01002c93		FUN_01002c93	body:1002c93-1002cf4
	// 01002cf5		FUN_01002cf5	body:1002cf5-1002d6d
	// 01002f01		FUN_01002f01	body:1002f01-10030c5
	// 010031ee		FUN_010031ee	body:10031ee-100324f
	// 01003250		FUN_01003250	body:1003250-10032d4
	// 01003bed		FUN_01003bed	body:1003bed-1003efb
	// 01005c6f		FUN_01005c6f	body:[1005c6f-1005fbd][1005ff5-10061e2]
	// 01006420		entry			body:[1006420-1006581][10065a4-10065cd]

	/*
	 * Test generic Namespace symbols being removed from either the LATEST or
	 * CHECKED OUT program when it doesn't result in a conflict.
	 * @throws Exception
	 */
	@Test
	public void testRemoveNamespaceSymbolNoConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol symbol;
					symbol = getUniqueSymbol(program, "EmptyNamespace");
					assertNotNull(symbol);
					symtab.removeSymbolSpecial(symbol);

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
					SymbolTable symtab = program.getSymbolTable();
					Symbol symbol;
					symbol = getUniqueSymbol(program, "FirstNamespace");
					assertNotNull(symbol);
					symtab.removeSymbolSpecial(symbol);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		resultProgram = mtf.getResultProgram();
		resultAddressFactory = resultProgram.getAddressFactory();
		FunctionManager funcMgr = resultProgram.getFunctionManager();
		assertNotNull(funcMgr.getFunctionAt(addr("0x0100194b")));
		assertNotNull(funcMgr.getFunctionAt(addr("0x01004bc0")));

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertNull(getUniqueSymbol(resultProgram, "EmptyNamespace"));
		assertNull(getUniqueSymbol(resultProgram, "FirstNamespace"));
		assertNull(funcMgr.getFunctionAt(addr("0x0100194b")));
		assertNull(funcMgr.getFunctionAt(addr("0x01004bc0")));
	}

	/*
	 * Test Class symbols being removed from either the LATEST or
	 * CHECKED OUT program when it doesn't result in a conflict.
	 * @throws Exception
	 */
	@Test
	public void testRemoveClassSymbolNoConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol symbol;
					symbol = getUniqueSymbol(program, "EmptyClass");
					assertNotNull(symbol);
					symtab.removeSymbolSpecial(symbol);

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
					SymbolTable symtab = program.getSymbolTable();
					Symbol symbol;
					symbol = getUniqueSymbol(program, "FirstClass");
					assertNotNull(symbol);
					symtab.removeSymbolSpecial(symbol);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		resultProgram = mtf.getResultProgram();
		resultAddressFactory = resultProgram.getAddressFactory();
		FunctionManager funcMgr = resultProgram.getFunctionManager();
		assertNotNull(funcMgr.getFunctionAt(addr("0x01005887")));
		assertNotNull(funcMgr.getFunctionAt(addr("0x010058b8")));

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertNull(getUniqueSymbol(resultProgram, "EmptyClass"));
		assertNull(getUniqueSymbol(resultProgram, "FirstClass"));
		assertNull(funcMgr.getFunctionAt(addr("0x01005887")));
		assertNull(funcMgr.getFunctionAt(addr("0x010058b8")));
	}

	@Test
	public void testAddNamespaceNoConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					symtab.createNameSpace(program.getGlobalNamespace(), "NewLatestNamespace",
						SourceType.USER_DEFINED);
					symtab.createNameSpace(program.getGlobalNamespace(), "NewSameNamespace",
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
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
					SymbolTable symtab = program.getSymbolTable();
					symtab.createNameSpace(program.getGlobalNamespace(), "NewMyNamespace",
						SourceType.USER_DEFINED);
					symtab.createNameSpace(program.getGlobalNamespace(), "NewSameNamespace",
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		resultProgram = mtf.getResultProgram();
		resultAddressFactory = resultProgram.getAddressFactory();

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertEquals(SymbolType.NAMESPACE,
			getUniqueSymbol(resultProgram, "NewLatestNamespace").getSymbolType());
		assertEquals(SymbolType.NAMESPACE,
			getUniqueSymbol(resultProgram, "NewMyNamespace").getSymbolType());
		assertEquals(SymbolType.NAMESPACE,
			getUniqueSymbol(resultProgram, "NewSameNamespace").getSymbolType());
	}

	@Test
	public void testAddNamespaceAndSymbolNoConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Namespace ns;
					ns = symtab.createNameSpace(program.getGlobalNamespace(), "NewLatestNamespace",
						SourceType.USER_DEFINED);
					symtab.createLabel(addr(program, "0x1001004"), "popcorn", ns,
						SourceType.USER_DEFINED);
					ns = symtab.createNameSpace(program.getGlobalNamespace(), "NewSameNamespace",
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
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
					SymbolTable symtab = program.getSymbolTable();
					Namespace ns;
					ns = symtab.createNameSpace(program.getGlobalNamespace(), "NewMyNamespace",
						SourceType.USER_DEFINED);
					symtab.createLabel(addr(program, "0x1001008"), "peanuts", ns,
						SourceType.USER_DEFINED);
					ns = symtab.createNameSpace(program.getGlobalNamespace(), "NewSameNamespace",
						SourceType.USER_DEFINED);
					symtab.createLabel(addr(program, "0x1006420"), "CrackerJacks", ns,
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		resultProgram = mtf.getResultProgram();
		resultAddressFactory = resultProgram.getAddressFactory();

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol latest = getUniqueSymbol(resultProgram, "NewLatestNamespace");
		Symbol my = getUniqueSymbol(resultProgram, "NewMyNamespace");
		Symbol same = getUniqueSymbol(resultProgram, "NewSameNamespace");
		assertEquals(SymbolType.NAMESPACE, latest.getSymbolType());
		assertEquals(SymbolType.NAMESPACE, my.getSymbolType());
		assertEquals(SymbolType.NAMESPACE, same.getSymbolType());
		Namespace latestNs = (Namespace) latest.getObject();
		Namespace myNs = (Namespace) my.getObject();
		Namespace sameNs = (Namespace) same.getObject();
		Symbol popcorn = symtab.getSymbol("popcorn", addr("0x1001004"), latestNs);
		Symbol peanuts = symtab.getSymbol("peanuts", addr("0x1001008"), myNs);
		Symbol crackerjacks = symtab.getSymbol("CrackerJacks", addr("0x1006420"), sameNs);
		assertNotNull(popcorn);
		assertNotNull(peanuts);
		assertNotNull(crackerjacks);
		assertEquals(latestNs, popcorn.getParentNamespace());
		assertEquals(myNs, peanuts.getParentNamespace());
		assertEquals(sameNs, crackerjacks.getParentNamespace());
	}

	@Test
	public void testAddClassNoConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					symtab.createClass(program.getGlobalNamespace(), "NewLatestClass",
						SourceType.USER_DEFINED);
					symtab.createClass(program.getGlobalNamespace(), "NewSameClass",
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
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
					SymbolTable symtab = program.getSymbolTable();
					symtab.createClass(program.getGlobalNamespace(), "NewMyClass",
						SourceType.USER_DEFINED);
					symtab.createClass(program.getGlobalNamespace(), "NewSameClass",
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		resultProgram = mtf.getResultProgram();
		resultAddressFactory = resultProgram.getAddressFactory();

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertEquals(SymbolType.CLASS,
			getUniqueSymbol(resultProgram, "NewLatestClass").getSymbolType());
		assertEquals(SymbolType.CLASS,
			getUniqueSymbol(resultProgram, "NewMyClass").getSymbolType());
		assertEquals(SymbolType.CLASS,
			getUniqueSymbol(resultProgram, "NewSameClass").getSymbolType());
	}

	@Test
	public void testAddClassAndFunctionNoConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					GhidraClass gc;
					Function f;
					gc = symtab.createClass(program.getGlobalNamespace(), "NewLatestClass",
						SourceType.USER_DEFINED);
					f = getFunction(program, "0x1002a91");
					f.setParentNamespace(gc);
					f.setName("popcorn", SourceType.USER_DEFINED);
					gc = symtab.createClass(program.getGlobalNamespace(), "NewSameClass",
						SourceType.USER_DEFINED);
					f = getFunction(program, "0x1006420");
					f.setParentNamespace(gc);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
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
					SymbolTable symtab = program.getSymbolTable();
					GhidraClass gc;
					Function f;
					gc = symtab.createClass(program.getGlobalNamespace(), "NewMyClass",
						SourceType.USER_DEFINED);
					f = getFunction(program, "0x1002c93");
					f.setParentNamespace(gc);
					f.setName("peanuts", SourceType.USER_DEFINED);
					gc = symtab.createClass(program.getGlobalNamespace(), "NewSameClass",
						SourceType.USER_DEFINED);
					f = getFunction(program, "0x1003bed");
					f.setParentNamespace(gc);
					f.setName("CrackerJacks", SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		resultProgram = mtf.getResultProgram();
		resultAddressFactory = resultProgram.getAddressFactory();

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol latest = getUniqueSymbol(resultProgram, "NewLatestClass");
		Symbol my = getUniqueSymbol(resultProgram, "NewMyClass");
		Symbol same = getUniqueSymbol(resultProgram, "NewSameClass");
		assertEquals(SymbolType.CLASS, latest.getSymbolType());
		assertEquals(SymbolType.CLASS, my.getSymbolType());
		assertEquals(SymbolType.CLASS, same.getSymbolType());
		GhidraClass latestGc = (GhidraClass) latest.getObject();
		GhidraClass myGc = (GhidraClass) my.getObject();
		GhidraClass sameGc = (GhidraClass) same.getObject();
		Symbol popcorn = symtab.getSymbol("popcorn", addr("0x1002a91"), latestGc);
		Symbol peanuts = symtab.getSymbol("peanuts", addr("0x1002c93"), myGc);
		Symbol crackerjacks = symtab.getSymbol("CrackerJacks", addr("0x1003bed"), sameGc);
		Symbol entry = symtab.getSymbol("entry", addr("0x1006420"), sameGc);
		assertNotNull(popcorn);
		assertNotNull(peanuts);
		assertNotNull(crackerjacks);
		assertNotNull(entry);
		assertEquals(SymbolType.FUNCTION, popcorn.getSymbolType());
		assertEquals(SymbolType.FUNCTION, peanuts.getSymbolType());
		assertEquals(SymbolType.FUNCTION, crackerjacks.getSymbolType());
		assertEquals(SymbolType.FUNCTION, entry.getSymbolType());
		assertEquals(latestGc, popcorn.getParentNamespace());
		assertEquals(myGc, peanuts.getParentNamespace());
		assertEquals(sameGc, crackerjacks.getParentNamespace());
		assertEquals(sameGc, entry.getParentNamespace());
	}

	@Test
	public void testSimpleAddClassAddNamespaceConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Namespace ns;
					GhidraClass gc;
					ns = program.getSymbolTable()
							.createNameSpace(program.getGlobalNamespace(),
								"Blue", SourceType.USER_DEFINED);
					assertNotNull(ns);
					ns = program.getSymbolTable()
							.createNameSpace(program.getGlobalNamespace(),
								"Green", SourceType.USER_DEFINED);
					assertNotNull(ns);
					gc = program.getSymbolTable()
							.createClass(program.getGlobalNamespace(), "Red",
								SourceType.USER_DEFINED);
					assertNotNull(gc);
					gc = program.getSymbolTable()
							.createClass(program.getGlobalNamespace(),
								"Yellow", SourceType.USER_DEFINED);
					assertNotNull(gc);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
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
					Namespace ns;
					GhidraClass gc;
					gc = program.getSymbolTable()
							.createClass(program.getGlobalNamespace(), "Blue",
								SourceType.USER_DEFINED);
					assertNotNull(gc);
					gc = program.getSymbolTable()
							.createClass(program.getGlobalNamespace(), "Green",
								SourceType.USER_DEFINED);
					assertNotNull(gc);
					ns = program.getSymbolTable()
							.createNameSpace(program.getGlobalNamespace(),
								"Red", SourceType.USER_DEFINED);
					assertNotNull(ns);
					ns = program.getSymbolTable()
							.createNameSpace(program.getGlobalNamespace(),
								"Yellow", SourceType.USER_DEFINED);
					assertNotNull(ns);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
//		chooseRadioButton(RENAME_CHECKED_OUT_BUTTON_NAME); // blue
//		chooseRadioButton(REMOVE_CHECKED_OUT_BUTTON_NAME); // green
//		chooseRadioButton(RENAME_CHECKED_OUT_BUTTON_NAME); // red
//		chooseRadioButton(REMOVE_CHECKED_OUT_BUTTON_NAME); // yellow
		waitForReadTextDialog("Symbol Merge Information", "The following symbols were renamed",
			4000);
		waitForMergeCompletion();

		Namespace globalNS = resultProgram.getGlobalNamespace();
		Symbol blue = getUniqueSymbol(resultProgram, "Blue", globalNS);
		Symbol blueConflict = getUniqueSymbol(resultProgram, "Blue_conflict1", globalNS);
		Symbol green = getUniqueSymbol(resultProgram, "Green", globalNS);
		Symbol greenConflict = getUniqueSymbol(resultProgram, "Green_conflict1", globalNS);
		Symbol red = getUniqueSymbol(resultProgram, "Red", globalNS);
		Symbol redConflict = getUniqueSymbol(resultProgram, "Red_conflict1", globalNS);
		Symbol yellow = getUniqueSymbol(resultProgram, "Yellow", globalNS);
		Symbol yellowConflict = getUniqueSymbol(resultProgram, "Yellow_conflict1", globalNS);
		assertEquals(SymbolType.NAMESPACE, blue.getSymbolType());
		assertEquals(SymbolType.CLASS, blueConflict.getSymbolType());
		assertEquals(SymbolType.NAMESPACE, green.getSymbolType());
		assertEquals(SymbolType.CLASS, greenConflict.getSymbolType());
		assertEquals(SymbolType.CLASS, red.getSymbolType());
		assertEquals(SymbolType.NAMESPACE, redConflict.getSymbolType());
		assertEquals(SymbolType.CLASS, yellow.getSymbolType());
		assertEquals(SymbolType.NAMESPACE, yellowConflict.getSymbolType());
	}

	@Test
	public void testSimpleAddSubClassAddSubNamespaceConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Namespace emptyNamespace = (Namespace) getUniqueSymbol(program,
						"EmptyNamespace", program.getGlobalNamespace()).getObject();
					Namespace ns;
					GhidraClass gc;
					ns = program.getSymbolTable()
							.createNameSpace(emptyNamespace, "Blue",
								SourceType.USER_DEFINED);
					assertNotNull(ns);
					ns = program.getSymbolTable()
							.createNameSpace(emptyNamespace, "Green",
								SourceType.USER_DEFINED);
					assertNotNull(ns);
					gc = program.getSymbolTable()
							.createClass(emptyNamespace, "Red",
								SourceType.USER_DEFINED);
					assertNotNull(gc);
					gc = program.getSymbolTable()
							.createClass(emptyNamespace, "Yellow",
								SourceType.USER_DEFINED);
					assertNotNull(gc);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
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
					Namespace emptyNamespace = (Namespace) getUniqueSymbol(program,
						"EmptyNamespace", program.getGlobalNamespace()).getObject();
					Namespace ns;
					GhidraClass gc;
					gc = program.getSymbolTable()
							.createClass(emptyNamespace, "Blue",
								SourceType.USER_DEFINED);
					assertNotNull(gc);
					gc = program.getSymbolTable()
							.createClass(emptyNamespace, "Green",
								SourceType.USER_DEFINED);
					assertNotNull(gc);
					ns = program.getSymbolTable()
							.createNameSpace(emptyNamespace, "Red",
								SourceType.USER_DEFINED);
					assertNotNull(ns);
					ns = program.getSymbolTable()
							.createNameSpace(emptyNamespace, "Yellow",
								SourceType.USER_DEFINED);
					assertNotNull(ns);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
//		chooseRadioButton(RENAME_CHECKED_OUT_BUTTON_NAME); // blue
//		chooseRadioButton(REMOVE_CHECKED_OUT_BUTTON_NAME); // green
//		chooseRadioButton(RENAME_CHECKED_OUT_BUTTON_NAME); // red
//		chooseRadioButton(REMOVE_CHECKED_OUT_BUTTON_NAME); // yellow
		waitForReadTextDialog("Symbol Merge Information", "The following symbols were renamed",
			4000);
		waitForMergeCompletion();

		Namespace emptyNamespace = (Namespace) getUniqueSymbol(resultProgram, "EmptyNamespace",
			resultProgram.getGlobalNamespace()).getObject();
		Symbol blue = getUniqueSymbol(resultProgram, "Blue", emptyNamespace);
		Symbol blueConflict = getUniqueSymbol(resultProgram, "Blue_conflict1", emptyNamespace);
		Symbol green = getUniqueSymbol(resultProgram, "Green", emptyNamespace);
		Symbol greenConflict = getUniqueSymbol(resultProgram, "Green_conflict1", emptyNamespace);
		Symbol red = getUniqueSymbol(resultProgram, "Red", emptyNamespace);
		Symbol redConflict = getUniqueSymbol(resultProgram, "Red_conflict1", emptyNamespace);
		Symbol yellow = getUniqueSymbol(resultProgram, "Yellow", emptyNamespace);
		Symbol yellowConflict = getUniqueSymbol(resultProgram, "Yellow_conflict1", emptyNamespace);
		assertEquals(SymbolType.NAMESPACE, blue.getSymbolType());
		assertEquals(SymbolType.CLASS, blueConflict.getSymbolType());
		assertEquals(SymbolType.NAMESPACE, green.getSymbolType());
		assertEquals(SymbolType.CLASS, greenConflict.getSymbolType());
		assertEquals(SymbolType.CLASS, red.getSymbolType());
		assertEquals(SymbolType.NAMESPACE, redConflict.getSymbolType());
		assertEquals(SymbolType.CLASS, yellow.getSymbolType());
		assertEquals(SymbolType.NAMESPACE, yellowConflict.getSymbolType());
	}

	@Test
	public void testComplexAddClassAddNamespaceConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			// primary global "XXX" @ "0x1002721"
			// primary global "YYY" @ "0x1003075"
			// non-primary global "ZZZ" @ "0x1003075"
			// non-primary global "QQQ" @ "0x1003075"
			// primary global "DDD" @ "0x10044d0"
			// non-primary global "EEE" @ "0x1004bdc"
			// primary global "AAA" @ "0x100e483"

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Namespace ns;
					GhidraClass gc;
					ns = program.getSymbolTable()
							.createNameSpace(program.getGlobalNamespace(),
								"Blue", SourceType.USER_DEFINED);
					assertNotNull(ns);
					ns = program.getSymbolTable()
							.createNameSpace(program.getGlobalNamespace(),
								"Green", SourceType.USER_DEFINED);
					assertNotNull(ns);
					gc = program.getSymbolTable()
							.createClass(program.getGlobalNamespace(), "Red",
								SourceType.USER_DEFINED);
					assertNotNull(gc);
					gc = program.getSymbolTable()
							.createClass(program.getGlobalNamespace(),
								"Yellow", SourceType.USER_DEFINED);
					assertNotNull(gc);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
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
					Namespace ns;
					GhidraClass gc;
					gc = program.getSymbolTable()
							.createClass(program.getGlobalNamespace(), "Blue",
								SourceType.USER_DEFINED);
					assertNotNull(gc);
					gc = program.getSymbolTable()
							.createClass(program.getGlobalNamespace(), "Green",
								SourceType.USER_DEFINED);
					assertNotNull(gc);
					ns = program.getSymbolTable()
							.createNameSpace(program.getGlobalNamespace(),
								"Red", SourceType.USER_DEFINED);
					assertNotNull(ns);
					gc = program.getSymbolTable()
							.createClass(ns, "SubRed",
								SourceType.USER_DEFINED);
					assertNotNull(gc);
					ns = program.getSymbolTable()
							.createNameSpace(program.getGlobalNamespace(),
								"Yellow", SourceType.USER_DEFINED);
					assertNotNull(ns);
					ns = program.getSymbolTable()
							.createNameSpace(ns, "SubYellow",
								SourceType.USER_DEFINED);
					assertNotNull(ns);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
//		chooseRadioButton(RENAME_CHECKED_OUT_BUTTON_NAME); // blue
//		chooseRadioButton(REMOVE_CHECKED_OUT_BUTTON_NAME); // green
//		chooseRadioButton(RENAME_CHECKED_OUT_BUTTON_NAME); // red
//		chooseRadioButton(REMOVE_CHECKED_OUT_BUTTON_NAME); // yellow
		waitForReadTextDialog("Symbol Merge Information", "The following symbols were renamed",
			4000);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		Namespace globalNS = resultProgram.getGlobalNamespace();
		Symbol blue = getUniqueSymbol(resultProgram, "Blue", globalNS);
		Symbol blueConflict = getUniqueSymbol(resultProgram, "Blue_conflict1", globalNS);
		Symbol green = getUniqueSymbol(resultProgram, "Green", globalNS);
		Symbol greenConflict = getUniqueSymbol(resultProgram, "Green_conflict1", globalNS);
		Symbol red = getUniqueSymbol(resultProgram, "Red", globalNS);
		Symbol redConflict = getUniqueSymbol(resultProgram, "Red_conflict1", globalNS);
		Symbol yellow = getUniqueSymbol(resultProgram, "Yellow", globalNS);
		Symbol yellowConflict = getUniqueSymbol(resultProgram, "Yellow_conflict1", globalNS);
		Symbol subRed =
			getUniqueSymbol(resultProgram, "SubRed", (Namespace) redConflict.getObject());
		SymbolIterator subYellowIter = symtab.getSymbols("SubYellow");
		Symbol subYellow = null;
		if (subYellowIter.hasNext()) {
			subYellow = subYellowIter.next();
		}
		assertNotNull(subYellow);
		assertEquals(SymbolType.NAMESPACE, blue.getSymbolType());
		assertEquals(SymbolType.CLASS, blueConflict.getSymbolType());
		assertEquals(SymbolType.NAMESPACE, green.getSymbolType());
		assertEquals(SymbolType.CLASS, greenConflict.getSymbolType());
		assertEquals(SymbolType.CLASS, red.getSymbolType());
		assertEquals(SymbolType.NAMESPACE, redConflict.getSymbolType());
		assertEquals(SymbolType.CLASS, yellow.getSymbolType());
		assertEquals(SymbolType.NAMESPACE, yellowConflict.getSymbolType());
		assertEquals(SymbolType.CLASS, subRed.getSymbolType());
		assertEquals(redConflict, subRed.getParentSymbol());
		assertEquals(SymbolType.NAMESPACE, subYellow.getSymbolType());
		assertEquals(yellowConflict, subYellow.getParentSymbol());
	}

//	public void testAddClassAddNamespaceConflict() throws Exception {
//	}
//
//	public void testAddClassAddNamespaceConflict() throws Exception {
//	}
//
//	public void testAddClassAddNamespaceConflict() throws Exception {
//	}
//
//	public void testAddClassAddNamespaceConflict() throws Exception {
//	}
//
//	public void testAddClassAddNamespaceConflict() throws Exception {
//	}
//
//	public void testAddClassAddNamespaceConflict() throws Exception {
//	}
//
//	public void testAddClassAddNamespaceConflict() throws Exception {
//	}

	@Test
	public void testSimpleAddNamespaceAddSymbolNoConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Namespace ns;
					GhidraClass gc;
					SymbolTable symtab = program.getSymbolTable();
					FunctionManager funcMgr = program.getFunctionManager();
					ns = symtab.createNameSpace(program.getGlobalNamespace(), "Blue",
						SourceType.USER_DEFINED);
					assertNotNull(ns);
					symtab.createLabel(addr(program, "0x1001000"), "BlueSymbolLatest", ns,
						SourceType.USER_DEFINED);
					gc = symtab.createClass(program.getGlobalNamespace(), "Red",
						SourceType.USER_DEFINED);
					assertNotNull(gc);
					Function redFunction = funcMgr.getFunctionAt(addr(program, "0x1002a91"));
//					redFunction.setName("RedSymbolLatest");
					redFunction.getSymbol().setNamespace(gc);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
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
					Namespace ns;
					GhidraClass gc;
					SymbolTable symtab = program.getSymbolTable();
					FunctionManager funcMgr = program.getFunctionManager();
					gc = symtab.createClass(program.getGlobalNamespace(), "Blue",
						SourceType.USER_DEFINED);
					assertNotNull(gc);
					Function blueFunction = funcMgr.getFunctionAt(addr(program, "0x1006420"));
//					blueFunction.setName("BlueSymbolMy");
					blueFunction.getSymbol().setNamespace(gc);
					assertEquals(gc, blueFunction.getSymbol().getParentNamespace());
					ns = symtab.createNameSpace(program.getGlobalNamespace(), "Red",
						SourceType.USER_DEFINED);
					assertNotNull(ns);
					symtab.createLabel(addr(program, "0x1001000"), "RedSymbolMy", ns,
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
//		chooseRadioButton(RENAME_CHECKED_OUT_BUTTON_NAME); // blue class
//		chooseRadioButton(RENAME_CHECKED_OUT_BUTTON_NAME); // red namespace
		waitForReadTextDialog("Symbol Merge Information", "The following symbols were renamed",
			4000);
		waitForMergeCompletion();

		Namespace globalNS = resultProgram.getGlobalNamespace();

		Symbol blue = getUniqueSymbol(resultProgram, "Blue", globalNS);
		assertEquals(SymbolType.NAMESPACE, blue.getSymbolType());
		Namespace blueNs = (Namespace) blue.getObject();
		Symbol blueConflict = getUniqueSymbol(resultProgram, "Blue_conflict1", globalNS);
		assertEquals(SymbolType.CLASS, blueConflict.getSymbolType());
		GhidraClass blueGc = (GhidraClass) blueConflict.getObject();
		Symbol blueSymLatest = getUniqueSymbol(resultProgram, "BlueSymbolLatest", blueNs);
		assertNotNull(blueSymLatest);
		Function blueFunction = resultProgram.getFunctionManager().getFunctionAt(addr("0x1006420"));
		assertNotNull(blueFunction);
		Symbol blueSymMy = blueFunction.getSymbol();
		assertNotNull(blueSymMy);
		assertEquals(blueGc, blueSymMy.getParentNamespace());

		Symbol red = getUniqueSymbol(resultProgram, "Red", globalNS);
		assertEquals(SymbolType.CLASS, red.getSymbolType());
		GhidraClass redGc = (GhidraClass) red.getObject();
		Symbol redConflict = getUniqueSymbol(resultProgram, "Red_conflict1", globalNS);
		assertEquals(SymbolType.NAMESPACE, redConflict.getSymbolType());
		Namespace redNs = (Namespace) redConflict.getObject();
		Function redFunction = resultProgram.getFunctionManager().getFunctionAt(addr("0x1002a91"));
		assertNotNull(redFunction);
		Symbol redSymLatest = redFunction.getSymbol();
		assertNotNull(redSymLatest);
		assertEquals(redGc, redSymLatest.getParentNamespace());
		Symbol redSymMy = getUniqueSymbol(resultProgram, "RedSymbolMy", redNs);
		assertNotNull(redSymMy);
	}

	@Test
	public void testSimpleRenameNamespaceAddSymbolNoConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Namespace emptyNamespace = (Namespace) getUniqueSymbol(program,
						"EmptyNamespace", program.getGlobalNamespace()).getObject();
					emptyNamespace.getSymbol().setName("ChangedNS", SourceType.USER_DEFINED);
					assertEquals("ChangedNS", emptyNamespace.getName());
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
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
					SymbolTable symtab = program.getSymbolTable();
					Namespace emptyNamespace = (Namespace) getUniqueSymbol(program,
						"EmptyNamespace", program.getGlobalNamespace()).getObject();
					symtab.createLabel(addr(program, "0x1001000"), "bats", emptyNamespace,
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Symbol emptyNsSymbol =
			getUniqueSymbol(resultProgram, "EmptyNamespace", resultProgram.getGlobalNamespace());
		assertNull(emptyNsSymbol);
		Symbol changedNsSymbol =
			getUniqueSymbol(resultProgram, "ChangedNS", resultProgram.getGlobalNamespace());
		Namespace changedNamespace = (Namespace) changedNsSymbol.getObject();
		assertNotNull(changedNamespace);
		Symbol batsSymbol = getUniqueSymbol(resultProgram, "bats", changedNamespace);
		assertNotNull(batsSymbol);
		assertEquals(addr("0x1001000"), batsSymbol.getAddress());
		assertEquals("bats", batsSymbol.getName());
	}

	@Test
	public void testRenameNSAddSymbolNoConflict() throws Exception {
		// *** NotepadMergeListingTest ***
		// Global
		//		FirstClass
		//			FUN_01005887
		//			FUN_010058b8
		//		SecondClass
		//			FUN_01005320
		//			FUN_010062f0
		//		EmptyClass
		//		FirstNamespace
		//			FUN_0100194b
		//			FUN_01004bc0
		//		SecondNamespace
		//			FUN_01002239
		//			SubClass
		//				FUN_01004a5e
		//				FUN_01004c30
		//			SubNamespace
		//				FUN_010053c6
		//		EmptyNamespace

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Namespace firstNamespace = (Namespace) getUniqueSymbol(program,
						"FirstNamespace", program.getGlobalNamespace()).getObject();
					firstNamespace.getSymbol().setName("First", SourceType.USER_DEFINED);
					assertEquals("First", firstNamespace.getName());
					Namespace secondNamespace = (Namespace) getUniqueSymbol(program,
						"SecondNamespace", program.getGlobalNamespace()).getObject();
					symtab.createLabel(addr(program, "0x1001000"), "soccer", secondNamespace,
						SourceType.USER_DEFINED);
					Function f = getFunction(program, "0x1002239");
					f.setName("Stuff", SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
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
					SymbolTable symtab = program.getSymbolTable();
					Namespace secondNamespace = (Namespace) getUniqueSymbol(program,
						"SecondNamespace", program.getGlobalNamespace()).getObject();
					secondNamespace.getSymbol().setName("Second", SourceType.USER_DEFINED);
					assertEquals("Second", secondNamespace.getName());
					Namespace firstNamespace = (Namespace) getUniqueSymbol(program,
						"FirstNamespace", program.getGlobalNamespace()).getObject();
					symtab.createLabel(addr(program, "0x1001000"), "football", firstNamespace,
						SourceType.USER_DEFINED);
					Function f = getFunction(program, "0x100194b");
					f.setName("Junk", SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Symbol firstNsSymbol =
			getUniqueSymbol(resultProgram, "First", resultProgram.getGlobalNamespace());
		assertNotNull(firstNsSymbol);
		Namespace firstNamespace = (Namespace) firstNsSymbol.getObject();
		assertNotNull(firstNamespace);
		Symbol secondNsSymbol =
			getUniqueSymbol(resultProgram, "Second", resultProgram.getGlobalNamespace());
		assertNotNull(secondNsSymbol);
		Namespace secondNamespace = (Namespace) secondNsSymbol.getObject();
		assertNotNull(secondNamespace);

		Symbol sym;
		sym = getUniqueSymbol(resultProgram, "soccer", secondNamespace);
		assertNotNull(sym);
		assertEquals(addr("0x1001000"), sym.getAddress());

		sym = getUniqueSymbol(resultProgram, "Stuff", secondNamespace);
		assertNotNull(sym);
		assertEquals(addr("0x1002239"), sym.getAddress());

		sym = getUniqueSymbol(resultProgram, "football", firstNamespace);
		assertNotNull(sym);
		assertEquals(addr("0x1001000"), sym.getAddress());

		sym = getUniqueSymbol(resultProgram, "Junk", firstNamespace);
		assertNotNull(sym);
		assertEquals(addr("0x100194b"), sym.getAddress());
	}

	@Test
	public void testRemoveNSAddSymbolNoConflict() throws Exception {
		// *** NotepadMergeListingTest ***
		// Global
		//		FirstClass
		//			FUN_01005887
		//			FUN_010058b8
		//		SecondClass
		//			FUN_01005320
		//			FUN_010062f0
		//		EmptyClass
		//		FirstNamespace
		//			FUN_0100194b
		//			FUN_01004bc0
		//		SecondNamespace
		//			FUN_01002239
		//			SubClass
		//				FUN_01004a5e
		//				FUN_01004c30
		//			SubNamespace
		//				FUN_010053c6
		//		EmptyNamespace

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol firstNsSym =
						getUniqueSymbol(program, "FirstNamespace", program.getGlobalNamespace());
					symtab.removeSymbolSpecial(firstNsSym);
					Namespace secondNamespace = (Namespace) getUniqueSymbol(program,
						"SecondNamespace", program.getGlobalNamespace()).getObject();
					symtab.createLabel(addr(program, "0x1001000"), "soccer", secondNamespace,
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
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
					SymbolTable symtab = program.getSymbolTable();
					Symbol secondNsSym =
						getUniqueSymbol(program, "SecondNamespace", program.getGlobalNamespace());
					symtab.removeSymbolSpecial(secondNsSym);
					Namespace firstNamespace = (Namespace) getUniqueSymbol(program,
						"FirstNamespace", program.getGlobalNamespace()).getObject();
					symtab.createLabel(addr(program, "0x1001000"), "football", firstNamespace,
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForReadTextDialog("Symbol Merge Information",
			"The following namespaces were not removed", 4000);
		waitForMergeCompletion();

		Symbol firstNsSymbol =
			getUniqueSymbol(resultProgram, "FirstNamespace", resultProgram.getGlobalNamespace());
		assertNotNull(firstNsSymbol);
		Namespace firstNamespace = (Namespace) firstNsSymbol.getObject();
		assertNotNull(firstNamespace);
		Symbol secondNsSymbol =
			getUniqueSymbol(resultProgram, "SecondNamespace", resultProgram.getGlobalNamespace());
		assertNotNull(secondNsSymbol);
		Namespace secondNamespace = (Namespace) secondNsSymbol.getObject();
		assertNotNull(secondNamespace);

		Symbol sym;
		sym = getUniqueSymbol(resultProgram, "soccer", secondNamespace);
		assertNotNull(sym);
		assertEquals(addr("0x1001000"), sym.getAddress());

		Function f = getFunction(resultProgram, "0x1002239");
		assertNull(f); // Function was removed with namespace.

		sym = getUniqueSymbol(resultProgram, "football", firstNamespace);
		assertNotNull(sym);
		assertEquals(addr("0x1001000"), sym.getAddress());

		f = getFunction(resultProgram, "0x100194b");
		assertNull(f); // function was removed with namespace
	}

	@Test
	public void testRemoveNSRenameFunctionConflict() throws Exception {
		// *** NotepadMergeListingTest ***
		// Global
		//		FirstClass
		//			FUN_01005887
		//			FUN_010058b8
		//		SecondClass
		//			FUN_01005320
		//			FUN_010062f0
		//		EmptyClass
		//		FirstNamespace
		//			FUN_0100194b
		//			FUN_01004bc0
		//		SecondNamespace
		//			FUN_01002239
		//			SubClass
		//				FUN_01004a5e
		//				FUN_01004c30
		//			SubNamespace
		//				FUN_010053c6
		//		EmptyNamespace

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					Symbol firstNsSym =
						getUniqueSymbol(program, "FirstNamespace", program.getGlobalNamespace());
					symtab.removeSymbolSpecial(firstNsSym);
					Function f = getFunction(program, "0x1002239");
					f.setName("Stuff", SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
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
					SymbolTable symtab = program.getSymbolTable();
					Symbol secondNsSym =
						getUniqueSymbol(program, "SecondNamespace", program.getGlobalNamespace());
					symtab.removeSymbolSpecial(secondNsSym);
					Function f = getFunction(program, "0x100194b");
					f.setName("Junk", SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		chooseRadioButton(LATEST_BUTTON_NAME);
		waitForReadTextDialog("Symbol Merge Information",
			"The following namespaces were not removed", 4000);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		Namespace globalNS = resultProgram.getGlobalNamespace();
		SymbolIterator iter = symtab.getSymbols(globalNS);
		while (iter.hasNext()) {
			Symbol s = iter.next();
			if (s.getSymbolType().equals(SymbolType.NAMESPACE)) {
				System.out.println("Namespace = " + s.getName(true));
			}
		}
		Symbol firstNsSymbol =
			getUniqueSymbol(resultProgram, "FirstNamespace", resultProgram.getGlobalNamespace());
		assertNotNull(firstNsSymbol);
		Namespace firstNamespace = (Namespace) firstNsSymbol.getObject();
		assertNotNull(firstNamespace);
		Symbol secondNsSymbol =
			getUniqueSymbol(resultProgram, "SecondNamespace", resultProgram.getGlobalNamespace());
		assertNotNull(secondNsSymbol);
		Namespace secondNamespace = (Namespace) secondNsSymbol.getObject();
		assertNotNull(secondNamespace);

		Symbol sym;
		sym = getUniqueSymbol(resultProgram, "Stuff", secondNamespace);
		assertNotNull(sym);
		assertEquals(addr("0x1002239"), sym.getAddress());

		sym = getUniqueSymbol(resultProgram, "Junk", firstNamespace);
		assertNotNull(sym);
		assertEquals(addr("0x100194b"), sym.getAddress());
	}

	@Test
	public void testChangeFunctionNamespaceSameInBoth() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					FunctionManager functionMgr = program.getFunctionManager();

					Address entry = addr(program, "0x0100219c");
					Function f = functionMgr.getFunctionAt(entry);
					Namespace parentNamespace = symtab.createNameSpace(program.getGlobalNamespace(),
						"Foo", SourceType.USER_DEFINED);
					f.setParentNamespace(parentNamespace);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
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
					SymbolTable symtab = program.getSymbolTable();
					FunctionManager functionMgr = program.getFunctionManager();

					Address entry = addr(program, "0x0100219c");
					Function f = functionMgr.getFunctionAt(entry);
					Namespace parentNamespace = symtab.createNameSpace(program.getGlobalNamespace(),
						"Foo", SourceType.USER_DEFINED);
					f.setParentNamespace(parentNamespace);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		FunctionManager fm = resultProgram.getFunctionManager();

		Address entry = addr(resultProgram, "0x0100219c");
		Function f = fm.getFunctionAt(entry);
		assertEquals("Foo", f.getParentNamespace().getName(true));
	}

	@Test
	public void testChangeFunctionNamespaceDiffInBoth() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					FunctionManager functionMgr = program.getFunctionManager();

					Address entry = addr(program, "0x0100219c");
					Function f = functionMgr.getFunctionAt(entry);
					Namespace parentNamespace = symtab.createNameSpace(program.getGlobalNamespace(),
						"Foo", SourceType.USER_DEFINED);
					f.setParentNamespace(parentNamespace);

					entry = addr(program, "0x0100415a");
					f = functionMgr.getFunctionAt(entry);
					parentNamespace = symtab.createNameSpace(program.getGlobalNamespace(), "NS1",
						SourceType.USER_DEFINED);
					f.setParentNamespace(parentNamespace);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
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
					SymbolTable symtab = program.getSymbolTable();
					FunctionManager functionMgr = program.getFunctionManager();

					Address entry = addr(program, "0x0100219c");
					Function f = functionMgr.getFunctionAt(entry);
					Namespace parentNamespace = symtab.createNameSpace(program.getGlobalNamespace(),
						"Bar", SourceType.USER_DEFINED);
					f.setParentNamespace(parentNamespace);

					entry = addr(program, "0x0100415a");
					f = functionMgr.getFunctionAt(entry);
					parentNamespace = symtab.createNameSpace(program.getGlobalNamespace(), "NS2",
						SourceType.USER_DEFINED);
					f.setParentNamespace(parentNamespace);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
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

		FunctionManager fm = resultProgram.getFunctionManager();

		Address entry = addr(resultProgram, "0x0100219c");
		Function f = fm.getFunctionAt(entry);
		assertEquals("Foo", f.getParentNamespace().getName(true));

		entry = addr(resultProgram, "0x0100415a");
		f = fm.getFunctionAt(entry);
		assertEquals("NS2", f.getParentNamespace().getName(true));
	}

}
