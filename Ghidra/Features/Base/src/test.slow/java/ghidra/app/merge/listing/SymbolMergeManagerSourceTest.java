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
import ghidra.program.model.symbol.*;

/**
 * Test the merge of the versioned program's listing.
 */
public class SymbolMergeManagerSourceTest extends AbstractListingMergeManagerTest {

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

	/**
	 *
	 * @param arg0
	 */
	public SymbolMergeManagerSourceTest() {
		super();
	}

	/** Test add of same symbol with same source to both Latest and My. */
	@Test
	public void testAddSameSourceSymbol() throws Exception {
		// 01002691: primary local "AAA" scope=FUN_0100248f
		// 010032a7: no symbol

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					program.getSymbolTable().createLabel(addr(program, "0x10032a7"), "Lucy", null,
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
					program.getSymbolTable().createLabel(addr(program, "0x10032a7"), "Lucy", null,
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

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol s;
		s = symtab.getPrimarySymbol(addr("0x10032a7"));
		checkSymbol(s, "Lucy", true);
		assertTrue(s.isPrimary());
		assertEquals(SourceType.USER_DEFINED, s.getSource());
	}

	/** Test add of same symbol and source to both Latest and My, but different symbol comments. */
//	public void testAddSameSourceSymbolAndComment() throws Exception {
//		// 010032a7: no symbol
//		// 01004bf4: no symbol
//
//		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyLatest(ProgramDB program) {
//				int txId = program.startTransaction("Modify My Program");
//				boolean commit = false;
//				try {
//					Symbol s = program.getSymbolTable().createSymbol(addr(program, "0x10032a7"),
//							"Lucy", null, SourceType.USER_DEFINED);
//					s.setSymbolData3("This is a symbol comment.");
//
//					s = program.getSymbolTable().createSymbol(addr(program, "0x1004bf4"),
//							"red", null, SourceType.IMPORTED);
//					s.setSymbolData3(longComment1);
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyPrivate(ProgramDB program) {
//				int txId = program.startTransaction("Modify My Program");
//				boolean commit = false;
//				try {
//					Symbol s = program.getSymbolTable().createSymbol(addr(program, "0x10032a7"), "Lucy", null,
//							SourceType.USER_DEFINED);
//					s.setSymbolData3("This is a symbol comment.");
//
//					s = program.getSymbolTable().createSymbol(addr(program, "0x1004bf4"),
//							"red", null, SourceType.IMPORTED);
//					s.setSymbolData3(longComment1);
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//		});
//
//		executeMerge(ASK_USER);
//		waitForMergeCompletion(5000);
//
//		SymbolTable symtab = resultProgram.getSymbolTable();
//		Symbol s;
//		s = symtab.getPrimarySymbol(addr("0x10032a7"));
//		checkSymbol(s, "Lucy", true);
//		assertTrue(s.isPrimary());
//		assertEquals(SourceType.USER_DEFINED, s.getSource());
//		assertEquals("This is a symbol comment.", s.getSymbolData3());
//
//		s = symtab.getPrimarySymbol(addr("0x1004bf4"));
//		checkSymbol(s, "red", true);
//		assertTrue(s.isPrimary());
//		assertEquals(SourceType.IMPORTED, s.getSource());
//		assertEquals(longComment1, s.getSymbolData3());
//	}

	/** Test add of same symbol and source to both Latest and My, but different symbol comments. */
//	public void testAddSameSourceSymbolWithDiffComment() throws Exception {
//		// 010032a7: no symbol
//		// 01004bf4: no symbol
//
//		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyLatest(ProgramDB program) {
//				int txId = program.startTransaction("Modify My Program");
//				boolean commit = false;
//				try {
//					Symbol s = program.getSymbolTable().createSymbol(addr(program, "0x10032a7"),
//							"Lucy", null, SourceType.USER_DEFINED);
//					s.setSymbolData3("This is a symbol comment.");
//
//					s = program.getSymbolTable().createSymbol(addr(program, "0x1004bf4"),
//							"red", null, SourceType.IMPORTED);
//					s.setSymbolData3(longComment1);
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyPrivate(ProgramDB program) {
//				int txId = program.startTransaction("Modify My Program");
//				boolean commit = false;
//				try {
//					Symbol s = program.getSymbolTable().createSymbol(addr(program, "0x10032a7"), "Lucy", null,
//							SourceType.USER_DEFINED);
//					s.setSymbolData3("Different comment.");
//
//					s = program.getSymbolTable().createSymbol(addr(program, "0x1004bf4"),
//							"red", null, SourceType.IMPORTED);
//					s.setSymbolData3(longComment2);
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//		});
//
//		executeMerge(ASK_USER);
//		chooseRadioButton(RESULT_BUTTON_NAME);
//		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
//		waitForMergeCompletion(5000);
//
//		SymbolTable symtab = resultProgram.getSymbolTable();
//		Symbol s;
//		s = symtab.getPrimarySymbol(addr("0x10032a7"));
//		checkSymbol(s, "Lucy", true);
//		assertTrue(s.isPrimary());
//		assertEquals(SourceType.USER_DEFINED, s.getSource());
//		assertEquals("This is a symbol comment.", s.getSymbolData3());
//
//		s = symtab.getPrimarySymbol(addr("0x1004bf4"));
//		checkSymbol(s, "red", true);
//		assertTrue(s.isPrimary());
//		assertEquals(SourceType.IMPORTED, s.getSource());
//		assertEquals(longComment2, s.getSymbolData3());
//	}

	/** Test add of same symbol and source to both Latest and My, but symbol comment only in Latest or only in My. */
//	public void testAddSameSourceSymbolBothWithCommentOnlyInOne() throws Exception {
//		// 010032a7: no symbol
//		// 01004bf4: no symbol
//
//		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyLatest(ProgramDB program) {
//				int txId = program.startTransaction("Modify My Program");
//				boolean commit = false;
//				try {
//					Symbol s = program.getSymbolTable().createSymbol(addr(program, "0x10032a7"),
//							"Lucy", null, SourceType.USER_DEFINED);
//
//					s = program.getSymbolTable().createSymbol(addr(program, "0x1004bf4"),
//							"red", null, SourceType.IMPORTED);
//					s.setSymbolData3(longComment1);
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyPrivate(ProgramDB program) {
//				int txId = program.startTransaction("Modify My Program");
//				boolean commit = false;
//				try {
//					Symbol s = program.getSymbolTable().createSymbol(addr(program, "0x10032a7"), "Lucy", null,
//							SourceType.USER_DEFINED);
//					s.setSymbolData3("Different comment.");
//
//					s = program.getSymbolTable().createSymbol(addr(program, "0x1004bf4"),
//							"red", null, SourceType.IMPORTED);
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//		});
//
//		executeMerge(ASK_USER);
//		waitForMergeCompletion(5000);
//
//		SymbolTable symtab = resultProgram.getSymbolTable();
//		Symbol s;
//		s = symtab.getPrimarySymbol(addr("0x10032a7"));
//		checkSymbol(s, "Lucy", true);
//		assertTrue(s.isPrimary());
//		assertEquals(SourceType.USER_DEFINED, s.getSource());
//		assertEquals("Different comment.", s.getSymbolData3());
//
//		s = symtab.getPrimarySymbol(addr("0x1004bf4"));
//		checkSymbol(s, "red", true);
//		assertTrue(s.isPrimary());
//		assertEquals(SourceType.IMPORTED, s.getSource());
//		assertEquals(longComment1, s.getSymbolData3());
//	}

	/** Test add of same symbol with different sources. */
	@Test
	public void testAddDiffSourceSymbol() throws Exception {
		// 01002691: primary local "AAA" scope=FUN_0100248f
		// 010032a7: no symbol

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					program.getSymbolTable().createLabel(addr(program, "0x10032a7"), "Charlie",
						null, SourceType.ANALYSIS);
					program.getSymbolTable().createLabel(addr(program, "0x10032a7"), "Lucy", null,
						SourceType.IMPORTED);
					program.getSymbolTable().createLabel(addr(program, "0x10032a7"), "Linus", null,
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
					program.getSymbolTable().createLabel(addr(program, "0x10032a7"), "Charlie",
						null, SourceType.USER_DEFINED);
					program.getSymbolTable().createLabel(addr(program, "0x10032a7"), "Lucy", null,
						SourceType.ANALYSIS);
					program.getSymbolTable().createLabel(addr(program, "0x10032a7"), "Linus", null,
						SourceType.IMPORTED);
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

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol s;
		s = symtab.getGlobalSymbol("Charlie", addr("0x10032a7"));
		checkSymbol(s, "Charlie", true);
		assertEquals(SourceType.ANALYSIS, s.getSource());

		s = symtab.getGlobalSymbol("Lucy", addr("0x10032a7"));
		checkSymbol(s, "Lucy", true);
		assertEquals(SourceType.IMPORTED, s.getSource());

		s = symtab.getGlobalSymbol("Linus", addr("0x10032a7"));
		checkSymbol(s, "Linus", true);
		assertEquals(SourceType.USER_DEFINED, s.getSource());
	}

	/** Test add of symbol for each source type to Latest program version only. */
	@Test
	public void testAddSourceSymbolToLatestOnly() throws Exception {
		// 01002691: primary local "AAA" scope=FUN_0100248f
		// 010032a7: no symbol

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					program.getSymbolTable().createLabel(addr(program, "0x10032a7"), "Lucy", null,
						SourceType.IMPORTED);
					program.getSymbolTable().createLabel(addr(program, "0x10032a7"), "Linus", null,
						SourceType.ANALYSIS);
					program.getSymbolTable().createLabel(addr(program, "0x10032a7"), "Sally", null,
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
				// No changes for My program.
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol s;
		s = symtab.getGlobalSymbol("Lucy", addr("0x10032a7"));
		checkSymbol(s, "Lucy", true);
		assertEquals(SourceType.IMPORTED, s.getSource());

		s = symtab.getGlobalSymbol("Linus", addr("0x10032a7"));
		checkSymbol(s, "Linus", true);
		assertEquals(SourceType.ANALYSIS, s.getSource());

		s = symtab.getGlobalSymbol("Sally", addr("0x10032a7"));
		checkSymbol(s, "Sally", true);
		assertEquals(SourceType.USER_DEFINED, s.getSource());
	}

	/** Test add of symbol for each source type to My program version only. */
	@Test
	public void testAddSourceSymbolToMyOnly() throws Exception {
		// 01002691: primary local "AAA" scope=FUN_0100248f
		// 010032a7: no symbol

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes for Latest program.
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					program.getSymbolTable().createLabel(addr(program, "0x10032a7"), "Charlie",
						null, SourceType.USER_DEFINED);
					program.getSymbolTable().createLabel(addr(program, "0x10032a7"), "Lucy", null,
						SourceType.ANALYSIS);
					program.getSymbolTable().createLabel(addr(program, "0x10032a7"), "Linus", null,
						SourceType.IMPORTED);
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

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol s;
		s = symtab.getGlobalSymbol("Charlie", addr("0x10032a7"));
		checkSymbol(s, "Charlie", true);
		assertEquals(SourceType.USER_DEFINED, s.getSource());

		s = symtab.getGlobalSymbol("Lucy", addr("0x10032a7"));
		checkSymbol(s, "Lucy", true);
		assertEquals(SourceType.ANALYSIS, s.getSource());

		s = symtab.getGlobalSymbol("Linus", addr("0x10032a7"));
		checkSymbol(s, "Linus", true);
		assertEquals(SourceType.IMPORTED, s.getSource());
	}

	/** Test changing source on existing symbol to same source in both Latest and My. */
	@Test
	public void testChangeSymbolSourceSameInBoth() throws Exception {
		// 01002721: primary global "XXX"

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Symbol symbol = getUniqueSymbol(program, "XXX");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setSource(SourceType.ANALYSIS);
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
					Symbol symbol = getUniqueSymbol(program, "XXX");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setSource(SourceType.ANALYSIS);
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

		Symbol s;
		s = getUniqueSymbol(resultProgram, "XXX");
		checkSymbol(s, "XXX", true);
		assertEquals(SourceType.ANALYSIS, s.getSource());
	}

	/** Test changing source on existing symbol to different source in both Latest and My. */
	@Test
	public void testChangeSymbolSourceDiffInBoth() throws Exception {
		// 01002721: primary global "XXX"

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Symbol symbol = getUniqueSymbol(program, "XXX");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setSource(SourceType.ANALYSIS);
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
					Symbol symbol = getUniqueSymbol(program, "XXX");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setSource(SourceType.IMPORTED);
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

		Symbol s;
		s = getUniqueSymbol(resultProgram, "XXX");
		checkSymbol(s, "XXX", true);
		assertEquals(SourceType.ANALYSIS, s.getSource());
	}

	/** Test changing source on existing symbol only in Latest. */
	@Test
	public void testChangeSymbolSourceOnlyInLatest() throws Exception {
		// 01002721: primary global "XXX"

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Symbol symbol = getUniqueSymbol(program, "XXX");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setSource(SourceType.ANALYSIS);
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
				// No changes for My program.
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Symbol s;
		s = getUniqueSymbol(resultProgram, "XXX");
		checkSymbol(s, "XXX", true);
		assertEquals(SourceType.ANALYSIS, s.getSource());
	}

	/** Test changing source on existing symbol only in My. */
	@Test
	public void testChangeSymbolSourceOnlyInMy() throws Exception {
		// 01002721: primary global "XXX"

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes for Latest program.
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Symbol symbol = getUniqueSymbol(program, "XXX");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setSource(SourceType.IMPORTED);
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

		Symbol s;
		s = getUniqueSymbol(resultProgram, "XXX");
		checkSymbol(s, "XXX", true);
		assertEquals(SourceType.IMPORTED, s.getSource());
	}

	/** Test changing name and source on existing symbol to same name and source in both Latest and My. */
	@Test
	public void testChangeSymbolNameSourceSameInBoth() throws Exception {
		// 01002721: primary global "XXX"

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Symbol symbol = getUniqueSymbol(program, "XXX");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setName("Five", SourceType.ANALYSIS);
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
					Symbol symbol = getUniqueSymbol(program, "XXX");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setName("Five", SourceType.ANALYSIS);
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

		Symbol s;
		s = getUniqueSymbol(resultProgram, "Five");
		checkSymbol(s, "Five", true);
		assertEquals(SourceType.ANALYSIS, s.getSource());
	}

	/** Test changing name and source on existing symbol to different names and sources in both Latest and My. */
	@Test
	public void testChangeSymbolNameSourceDiffInBoth() throws Exception {
		// 01002721: primary global "XXX"

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Symbol symbol = getUniqueSymbol(program, "XXX");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setName("uno", SourceType.ANALYSIS);

					symbol = getUniqueSymbol(program, "YYY");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setName("ein", SourceType.ANALYSIS);

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
					Symbol symbol = getUniqueSymbol(program, "XXX");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setName("dos", SourceType.IMPORTED);

					symbol = getUniqueSymbol(program, "YYY");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setName("zwei", SourceType.IMPORTED);

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
		chooseRadioButton(MY_BUTTON);
		chooseRadioButton(LATEST_BUTTON);
		waitForMergeCompletion();

		Symbol s;
		s = getUniqueSymbol(resultProgram, "XXX");
		assertNull(s);
		s = getUniqueSymbol(resultProgram, "dos");
		checkSymbol(s, "dos", true);
		assertEquals(SourceType.IMPORTED, s.getSource());
		s = getUniqueSymbol(resultProgram, "YYY");
		assertNull(s);
		s = getUniqueSymbol(resultProgram, "ein");
		checkSymbol(s, "ein", true);
		assertEquals(SourceType.ANALYSIS, s.getSource());
	}

	/** Test changing name and source on existing symbol in only Latest. */
	@Test
	public void testChangeSymbolNameSourceOnlyInLatest() throws Exception {
		// 01002721: primary global "XXX"

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Symbol symbol = getUniqueSymbol(program, "XXX");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setName("NewName", SourceType.ANALYSIS);
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
				// No changes for My program.
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Symbol s;
		s = getUniqueSymbol(resultProgram, "XXX");
		assertNull(s);
		s = getUniqueSymbol(resultProgram, "NewName");
		checkSymbol(s, "NewName", true);
		assertEquals(SourceType.ANALYSIS, s.getSource());
	}

	/** Test changing name and source on existing symbol in only My. */
	@Test
	public void testChangeSymbolNameSourceOnlyInMy() throws Exception {
		// 01002721: primary global "XXX"

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes for Latest program.
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Symbol symbol = getUniqueSymbol(program, "XXX");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setName("NewName", SourceType.IMPORTED);
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

		Symbol s;
		s = getUniqueSymbol(resultProgram, "XXX");
		assertNull(s);
		s = getUniqueSymbol(resultProgram, "NewName");
		checkSymbol(s, "NewName", true);
		assertEquals(SourceType.IMPORTED, s.getSource());
	}

	/** Test changing symbol name and source for different named symbols at the same
	 * address in Latest and My. */
	@Test
	public void testChangeDifferentSymbolNameSourceAtAddressInBoth() throws Exception {
		// 01003075: primary global "YYY"
		// 01003075: non-primary global "ZZZ"
		// 01003075: non-primary global "QQQ"

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable st = program.getSymbolTable();
					Symbol symbol = st.getGlobalSymbol("ZZZ", addr(program, "0x01003075"));
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setName("horse", SourceType.IMPORTED);
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
					SymbolTable st = program.getSymbolTable();
					Symbol symbol = st.getGlobalSymbol("QQQ", addr(program, "0x01003075"));
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setName("mule", SourceType.ANALYSIS);
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

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol s;
		Address addr = addr(resultProgram, "0x01003075");
		s = symtab.getGlobalSymbol("ZZZ", addr);
		assertNull(s);
		s = symtab.getGlobalSymbol("QQQ", addr);
		assertNull(s);
		s = getUniqueSymbol(resultProgram, "horse");
		checkSymbol(s, "horse", true);
		assertEquals(SourceType.IMPORTED, s.getSource());
		assertEquals(addr, s.getAddress());
		s = getUniqueSymbol(resultProgram, "mule");
		checkSymbol(s, "mule", true);
		assertEquals(SourceType.ANALYSIS, s.getSource());
		assertEquals(addr, s.getAddress());
	}

	/** Test changing symbol name and source in both. Pick Latest version. */
	@Test
	public void testChangeLatestAndMyNameSame() throws Exception {
		// 01002721: primary global "XXX"

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Symbol symbol = getUniqueSymbol(program, "XXX");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setName("apple", SourceType.ANALYSIS);
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
					Symbol symbol = getUniqueSymbol(program, "XXX");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setName("apple", SourceType.ANALYSIS);
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

		Symbol s;
		s = getUniqueSymbol(resultProgram, "XXX");
		assertNull(s);
		s = getUniqueSymbol(resultProgram, "apple");
		checkSymbol(s, "apple", true);
		assertEquals(SourceType.ANALYSIS, s.getSource());
	}

	/** Test changing symbol name and source in both. Pick Latest version. */
	@Test
	public void testChangeLatestAndMyNamePickLatest() throws Exception {
		// 01002721: primary global "XXX"

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Symbol symbol = getUniqueSymbol(program, "XXX");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setName("apple", SourceType.ANALYSIS);
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
					Symbol symbol = getUniqueSymbol(program, "XXX");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setName("orange", SourceType.IMPORTED);
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
		chooseRadioButton(LATEST_BUTTON);
		waitForMergeCompletion();

		Symbol s;
		s = getUniqueSymbol(resultProgram, "XXX");
		assertNull(s);
		s = getUniqueSymbol(resultProgram, "orange");
		assertNull(s);
		s = getUniqueSymbol(resultProgram, "apple");
		checkSymbol(s, "apple", true);
		assertEquals(SourceType.ANALYSIS, s.getSource());
	}

	/** Test changing symbol name and source in both. Pick My version. */
	@Test
	public void testChangeLatestAndMyNamePickMy() throws Exception {
		// 01002721: primary global "XXX"

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Symbol symbol = getUniqueSymbol(program, "XXX");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setName("apple", SourceType.ANALYSIS);
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
					Symbol symbol = getUniqueSymbol(program, "XXX");
					assertEquals(SourceType.USER_DEFINED, symbol.getSource());
					symbol.setName("orange", SourceType.IMPORTED);
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
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		Symbol s;
		s = getUniqueSymbol(resultProgram, "XXX");
		assertNull(s);
		s = getUniqueSymbol(resultProgram, "apple");
		assertNull(s);
		s = getUniqueSymbol(resultProgram, "orange");
		checkSymbol(s, "orange", true);
		assertEquals(SourceType.IMPORTED, s.getSource());
	}

}
