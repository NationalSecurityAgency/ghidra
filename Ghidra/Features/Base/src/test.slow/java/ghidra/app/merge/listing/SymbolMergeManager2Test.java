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

import java.util.Arrays;
import java.util.Comparator;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.*;

/**
 * Test the merge of the versioned program's listing.
 */
public class SymbolMergeManager2Test extends AbstractListingMergeManagerTest {

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
	public SymbolMergeManager2Test() {
		super();
	}

	@Test
	public void testAddFunctionSymbolNoConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createScopedSymbol(program, "0x1001b97", "FOO");
					createScopedSymbol(program, "0x10032a7", "FRED");
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
					createScopedSymbol(program, "0x10028eb", "BAR");
					createScopedSymbol(program, "0x10032a7", "FRED");
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
		Symbol symbol;
		symbol = symtab.getPrimarySymbol(addr("0x1001b97"));
		checkSymbol(symbol, "FOO", false); // Added in LATEST

		symbol = symtab.getPrimarySymbol(addr("0x10028eb"));
		checkSymbol(symbol, "BAR", false); // Added in MY

		symbol = symtab.getPrimarySymbol(addr("0x10032a7"));
		checkSymbol(symbol, "FRED", false); // Added in both
	}

	@Test
	public void testAddGlobalNoConflict() throws Exception {
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
					SymbolTable symtab = program.getSymbolTable();
					symtab.createLabel(addr(program, "0x1001b97"), "FOO", SourceType.USER_DEFINED);
					symtab.createLabel(addr(program, "0x10032a7"), "FRED", SourceType.USER_DEFINED);
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
					symtab.createLabel(addr(program, "0x10028eb"), "BAR", SourceType.USER_DEFINED);
					symtab.createLabel(addr(program, "0x10032a7"), "FRED", SourceType.USER_DEFINED);
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
		Symbol symbol;
		symbol = symtab.getPrimarySymbol(addr("0x1001b97"));
		checkSymbol(symbol, "FOO", true); // Added in LATEST

		symbol = symtab.getPrimarySymbol(addr("0x10028eb"));
		checkSymbol(symbol, "BAR", true); // Added in MY

		symbol = symtab.getPrimarySymbol(addr("0x10032a7"));
		checkSymbol(symbol, "FRED", true); // Added in both
	}

	@Test
	public void testRemoveGlobalvsPrimaryNoConflict() throws Exception {
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
					SymbolTable symtab = program.getSymbolTable();
					symtab.removeSymbolSpecial(getGlobalSymbol(program, "0x10044d0", "DDD"));
					getGlobalSymbol(program, "0x1003075", "ZZZ").setPrimary();
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
					getScopedSymbol(program, "0x10044d0", "DDD6").setPrimary();
					symtab.removeSymbolSpecial(getGlobalSymbol(program, "0x1003075", "QQQ"));
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		assertNull(symtab.getSymbol("QQQ", addr("0x1003075"), null));
		assertNull(symtab.getSymbol("DDD", addr("0x10044d0"), null));
		assertNotNull(symtab.getSymbol("ZZZ", addr("0x1003075"), null));
		assertNotNull(
			symtab.getSymbol("DDD6", addr("0x10044d0"), symtab.getNamespace(addr("0x10044d0"))));
	}

	@Test
	public void testRemoveGlobalvsPrimaryPickLatest() throws Exception {
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
					SymbolTable symtab = program.getSymbolTable();
					symtab.removeSymbolSpecial(getGlobalSymbol(program, "0x1004bdc", "EEE"));
					getGlobalSymbol(program, "0x1003075", "QQQ").setPrimary();
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
					getGlobalSymbol(program, "0x1004bdc", "EEE").setPrimary();
					symtab.removeSymbolSpecial(getGlobalSymbol(program, "0x1003075", "QQQ"));
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
//		chooseOption("Symbol", "0x1003075", KEEP_LATEST);
//		chooseOption("Symbol", "0x1004bdc", KEEP_LATEST);
		chooseRadioButton(LATEST_BUTTON);
		chooseRadioButton(LATEST_BUTTON);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol s = symtab.getSymbol("QQQ", addr("0x1003075"), null);
		assertNotNull(s);
		assertTrue(s.isPrimary());
		assertNull(symtab.getSymbol("EEE", addr("0x1004bdc"), null));
	}

	@Test
	public void testRemoveGlobalvsPrimaryPickMy() throws Exception {
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
					SymbolTable symtab = program.getSymbolTable();
					symtab.removeSymbolSpecial(getGlobalSymbol(program, "0x1004bdc", "EEE"));
					getGlobalSymbol(program, "0x1003075", "QQQ").setPrimary();
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
					getGlobalSymbol(program, "0x1004bdc", "EEE").setPrimary();
					symtab.removeSymbolSpecial(getGlobalSymbol(program, "0x1003075", "QQQ"));
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
//		chooseOption("Symbol", "0x1003075", KEEP_MY);
//		chooseOption("Symbol", "0x1004bdc", KEEP_MY);
		chooseRadioButton(MY_BUTTON);
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		assertNull(symtab.getSymbol("QQQ", addr("0x1003075"), null));
		Symbol s = symtab.getSymbol("EEE", addr("0x1004bdc"), null);

		assertNotNull(s);
		assertTrue(s.isPrimary());
	}

	@Test
	public void testAddSameNoConflict() throws Exception {
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
					symtab.createLabel(addr(program, "0x10032a7"), "Foo", SourceType.USER_DEFINED);
					createScopedSymbol(program, "0x1004bf4", "Foo");
					symtab.createLabel(addr(program, "0x1005c2f"), "Fred", SourceType.USER_DEFINED);
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
					symtab.createLabel(addr(program, "0x10032a7"), "Foo", SourceType.USER_DEFINED);
					createScopedSymbol(program, "0x1004bf4", "Foo");
					symtab.createLabel(addr(program, "0x1005c2f"), "Fred", SourceType.USER_DEFINED);
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

		Symbol[] symbols = symtab.getSymbols(addr("0x10032a7"));
		sort(symbols);
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "Foo", true); // Both added global Foo

		symbols = symtab.getSymbols(addr("0x1004bf4"));
		sort(symbols);
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "Foo", false); // Both added local Foo

		symbols = symtab.getSymbols(addr("0x1005c2f"));
		sort(symbols);
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "Fred", true); // Both added global Fred
	}

	@Test
	public void testAddDiffNoConflict() throws Exception {
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
					symtab.createLabel(addr(program, "0x1001bde"), "Prime",
						SourceType.USER_DEFINED);
					createScopedSymbol(program, "0x1001bde", "Foo");
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
					symtab.createLabel(addr(program, "0x1001bde"), "Prime",
						SourceType.USER_DEFINED);
					symtab.createLabel(addr(program, "0x1001bde"), "Bar", SourceType.USER_DEFINED);
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

		Symbol[] symbols = symtab.getSymbols(addr("0x1001bde"));
		sort(symbols);
		assertEquals(3, symbols.length);
		checkSymbol(symbols[0], "Bar", true);
		checkSymbol(symbols[1], "Foo", false);
		checkSymbol(symbols[2], "Prime", true);
	}

	@Test
	public void testAddDiffPrimaryConflictsChooseMy() throws Exception {
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
					symtab.createLabel(addr(program, "0x10032a7"), "Foo", SourceType.USER_DEFINED);
					createScopedSymbol(program, "0x1004bf4", "Bud");
					symtab.createLabel(addr(program, "0x1005c2f"), "Fred", SourceType.USER_DEFINED);
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
					symtab.createLabel(addr(program, "0x10032a7"), "Bar", SourceType.USER_DEFINED);
					symtab.createLabel(addr(program, "0x1004bf4"), "Bud", SourceType.USER_DEFINED);
					createScopedSymbol(program, "0x1005c2f", "Fred");
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
		chooseRadioButton(MY_BUTTON); // rename has now caused a primary conflict.
		chooseRadioButton(MY_BUTTON); // rename has now caused a primary conflict.
		chooseRadioButton(MY_BUTTON); // rename has now caused a primary conflict.
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();

		Symbol[] symbols = symtab.getSymbols(addr("0x10032a7"));
		sort(symbols);
		assertEquals(2, symbols.length);
		checkSymbol(symbols[0], "Bar", true);
		checkSymbol(symbols[1], "Foo", true);
		assertTrue(symbols[0].isPrimary());

		symbols = symtab.getSymbols(addr("0x1004bf4"));
		sort(symbols);
		assertEquals(2, symbols.length);
		checkSymbol(symbols[1], "Bud", false); // Both added local Foo

		symbols = symtab.getSymbols(addr("0x1005c2f"));
		sort(symbols);
		assertEquals(2, symbols.length);
		checkSymbol(symbols[1], "Fred", true); // Both added global Fred
	}

	@Test
	public void testAddDiffPrimaryConflictsChooseLatest() throws Exception {
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
					symtab.createLabel(addr(program, "0x10032a7"), "Foo", SourceType.USER_DEFINED);
					createScopedSymbol(program, "0x1004bf4", "Bud");
					symtab.createLabel(addr(program, "0x1005c2f"), "Fred", SourceType.USER_DEFINED);
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
					symtab.createLabel(addr(program, "0x10032a7"), "Bar", SourceType.USER_DEFINED);
					symtab.createLabel(addr(program, "0x1004bf4"), "Bud", SourceType.USER_DEFINED);
					createScopedSymbol(program, "0x1005c2f", "Fred");
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
		chooseRadioButton(LATEST_BUTTON); // pick latest as primary
		chooseRadioButton(LATEST_BUTTON); // pick latest as primary
		chooseRadioButton(LATEST_BUTTON); // pick latest as primary
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();

		Symbol[] symbols = symtab.getSymbols(addr("0x10032a7"));
		sort(symbols);
		assertEquals(2, symbols.length);
		checkSymbol(symbols[0], "Bar", true);
		checkSymbol(symbols[1], "Foo", true);
		assertTrue(symbols[1].isPrimary());

		symbols = symtab.getSymbols(addr("0x1004bf4"));
		sort(symbols);
		assertEquals(2, symbols.length);
		checkSymbol(symbols[0], "Bud", false);
		checkSymbol(symbols[1], "Bud", true);
		assertTrue(symbols[0].isPrimary());

		symbols = symtab.getSymbols(addr("0x1005c2f"));
		sort(symbols);
		assertEquals(2, symbols.length);
		checkSymbol(symbols[0], "Fred", true);
		checkSymbol(symbols[1], "Fred", false);
		assertTrue(symbols[0].isPrimary());
	}

	@Test
	public void testAddDiffPrimarySymbolsWithoutConflict() throws Exception {
		mtf.initialize("notepad3", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {

				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Address addr01002f01 = addr(program, "0x01002f01");
					AddressSet addressSet =
						new AddressSet(addr01002f01, addr(program, "0x010030c5"));

					FunctionManager functionManager = program.getFunctionManager();
					assertNull(functionManager.getFunctionAt(addr01002f01));

					disassemble(program, addressSet, true);

					assertNull(functionManager.getFunctionAt(addr01002f01));
					createFunction(program, "0x01002f01",
						SymbolUtilities.getDefaultFunctionName(addr01002f01), addressSet);
					assertNotNull(functionManager.getFunctionAt(addr01002f01));

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
					symtab.createLabel(addr(program, "0x01002f01"), "Bar", SourceType.USER_DEFINED);

					Address addr01002f01 = addr(program, "0x01002f01");
					FunctionManager functionManager = program.getFunctionManager();
					assertNull(functionManager.getFunctionAt(addr01002f01));

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

		Symbol[] symbols = symtab.getSymbols(addr("0x01002f01"));
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "Bar", true);
		assertTrue(symbols[0].isPrimary());
		assertEquals(SymbolType.FUNCTION, symbols[0].getSymbolType());
		assertEquals(SourceType.USER_DEFINED, symbols[0].getSource());
	}

//	public void testAddressConflict() throws Exception {
//		// Function is 1001ae3-1002199
//		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyLatest(ProgramDB program) {
//				int txId = program.startTransaction("Modify Latest Program");
//				boolean commit = false;
//				try {
//					createScopedSymbol(program, "0x1001b97", "FOO");
//					commit = true;
//				} catch (DuplicateNameException e) {
//					e.printStackTrace();
//				} catch (InvalidInputException e) {
//					e.printStackTrace();
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
//					createScopedSymbol(program, "0x1001b9d", "FOO");
//					commit = true;
//				} catch (DuplicateNameException e) {
//					e.printStackTrace();
//				} catch (InvalidInputException e) {
//					e.printStackTrace();
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//		});
//
//		executeMerge(ASK_USER);
////		chooseScopedSymbol();
//		waitWhileFocusWindow("Merge Programs", 5000);
//
//		SymbolTable symtab = resultProgram.getSymbolTable();
//		Symbol symbol;
//		symbol = symtab.getPrimarySymbol(addr("0x1001b97"));
//		checkSymbol(symbol, "FOO", false);
//
//		symbol = symtab.getPrimarySymbol(addr("0x1001b9d"));
//		checkSymbol(symbol, "FOO.1", false);
//	}

//	public void testAddressConflict() throws Exception {
//		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyLatest(ProgramDB program) {
//				int txId = program.startTransaction("Modify Latest Program");
//				boolean commit = false;
//				try {
//					createGlobalSymbol(program, "0x1001b97", "FOO");
//					commit = true;
//				} catch (DuplicateNameException e) {
//					e.printStackTrace();
//				} catch (InvalidInputException e) {
//					e.printStackTrace();
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
//					createScopedSymbol(program, "0x1001b97", "FOO");
//					commit = true;
//				} catch (DuplicateNameException e) {
//					e.printStackTrace();
//				} catch (InvalidInputException e) {
//					e.printStackTrace();
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//		});
//
//		executeMerge(ASK_USER);
////		chooseScopedSymbol();
//		waitWhileFocusWindow("Merge Programs", 5000);
//
//		SymbolTable symtab = resultProgram.getSymbolTable();
//		Symbol symbol;
//		symbol = symtab.getPrimarySymbol(addr("0x1001b97"));
//		checkSymbol(symbol, "FOO", true);
//
//		symbol = symtab.getPrimarySymbol(addr("0x1001b97"));
//		checkSymbol(symbol, "FOO.1", false);
//	}

	@Test
	public void testGlobalScopeConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createGlobalSymbol(program, "0x1001b97", "FOO");
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
					createGlobalSymbol(program, "0x1001ba5", "FOO");
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
		Symbol symbol;
		symbol = symtab.getPrimarySymbol(addr("0x1001b97"));
		checkSymbol(symbol, "FOO", true);

		symbol = symtab.getPrimarySymbol(addr("0x1001ba5"));
		checkSymbol(symbol, "FOO", true);
	}

	@Test
	public void testSameNameNoConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createGlobalSymbol(program, "0x1001b97", "FOO");
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
					createScopedSymbol(program, "0x1001b9d", "FOO");
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
		Symbol symbol;
		symbol = symtab.getPrimarySymbol(addr("0x1001b97"));
		checkSymbol(symbol, "FOO", true);

		symbol = symtab.getPrimarySymbol(addr("0x1001b9d"));
		checkSymbol(symbol, "FOO", false);
	}

	@Test
	public void testOppositesConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createGlobalSymbol(program, "0x1001b97", "FOO");
					createScopedSymbol(program, "0x1001b9d", "BAR");
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
					createGlobalSymbol(program, "0x1001b97", "BAR");
					createScopedSymbol(program, "0x1001b9d", "FOO");
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
		chooseRadioButton(LATEST_BUTTON);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol symbol;
		symbol = symtab.getPrimarySymbol(addr("0x1001b97"));
		checkSymbol(symbol, "FOO", true);

		symbol = symtab.getPrimarySymbol(addr("0x1001b9d"));
		checkSymbol(symbol, "BAR", false);
	}

	@Test
	public void testScopeConflictRenameMy() throws Exception {
		// Same name at different addresses in same scope.
		// ME is conflict in global namespace
		// YOU is conflict in function namespace
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createGlobalSymbol(program, "0x1001000", "ME");
					createScopedSymbol(program, "0x1001b97", "YOU");
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
					createGlobalSymbol(program, "0x1001b9d", "ME");
					createScopedSymbol(program, "0x1001b9d", "YOU");
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
		Symbol[] symbols;

		symbols = symtab.getSymbols(addr("0x1001000"));
		assertEquals(2, symbols.length);
		checkSymbol(symbols[0], "ADVAPI32.DLL::IsTextUnicode", true);
		assertTrue(symbols[0].isPrimary());
		checkSymbol(symbols[1], "ME", true);
		assertTrue(!symbols[1].isPrimary());

		symbols = symtab.getSymbols(addr("0x1001b97"));
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "YOU", false);
		assertTrue(symbols[0].isPrimary());

		symbols = symtab.getSymbols(addr("0x1001b9d"));
		assertEquals(2, symbols.length);
		checkSymbol(symbols[0], "ME", true);
		assertTrue(symbols[0].isPrimary());
		checkSymbol(symbols[1], "YOU", false);
		assertTrue(!symbols[1].isPrimary());
	}

	@Test
	public void testAddDiffPrimary() throws Exception {
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
					Symbol s;
					s = createScopedSymbol(program, "0x1002691", "Jack");
					s.setPrimary();
					assertTrue(s.isPrimary());

					s = createGlobalSymbol(program, "0x10032a7", "Lucy");
					s.setPrimary();
					assertTrue(s.isPrimary());

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
					Symbol s;
					s = createScopedSymbol(program, "0x1002691", "Jill");
					s.setPrimary();
					assertTrue(s.isPrimary());

					s = createGlobalSymbol(program, "0x10032a7", "Linus");
					s.setPrimary();
					assertTrue(s.isPrimary());

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
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol s;
		s = symtab.getPrimarySymbol(addr("0x1002691"));
		checkSymbol(s, "Jack", false);
		assertTrue(s.isPrimary());

		s = symtab.getPrimarySymbol(addr("0x10032a7"));
		checkSymbol(s, "Linus", true);
		assertTrue(s.isPrimary());
	}

	private void sort(Symbol[] s) {
		Comparator<Symbol> c = SymbolUtilities.getSymbolNameComparator();
		Arrays.sort(s, c);
	}
}
