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
import ghidra.program.model.symbol.*;

/**
 * Test the merge of the versioned program's listing.
 */
public class SymbolMergeManager1Test extends AbstractListingMergeManagerTest {

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
	public SymbolMergeManager1Test() {
		super();
	}

	/**
	 * Test function namespace symbols being removed from either the LATEST or
	 * CHECKED OUT program when it doesn't result in a conflict.
	 * @throws Exception
	 */
	@Test
	public void testRemoveFunctionSymbolNoConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			// 01002691: primary local "AAA" scope=FUN_0100248f
			// 01003439: primary local "BBB" scope=FUN_010033f6
			// 01003e25: primary local "CCC" scope=FUN_01003bed

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symtab = program.getSymbolTable();
					symtab.removeSymbolSpecial(getScopedSymbol(program, "0x1002691", "AAA"));
					symtab.removeSymbolSpecial(getScopedSymbol(program, "0x1003e25", "CCC"));
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
					symtab.removeSymbolSpecial(getScopedSymbol(program, "0x1003439", "BBB"));
					symtab.removeSymbolSpecial(getScopedSymbol(program, "0x1003e25", "CCC"));
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
		assertNull(symtab.getPrimarySymbol(addr("0x1002691"))); // Removed AAA in LATEST
		assertNull(symtab.getPrimarySymbol(addr("0x1003439"))); // Removed BBB in MY
		assertNull(symtab.getPrimarySymbol(addr("0x1003e25"))); // Removed CCC in both
	}

	/**
	 * Test global namespace symbols being removed from either the LATEST or
	 * CHECKED OUT program when it doesn't result in a conflict.
	 * @throws Exception
	 */
	@Test
	public void testRemoveGlobalNoConflict() throws Exception {
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
					symtab.removeSymbolSpecial(getGlobalSymbol(program, "0x100e483", "AAA"));
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
					symtab.removeSymbolSpecial(getGlobalSymbol(program, "0x1004bdc", "EEE"));
					symtab.removeSymbolSpecial(getGlobalSymbol(program, "0x100e483", "AAA"));
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
		assertNull(symtab.getSymbol("DDD", addr("0x10044d0"), null)); // Removed in LATEST
		assertNull(symtab.getSymbol("EEE", addr("0x1004bdc"), null)); // Removed in MY
		assertNull(symtab.getSymbol("AAA", addr("0x100e483"), null)); // Removed in both
	}

	/**
	 * Test a conflict between a global namespace symbol being removed in
	 * one program (LATEST or CHECKED OUT) and its name changed in the other.
	 * @throws Exception
	 */
	@Test
	public void testRemoveGlobalvsChangeConflictPickLatest() throws Exception {
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
					getGlobalSymbol(program, "0x1004bdc", "EEE").setName("EEEFFF",
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
					getGlobalSymbol(program, "0x10044d0", "DDD").setName("DDDEEE",
						SourceType.USER_DEFINED);
					symtab.removeSymbolSpecial(getGlobalSymbol(program, "0x1004bdc", "EEE"));
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
		assertNull(symtab.getSymbol("DDD", addr("0x10044d0"), null));
		assertNull(symtab.getSymbol("DDDEEE", addr("0x10044d0"), null));
		assertNull(symtab.getSymbol("EEE", addr("0x1004bdc"), null));
		assertNotNull(symtab.getSymbol("EEEFFF", addr("0x1004bdc"), null));
	}

	/**
	 * Test a conflict between a global namespace symbol being removed in
	 * one program (LATEST or CHECKED OUT) and its name changed in the other.
	 * @throws Exception
	 */
	@Test
	public void testRemoveGlobalvsChangeConflictPickMy() throws Exception {
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
					getGlobalSymbol(program, "0x1004bdc", "EEE").setName("EEEFFF",
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
					getGlobalSymbol(program, "0x10044d0", "DDD").setName("DDDEEE",
						SourceType.USER_DEFINED);
					symtab.removeSymbolSpecial(getGlobalSymbol(program, "0x1004bdc", "EEE"));
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
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		assertNull(symtab.getSymbol("DDD", addr("0x10044d0"), null));
		assertNotNull(symtab.getSymbol("DDDEEE", addr("0x10044d0"), null));
		assertNull(symtab.getSymbol("EEE", addr("0x1004bdc"), null));
		assertNull(symtab.getSymbol("EEEFFF", addr("0x1004bdc"), null));
	}

	/**
	 * Test a conflict between a global namespace symbol being removed in
	 * one program (LATEST or CHECKED OUT) and its name changed in the other.
	 * @throws Exception
	 */
	@Test
	public void testRemoveGlobalvsChangeNamespacePickLatest() throws Exception {
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

					Symbol s = getGlobalSymbol(program, "0x1004bdc", "EEE");
					Namespace scope = program.getSymbolTable().getNamespace(s.getAddress());
					s.setNamespace(scope);

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

					Symbol s = getGlobalSymbol(program, "0x10044d0", "DDD");
					Namespace scope = program.getSymbolTable().getNamespace(s.getAddress());
					s.setNamespace(scope);

					symtab.removeSymbolSpecial(getGlobalSymbol(program, "0x1004bdc", "EEE"));

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
		Address addr10044d0 = addr(resultProgram, "0x10044d0");
		Address addr1004bdc = addr(resultProgram, "0x1004bdc");
		assertNull(symtab.getSymbol("DDD", addr10044d0, null));
		assertNull(symtab.getSymbol("DDD", addr10044d0, symtab.getNamespace(addr10044d0)));
		assertNull(symtab.getSymbol("EEE", addr1004bdc, null));
		assertNotNull(symtab.getSymbol("EEE", addr1004bdc, symtab.getNamespace(addr1004bdc)));
	}

	/**
	 * Test a conflict between a global namespace symbol being removed in
	 * one program (LATEST or CHECKED OUT) and its name changed in the other.
	 * @throws Exception
	 */
	@Test
	public void testRemoveGlobalvsChangeNamespacePickMy() throws Exception {
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

					Symbol s = getGlobalSymbol(program, "0x1004bdc", "EEE");
					Namespace scope = program.getSymbolTable().getNamespace(s.getAddress());
					s.setNamespace(scope);

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

					Symbol s = getGlobalSymbol(program, "0x10044d0", "DDD");
					Namespace scope = program.getSymbolTable().getNamespace(s.getAddress());
					s.setNamespace(scope);

					symtab.removeSymbolSpecial(getGlobalSymbol(program, "0x1004bdc", "EEE"));

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
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		Address addr10044d0 = addr(resultProgram, "0x10044d0");
		Address addr1004bdc = addr(resultProgram, "0x1004bdc");
		assertNull(symtab.getSymbol("DDD", addr10044d0, null));
		assertNotNull(symtab.getSymbol("DDD", addr10044d0, symtab.getNamespace(addr10044d0)));
		assertNull(symtab.getSymbol("EEE", addr1004bdc, null));
		assertNull(symtab.getSymbol("EEE", addr1004bdc, symtab.getNamespace(addr1004bdc)));
	}

	/**
	 * Test a conflict between a global namespace symbol being removed in
	 * one program (LATEST or CHECKED OUT) and its name changed in the other.
	 * @throws Exception
	 */
	@Test
	public void testRemoveVsRenameWithTransitionConflictPickRemove() throws Exception {
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
					createScopedSymbol(program, "0x10044d0", "DDD");
					createGlobalSymbol(program, "0x10044d0", "DDDEEE");

					Symbol s = getGlobalSymbol(program, "0x1004bdc", "EEE");
					Namespace scope = program.getSymbolTable().getNamespace(s.getAddress());
					s.setNamespace(scope);
					s.setName("EEEFFF", SourceType.USER_DEFINED);

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

					Symbol s = getGlobalSymbol(program, "0x10044d0", "DDD");
					Namespace scope = program.getSymbolTable().getNamespace(s.getAddress());
					s.setNamespace(scope);
					s.setName("DDDEEE", SourceType.USER_DEFINED);

					symtab.removeSymbolSpecial(getGlobalSymbol(program, "0x1004bdc", "EEE"));
					createScopedSymbol(program, "0x1004bdc", "EEE");
					createGlobalSymbol(program, "0x1004bdc", "EEEFFF");

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
		chooseRadioButton(LATEST_BUTTON); // remove or rename DDDEEE
		chooseRadioButton(MY_BUTTON); // remove or rename EEEFFF
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		Address addr10044d0 = addr(resultProgram, "0x10044d0");
		Address addr1004bdc = addr(resultProgram, "0x1004bdc");
		assertNotNull(symtab.getSymbol("DDDEEE", addr10044d0, null));
		assertNull(symtab.getSymbol("DDDEEE", addr10044d0, symtab.getNamespace(addr10044d0)));
		assertNull(
			symtab.getSymbol("DDDEEE_conflict1", addr10044d0, symtab.getNamespace(addr10044d0)));
		assertNotNull(symtab.getSymbol("EEEFFF", addr1004bdc, null));
		assertNull(symtab.getSymbol("EEEFFF", addr1004bdc, symtab.getNamespace(addr1004bdc)));
		assertNull(symtab.getSymbol("EEEFFF_conflict1", addr1004bdc, null));
	}

	/**
	 * Test a conflict between a global namespace symbol being removed in
	 * one program (LATEST or CHECKED OUT) and its name changed in the other.
	 * @throws Exception
	 */
	@Test
	public void testRemoveVsRenameWithTransitionConflictPickRename() throws Exception {
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
					createScopedSymbol(program, "0x10044d0", "DDD");
					createGlobalSymbol(program, "0x10044d0", "DDDEEE");

					Symbol s = getGlobalSymbol(program, "0x1004bdc", "EEE");
					Namespace scope = program.getSymbolTable().getNamespace(s.getAddress());
					s.setNamespace(scope);
					s.setName("EEEFFF", SourceType.USER_DEFINED);

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

					Symbol s = getGlobalSymbol(program, "0x10044d0", "DDD");
					Namespace scope = program.getSymbolTable().getNamespace(s.getAddress());
					s.setNamespace(scope);
					s.setName("DDDEEE", SourceType.USER_DEFINED);

					symtab.removeSymbolSpecial(getGlobalSymbol(program, "0x1004bdc", "EEE"));
					createScopedSymbol(program, "0x1004bdc", "EEE");
					createGlobalSymbol(program, "0x1004bdc", "EEEFFF");

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
		chooseRadioButton(MY_BUTTON); // remove or rename DDDEEE
		chooseRadioButton(LATEST_BUTTON); // remove or rename EEEFFF
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		Address addr10044d0 = addr(resultProgram, "0x10044d0");
		Address addr1004bdc = addr(resultProgram, "0x1004bdc");
		assertNotNull(symtab.getSymbol("DDDEEE", addr10044d0, null));
		assertNotNull(symtab.getSymbol("DDDEEE", addr10044d0, symtab.getNamespace(addr10044d0)));
		assertNull(
			symtab.getSymbol("DDDEEE_conflict1", addr10044d0, symtab.getNamespace(addr10044d0)));
		assertNotNull(symtab.getSymbol("EEEFFF", addr1004bdc, null));
		assertNotNull(symtab.getSymbol("EEEFFF", addr1004bdc, symtab.getNamespace(addr1004bdc)));
		assertNull(symtab.getSymbol("EEEFFF_conflict1", addr1004bdc, null));
	}

	@Test
	public void testRenameXXXToXYZAddXXX() throws Exception {
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
					SymbolTable symtab = program.getSymbolTable();
					Symbol s = getGlobalSymbol(program, "0x1002721", "XXX");
					s.setName("XYZ", SourceType.USER_DEFINED);
					assertTrue(s.isPrimary());
					symtab.createLabel(addr(program, "0x1002721"), "XXX", SourceType.USER_DEFINED);
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
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol[] symbols = symtab.getSymbols(addr("0x1002721"));
		Comparator<Symbol> c = SymbolUtilities.getSymbolNameComparator();
		Arrays.sort(symbols, c);
		assertEquals(2, symbols.length);
		checkSymbol(symbols[0], "XXX", true);
		checkSymbol(symbols[1], "XYZ", true);
		assertTrue(!symbols[0].isPrimary());
		assertTrue(symbols[1].isPrimary());
	}

	@Test
	public void testDiffRenameXXX() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Symbol s = getScopedSymbol(program, "0x1002691", "AAA");
					s.setName("A1", SourceType.USER_DEFINED);

					s = getGlobalSymbol(program, "0x1002721", "XXX");
					s.setName("Dog", SourceType.USER_DEFINED);

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
					Symbol s = getScopedSymbol(program, "0x1002691", "AAA");
					s.setName("A2", SourceType.USER_DEFINED);

					s = getGlobalSymbol(program, "0x1002721", "XXX");
					s.setName("Cat", SourceType.USER_DEFINED);

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
		Symbol[] symbols;

		symbols = symtab.getSymbols(addr("0x1002691"));
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "A1", false);
		assertTrue(symbols[0].isPrimary());

		symbols = symtab.getSymbols(addr("0x1002721"));
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "Cat", true);
		assertTrue(symbols[0].isPrimary());
	}

	@Test
	public void testRenameWithNameConflict() throws Exception {
		// Same name at different addresses in same scope.
		// 01002691: primary local "AAA" scope=FUN_0100248f
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
					SymbolTable symtab = program.getSymbolTable();
					Symbol symbol = symtab.getPrimarySymbol(addr(program, "0x1002691"));
					symbol.setName("LATEST_LOCAL", SourceType.USER_DEFINED);

					symbol = symtab.getPrimarySymbol(addr(program, "0x1002721"));
					symbol.setName("LATEST_GLOBAL", SourceType.USER_DEFINED);

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
					Symbol symbol = symtab.getPrimarySymbol(addr(program, "0x1002691"));
					symbol.setName("MY_LOCAL", SourceType.USER_DEFINED);

					symbol = symtab.getPrimarySymbol(addr(program, "0x1002721"));
					symbol.setName("MY_GLOBAL", SourceType.USER_DEFINED);

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

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol[] symbols;

		symbols = symtab.getSymbols(addr("0x1002691"));
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "MY_LOCAL", false);
		assertTrue(symbols[0].isPrimary());

		symbols = symtab.getSymbols(addr("0x1002721"));
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "LATEST_GLOBAL", true);
		assertTrue(symbols[0].isPrimary());
	}

	@Test
	public void testRenameWithNamespaceConflictPickLatest() throws Exception {
		// Same name at different addresses in same scope.
		// 01002691: primary local "AAA" scope=FUN_0100248f
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
					SymbolTable symtab = program.getSymbolTable();
					Symbol symbol = symtab.getPrimarySymbol(addr(program, "0x1002691"));
					symbol.setName("ME", SourceType.USER_DEFINED);

					symbol = symtab.getPrimarySymbol(addr(program, "0x1002721"));
					Namespace scope =
						program.getNamespaceManager().getNamespaceContaining(symbol.getAddress());
					symbol.setName("YOU", SourceType.USER_DEFINED);
					symbol.setNamespace(scope); // Change to function

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
					Symbol symbol = symtab.getPrimarySymbol(addr(program, "0x1002691"));
					symbol.setName("ME", SourceType.USER_DEFINED);
					Namespace scope = program.getNamespaceManager().getGlobalNamespace();
					symbol.setNamespace(scope); // Change to Global

					symbol = symtab.getPrimarySymbol(addr(program, "0x1002721"));
					symbol.setName("YOU", SourceType.USER_DEFINED);

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
		Symbol[] symbols;

		symbols = symtab.getSymbols(addr("0x1002691"));
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "ME", false);
		assertTrue(symbols[0].isPrimary());

		symbols = symtab.getSymbols(addr("0x1002721"));
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "YOU", false);
		assertTrue(symbols[0].isPrimary());
	}

	@Test
	public void testRenameWithNamespaceConflictPickMy() throws Exception {
		// Same name at different addresses in same scope.
		// 01002691: primary local "AAA" scope=FUN_0100248f
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
					SymbolTable symtab = program.getSymbolTable();
					Symbol symbol = symtab.getPrimarySymbol(addr(program, "0x1002691"));
					symbol.setName("ME", SourceType.USER_DEFINED);

					symbol = symtab.getPrimarySymbol(addr(program, "0x1002721"));
					Namespace scope =
						program.getNamespaceManager().getNamespaceContaining(symbol.getAddress());
					symbol.setName("YOU", SourceType.USER_DEFINED);
					symbol.setNamespace(scope); // Change to function

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
					Symbol symbol = symtab.getPrimarySymbol(addr(program, "0x1002691"));
					symbol.setName("ME", SourceType.USER_DEFINED);
					Namespace scope = program.getNamespaceManager().getGlobalNamespace();
					symbol.setNamespace(scope); // Change to Global

					symbol = symtab.getPrimarySymbol(addr(program, "0x1002721"));
					symbol.setName("YOU", SourceType.USER_DEFINED);

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
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol[] symbols;

		symbols = symtab.getSymbols(addr("0x1002691"));
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "ME", true);
		assertTrue(symbols[0].isPrimary());

		symbols = symtab.getSymbols(addr("0x1002721"));
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "YOU", true);
		assertTrue(symbols[0].isPrimary());
	}

	@Test
	public void testRenameWithTransitionConflict() throws Exception {
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
					createGlobalSymbol(program, "0x1002725", "DUDE");
					createScopedSymbol(program, "0x1002725", "XXX");
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
					Symbol symbol = symtab.getPrimarySymbol(addr(program, "0x1002721"));
					symbol.setName("DUDE", SourceType.USER_DEFINED);
					Namespace scope =
						program.getNamespaceManager().getNamespaceContaining(symbol.getAddress());
					symbol.setNamespace(scope);
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

		symbols = symtab.getSymbols(addr(resultProgram, "0x1002721"));
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "DUDE", false);
		assertTrue(symbols[0].isPrimary());
	}

	private void setupRemoveSymbolUseForAll() throws Exception {
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
					getGlobalSymbol(program, "0x1004bdc", "EEE").setName("EEEFFF",
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
					getGlobalSymbol(program, "0x10044d0", "DDD").setName("DDDEEE",
						SourceType.USER_DEFINED);
					symtab.removeSymbolSpecial(getGlobalSymbol(program, "0x1004bdc", "EEE"));
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
	}

	/**
	 * Test a conflict between a global namespace symbol being removed in
	 * one program (LATEST or CHECKED OUT) and its name changed in the other with
	 * the UseForAll box not checked.
	 * @throws Exception
	 */
	@Test
	public void testRemoveConflictDontUseForAll() throws Exception {
		setupRemoveSymbolUseForAll();

		executeMerge(ASK_USER);
		chooseSymbol("0x10044d0", KEEP_LATEST, false);
		chooseSymbol("0x1004bdc", KEEP_MY, false);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		assertNull(symtab.getSymbol("DDD", addr("0x10044d0"), null));
		assertNull(symtab.getSymbol("DDDEEE", addr("0x10044d0"), null));
		assertNull(symtab.getSymbol("EEE", addr("0x1004bdc"), null));
		assertNull(symtab.getSymbol("EEEFFF", addr("0x1004bdc"), null));
	}

	@Test
	public void testRemoveConflictUseForAllPickLatest() throws Exception {
		setupRemoveSymbolUseForAll();

		executeMerge(ASK_USER);
		chooseSymbol("0x10044d0", KEEP_LATEST, true);
//		chooseSymbol("0x1004bdc", KEEP_LATEST, false);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		assertNull(symtab.getSymbol("DDD", addr("0x10044d0"), null));
		assertNull(symtab.getSymbol("DDDEEE", addr("0x10044d0"), null));
		assertNull(symtab.getSymbol("EEE", addr("0x1004bdc"), null));
		assertNotNull(symtab.getSymbol("EEEFFF", addr("0x1004bdc"), null));
	}

	@Test
	public void testRemoveConflictUseForAllPickMy() throws Exception {
		setupRemoveSymbolUseForAll();

		executeMerge(ASK_USER);
		chooseSymbol("0x10044d0", KEEP_MY, true);
//		chooseSymbol("0x1004bdc", KEEP_MY, false);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		assertNull(symtab.getSymbol("DDD", addr("0x10044d0"), null));
		assertNotNull(symtab.getSymbol("DDDEEE", addr("0x10044d0"), null));
		assertNull(symtab.getSymbol("EEE", addr("0x1004bdc"), null));
		assertNull(symtab.getSymbol("EEEFFF", addr("0x1004bdc"), null));
	}

	private void setupRenameConflictUseForAll() throws Exception {
		// Same name at different addresses in same scope.
		// 01002691: primary local "AAA" scope=FUN_0100248f
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
					SymbolTable symtab = program.getSymbolTable();
					Symbol symbol = symtab.getPrimarySymbol(addr(program, "0x1002691"));
					symbol.setName("LATEST_LOCAL", SourceType.USER_DEFINED);

					symbol = symtab.getPrimarySymbol(addr(program, "0x1002721"));
					symbol.setName("LATEST_GLOBAL", SourceType.USER_DEFINED);

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
					Symbol symbol = symtab.getPrimarySymbol(addr(program, "0x1002691"));
					symbol.setName("MY_LOCAL", SourceType.USER_DEFINED);

					symbol = symtab.getPrimarySymbol(addr(program, "0x1002721"));
					symbol.setName("MY_GLOBAL", SourceType.USER_DEFINED);

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
	}

	@Test
	public void testRenameConflictDontUseForAll() throws Exception {
		setupRenameConflictUseForAll();

		executeMerge(ASK_USER);
		chooseSymbol("0x1002691", KEEP_MY, false);
		chooseSymbol("0x1002721", KEEP_LATEST, false);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol[] symbols;

		symbols = symtab.getSymbols(addr("0x1002691"));
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "MY_LOCAL", false);
		assertTrue(symbols[0].isPrimary());

		symbols = symtab.getSymbols(addr("0x1002721"));
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "LATEST_GLOBAL", true);
		assertTrue(symbols[0].isPrimary());
	}

	@Test
	public void testRenameConflictUseForAllPickLatest() throws Exception {
		setupRenameConflictUseForAll();

		executeMerge(ASK_USER);
		chooseSymbol("0x1002691", KEEP_LATEST, true);
//		chooseSymbol("0x1002721", KEEP_LATEST, false);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol[] symbols;

		symbols = symtab.getSymbols(addr("0x1002691"));
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "LATEST_LOCAL", false);
		assertTrue(symbols[0].isPrimary());

		symbols = symtab.getSymbols(addr("0x1002721"));
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "LATEST_GLOBAL", true);
		assertTrue(symbols[0].isPrimary());
	}

	@Test
	public void testRenameConflictUseForAllPickMy() throws Exception {
		setupRenameConflictUseForAll();

		executeMerge(ASK_USER);
		chooseSymbol("0x1002691", KEEP_MY, true);
//		chooseSymbol("0x1002721", KEEP_MY, false);
		waitForMergeCompletion();

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol[] symbols;

		symbols = symtab.getSymbols(addr("0x1002691"));
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "MY_LOCAL", false);
		assertTrue(symbols[0].isPrimary());

		symbols = symtab.getSymbols(addr("0x1002721"));
		assertEquals(1, symbols.length);
		checkSymbol(symbols[0], "MY_GLOBAL", true);
		assertTrue(symbols[0].isPrimary());
	}
}
