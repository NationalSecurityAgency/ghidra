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

import static org.junit.Assert.assertEquals;

import org.junit.Assert;
import org.junit.Test;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.*;

/**
 * Test the merge of the versioned program's listing.
 */
public class SymbolMergeManagerFunctionSourceTest extends AbstractListingMergeManagerTest {

	// *** NotepadMergeListingTest ***
	// 010018a0: FUN_010018a0() 1 reg local
	// 0100194b: FirstNamespace::FUN_0100194b() no vars
	// 0100219c: FUN_0100219c() no vars
	// 01002950: FUN_01002950() 1 param, 1 reg local
	// 0100415a: FUN_0100415a() 3 params, 3 locals
	// 010041a8: FUN_010041a8() 5 params
	// 010041fc: FUN_010041fc() 6 locals
	// 01006420: entry()

	// *** NotepadMergeListingTest ***
	// 01002239: noFunction will become FUN_01002239() 1 param, 2 locals
	// 010033f6: noFunction will become FUN_010033f6() 1 param
	// 010063b4: noFunction will become FUN_010063b4() 2 params, 2 locals

	/**
	 *
	 * @param arg0
	 */
	public SymbolMergeManagerFunctionSourceTest() {
		super();
	}

	@Test
	public void testChangeFunctionNameSourceSameInBoth() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Address entry = addr(program, "0x0100219c");
					Function f = program.getFunctionManager().getFunctionAt(entry);
					f.setName("printf", SourceType.ANALYSIS);
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
					Address entry = addr(program, "0x0100219c");
					Function f = program.getFunctionManager().getFunctionAt(entry);
					f.setName("printf", SourceType.ANALYSIS);
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

		Address entry = addr(resultProgram, "0x0100219c");
		FunctionManager fm = resultProgram.getFunctionManager();
		Function f = fm.getFunctionAt(entry);
		assertEquals("printf", f.getName());
		Symbol fs = f.getSymbol();
		assertEquals("printf", fs.getName());
		assertEquals(SourceType.ANALYSIS, fs.getSource());

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol s = symtab.getGlobalSymbol("printf", entry);
		assertEquals(SourceType.ANALYSIS, s.getSource());
		assertEquals(fs, s);
	}

	@Test
	public void testChangeFunctionNameSourceDiffInBoth() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Address entry = addr(program, "0x0100219c");
					Function f = program.getFunctionManager().getFunctionAt(entry);
					f.setName("printf", SourceType.ANALYSIS);
					entry = addr(program, "0x0100415a");
					f = program.getFunctionManager().getFunctionAt(entry);
					f.setName("Fred", SourceType.ANALYSIS);
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
					Address entry = addr(program, "0x0100219c");
					Function f = program.getFunctionManager().getFunctionAt(entry);
					f.setName("scanf", SourceType.IMPORTED);
					entry = addr(program, "0x0100415a");
					f = program.getFunctionManager().getFunctionAt(entry);
					f.setName("Barney", SourceType.IMPORTED);
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
		chooseVariousOptions("0x100219c", new int[] { INFO_ROW, KEEP_LATEST });
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_MY });
		waitForMergeCompletion();

		FunctionManager fm = resultProgram.getFunctionManager();
		SymbolTable symtab = resultProgram.getSymbolTable();

		Address entry = addr(resultProgram, "0x0100219c");
		Function f = fm.getFunctionAt(entry);
		assertEquals("printf", f.getName());
		Symbol fs = f.getSymbol();
		assertEquals("printf", fs.getName());
		assertEquals(SourceType.ANALYSIS, fs.getSource());
		Symbol s = symtab.getGlobalSymbol("printf", entry);
		assertEquals(SourceType.ANALYSIS, s.getSource());
		assertEquals(fs, s);

		entry = addr(resultProgram, "0x0100415a");
		f = fm.getFunctionAt(entry);
		assertEquals("Barney", f.getName());
		fs = f.getSymbol();
		assertEquals("Barney", fs.getName());
		assertEquals(SourceType.IMPORTED, fs.getSource());
		s = symtab.getGlobalSymbol("Barney", entry);
		assertEquals(SourceType.IMPORTED, s.getSource());
		assertEquals(fs, s);
	}

	@Test
	public void testChangeFunctionSourceSame() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Address entry = addr(program, "0x01006420");
					Function f = program.getFunctionManager().getFunctionAt(entry);
					f.getSymbol().setSource(SourceType.ANALYSIS);
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
					Address entry = addr(program, "0x01006420");
					Function f = program.getFunctionManager().getFunctionAt(entry);
					f.getSymbol().setSource(SourceType.ANALYSIS);
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

		Address entry = addr(resultProgram, "0x01006420");
		FunctionManager fm = resultProgram.getFunctionManager();
		Function f = fm.getFunctionAt(entry);
		assertEquals("entry", f.getName());
		Symbol fs = f.getSymbol();
		assertEquals("entry", fs.getName());
		assertEquals(SourceType.ANALYSIS, fs.getSource());

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol s = symtab.getGlobalSymbol("entry", entry);
		assertEquals(SourceType.ANALYSIS, s.getSource());
		assertEquals(fs, s);
	}

	@Test
	public void testChangeFunctionSourceDiff() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Address entry = addr(program, "0x01006420");
					Function f = program.getFunctionManager().getFunctionAt(entry);
					f.getSymbol().setSource(SourceType.IMPORTED);
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
					Address entry = addr(program, "0x01006420");
					Function f = program.getFunctionManager().getFunctionAt(entry);
					f.getSymbol().setSource(SourceType.ANALYSIS);
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

		Address entry = addr(resultProgram, "0x01006420");
		FunctionManager fm = resultProgram.getFunctionManager();
		Function f = fm.getFunctionAt(entry);
		assertEquals("entry", f.getName());
		Symbol fs = f.getSymbol();
		assertEquals("entry", fs.getName());
		assertEquals(SourceType.IMPORTED, fs.getSource());

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol s = symtab.getGlobalSymbol("entry", entry);
		assertEquals(SourceType.IMPORTED, s.getSource());
		assertEquals(fs, s);
	}

	@Test
	public void testChangeFunctionSourceOnlyInLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Address entry = addr(program, "0x01006420");
					Function f = program.getFunctionManager().getFunctionAt(entry);
					f.getSymbol().setSource(SourceType.ANALYSIS);
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

		Address entry = addr(resultProgram, "0x01006420");
		FunctionManager fm = resultProgram.getFunctionManager();
		Function f = fm.getFunctionAt(entry);
		assertEquals("entry", f.getName());
		Symbol fs = f.getSymbol();
		assertEquals("entry", fs.getName());
		assertEquals(SourceType.ANALYSIS, fs.getSource());

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol s = symtab.getGlobalSymbol("entry", entry);
		assertEquals(SourceType.ANALYSIS, s.getSource());
		assertEquals(fs, s);
	}

	@Test
	public void testChangeFunctionSourceOnlyInMy() throws Exception {

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
					Address entry = addr(program, "0x01006420");
					Function f = program.getFunctionManager().getFunctionAt(entry);
					f.getSymbol().setSource(SourceType.IMPORTED);
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

		Address entry = addr(resultProgram, "0x01006420");
		FunctionManager fm = resultProgram.getFunctionManager();
		Function f = fm.getFunctionAt(entry);
		assertEquals("entry", f.getName());
		Symbol fs = f.getSymbol();
		assertEquals("entry", fs.getName());
		assertEquals(SourceType.IMPORTED, fs.getSource());

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol s = symtab.getGlobalSymbol("entry", entry);
		assertEquals(SourceType.IMPORTED, s.getSource());
		assertEquals(fs, s);
	}

	@Test
	public void testAddFunctionNameSourceSameInBoth() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Address entry = addr(program, "0x01002239");
					CreateFunctionCmd cmd =
						new CreateFunctionCmd("FunctionOne", entry, null, SourceType.ANALYSIS);
					cmd.applyTo(program);
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
					Address entry = addr(program, "0x01002239");
					CreateFunctionCmd cmd =
						new CreateFunctionCmd("FunctionOne", entry, null, SourceType.ANALYSIS);
					cmd.applyTo(program);
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

		Address entry = addr(resultProgram, "0x01002239");
		FunctionManager fm = resultProgram.getFunctionManager();
		Function f = fm.getFunctionAt(entry);
		assertEquals("FunctionOne", f.getName());
		Symbol fs = f.getSymbol();
		assertEquals("FunctionOne", fs.getName());
		assertEquals(SourceType.ANALYSIS, fs.getSource());

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol s = symtab.getGlobalSymbol("FunctionOne", entry);
		assertEquals(SourceType.ANALYSIS, s.getSource());
		assertEquals(fs, s);
	}

	@Test
	public void testAddFunctionNameSourceDiffInBoth() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Address entry = addr(program, "0x01002239");
					CreateFunctionCmd cmd =
						new CreateFunctionCmd("FunctionOne", entry, null, SourceType.ANALYSIS);
					cmd.applyTo(program);

					entry = addr(program, "0x010033f6");
					cmd = new CreateFunctionCmd("Barney", entry, null, SourceType.IMPORTED);
					cmd.applyTo(program);

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
					Address entry = addr(program, "0x01002239");
					CreateFunctionCmd cmd =
						new CreateFunctionCmd("FunctionOne", entry, null, SourceType.IMPORTED);
					cmd.applyTo(program);

					entry = addr(program, "0x010033f6");
					cmd = new CreateFunctionCmd("Barney", entry, null, SourceType.ANALYSIS);
					cmd.applyTo(program);

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
		SymbolTable symtab = resultProgram.getSymbolTable();

		Address entry = addr(resultProgram, "0x01002239");
		Function f = fm.getFunctionAt(entry);
		assertEquals("FunctionOne", f.getName());
		Symbol fs = f.getSymbol();
		assertEquals("FunctionOne", fs.getName());
		assertEquals(SourceType.ANALYSIS, fs.getSource());
		Symbol s = symtab.getGlobalSymbol("FunctionOne", entry);
		assertEquals(SourceType.ANALYSIS, s.getSource());
		assertEquals(fs, s);

		entry = addr(resultProgram, "0x010033f6");
		f = fm.getFunctionAt(entry);
		assertEquals("Barney", f.getName());
		fs = f.getSymbol();
		assertEquals("Barney", fs.getName());
		assertEquals(SourceType.IMPORTED, fs.getSource());
		s = symtab.getGlobalSymbol("Barney", entry);
		assertEquals(SourceType.IMPORTED, s.getSource());
		assertEquals(fs, s);
	}

	@Test
	public void testAddFunctionSourceSame() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Address entry = addr(program, "0x010063b4");
					CreateFunctionCmd cmd =
						new CreateFunctionCmd("FUNCTION63b4", entry, null, SourceType.ANALYSIS);
					cmd.applyTo(program);
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
					Address entry = addr(program, "0x010063b4");
					CreateFunctionCmd cmd =
						new CreateFunctionCmd("FUNCTION63b4", entry, null, SourceType.ANALYSIS);
					cmd.applyTo(program);
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

		Address entry = addr(resultProgram, "0x010063b4");
		FunctionManager fm = resultProgram.getFunctionManager();
		Function f = fm.getFunctionAt(entry);
		assertEquals("FUNCTION63b4", f.getName());
		Symbol fs = f.getSymbol();
		assertEquals("FUNCTION63b4", fs.getName());
		assertEquals(SourceType.ANALYSIS, fs.getSource());

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol s = symtab.getGlobalSymbol("FUNCTION63b4", entry);
		assertEquals(SourceType.ANALYSIS, s.getSource());
		assertEquals(fs, s);
	}

	@Test
	public void testAddFunctionSourceDiff() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Address entry = addr(program, "0x010063b4");
					CreateFunctionCmd cmd =
						new CreateFunctionCmd("FUNCTION63b4", entry, null, SourceType.IMPORTED);
					cmd.applyTo(program);
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
					Address entry = addr(program, "0x010063b4");
					CreateFunctionCmd cmd =
						new CreateFunctionCmd("FUNCTION63b4", entry, null, SourceType.ANALYSIS);
					cmd.applyTo(program);
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

		Address entry = addr(resultProgram, "0x010063b4");
		FunctionManager fm = resultProgram.getFunctionManager();
		Function f = fm.getFunctionAt(entry);
		assertEquals("FUNCTION63b4", f.getName());
		Symbol fs = f.getSymbol();
		assertEquals("FUNCTION63b4", fs.getName());
		assertEquals(SourceType.IMPORTED, fs.getSource());

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol s = symtab.getGlobalSymbol("FUNCTION63b4", entry);
		assertEquals(SourceType.IMPORTED, s.getSource());
		assertEquals(fs, s);
	}

	@Test
	public void testAddFunctionSourceOnlyInLatest() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Address entry = addr(program, "0x010063b4");
					CreateFunctionCmd cmd =
						new CreateFunctionCmd("FUNCTION63b4", entry, null, SourceType.ANALYSIS);
					cmd.applyTo(program);
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
				// No changes to My program.
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Address entry = addr(resultProgram, "0x010063b4");
		FunctionManager fm = resultProgram.getFunctionManager();
		Function f = fm.getFunctionAt(entry);
		assertEquals("FUNCTION63b4", f.getName());
		Symbol fs = f.getSymbol();
		assertEquals("FUNCTION63b4", fs.getName());
		assertEquals(SourceType.ANALYSIS, fs.getSource());

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol s = symtab.getGlobalSymbol("FUNCTION63b4", entry);
		assertEquals(SourceType.ANALYSIS, s.getSource());
		assertEquals(fs, s);
	}

	@Test
	public void testAddFunctionSourceOnlyInMy() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes to Latest program.
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Address entry = addr(program, "0x010063b4");
					CreateFunctionCmd cmd =
						new CreateFunctionCmd("FUNCTION63b4", entry, null, SourceType.IMPORTED);
					cmd.applyTo(program);
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

		Address entry = addr(resultProgram, "0x010063b4");
		FunctionManager fm = resultProgram.getFunctionManager();
		Function f = fm.getFunctionAt(entry);
		assertEquals("FUNCTION63b4", f.getName());
		Symbol fs = f.getSymbol();
		assertEquals("FUNCTION63b4", fs.getName());
		assertEquals(SourceType.IMPORTED, fs.getSource());

		SymbolTable symtab = resultProgram.getSymbolTable();
		Symbol s = symtab.getGlobalSymbol("FUNCTION63b4", entry);
		assertEquals(SourceType.IMPORTED, s.getSource());
		assertEquals(fs, s);
	}

}
