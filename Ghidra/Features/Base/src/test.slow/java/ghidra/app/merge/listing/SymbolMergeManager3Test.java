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

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.FunctionStackAnalysisCmd;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

/**
 * Test the merge of the versioned program's listing.
 */
public class SymbolMergeManager3Test extends AbstractListingMergeManagerTest {

	/**
	 * 
	 * @param arg0
	 */
	public SymbolMergeManager3Test() {
		super();
	}

	@Test
	public void testVariousNameNoConflictsInOverlay() throws Exception {
		mtf.initialize("overlayCalc", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createGlobalSymbol(program, "TextOverlay::01001630", "FOO");
					createGlobalSymbol(program, "TextOverlay::01001639", "ONE");
					createGlobalSymbol(program, "TextOverlay::01001646", "UNO");
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
					createGlobalSymbol(program, "TextOverlay::01001630", "FOO");
					createGlobalSymbol(program, "TextOverlay::01001639", "TWO");
					createGlobalSymbol(program, "TextOverlay::01001646", "DOS");
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

		executeMerge(ListingMergeConstants.ASK_USER);
		chooseRadioButton(LATEST_BUTTON);
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		SymbolTable resultSymTab = resultProgram.getSymbolTable();
		Symbol[] symbols = resultSymTab.getSymbols(addr(resultProgram, "TextOverlay::01001630"));
		assertEquals(1, symbols.length);
		assertEquals("FOO", symbols[0].getName());
		symbols = resultSymTab.getSymbols(addr(resultProgram, "TextOverlay::01001639"));
		assertEquals(2, symbols.length);
		assertEquals("ONE", symbols[0].getName());
		assertEquals("TWO", symbols[1].getName());
		assertEquals("ONE",
			resultSymTab.getPrimarySymbol(addr(resultProgram, "TextOverlay::01001639")).getName());
		symbols = resultSymTab.getSymbols(addr(resultProgram, "TextOverlay::01001646"));
		assertEquals(2, symbols.length);
		assertEquals("DOS", symbols[0].getName());
		assertEquals("DOS",
			resultSymTab.getPrimarySymbol(addr(resultProgram, "TextOverlay::01001646")).getName());
		assertEquals("UNO", symbols[1].getName());
	}

	@Test
	public void testLabelvsFunctionChange() throws Exception {
		mtf.initialize("notepad3", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createGlobalSymbol(program, "01002efc", "FOO");
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
					Address addr = addr(program, "01002f01");
					disassemble(program, new AddressSet(addr, addr), true);
					createAnalyzedFunction(program, "01002f01", null);
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
		mtf.getTestEnvironment().showTool();

		executeMerge(ListingMergeConstants.ASK_USER);
		waitForMergeCompletion();

		SymbolTable resultSymTab = resultProgram.getSymbolTable();
		Symbol[] symbols = resultSymTab.getSymbols(addr(resultProgram, "01002efc"));
		assertEquals(1, symbols.length);
		assertEquals("FOO", symbols[0].getName());

		Function function =
			resultProgram.getFunctionManager().getFunctionAt(addr(resultProgram, "01002f01"));
		assertNotNull(function);
	}

	@Override
	protected void disassemble(Program program, AddressSet addrSet, boolean followFlow) {
		DisassembleCommand disCmd =
			new DisassembleCommand(addrSet.getMinAddress(), addrSet, followFlow);
		disCmd.applyTo(program);
	}

	@Override
	protected void createAnalyzedFunction(ProgramDB program, String entryPoint, String name) {
		Address addr = addr(program, entryPoint);
		try {
			CreateFunctionCmd functionCmd =
				new CreateFunctionCmd(name, addr, null, SourceType.ANALYSIS);
			assertTrue("Failed to create function " + name + " @ " + addr,
				functionCmd.applyTo(program));
			Function newFunction = program.getFunctionManager().getFunctionAt(addr);
			assertNotNull(newFunction);
			FunctionStackAnalysisCmd analyzeCmd = new FunctionStackAnalysisCmd(addr, true);
			assertTrue("Failed to analyze stack for " + name + " @ " + addr,
				analyzeCmd.applyTo(program));
		}
		catch (Exception e) {
			e.printStackTrace();
			Assert.fail("Can't create analyzed function @ " + entryPoint + e.getMessage());
		}
	}
}
