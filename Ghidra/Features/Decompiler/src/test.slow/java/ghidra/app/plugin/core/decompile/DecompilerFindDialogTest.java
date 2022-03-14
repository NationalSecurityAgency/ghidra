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
package ghidra.app.plugin.core.decompile;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.Test;

import docking.action.DockingActionIf;
import docking.widgets.FindDialog;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.core.decompile.actions.FieldBasedSearchLocation;
import ghidra.program.model.listing.Program;
import ghidra.test.ClassicSampleX86ProgramBuilder;

public class DecompilerFindDialogTest extends AbstractDecompilerTest {

	private FindDialog findDialog;

	@Override
	@After
	public void tearDown() throws Exception {
		close(findDialog);
		super.tearDown();
	}

	@Override
	protected Program getProgram() throws Exception {
		return buildProgram();
	}

	private Program buildProgram() throws Exception {
		ClassicSampleX86ProgramBuilder builder =
			new ClassicSampleX86ProgramBuilder("notepad", false, this);
		return builder.getProgram();
	}

	@Test
	public void testFind() {

		/*
		 
		 	bool FUN_01002239(int param_1)
		
			{
			  undefined4 uVar1;
			  int iVar2;
			  undefined4 *puVar3;
			  bool bVar4;
			  undefined *puVar5;
			  undefined2 local_210;
			  undefined4 local_20e [129];
			  int local_8;
			  
			  local_210 = 0;
			  puVar3 = local_20e;
			  ...
			  ...
			  ...
		 */

		decompile("1002239");

		String text = "puVar";
		showFind(text);
		next();

		int length = text.length();
		int line = 9;
		int column = 12;
		assertSearchHit(line, column, length);

		line = 11;
		column = 11;
		next();
		assertSearchHit(line, column, length);

		line = 17;
		column = 0;
		next();
		assertSearchHit(line, column, length);

		line = 11;
		column = 11;
		previous();
		assertSearchHit(line, column, length);

		line = 9;
		column = 12;
		previous();
		assertSearchHit(line, column, length);
	}

	@Test
	public void testSearchWithinField() {

		//
		// Test that we find multiple search hits within a field in both directions
		//

		/*
		 
		 	bool FUN_01002239(int param_1)
		
			{
			  undefined4 uVar1;
			  int iVar2;
			  undefined4 *pu1111Var;
			  bool bVar4;
			  undefined *puVar5;
			  undefined2 local_210;
			  undefined4 local_20e [129];
			  int local_8;
			  
			  local_210 = 0;
			  puVar3 = local_20e;
			  ...
			  ...
			  ...
		 */

		decompile("1002239");

		int line = 9;
		int column = 12;
		setDecompilerLocation(line, column);

		rename("pu1111Var");

		// reset
		setDecompilerLocation(1, 0);

		String text = "11";
		showFind(text);
		next();

		int length = 2;
		line = 9;
		column = 14;
		assertSearchHit(line, column, length);

		column++; // same variable; one char over
		next();
		assertSearchHit(line, column, length);

		column++; // same variable; one char over
		next();
		assertSearchHit(line, column, length);

		column--; // same variable; one char over
		previous();
		assertSearchHit(line, column, length);

		column--; // same variable; one char over
		previous();
		assertSearchHit(line, column, length);
	}

	@Test
	public void testMultipleSearchHitsOnTheSameLine() {

		//
		// Test that we find multiple search hits within a single line
		//

		/*
		 
		 	bool FUN_01002239(int param_1)
		
			{
			  undefined4 uVar1;
			  int iVar2;
			  undefined4 *puVar3;
			  bool bVar4;
			  undefined *puVar5;
			  undefined2 local_210;
			  undefined4 local_20e [129];
			  int local_8;
			  
			  local_210 = 0;
			  puVar3 = local_20e;
			  
			  local_210 = 0;
			  puVar3 = local_20e;
			  for (iVar2 = 0x81; iVar2 != 0; iVar2 = iVar2 + -1) {
			    *puVar3 = 0;
			    puVar3 = puVar3 + 1;
			  }
			  
			  ...
			  ...
			  ...
		 */

		decompile("1002239");

		// skip past some search hits for test brevity
		setDecompilerLocation(18, 0);

		String text = "puVar3";
		showFind(text);
		next();

		int length = text.length();
		int line = 19;
		int column = 1;
		assertSearchHit(line, column, length); // *|puVar3 = 0;

		line = 20;
		column = 0;
		next();
		assertSearchHit(line, column, length); // |puVar3 = puVar3 + 1;

		line = 20;
		column = 9;
		next();
		assertSearchHit(line, column, length); // puVar3 = |puVar3 + 1;

		line = 20;
		column = 0;
		previous();
		assertSearchHit(line, column, length);

		line = 19;
		column = 1;
		previous();
		assertSearchHit(line, column, length);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void next() {
		runSwing(() -> findDialog.next());
	}

	private void previous() {
		runSwing(() -> findDialog.previous());
	}

	private void assertSearchHit(int line, int column, int length) {

		waitForSwing();
		assertCurrentLocation(line, column);

		DecompilerPanel panel = getDecompilerPanel();
		FieldBasedSearchLocation searchResults = panel.getSearchResults();
		FieldLocation searchCursorLocation = searchResults.getFieldLocation();
		int searchLineNumber = searchCursorLocation.getIndex().intValue() + 1;
		assertEquals("Search result is on the wrong line", line, searchLineNumber);

		int searchStartColumn = searchResults.getStartIndexInclusive();
		assertEquals("Search result does not start on the correct character", column,
			searchStartColumn);

		int searchEndColumn = searchResults.getEndIndexInclusive();
		assertEquals("Search result does not end on the correct character", column + length - 1,
			searchEndColumn);
	}

	private void assertCurrentLocation(int line, int col) {
		DecompilerPanel panel = provider.getDecompilerPanel();
		FieldLocation actual = panel.getCursorPosition();
		FieldLocation expected = loc(line, col);
		assertEquals("Decompiler cursor is not at the expected location", expected, actual);
	}

	private void showFind(String text) {
		DockingActionIf findAction = getAction(decompiler, "Find");
		performAction(findAction, provider, true);
		findDialog = waitForDialogComponent(FindDialog.class);
		runSwing(() -> findDialog.setSearchText(text));
	}

	private void rename(String newName) {
		DockingActionIf action = getAction(decompiler, "Rename Variable");
		performAction(action, provider.getActionContext(null), false);

		InputDialog dialog = waitForDialogComponent(InputDialog.class);
		runSwing(() -> dialog.setValue(newName));

		pressButtonByText(dialog, "OK");
		waitForDecompiler();
	}

}
