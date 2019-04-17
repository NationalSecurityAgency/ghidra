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
package help.screenshot;

import java.awt.Component;

import javax.swing.JButton;

import org.junit.Before;
import org.junit.Test;

import docking.DialogComponentProvider;
import docking.action.DockingActionIf;
import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;
import ghidra.app.plugin.core.instructionsearch.ui.*;
import ghidra.app.plugin.core.table.TableComponentProvider;

/**
 * Screenshots for help/topics/Search/Search_Instruction_Patterns.htm
 */
public class InstructionPatternSearchScreenShots extends AbstractSearchScreenShots {

	private InstructionSearchPlugin instructionSearchPlugin;

	@Override
	@Before
	public void setUp() throws Exception {

		super.setUp();

		instructionSearchPlugin = env.getPlugin(InstructionSearchPlugin.class);

		env.showTool();
	}

	@Test
	public void testSearchInstructionsManualSearchDialog() {

		DockingActionIf openSearchDialogAction =
			getAction(instructionSearchPlugin, "Search Instruction Patterns");
		performAction(openSearchDialogAction, true);

		waitForSwing();

		DialogComponentProvider dialog = getDialog();
		JButton manualEntryButton =
			(JButton) AbstractGenericTest.findComponentByName(dialog.getComponent(), "manual entry");
		pressButton(manualEntryButton);

		InsertBytesWidget comp = waitForDialogComponent(InsertBytesWidget.class);

		captureComponent(comp.getComponent());
	}

	/**
	 * Grabs a screenshot of the full {@link InstructionSearchDialog} window.
	 */
	@Test
	public void testSearchInstructionPatterns() {
		goToListing(0x00401221, "Address", false);
		makeSelection(0x00401221, 0x00401236);
		waitForSwing();

		DockingActionIf openSearchDialogAction =
			getAction(instructionSearchPlugin, "Search Instruction Patterns");
		performAction(openSearchDialogAction, true);
		waitForSwing();

		captureDialog(DialogComponentProvider.class, 900, 461);
	}

	/**
	 * Grabs a screenshot of the {@link InstructionTable} panel within the main
	 * instruction search dialog.
	 */
	@Test
	public void testSearchInstructionPatternsInstructionTable() {
		goToListing(0x00401221, "Address", false);
		makeSelection(0x00401221, 0x00401236);
		waitForSwing();

		DockingActionIf openSearchDialogAction =
			getAction(instructionSearchPlugin, "Search Instruction Patterns");
		performAction(openSearchDialogAction, true);
		waitForSwing();

		Component instrTable =
			findComponentByName(this.getDialog().getComponent(), "InstructionTablePanel");

		captureComponent(instrTable);
	}

	/**
	 * Grabs a screenshot of the {@link PreviewTable} panel within the main
	 * instruction search dialog.
	 */
	@Test
	public void testSearchInstructionPatternsPreviewTable() {
		goToListing(0x00401221, "Address", false);
		makeSelection(0x00401221, 0x00401236);
		waitForSwing();

		DockingActionIf openSearchDialogAction =
			getAction(instructionSearchPlugin, "Search Instruction Patterns");
		performAction(openSearchDialogAction, true);
		waitForSwing();

		Component previewTable =
			this.findChildWithType(this.getDialog().getComponent(), PreviewTablePanel.class, null);

		captureComponent(previewTable);
	}

	/**
	 * Grabs a screenshot of the {@link ControlPanel} within the main instruction search dialog.
	 */
	@Test
	public void testSearchInstructionPatternsControlPanel() {
		goToListing(0x00401221, "Address", false);
		makeSelection(0x00401221, 0x00401236);
		waitForSwing();

		DockingActionIf openSearchDialogAction =
			getAction(instructionSearchPlugin, "Search Instruction Patterns");
		performAction(openSearchDialogAction, true);
		waitForSwing();

		Component controlPanel =
			this.findChildWithType(this.getDialog().getComponent(), ControlPanel.class, null);

		captureComponent(controlPanel);
	}

	/**
	 * Grabs a screenshot of the toolbar for the {@link InstructionTable} within the main
	 * instruction search dialog.
	 */
	@Test
	public void testSearchInstructionPatternsInstructionTableToolbar() {
		goToListing(0x00401221, "Address", false);
		makeSelection(0x00401221, 0x00401236);
		waitForSwing();

		DockingActionIf openSearchDialogAction =
			getAction(instructionSearchPlugin, "Search Instruction Patterns");
		performAction(openSearchDialogAction, true);
		waitForSwing();

		Component instructionTable =
			this.findChildWithType(this.getDialog().getComponent(), InstructionTable.class, null);

		InstructionTable instrTable = (InstructionTable) instructionTable;
		captureComponent(instrTable.getToolbar());
	}

	/**
	 * Grabs a screenshot of the toolbar for the {@link PreviewTable} within the main
	 * instruction search dialog.
	 */
	@Test
	public void testSearchInstructionPatternsPreviewTableToolbar() {
		goToListing(0x00401221, "Address", false);
		makeSelection(0x00401221, 0x00401236);
		waitForSwing();

		DockingActionIf openSearchDialogAction =
			getAction(instructionSearchPlugin, "Search Instruction Patterns");
		performAction(openSearchDialogAction, true);
		waitForSwing();

		Component previewTable =
			this.findChildWithType(this.getDialog().getComponent(), PreviewTable.class, null);

		PreviewTable prevTable = (PreviewTable) previewTable;
		captureComponent(prevTable.getToolbar());
	}

	/**
	 * Grabs a screenshot of the results table displayed when performing a search using the
	 * {@link InstructionSearchDialog}.
	 */
	@Test
	public void testSearchInstructionPatternsResultsTable() {

		moveTool(500, 500);

		goToListing(0x00401221, "Address", false);
		makeSelection(0x00401221, 0x00401236);
		waitForSwing();

		DockingActionIf openSearchDialogAction =
			getAction(instructionSearchPlugin, "Search Instruction Patterns");
		performAction(openSearchDialogAction, true);
		waitForSwing();

		DialogComponentProvider dialog = getDialog();
		JButton searchButton =
			(JButton) AbstractGenericTest.findAbstractButtonByText(dialog.getComponent(), "Search All");
		pressButton(searchButton);

		waitForComponentProvider(TableComponentProvider.class);

		captureIsolatedProvider(TableComponentProvider.class, 500, 450);
	}
}
