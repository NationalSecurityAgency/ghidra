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
package ghidra.app.plugin.core.diff;

import static org.junit.Assert.*;

import java.awt.Window;

import javax.swing.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;

public class DiffGetTest extends DiffTestAdapter {

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);
	}

	@Test
	public void testDiffAgainstSelf() throws Exception {
		getDiffDialog(diffTestP1, diffTestP1);

		assertTrue(programContextCB.isSelected());
		assertTrue(byteCB.isSelected());
		assertTrue(codeUnitCB.isSelected());
		assertTrue(refCB.isSelected());
		assertTrue(commentCB.isSelected());
		assertTrue(labelCB.isSelected());
		assertTrue(functionCB.isSelected());
		assertTrue(bookmarkCB.isSelected());
		assertTrue(propertiesCB.isSelected());

		assertTrue(!limitToSelectionCB.isSelected());
		assertEquals("Entire Program", limitText.getText());

		pressButtonByText(getDiffsDialog, "OK");
		waitForDiff();

		assertEquals(new ProgramSelection(), diffPlugin.getDiffHighlightSelection());
		Window w = waitForWindow("No Differences");
		close(w);
	}

	@Test
	public void testDiffNoTypes() throws Exception {
		getDiffDialog(diffTestP1, diffTestP2);
		setAllTypes(false);

		assertTrue(!programContextCB.isSelected());
		assertTrue(!byteCB.isSelected());
		assertTrue(!codeUnitCB.isSelected());
		assertTrue(!refCB.isSelected());
		assertTrue(!commentCB.isSelected());
		assertTrue(!labelCB.isSelected());
		assertTrue(!functionCB.isSelected());
		assertTrue(!bookmarkCB.isSelected());
		assertTrue(!propertiesCB.isSelected());

		assertTrue(!limitToSelectionCB.isSelected());
		assertEquals("Entire Program", limitText.getText());

		pressButtonByText(getDiffsDialog, "OK");
		getDiffsDialog = waitForDialogComponent(ExecuteDiffDialog.class);
		assertNotNull(getDiffsDialog);
		JLabel statusLabel = (JLabel) findComponentByName(getDiffsDialog, "statusLabel");
		assertEquals("At least one difference type must be checked.", statusLabel.getText());
		assertEquals(new ProgramSelection(), diffPlugin.getDiffHighlightSelection());
		close(getDiffsDialog);
	}

	@Test
	public void testGetDefaultDiffsAction() throws Exception {
		getDiffDialog(diffTestP1, diffTestP2);

		assertTrue(programContextCB.isSelected());
		assertTrue(byteCB.isSelected());
		assertTrue(codeUnitCB.isSelected());
		assertTrue(refCB.isSelected());
		assertTrue(commentCB.isSelected());
		assertTrue(labelCB.isSelected());
		assertTrue(functionCB.isSelected());
		assertTrue(bookmarkCB.isSelected());
		assertTrue(propertiesCB.isSelected());

		assertTrue(!limitToSelectionCB.isSelected());
		assertEquals("Entire Program", limitText.getText());

		pressButtonByText(getDiffsDialog, "OK");
		waitForDiff();
		waitForSwing();
		assertEquals(getSetupAllDiffsSet(), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testKeepGetDiffsCheckboxState() throws Exception {
		getDiffDialog(diffTestP1, diffTestP2);
		setAllTypes(false);
		setCheckBoxes(true, new JCheckBox[] { propertiesCB, commentCB });

		assertTrue(!programContextCB.isSelected());
		assertTrue(!byteCB.isSelected());
		assertTrue(!codeUnitCB.isSelected());
		assertTrue(!refCB.isSelected());
		assertTrue(commentCB.isSelected());
		assertTrue(!labelCB.isSelected());
		assertTrue(!functionCB.isSelected());
		assertTrue(!bookmarkCB.isSelected());
		assertTrue(propertiesCB.isSelected());

		pressButtonByText(getDiffsDialog, "OK");
		waitForDiff();
		AddressSet as = getSetupCommentDiffs().union(getSetupPropertyDiffs());
		assertEquals(new ProgramSelection(as), diffPlugin.getDiffHighlightSelection());

		invokeLater(getDiffs);

		assertTrue(!programContextCB.isSelected());
		assertTrue(!byteCB.isSelected());
		assertTrue(!codeUnitCB.isSelected());
		assertTrue(!refCB.isSelected());
		assertTrue(commentCB.isSelected());
		assertTrue(!labelCB.isSelected());
		assertTrue(!functionCB.isSelected());
		assertTrue(!bookmarkCB.isSelected());
		assertTrue(propertiesCB.isSelected());

		setCheckBoxes(true, new JCheckBox[] { refCB });
		as = as.union(getSetupReferenceDiffs());

		pressButtonByText(getDiffsDialog, "OK");
		waitForDiff();
		assertEquals(new ProgramSelection(as), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testSelectionAllDiffs() throws Exception {
		openSecondProgram(diffTestP1, diffTestP2);
		AddressSet selectionSet = new AddressSet(addr("1001708"), addr("1003001"));
		tool.firePluginEvent(
			new ProgramSelectionPluginEvent("test", new ProgramSelection(selectionSet), program));

		invokeLater(getDiffs);
		getDiffsDialog = waitForDialogComponent(ExecuteDiffDialog.class);
		assertNotNull(getDiffsDialog);
		getDiffDialogComponents(getDiffsDialog.getComponent());

		assertTrue(limitToSelectionCB.isSelected());
		assertEquals("[01001708, 01003001]\n", limitText.getText());

		pressButtonByText(getDiffsDialog, "OK");
		waitForDiff();

		assertEquals(getSetupAllDiffsSet().intersect(selectionSet),
			diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testDeselectAndSelectAllTypesOfDiffs() throws Exception {
		openSecondProgram(diffTestP1, diffTestP2);
//		AddressSet selectionSet = new AddressSet(addrFactory, addr("1001708"), addr("1003001"));
//		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", 
//				new ProgramSelection(selectionSet), program));

		invokeLater(getDiffs);
		getDiffsDialog = waitForDialogComponent(ExecuteDiffDialog.class);
		assertNotNull(getDiffsDialog);
		getDiffDialogComponents(getDiffsDialog.getComponent());

		assertEquals(true, programContextCB.isSelected());
		assertEquals(true, byteCB.isSelected());
		assertEquals(true, codeUnitCB.isSelected());
		assertEquals(true, refCB.isSelected());
		assertEquals(true, commentCB.isSelected());
		assertEquals(true, labelCB.isSelected());
		assertEquals(true, functionCB.isSelected());
		assertEquals(true, bookmarkCB.isSelected());
		assertEquals(true, propertiesCB.isSelected());
		assertEquals(false, limitToSelectionCB.isSelected());

		pressButtonByText(getDiffsDialog, "Deselect All");
		waitForDiff();

		assertEquals(false, programContextCB.isSelected());
		assertEquals(false, byteCB.isSelected());
		assertEquals(false, codeUnitCB.isSelected());
		assertEquals(false, refCB.isSelected());
		assertEquals(false, commentCB.isSelected());
		assertEquals(false, labelCB.isSelected());
		assertEquals(false, functionCB.isSelected());
		assertEquals(false, bookmarkCB.isSelected());
		assertEquals(false, propertiesCB.isSelected());
		assertEquals(false, limitToSelectionCB.isSelected());

		pressButtonByText(getDiffsDialog, "OK");
		waitForDiff();
		assertEquals("At least one difference type must be checked.",
			getDiffsDialog.getStatusText());

		pressButtonByText(getDiffsDialog, "Select All");
		waitForDiff();

		assertEquals(true, programContextCB.isSelected());
		assertEquals(true, byteCB.isSelected());
		assertEquals(true, codeUnitCB.isSelected());
		assertEquals(true, refCB.isSelected());
		assertEquals(true, commentCB.isSelected());
		assertEquals(true, labelCB.isSelected());
		assertEquals(true, functionCB.isSelected());
		assertEquals(true, bookmarkCB.isSelected());
		assertEquals(true, propertiesCB.isSelected());
		assertEquals(false, limitToSelectionCB.isSelected());

		pressButtonByText(getDiffsDialog, "OK");
		waitForDiff();
		waitForSwing(); // Wait for Diff Highlight to get displayed.
		assertEquals(getSetupAllDiffsSet(), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testSelectionUnchecked() throws Exception {
		openSecondProgram(diffTestP1, diffTestP2);
		AddressSet selectionSet = new AddressSet(addr("1001708"), addr("1003001"));
		tool.firePluginEvent(
			new ProgramSelectionPluginEvent("test", new ProgramSelection(selectionSet), program));

		invokeLater(getDiffs);
		getDiffsDialog = waitForDialogComponent(ExecuteDiffDialog.class);
		assertNotNull(getDiffsDialog);
		getDiffDialogComponents(getDiffsDialog.getComponent());

		assertTrue(limitToSelectionCB.isSelected());
		assertEquals("[01001708, 01003001]\n", limitText.getText());

		SwingUtilities.invokeLater(() -> limitToSelectionCB.doClick());
		waitForSwing();

		assertTrue(!limitToSelectionCB.isSelected());
		assertEquals("Entire Program", limitText.getText());

		pressButtonByText(getDiffsDialog, "OK");
		waitForDiff();
		waitForSwing();

		assertEquals(getSetupAllDiffsSet(), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testSelectionLabelDiffs() throws Exception {
		openSecondProgram(diffTestP1, diffTestP2);
		AddressSet selectionSet = new AddressSet(addr("1006202"), addr("1006400"));
		tool.firePluginEvent(
			new ProgramSelectionPluginEvent("test", new ProgramSelection(selectionSet), program));

		invokeLater(getDiffs);
		getDiffsDialog = waitForDialogComponent(ExecuteDiffDialog.class);
		assertNotNull(getDiffsDialog);
		getDiffDialogComponents(getDiffsDialog.getComponent());

		setAllTypes(false);
		setToggleButtonSelected(labelCB, true);
		assertTrue(limitToSelectionCB.isSelected());
		assertEquals("[01006202, 01006400]\n", limitText.getText());
		waitForSwing();

		pressButtonByText(getDiffsDialog, "OK");
		waitForDiff();

		assertEquals(getSetupLabelDiffs().intersect(selectionSet),
			diffPlugin.getDiffHighlightSelection());
		Window window = waitForWindow("No Differences In Selection");
		close(window);
	}

	@Test
	public void testGetReferenceDiffsAction() throws Exception {
		getDiffDialog(diffTestP1, diffTestP2);
		setAllTypes(false);
		setToggleButtonSelected(refCB, true);
		waitForSwing();
		pressButtonByText(getDiffsDialog, "OK");
		waitForDiff();
		assertEquals(getSetupReferenceDiffs(), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testGetLabelDiffsAction() throws Exception {
		getDiffDialog(diffTestP1, diffTestP2);
		setAllTypes(false);
		setToggleButtonSelected(labelCB, true);
		waitForSwing();
		pressButtonByText(getDiffsDialog, "OK");
		waitForDiff();
		assertEquals(getSetupLabelDiffs(), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testGetFunctionDiffsAction() throws Exception {
		getDiffDialog(diffTestP1, diffTestP2);
		setAllTypes(false);
		setToggleButtonSelected(functionCB, true);
		waitForSwing();
		pressButtonByText(getDiffsDialog, "OK");
		waitForDiff();
		assertEquals(getSetupFunctionDiffs(), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testGetPropertyDiffsAction() throws Exception {

		getDiffDialog(diffTestP1, diffTestP2);
		setAllTypes(false);

		setToggleButtonSelected(propertiesCB, true);
		waitForSwing();

		pressButtonByText(getDiffsDialog, "OK");
		waitForDiff();

		assertEquals(getSetupPropertyDiffs(), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testDifferentLanguages() throws Exception {

		loadProgram(diffTestP1);

		pickSecondProgram(getSparcProgram());

		assertNull(fp2.getTopLevelAncestor());
		Window win = waitForWindow("Can't Open Selected Program");
		pressButton(win, "OK");
		win = waitForWindow("Select Other Program");
		assertNotNull(win);
		pressButton(win, "Cancel");
		assertFalse(win.isShowing());
		assertNull(fp2.getTopLevelAncestor());
	}

	private Program getSparcProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Sparc", ProgramBuilder._SPARC64);
		builder.createMemory("test", "0x100", 0x1000);
		return builder.getProgram();
	}

}
