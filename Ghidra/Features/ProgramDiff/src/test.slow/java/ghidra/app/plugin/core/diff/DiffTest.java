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

import java.awt.Color;
import java.awt.Window;
import java.math.BigInteger;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.swing.*;
import javax.swing.tree.TreePath;

import org.junit.Test;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingActionIf;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.progmgr.MultiTabPanel;
import ghidra.app.plugin.core.progmgr.MultiTabPlugin;
import ghidra.app.util.viewer.field.OpenCloseField;
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

public class DiffTest extends DiffTestAdapter {

	@Test
	public void testViewDiffsEnablement() throws Exception {
		getDiffActions();
		assertNotNull(openClosePgm2);
		assertTrue(!openClosePgm2.isEnabled());
		loadProgram(diffTestP1);
		assertTrue(openClosePgm2.isEnabled());
		closeProgram();
		assertTrue(!openClosePgm2.isEnabled());
	}

	@Test
	public void testOpenDiffProgram() {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		openDiff(diffTestP1, diffTestP2);
		assertNotNull(fp2.getTopLevelAncestor());
		ProgramSelection expectedSelection = new ProgramSelection(getSetupAllDiffsSet());
		checkIfSameSelection(expectedSelection, diffPlugin.getDiffHighlightSelection());
		// Check action enablement.
		assertTrue(viewDiffs.isEnabled());
		assertTrue(!applyDiffs.isEnabled());
		assertTrue(!applyDiffsNext.isEnabled());
		assertTrue(!ignoreDiffs.isEnabled());
		assertTrue(nextDiff.isEnabled());
		assertTrue(!prevDiff.isEnabled());
		assertTrue(diffDetails.isEnabled());
		assertTrue(diffApplySettings.isEnabled());
		assertTrue(getDiffs.isEnabled());
		assertTrue(selectAllDiffs.isEnabled());
		assertTrue(!setPgm2Selection.isEnabled());

		// Check background color where there is and isn't a difference.
		setLocation("1009942");
		FieldLocation cursorPosition = fp2.getCursorLocation();
		BigInteger index = cursorPosition.getIndex();
		Color bg = getBgColor(fp1, index);
		Color bg2 = getBgColor(fp2, index);
		assertEquals(bg, bg2);

		setLocation("100a002");
		cursorPosition = fp2.getCursorLocation();
		index = cursorPosition.getIndex();
		bg = getBgColor(fp1, index);
		bg2 = getBgColor(fp2, index);
		assertEquals(bg, bg2);
	}

	@Test
	public void testCloseDiffProgram() throws Exception {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		openDiff(diffTestP1, diffTestP2);
		assertNotNull(fp2.getTopLevelAncestor());

		closeDiff();
		assertNull(diffListingPanel.getProgram());
	}

	@Test
	public void testCancelDiff() throws Exception {

		// this latch lets us keep the diff from progressing until we are ready
		CountDownLatch latch = installDiffBlockingLatch();

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		loadProgram(diffTestP1);

		pickSecondProgram(diffTestP2);
		waitForTasks();

		Window win = waitForWindow("Determine Program Differences");
		pressButton(win, "OK");

		win = waitForWindow("Checking Program Differences");
		pressButton(win, "Cancel");

		win = waitForWindow("Cancel?");
		pressButton(win, "Yes");

		// now that we have pressed cancel, it is safe to let the diff continue
		latch.countDown();

		waitForCondition(() -> getWindow("Checking Program Differences") == null);
	}

	@Test
	public void testViewDiffsAction() throws Exception {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		loadProgram(diffTestP1);

		pickSecondProgram(diffTestP2);

		waitForTasks();

		Window win = waitForWindow("Determine Program Differences");

		pressButton(win, "Cancel");
		getDiffActions();

		invokeLater(viewDiffs);
		Window window = waitForWindow("Diff Already In Progress");
		assertNotNull(window);
		pressButtonByText(window, "OK");

		invokeLater(getDiffs);
		win = waitForWindow("Determine Program Differences");
		pressButton(win, "OK");
		waitForSwing();

		waitForCondition(() -> getWindow("Checking Program Differences") == null);
		waitForTasks(); // this waits for the task and swing thread to finish posting results

		ProgramSelection expectedSelection = new ProgramSelection(getSetupAllDiffsSet());
		checkIfSameSelection(expectedSelection, diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testNextDiffAction() {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		openDiff(diffTestP1, diffTestP2);
		assertNotNull(nextDiff);
		assertTrue(nextDiff.isEnabled());

		assertEquals(addr("100"), getDiffAddress());
		assertEquals(cb.getCurrentSelection(), new ProgramSelection());

		invokeLater(nextDiff);

		assertEquals(addr("1001034"), getDiffAddress());
		assertEquals(cb.getCurrentSelection(),
			new ProgramSelection(addr("1001034"), addr("1001034")));
	}

	@Test
	public void testNextDiffAction2() {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		openDiff(diffTestP1, diffTestP2);
		assertNotNull(nextDiff);
		assertTrue(nextDiff.isEnabled());

		tool.firePluginEvent(new ProgramLocationPluginEvent("test",
			new ProgramLocation(program, addr("1004c61")), program));
		assertEquals(addr("1004c61"), getDiffAddress());
		assertEquals(cb.getCurrentSelection(), new ProgramSelection());

		invokeLater(nextDiff);

		assertEquals(addr("1005e4f"), getDiffAddress());
		assertEquals(cb.getCurrentSelection(),
			new ProgramSelection(addr("1005e4f"), addr("1005e53")));
	}

	@Test
	public void testPreviousDiffAction() {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		openDiff(diffTestP1, diffTestP2);
		assertNotNull(nextDiff);
		assertTrue(nextDiff.isEnabled());

		tool.firePluginEvent(new ProgramLocationPluginEvent("test",
			new ProgramLocation(program, addr("100f3ff")), program));
		assertEquals(addr("100f3ff"), getDiffAddress());
		assertEquals(cb.getCurrentSelection(), new ProgramSelection());

		invokeLater(prevDiff);

		assertEquals(addr("1005e4f"), getDiffAddress());
		assertEquals(cb.getCurrentSelection(),
			new ProgramSelection(addr("1005e4f"), addr("1005e53")));
	}

	@Test
	public void testPreviousDiffAction2() {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		openDiff(diffTestP1, diffTestP2);
		assertNotNull(nextDiff);
		assertTrue(nextDiff.isEnabled());

		tool.firePluginEvent(new ProgramLocationPluginEvent("test",
			new ProgramLocation(program, addr("1004c61")), program));
		assertEquals(addr("1004c61"), getDiffAddress());
		assertEquals(cb.getCurrentSelection(), new ProgramSelection());

		invokeLater(prevDiff);

		assertEquals(addr("100415a"), getDiffAddress());
		assertEquals(cb.getCurrentSelection(),
			new ProgramSelection(addr("100415a"), addr("100415a")));

		tool.firePluginEvent(new ProgramLocationPluginEvent("test",
			new ProgramLocation(program, addr("1002055")), program));
		assertEquals(addr("1002055"), getDiffAddress());

		invokeLater(prevDiff);

		assertEquals(addr("100204c"), getDiffAddress());
		assertEquals(cb.getCurrentSelection(),
			new ProgramSelection(addr("100204c"), addr("100204c")));
	}

	@Test
	public void testShowHideDiffDetails() {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		openDiff(diffTestP1, diffTestP2);
		assertNotNull(diffDetails);
		assertTrue(diffDetails.isEnabled());

		tool.firePluginEvent(new ProgramLocationPluginEvent("test",
			new ProgramLocation(program, addr("1004c61")), program));
		assertEquals(addr("1004c61"), getDiffAddress());
		assertEquals(cb.getCurrentSelection(), new ProgramSelection());

		assertEquals(false, isDiffDetailsDisplayed());

		invokeLater(diffDetails); // show
		waitForSwing();
		assertEquals(true, isDiffDetailsDisplayed());

		runSwing(() -> {
			DiffDetailsProvider detailsProvider = diffPlugin.getDiffDetailsProvider();
			detailsProvider.closeComponent(); // hide
		}, false);
		waitForSwing();
		assertEquals(false, isDiffDetailsDisplayed());
	}

	boolean isDiffDetailsDisplayed() {
		boolean shown = isProviderShown(tool.getToolFrame(), "Diff Details");
		if (!shown) {
			return false;
		}
		JPanel detailsPanel = (JPanel) findComponentByName(tool.getToolFrame(),
			DiffDetailsProvider.DIFF_DETAILS_PANEL);
		return detailsPanel != null;
	}

	void checkDetails() {
		JPanel detailsPanel =
			(JPanel) findComponentByName(tool.getToolFrame(), "Diff Details Panel");
		assertNotNull(detailsPanel);
		JTextArea textArea = (JTextArea) findComponentByName(detailsPanel,
			DiffDetailsProvider.DIFF_DETAILS_TEXT_AREA);
		assertNotNull(textArea);
		JCheckBox autoUpdateCB = (JCheckBox) findComponentByName(detailsPanel,
			DiffDetailsProvider.AUTO_UPDATE_CHECK_BOX);
		assertNotNull(autoUpdateCB);
	}

	@Test
	public void testDiffDetailsAction() {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		openDiff(diffTestP1, diffTestP2);
		assertNotNull(diffDetails);
		assertTrue(diffDetails.isEnabled());

		tool.firePluginEvent(new ProgramLocationPluginEvent("test",
			new ProgramLocation(program, addr("100")), program));
		assertEquals(addr("100"), getDiffAddress());
		invokeLater(diffDetails);

		// Check where there are differences
		assertEquals(true, isDiffDetailsDisplayed());
		JPanel detailsPanel = (JPanel) findComponentByName(tool.getToolFrame(),
			DiffDetailsProvider.DIFF_DETAILS_PANEL);
		assertNotNull(detailsPanel);
		JEditorPane textArea = (JEditorPane) findComponentByName(detailsPanel,
			DiffDetailsProvider.DIFF_DETAILS_TEXT_AREA);
		assertNotNull(textArea);
		String info = textArea.getText();
		assertTrue(info.indexOf("Byte Diffs") != -1);
		assertTrue(info.indexOf("Bookmark Diffs") == -1);
		assertEquals(addr("100"), getDiffAddress());

		tool.firePluginEvent(new ProgramLocationPluginEvent("test",
			new ProgramLocation(program, addr("1001014")), program));
		assertEquals(addr("1001014"), getDiffAddress());
		invokeLater(diffDetails);
		waitForSwing();
		assertEquals(true, isDiffDetailsDisplayed());

		// Check where there are no differences
		info = textArea.getText();
		assertTrue(info.indexOf("No differences") != -1);

		assertEquals(addr("1001014"), getDiffAddress());
	}

	@Test
	public void testSelectAllDiffsAction() {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		openDiff(diffTestP1, diffTestP2);
		assertNotNull(diffDetails);
		assertTrue(diffDetails.isEnabled());

		invokeLater(selectAllDiffs);

		ProgramSelection expectedSelection = new ProgramSelection(getSetupAllDiffsSet());
		checkIfSameSelection(expectedSelection, cb.getCurrentSelection());
	}

	@Test
	public void testSetPgm2SelectionAction() {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		openDiff(diffTestP1, diffTestP2);
		assertNotNull(setPgm2Selection);
		assertTrue(!setPgm2Selection.isEnabled());

		AddressSet as = new AddressSet();
		as.addRange(addr("1001008"), addr("100103f"));
		as.addRange(addr("1001965"), addr("1001968"));
		as.addRange(addr("1002053"), addr("1002054"));
		as.addRange(addr("10022e9"), addr("1002309"));
		as.addRange(addr("100a000"), addr("100a006"));

		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr("1001034"), addr("1001034"));
		diffAs.addRange(addr("10022ee"), addr("10022fc"));
		diffAs.addRange(addr("1002304"), addr("1002304"));
		diffAs.addRange(addr("1002306"), addr("1002306"));

		tool.firePluginEvent(
			new ProgramSelectionPluginEvent("test", new ProgramSelection(as), program));
		tool.firePluginEvent(new ProgramLocationPluginEvent("test",
			new ProgramLocation(program, addr("1001000")), program));
		assertTrue(setPgm2Selection.isEnabled());

		invokeLater(setPgm2Selection);

		assertEquals(new ProgramSelection(diffAs), cb.getCurrentSelection());
	}

	@Test
	public void testChangeToEntireViewWithDiff() throws Exception {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		openDiff(diffTestP1, diffTestP2);
		JTree tree = getProgramTree();

		// Replace view with .data
		selectTreeNodeByText(tree, ".data");
		invokeAndWait(replaceView);
		topOfFile(fp1);
		assertEquals(addr("1008000"), cb.getCurrentAddress());
		bottomOfFile(fp1);
		assertEquals(addr("10085ff"), cb.getCurrentAddress());

		// Replace with program view
		selectTreeNodeByText(tree, "DiffTestPgm1");
		invokeAndWait(replaceView);
		topOfFile(fp1);
		assertEquals(addr("100"), cb.getCurrentAddress());
		bottomOfFile(fp1);
		assertEquals(addr("100f3ff"), cb.getCurrentAddress());

		assertEquals(new ProgramSelection(getSetupAllDiffsSet()),
			diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testDisplaySingleFragmentWithDiff() throws Exception {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		openDiff(diffTestP1, diffTestP2);
		JTree tree = getProgramTree();
		selectTreeNodeByText(tree, ".data");

		runSwing(() -> replaceView.actionPerformed(new ActionContext()));

		topOfFile(fp1);
		assertEquals(addr("1008000"), cb.getCurrentAddress());
		bottomOfFile(fp1);
		assertEquals(addr("10085ff"), cb.getCurrentAddress());

		assertEquals(new ProgramSelection(getSetupAllDiffsSet()),
			diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testDisplayMultipleFragmentsWithDiff() throws Exception {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		programBuilderDiffTest2.createComment("0x01008000", "My comment", CodeUnit.EOL_COMMENT);
		programBuilderDiffTest2.createComment("0x01008607", "My comment", CodeUnit.EOL_COMMENT);
		programBuilderDiffTest2.createComment("0x01008a99", "My comment", CodeUnit.EOL_COMMENT);
		programBuilderDiffTest2.createComment("0x0100a001", "My comment", CodeUnit.EOL_COMMENT);

		openDiff(diffTestP1, diffTestP2);
		JTree tree = getProgramTree();
		selectTreeNodeByText(tree, ".data");

		runSwing(() -> replaceView.actionPerformed(new ActionContext()));

		selectTreeNodeByText(tree, ".rsrc");

		runSwing(() -> goToView.actionPerformed(new ActionContext()));

		topOfFile(fp1);
		assertEquals(addr("1008000"), cb.getCurrentAddress());
		bottomOfFile(fp1);
		assertEquals(addr("100f3ff"), cb.getCurrentAddress());

		AddressSet diffSet = new AddressSet(getSetupAllDiffsSet());
		diffSet.add(addr("0x01008000"));
		diffSet.add(addr("0x01008607"));
		diffSet.add(addr("0x01008a99"));
		diffSet.add(addr("0x0100a001"));
		assertEquals(new ProgramSelection(diffSet), diffPlugin.getDiffHighlightSelection());

		AddressSet viewSet = new AddressSet();
		viewSet.addRange(addr("1008000"), addr("10085ff")); // .data
		viewSet.addRange(addr("100a000"), addr("100f3ff")); // .rsrc
		assertEquals(viewSet, cb.getView());

		// top of View .rsrc
		cb.goTo(new ProgramLocation(program, addr("100a000")));
		assertEquals(addr("100a000"), cb.getCurrentAddress());
		assertEquals(addr("100a000"), getDiffAddress());

		// Previous Diff should add .datau to the view
		invokeLater(prevDiff);
		waitForSwing();
		viewSet.addRange(addr("1008600"), addr("1009943")); // .datau
		assertEquals(addr("1008a99"), cb.getCurrentAddress());
		assertEquals(addr("1008a99"), getDiffAddress());
		assertEquals(cb.getCurrentSelection(),
			new ProgramSelection(addr("1008a99"), addr("1008a99")));
		assertEquals(viewSet, cb.getView());

		// top of View .data
		topOfFile(fp1);
		assertEquals(addr("1008000"), cb.getCurrentAddress());
		assertEquals(addr("1008000"), getDiffAddress());

		// Previous Diff should add .text to the view
		invokeLater(prevDiff);

		viewSet.addRange(addr("1001000"), addr("10075ff"));
		assertEquals(addr("1005e4f"), cb.getCurrentAddress());
		assertEquals(addr("1005e4f"), getDiffAddress());
		assertEquals(cb.getCurrentSelection(),
			new ProgramSelection(addr("1005e4f"), addr("1005e53")));
		assertEquals(viewSet, cb.getView());
	}

	@Test
	public void testEmptyViewDiff() throws Exception {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		programBuilderDiffTest2.createComment("0x01008000", "My comment", CodeUnit.EOL_COMMENT);
		programBuilderDiffTest2.createComment("0x01008607", "My comment", CodeUnit.EOL_COMMENT);
		programBuilderDiffTest2.createComment("0x01009943", "My comment", CodeUnit.EOL_COMMENT);
		programBuilderDiffTest2.createComment("0x0100a001", "My comment", CodeUnit.EOL_COMMENT);

		openDiff(diffTestP1, diffTestP2);
		JTree tree = getProgramTree();
		selectTreeNodeByText(tree, "DiffTestPgm1");
		performAction(removeView, true);
		AddressSet viewSet = new AddressSet();
		assertEquals(viewSet, cb.getView());
		topOfFile(fp1);
		assertNull(cb.getCurrentAddress());
		bottomOfFile(fp1);
		assertNull(cb.getCurrentAddress());
		fp1.getHeight();
		assertEquals(0, fp1.getLayoutModel().getNumIndexes().intValue());
		assertEquals(0, fp2.getLayoutModel().getNumIndexes().intValue());

		AddressSet diffSet = new AddressSet(getSetupAllDiffsSet());
		diffSet.add(addr("0x01008000"));
		diffSet.add(addr("0x01008607"));
		diffSet.add(addr("0x01009943"));
		diffSet.add(addr("0x0100a001"));
		assertEquals(new ProgramSelection(diffSet), diffPlugin.getDiffHighlightSelection());
		assertEquals(addr("100"), diffPlugin.getCurrentAddress());
		assertEquals(addr("100"), getDiffAddress());

		// Next Diff should add .text to the view
		invokeLater(nextDiff);

		viewSet.addRange(addr("1001000"), addr("10075ff"));
		assertEquals(addr("1001034"), cb.getCurrentAddress());
		assertEquals(addr("1001034"), getDiffAddress());
		assertEquals(cb.getCurrentSelection(),
			new ProgramSelection(addr("1001034"), addr("1001034")));
		assertEquals(viewSet, cb.getView());

		// bottom of View .text
		bottomOfFile(fp1);
		assertEquals(addr("10075ff"), cb.getCurrentAddress());
		assertEquals(addr("10075ff"), getDiffAddress());

		// Next Diff should add .data to the view
		invokeLater(nextDiff);
		waitForSwing();
		viewSet.addRange(addr("1008000"), addr("10085ff"));
		assertEquals(addr("1008000"), cb.getCurrentAddress());
		assertEquals(addr("1008000"), getDiffAddress());
		assertEquals(cb.getCurrentSelection(),
			new ProgramSelection(addr("1008000"), addr("1008000")));
		assertEquals(viewSet, cb.getView());

		// bottom of View .data
		bottomOfFile(fp1);
		assertEquals(addr("10085ff"), cb.getCurrentAddress());
		assertEquals(addr("10085ff"), getDiffAddress());

		// Next Diff should add .datau to the view
		invokeLater(nextDiff);

		viewSet.addRange(addr("1008600"), addr("1009943"));
		assertEquals(addr("1008607"), cb.getCurrentAddress());
		assertEquals(addr("1008607"), getDiffAddress());
		assertEquals(cb.getCurrentSelection(),
			new ProgramSelection(addr("1008607"), addr("1008607")));
		assertEquals(viewSet, cb.getView());

		// bottom of View .datau
		bottomOfFile(fp1);
		assertEquals(addr("1009943"), cb.getCurrentAddress());
		assertEquals(addr("1009943"), getDiffAddress());

		// Next Diff should add .rsrc to the view
		invokeLater(nextDiff);

		viewSet.addRange(addr("100a000"), addr("100f3ff"));
		assertEquals(addr("100a001"), cb.getCurrentAddress());
		assertEquals(addr("100a001"), getDiffAddress());
		assertEquals(cb.getCurrentSelection(),
			new ProgramSelection(addr("100a001"), addr("100a001")));
		assertEquals(viewSet, cb.getView());
	}

	@Test
	public void testDiffWithChangeTabs() throws Exception {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		ProgramBuilder builder3 = new ProgramBuilder("Program3", ProgramBuilder._X86);
		builder3.createMemory(".text", "0x1001000", 0x6600);
		builder3.createMemory(".data", "0x1008000", 0x600);
		ProgramDB program3 = builder3.getProgram();

		ProgramBuilder builder4 = new ProgramBuilder("Program4", ProgramBuilder._X86);
		builder4.createMemory(".text", "0x1001000", 0x6600);
		builder4.createMemory(".data", "0x1008000", 0x600);
		ProgramDB program4 = builder4.getProgram();

		tool.removePlugins(new Plugin[] { pt });
		tool.addPlugin(MultiTabPlugin.class.getName());
		openProgram(program3);
		openProgram(program4);
		openProgram(diffTestP1);

		openDiff(diffTestP2);
		assertNotNull(fp2.getTopLevelAncestor());
		ProgramSelection expectedSelection = new ProgramSelection(getSetupAllDiffsSet());
		checkIfSameSelection(expectedSelection, diffPlugin.getDiffHighlightSelection());

		MultiTabPanel panel = findComponent(tool.getToolFrame(), MultiTabPanel.class);

		assertEquals(true, isDiffing());
		assertEquals(true, isShowingDiff());
		// Check action enablement.
		checkDiffAction("View Program Differences", true, true);
		checkDiffAction("Open/Close Program View", true, true);
		checkDiffAction("Apply Differences", true, false);
		checkDiffAction("Apply Differences and Goto Next Difference", true, false);
		checkDiffAction("Ignore Selection and Goto Next Difference", true, false);
		checkDiffAction("Next Difference", true, true);
		checkDiffAction("Previous Difference", true, false);
		checkDiffAction("Show Diff Location Details", true, true);
		checkDiffAction("Show Diff Apply Settings", true, true);
		checkDiffAction("Get Differences", true, true);
		checkDiffAction("Select All Differences", true, true);
		checkDiffAction("Set Program1 Selection On Program2", true, false);

		// Check background color where there is and isn't a difference.
		setLocation("1002995");
		assertEquals(addr("1002995"), diffPlugin.getCurrentAddress());
		BigInteger index = fp2.getCursorLocation().getIndex();
		Color bg = getBgColor(fp1, index);
		Color bg2 = getBgColor(fp2, index);
		assertEquals(bg, bg2);
		checkDiffAction("Next Difference", true, true);
		checkDiffAction("Previous Difference", true, true);
		setLocation("100299e");
		index = fp2.getCursorLocation().getIndex();
		assertEquals(addr("100299e"), diffPlugin.getCurrentAddress());
		bg = getBgColor(fp1, index);
		bg2 = getBgColor(fp2, index);
		assertEquals(bg, bg2);
		checkDiffAction("Next Difference", true, true);
		checkDiffAction("Previous Difference", true, true);

		selectTab(panel, program3);
		assertEquals(true, isDiffing());
		assertEquals(false, isShowingDiff());
		// Check action enablement.
		checkDiffAction("View Program Differences", true, true);
		checkDiffAction("Apply Differences", false, false);
		checkDiffAction("Apply Differences and Goto Next Difference", false, false);
		checkDiffAction("Ignore Selection and Goto Next Difference", false, false);
		checkDiffAction("Next Difference", false, false);
		checkDiffAction("Previous Difference", false, false);
		checkDiffAction("Show Diff Location Details", false, false);
		checkDiffAction("Show Diff Apply Settings", false, false);
		checkDiffAction("Get Differences", false, false);
		checkDiffAction("Select All Differences", false, false);
		checkDiffAction("Set Program1 Selection On Program2", false, false);

		selectTab(panel, program4);
		assertEquals(true, isDiffing());
		assertEquals(false, isShowingDiff());
		// Check action enablement.
		checkDiffAction("View Program Differences", true, true);
		checkDiffAction("Apply Differences", false, false);
		checkDiffAction("Apply Differences and Goto Next Difference", false, false);
		checkDiffAction("Ignore Selection and Goto Next Difference", false, false);
		checkDiffAction("Next Difference", false, false);
		checkDiffAction("Previous Difference", false, false);
		checkDiffAction("Show Diff Location Details", false, false);
		checkDiffAction("Show Diff Apply Settings", false, false);
		checkDiffAction("Get Differences", false, false);
		checkDiffAction("Select All Differences", false, false);
		checkDiffAction("Set Program1 Selection On Program2", false, false);

		selectTab(panel, diffTestP1);
		assertEquals(true, isDiffing());
		assertEquals(true, isShowingDiff());
		assertEquals(addr("100299e"), diffPlugin.getCurrentAddress());
		// Check action enablement.
		checkDiffAction("View Program Differences", true, true);
		checkDiffAction("Apply Differences", true, false);
		checkDiffAction("Apply Differences and Goto Next Difference", true, false);
		checkDiffAction("Ignore Selection and Goto Next Difference", true, false);
		checkDiffAction("Next Difference", true, true);
		checkDiffAction("Previous Difference", true, true);
		checkDiffAction("Show Diff Location Details", true, true);
		checkDiffAction("Show Diff Apply Settings", true, true);
		checkDiffAction("Get Differences", true, true);
		checkDiffAction("Select All Differences", true, true);
		checkDiffAction("Set Program1 Selection On Program2", true, false);

		// Now close the Diff.
		closeDiff();
		assertNull(diffListingPanel.getProgram());
		assertEquals(false, isDiffing());
		assertEquals(false, isShowingDiff());

	}

	@Test
	public void testOpenCloseProgramAction() throws Exception {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		ProgramBuilder builder3 = new ProgramBuilder("Program3", ProgramBuilder._X86);
		builder3.createMemory(".text", "0x1001000", 0x6600);
		builder3.createMemory(".data", "0x1008000", 0x600);
		ProgramDB program3 = builder3.getProgram();

		ProgramBuilder builder4 = new ProgramBuilder("Program4", ProgramBuilder._X86);
		builder4.createMemory(".text", "0x1001000", 0x6600);
		builder4.createMemory(".data", "0x1008000", 0x600);
		ProgramDB program4 = builder4.getProgram();

		tool.removePlugins(new Plugin[] { pt });
		tool.addPlugin(MultiTabPlugin.class.getName());
		openProgram(program3);
		openProgram(program4);
		openProgram(diffTestP1);

		openDiff(diffTestP2);
		assertNotNull(fp2.getTopLevelAncestor());
		ProgramSelection expectedSelection = new ProgramSelection(getSetupAllDiffsSet());
		checkIfSameSelection(expectedSelection, diffPlugin.getDiffHighlightSelection());

		MultiTabPanel panel = findComponent(tool.getToolFrame(), MultiTabPanel.class);

		assertEquals(true, isDiffing());
		assertEquals(true, isShowingDiff());
		checkDiffAction("Open/Close Program View", true, true);

		//
		// Different tab--still enabled
		//
		selectTab(panel, program3);
		checkDiffAction("Open/Close Program View", true, true);

		clickDiffButton();
		assertTrue("Not diffing after clicking the diff button when on a non-diff tab",
			isDiffing());
		assertTrue("Diff not showing after clicking the diff button when on a non-diff tab",
			isShowingDiff());

		//
		// Diff tab--still enabled
		//
		checkDiffAction("Open/Close Program View", true, true);

		clickDiffButton();

		DialogComponentProvider dialogProvider = waitForDialogComponent("Close Diff Session");
		assertNotNull("Did not get confirmation dialog", dialogProvider);
		pressButtonByText(dialogProvider.getComponent(), "Yes", true);
		waitForSwing();

		assertFalse("Still diffing after clicking the diff button when on the diff tab",
			isDiffing());
		assertFalse("Still showing diff after clicking the diff button when on the diff tab",
			isShowingDiff());
	}

	@Test
	public void testOpenCloseArrayWithDiffShowing() throws Exception {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		openDiff(diffTestP1, diffTestP2);
		waitForSwing();

		ArrayDataType array = new ArrayDataType(new WordDataType(), 12, 2);
		CreateDataCmd cmd = new CreateDataCmd(addr("0x00000106"), array);
		tool.execute(cmd, diffTestP1);

		Data data = diffTestP1.getListing().getDataAt(addr("0x00000106"));
		ListingModel listingModel = cb.getListingModel();
		cb.goToField(addr("0x00000106"), "+", 0, 0);
		assertTrue(cb.getCurrentField() instanceof OpenCloseField);
		assertFalse("Array is not closed as expected.", listingModel.isOpen(data));
		cb.goToField(addr("0x00000120"), "Address", 0, 0);
		assertEquals("00000120", cb.getCurrentFieldText());
		cb.goToField(addr("0x00000106"), "Address", 0, 0);
		assertEquals("00000106", cb.getCurrentFieldText());

		cb.goToField(addr("0x00000106"), "+", 0, 0);
		click(cb, 1);
		waitForSwing();
		assertTrue("Array failed to open.", listingModel.isOpen(data));

		cb.goToField(addr("0x00000106"), "+", 0, 0);
		click(cb, 1);
		waitForSwing();
		cb.goToField(addr("0x00000120"), "Address", 0, 0);
		cb.goToField(addr("0x00000106"), "Address", 0, 0);
		assertEquals("00000106", cb.getCurrentFieldText());
		assertFalse("Array failed to close.", listingModel.isOpen(data));

	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private Color getBgColor(FieldPanel fp, BigInteger index) {
		return runSwing(() -> fp.getBackgroundColor(index));
	}

	private CountDownLatch installDiffBlockingLatch() {
		final CountDownLatch continueLatch = new CountDownLatch(1);

		diffPlugin.setDiffTaskListener(inProgress -> {
			try {
				continueLatch.await(5, TimeUnit.SECONDS);
			}
			catch (InterruptedException e) {
				// shouldn't happen
				throw new RuntimeException("Unexpectedly interrupted while blocking the diff task!",
					e);
			}
		});
		return continueLatch;
	}

	private void clickDiffButton() {
		runSwing(() -> {
			openClosePgm2.setSelected(!openClosePgm2.isSelected());
			openClosePgm2.actionPerformed(new ActionContext());
		}, false);
		waitForSwing();
	}

	/**
	 * Checks that the specified Diff action is in the indicated state and
	 * causes a JUnit assert if not.
	 * 
	 * @param actionName the name of the DIff action.
	 * @param inTool the action is currently added to the tool.
	 * @param enabled the action is enabled.
	 */
	private void checkDiffAction(String actionName, boolean inTool, boolean enabled) {
		DockingActionIf tmpAction = getAction(diffPlugin, actionName);
		if (inTool) {
			if (tmpAction == null) {
				assertNotNull("Diff action, " + actionName + ", was not in the tool as expected.",
					tmpAction);
			}
		}
		else {
			if (tmpAction != null) {
				assertNull("Diff action, " + actionName + ", was unexpectedly found in the tool.",
					tmpAction);
			}
		}
		if (tmpAction == null) {
			return;
		}
		assertEquals("Diff action, " + actionName + ", was unexpectedly " +
			(enabled ? "disabled" : "enabled") + ".", enabled, tmpAction.isEnabled());
	}

	private boolean isDiffing() {
		if (diffPlugin == null) {
			return false;
		}
		if (diffPlugin.getFirstProgram() == null || diffPlugin.getDiffController() == null) {
			return false;
		}
		return true;
	}

	private boolean isShowingDiff() {
		if (diffPlugin == null) {
			return false;
		}
		Program currentProgram = diffPlugin.getCurrentProgram();
		Program firstProgram = diffPlugin.getFirstProgram();
		if (currentProgram == null || currentProgram != firstProgram) {
			return false;
		}
		return true;
	}

	private void selectTab(final MultiTabPanel panel, final Program pgm) {
		runSwing(() -> invokeInstanceMethod("setSelectedProgram", panel,
			new Class[] { Program.class }, new Object[] { pgm }), true);
		waitForSwing();
	}

	private void selectTreeNodeByText(final JTree tree, final String text) throws Exception {
		runSwing(() -> {
			TreePath path = findTreePathToText(tree, text);
			if (path == null) {
				throw new RuntimeException("tree path is null.");
			}
			tree.expandPath(path);
		});

		waitForSwing();

		runSwing(() -> {
			TreePath path = findTreePathToText(tree, text);
			if (path == null) {
				throw new RuntimeException("tree path is null.");
			}
			tree.getSelectionModel().setSelectionPath(path);
		});
	}

}
