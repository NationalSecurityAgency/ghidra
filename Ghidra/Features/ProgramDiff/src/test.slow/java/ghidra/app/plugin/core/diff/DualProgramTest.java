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

import java.awt.Component;
import java.awt.Window;
import java.awt.event.KeyEvent;

import javax.swing.JComboBox;
import javax.swing.JTree;
import javax.swing.tree.TreePath;

import org.junit.Test;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.widgets.MultiLineLabel;
import docking.widgets.fieldpanel.LayoutModel;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.services.ProgramManager;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.symbol.SourceType;

public class DualProgramTest extends DiffTestAdapter {

	@Test
	public void testOpenClosePgm2Enablement() throws Exception {
		assertNotNull(openClosePgm2);
		assertTrue(!openClosePgm2.isEnabled());
		loadProgram(diffTestP1);
		assertTrue(openClosePgm2.isEnabled());
		closeProgram();
		assertTrue(!openClosePgm2.isEnabled());
	}

	@Test
	public void testCancelOpenSecondProgram() throws Exception {
		Window win;
		Component comp;

		restoreProgram(diffTestP2);
		loadProgram(diffTestP1);
		launchDiffByAction();
		win = waitForWindow("Select Other Program");
		assertNotNull(win);
		comp = getComponentOfType(win, JComboBox.class);
		assertNotNull(comp);

		JTree tree = findComponent(win, JTree.class);
		TreeTestUtils.selectTreeNodeByText(tree, "DiffTestPgm2");
		pressButton(win, "Cancel");
		waitForSwing();
		assertNull(fp2.getTopLevelAncestor());

		win = getWindow("Select Other Program");
		assertNull(win);
		closeProgram();
		assertNull(cb.getCurrentLocation());
	}

	@Test
	public void testEscapeOpenSecondProgram() throws Exception {

		restoreProgram(diffTestP2);
		loadProgram(diffTestP1);
		launchDiffByAction();
		Window win = waitForWindow("Select Other Program");
		assertNotNull(win);
		waitForSwing();

		Component comp = getComponentOfType(win, JComboBox.class);
		assertNotNull(comp);

		JTree tree = findComponent(win, JTree.class);
		TreeTestUtils.selectTreeNodeByText(tree, "DiffTestPgm2");
		triggerActionKey(comp, 0, KeyEvent.VK_ESCAPE);
		waitForSwing();
		assertNull(fp2.getTopLevelAncestor());

		win = getWindow("Select Other Program");
		assertNull(win);
		closeProgram();
		assertNull(cb.getCurrentLocation());
	}

	@Test
	public void testOpenSecondProgram() throws Exception {
		openSecondProgram(diffTestP1, diffTestP2);
		assertNotNull(fp2.getTopLevelAncestor());

		// Check action enablement.
		assertTrue(viewDiffs.isEnabled());
		assertTrue(!applyDiffs.isEnabled());
		assertTrue(!applyDiffsNext.isEnabled());
		assertTrue(!ignoreDiffs.isEnabled());
		assertTrue(!nextDiff.isEnabled());
		assertTrue(!prevDiff.isEnabled());
		assertTrue(diffDetails.isEnabled());
		assertTrue(!diffApplySettings.isEnabled());
		assertTrue(getDiffs.isEnabled());
		assertTrue(selectAllDiffs.isEnabled());
		assertTrue(!setPgm2Selection.isEnabled());
	}

	@Test
	public void testCloseSecondProgram() throws Exception {
		openSecondProgram(diffTestP1, diffTestP2);
		assertNotNull(fp2.getTopLevelAncestor());

		closeDiff();
		assertNull(fp2.getTopLevelAncestor());
	}

	@Test
	public void testNonMatchingProgramType() throws Exception {
		ProgramBuilder otherBuilder = new ProgramBuilder("OtherProgram", ProgramBuilder._SPARC64);
		ProgramDB otherProgram = otherBuilder.getProgram();

		restoreProgram(otherProgram);
		loadProgram(diffTestP1);
		launchDiffByAction();
		Window win = waitForWindow("Select Other Program");
		assertNotNull(win);
		Component comp = getComponentOfType(win, JComboBox.class);
		assertNotNull(comp);

		JTree tree = findComponent(win, JTree.class);
		TreeTestUtils.selectTreeNodeByText(tree, "OtherProgram");
		pressButton(win, "OK");

		waitForTasks();
		win = waitForWindow("Can't Open Selected Program");
		pressButton(win, "OK");

		win = waitForWindow("Select Other Program");
		assertNotNull(win);
		pressButton(win, "Cancel");
	}

	@Test
	public void testNoMemInCommonContinueNo() throws Exception {
		ProgramBuilder otherBuilder = new ProgramBuilder("OtherProgram", ProgramBuilder._X86);
		ProgramDB otherProgram = otherBuilder.getProgram();
		otherBuilder.createMemory(".stuff", "0x1000600", 0x300);

		restoreProgram(otherProgram);
		loadProgram(diffTestP1);

		launchDiffByAction();
		Window win = waitForWindow("Select Other Program");
		assertNotNull(win);
		Component comp = getComponentOfType(win, JComboBox.class);
		assertNotNull(comp);

		JTree tree = findComponent(win, JTree.class);
		TreeTestUtils.selectTreeNodeByText(tree, "OtherProgram");
		pressButton(win, "OK");
		waitForTasks();
		win = waitForWindow("No Memory In Common");
		assertNotNull(win);
		MultiLineLabel mll = findComponent(win, MultiLineLabel.class);
		assertTrue(
			mll.getLabel().startsWith("The two programs have no memory addresses in common."));
		pressButton(win, "No");

		win = waitForWindow("Select Other Program");
		assertNotNull(win);
		pressButton(win, "Cancel");
	}

	@Test
	public void testNoMemInCommonContinueYes() throws Exception {
		ProgramBuilder otherBuilder = new ProgramBuilder("OtherProgram", ProgramBuilder._X86);
		ProgramDB otherProgram = otherBuilder.getProgram();
		otherBuilder.createMemory(".stuff", "0x1000600", 0x300);

		restoreProgram(otherProgram);
		loadProgram(diffTestP1);

		launchDiffByAction();
		Window win = waitForWindow("Select Other Program");
		assertNotNull(win);
		Component comp = getComponentOfType(win, JComboBox.class);
		assertNotNull(comp);

		JTree tree = findComponent(win, JTree.class);
		TreeTestUtils.selectTreeNodeByText(tree, "OtherProgram");
		pressButton(win, "OK");
		waitForTasks();

		win = waitForWindow("No Memory In Common");
		assertNotNull(win);
		MultiLineLabel mll = findComponent(win, MultiLineLabel.class);
		assertTrue(
			mll.getLabel().startsWith("The two programs have no memory addresses in common."));
		pressButton(win, "Yes");

		win = waitForWindow("Determine Program Differences");
		assertNotNull(win);
		pressButton(win, "OK");
		assertTrue(!win.isShowing());

		waitForTasks();

		win = waitForWindow("Memory Differs");
		assertNotNull(win);
		pressButton(win, "OK");
	}

	@Test
	public void testDiffPgmSameLanguage() throws Exception {
		ProgramBuilder otherBuilder = new ProgramBuilder("OtherProgram", ProgramBuilder._X86);
		ProgramDB otherProgram = otherBuilder.getProgram();
		otherBuilder.createMemory(".stuff", "0x1004000", 0x300);

		Window win;
		Component comp;
		//InfoWindow.showSplashScreen(); 
		showTool(frontEndTool);
		env.showTool();

		restoreProgram(otherProgram);
		loadProgram(diffTestP1);

		launchDiffByAction();
		waitForSwing();
		win = waitForWindow("Select Other Program");
		assertNotNull(win);
		comp = getComponentOfType(win, JComboBox.class);
		assertNotNull(comp);

		JTree tree = findComponent(win, JTree.class);
		TreeTestUtils.selectTreeNodeByText(tree, "OtherProgram");
		pressButton(win, "OK");
		waitForTasks();
		waitForSwing();
		win = getWindow("Select Other Program");
		assertNull(win);

		assertNotNull(fp2.getTopLevelAncestor());
		assertEquals("DiffTestPgm1", diffPlugin.getCurrentProgram().getName());
		assertEquals("OtherProgram", diffPlugin.getSecondProgram().getName());
	}

	@Test
	public void testReplacePgm2() throws Exception {
		ProgramBuilder otherBuilder = new ProgramBuilder("OtherProgram", ProgramBuilder._X86);
		ProgramDB otherProgram = otherBuilder.getProgram();
		otherBuilder.createMemory(".stuff", "0x1004000", 0x300);

		Window win;
		Component comp;

		restoreProgram(otherProgram);
		restoreProgram(diffTestP2);
		loadProgram(diffTestP1);
		getDiffActions();
		assertNull(fp2.getTopLevelAncestor());

		launchDiffByAction();

		win = waitForWindow("Select Other Program");
		assertNotNull(win);
		comp = getComponentOfType(win, JComboBox.class);
		assertNotNull(comp);

		JTree tree = findComponent(win, JTree.class);
		TreeTestUtils.selectTreeNodeByText(tree, "OtherProgram");
		pressButton(win, "OK");
		waitForTasks();
		waitForSwing();

		win = getWindow("Select Other Program");
		assertNull(win);

		assertNotNull(fp2.getTopLevelAncestor());
		ProgramManager pm = tool.getService(ProgramManager.class);
		assertEquals("DiffTestPgm1", pm.getCurrentProgram().getName());
		assertEquals("OtherProgram", diffPlugin.getSecondProgram().getName());

		DialogComponentProvider dialog = waitForDialogComponent(DialogComponentProvider.class);
		// press the Cancel button
		pressButtonByText(dialog, "Cancel");
		waitForSwing();

		closeDiff();
		assertFalse(openClosePgm2.isSelected());

		runSwing(() -> {
			openClosePgm2.setSelected(true);
			openClosePgm2.actionPerformed(new ActionContext());
		}, false);
		waitForSwing();

		waitForCondition(() -> openClosePgm2.isSelected());
		assertEquals(true, openClosePgm2.isSelected());

		win = waitForWindow("Select Other Program");
		assertNotNull(win);
		tree = findComponent(win, JTree.class);
		TreeTestUtils.selectTreeNodeByText(tree, "DiffTestPgm2");
		pressButton(win, "OK");
		waitForTasks();
		assertTrue(!win.isVisible());

		assertNotNull(fp2.getTopLevelAncestor());
		assertEquals("DiffTestPgm1", diffPlugin.getCurrentProgram().getName());
		assertEquals("DiffTestPgm2", diffPlugin.getSecondProgram().getName());

		dialog = waitForDialogComponent(DialogComponentProvider.class);
		// press the Cancel button
		pressButtonByText(dialog, "Cancel");
	}

	@Test
	public void testOpenSameSecondProgram() throws Exception {
		openSecondProgram(diffTestP1, diffTestP1);
		assertNotNull(fp2.getTopLevelAncestor());

		// Check action enablement.
		assertTrue(viewDiffs.isEnabled());
		assertTrue(!applyDiffs.isEnabled());
		assertTrue(!applyDiffsNext.isEnabled());
		assertTrue(!ignoreDiffs.isEnabled());
		assertTrue(!nextDiff.isEnabled());
		assertTrue(!prevDiff.isEnabled());
		assertTrue(diffDetails.isEnabled());
		assertTrue(!diffApplySettings.isEnabled());
		assertTrue(getDiffs.isEnabled());
		assertTrue(selectAllDiffs.isEnabled());
		assertTrue(!setPgm2Selection.isEnabled());

		// Modify the active program.
		setLocation("100f3ff");
		CompoundCmd cmd = new CompoundCmd("test");
		cmd.add(new AddLabelCmd(addr("100f3ff"), "TestLabel", false, SourceType.USER_DEFINED));
		cmd.add(
			new AddLabelCmd(addr("100f3ff"), "AnotherTestLabel", false, SourceType.USER_DEFINED));
		try {
			txId = diffTestP1.startTransaction("Modify Program");
			cmd.applyTo(diffTestP1);
		}
		finally {
			diffTestP1.endTransaction(txId, true);
		}

		// Check that the two programs now differ.
		assertTrue(viewDiffs.isEnabled());
		LayoutModel lm1 = fp1.getLayoutModel();
		LayoutModel lm2 = fp2.getLayoutModel();
		int num1 = lm1.getNumIndexes().intValue();
		int num2 = lm2.getNumIndexes().intValue();
		assertEquals(num1, num2);
	}

	@Test
	public void testEntireViewDiff() throws Exception {
		openSecondProgram(diffTestP1, diffTestP2);
		JTree tree = findComponent(tool.getToolFrame(), JTree.class);
		selectTreeNodeByText(tree, "DiffTestPgm1");
		performAction(replaceView, true);
		topOfFile(fp1);
		assertEquals(addr("00000100"), cb.getCurrentAddress());
		bottomOfFile(fp1);
		assertEquals(addr("100f3ff"), cb.getCurrentAddress());
	}

	@Test
	public void testSingleFragmentDiff() throws Exception {
		openSecondProgram(diffTestP1, diffTestP2);
		JTree tree = findComponent(tool.getToolFrame(), JTree.class);
		selectTreeNodeByText(tree, ".data");
		performAction(replaceView, true);
		topOfFile(fp1);
		assertEquals(addr("1008000"), cb.getCurrentAddress());
		bottomOfFile(fp1);
		assertEquals(addr("10085ff"), cb.getCurrentAddress());
	}

	@Test
	public void testMultipleFragmentsDiff() throws Exception {
		openSecondProgram(diffTestP1, diffTestP2);
		JTree tree = findComponent(tool.getToolFrame(), JTree.class);
		selectTreeNodeByText(tree, ".data");
		performAction(replaceView, true);
		selectTreeNodeByText(tree, ".rsrc");

		performAction(goToView, true);

		topOfFile(fp1);
		assertEquals(addr("1008000"), cb.getCurrentAddress());
		bottomOfFile(fp1);
		assertEquals(addr("100f3ff"), cb.getCurrentAddress());
	}

	@Test
	public void testEmptyViewDiff() throws Exception {
		openSecondProgram(diffTestP1, diffTestP2);
		JTree tree = findComponent(tool.getToolFrame(), JTree.class);
		selectTreeNodeByText(tree, "DiffTestPgm1");
		performAction(removeView, true);
		topOfFile(fp1);
		assertNull(cb.getCurrentAddress());
		bottomOfFile(fp1);
		assertNull(cb.getCurrentAddress());
		assertEquals(0, fp1.getLayoutModel().getNumIndexes().intValue());
		assertEquals(0, fp2.getLayoutModel().getNumIndexes().intValue());
	}

	/**
	 * Selects a tree node in the indicated tree with the specified text. 
	 * The matching tree node is determined by comparing the specified text 
	 * with the string returned by the tree node's toString() method.
	 * <br> Note: This method affects the expansion state of the tree. It
	 * will expand nodes starting at the root until a match is found or all
	 * of the tree is checked.
	 * @param tree the tree
	 * @param text the tree node's text
	 */
	public static void selectTreeNodeByText(final JTree tree, final String text) {
		runSwing(() -> {
			TreePath path = findTreePathToText(tree, text);
			if (path == null) {
				throw new RuntimeException("tree path is null.");
			}
			tree.expandPath(path);
		}, false);

		waitForSwing();

		runSwing(() -> {
			TreePath path = findTreePathToText(tree, text);
			if (path == null) {
				throw new RuntimeException("tree path is null.");
			}
			tree.getSelectionModel().setSelectionPath(path);
		}, false);
	}

}
