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

import java.util.List;

import javax.swing.JDialog;

import org.junit.Test;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.Equate;
import ghidra.program.util.ProgramSelection;

public class DiffApply2Test extends DiffApplyTestAdapter {

	@Test
	public void testApplyDiffsNextActionFirst() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForPostedSwingRunnables();
		showApplySettings();

		byte[] bytes = diffTestP1.getListing().getCodeUnitAt(addr("100")).getBytes();
		assertEquals((byte) 0xac, bytes[0]);

		AddressSet addrSet = new AddressSet(addr("100"), addr("1ff"));
		setDiffSelection(addrSet);
		setLocation("100");
		applyAndNext();

		checkDiffSelection(new AddressSet(addr("00000200"), addr("000002ff")));
		assertTrue(diffPlugin.getDiffHighlightSelection().intersect(addrSet).isEmpty());
		assertEquals(addr("00000200"), getDiffAddress());
		bytes = diffTestP1.getListing().getCodeUnitAt(addr("100")).getBytes();
		assertEquals((byte) 0xaf, bytes[0]);
	}

	@Test
	public void testApplyDiffsNextActionMiddle() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForPostedSwingRunnables();
		showApplySettings();

		List<Equate> eqs = diffTestP1.getEquateTable().getEquates(addr("1002261"), 0);
		assertEquals(0, eqs.size());

		AddressSet addrSet = new AddressSet(addr("1002261"), addr("1002262"));
		setDiffSelection(addrSet);
		setLocation("1002261"); // has Equate Diff
		applyAndNext();

		checkDiffSelection(new AddressSet(addr("10022d4"), addr("10022e5")));
		assertEquals(addr("10022d4"), getDiffAddress());
		eqs = program.getEquateTable().getEquates(addr("1002261"), 0);
		assertEquals(1, eqs.size());
		assertEquals(eqs.get(0).getName(), "uno");
		assertEquals(eqs.get(0).getValue(), 1);
	}

	@Test
	public void testApplyDiffsNextActionLast() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForPostedSwingRunnables();
		showApplySettings();

		AddressSet addrSet = new AddressSet(addr("1005e4f"), addr("1005e53"));
		setDiffSelection(addrSet);
		setLocation("1005e4f");
		assertTrue(!applyDiffsNext.isEnabled());
	}

	@Test
	public void testIgnoreEntireBlock() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForPostedSwingRunnables();
		showApplySettings();

		// Cursor in selection
		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		AddressSet addrSet = new AddressSet(addr("1002378"), addr("1002396"));
		setDiffSelection(addrSet);
		setLocation("1002378");
		assertNotNull(ignoreDiffs);
		assertTrue(ignoreDiffs.isEnabled());
		invokeLater(ignoreDiffs);
		waitForPostedSwingRunnables();
		AddressSet expectedDiffs = origDiffs.subtract(addrSet);
		ProgramSelection newSet = diffPlugin.getDiffHighlightSelection();
		assertTrue(newSet.intersect(addrSet).isEmpty());
		assertTrue(expectedDiffs.equals(newSet));

		ProgramSelection sel = runSwing(() -> cb.getCurrentSelection());
		assertFalse(sel.isEmpty());

		// Cursor outside selection
		origDiffs = diffPlugin.getDiffHighlightSelection();
		addrSet = new AddressSet(addr("100239d"), addr("100239d"));
		setDiffSelection(addrSet);
		setLocation("100239d");
		assertNotNull(ignoreDiffs);
		assertTrue(ignoreDiffs.isEnabled());
		invokeLater(ignoreDiffs);
		waitForPostedSwingRunnables();
		expectedDiffs = origDiffs.subtract(addrSet);
		newSet = diffPlugin.getDiffHighlightSelection();
		assertTrue(newSet.intersect(addrSet).isEmpty());
		assertTrue(expectedDiffs.equals(newSet));

		sel = runSwing(() -> cb.getCurrentSelection());
		assertFalse(sel.isEmpty());
	}

	@Test
	public void testIgnorePartialBlock() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForPostedSwingRunnables();
		showApplySettings();

		// Cursor in selection
		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		AddressSet addrSet = new AddressSet(addr("1002a0b"), addr("1002a0b"));
		addrSet.addRange(addr("1002a0d"), addr("1002a0d"));
		setDiffSelection(addrSet);
		setLocation("10029fe");
		assertNotNull(ignoreDiffs);
		assertTrue(ignoreDiffs.isEnabled());
		invokeLater(ignoreDiffs);
		waitForPostedSwingRunnables();
		AddressSet expectedDiffs = origDiffs.subtract(addrSet);
		ProgramSelection newSet = diffPlugin.getDiffHighlightSelection();
		assertTrue(newSet.intersect(addrSet).isEmpty());
		assertTrue(expectedDiffs.equals(newSet));

		ProgramSelection sel = runSwing(() -> cb.getCurrentSelection());
		assertFalse(sel.isEmpty());
	}

	@Test
	public void testUndoRedo() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForPostedSwingRunnables();
		showApplySettings();

		List<Equate> eqs = program.getEquateTable().getEquates(addr("1002261"), 0);
		assertEquals(0, eqs.size());

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();

		AddressSet addrSet = new AddressSet(addr("1002261"), addr("1002262"));
		ProgramSelection newDiffs = new ProgramSelection(origDiffs.subtract(addrSet));
		setDiffSelection(addrSet);
		setLocation("1002261"); // has Equate Diff
		apply();

		eqs = program.getEquateTable().getEquates(addr("1002261"), 0);
		assertEquals(1, eqs.size());
		assertEquals(eqs.get(0).getName(), "uno");
		assertEquals(eqs.get(0).getValue(), 1);
		assertEquals(newDiffs, diffPlugin.getDiffHighlightSelection());

		undo(program);

		eqs = program.getEquateTable().getEquates(addr("1002261"), 0);
		assertEquals(0, eqs.size());
		assertEquals(newDiffs, diffPlugin.getDiffHighlightSelection()); // For now we don't try to put diff hilights back.

		redo(program);

		eqs = program.getEquateTable().getEquates(addr("1002261"), 0);
		assertEquals(1, eqs.size());
		assertEquals(eqs.get(0).getName(), "uno");
		assertEquals(eqs.get(0).getValue(), 1);
		assertEquals(newDiffs, diffPlugin.getDiffHighlightSelection());
	}

}
