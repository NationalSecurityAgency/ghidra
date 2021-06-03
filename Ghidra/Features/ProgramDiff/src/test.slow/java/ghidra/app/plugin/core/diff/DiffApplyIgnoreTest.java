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

import java.util.Arrays;
import java.util.Comparator;

import javax.swing.JDialog;

import org.junit.Test;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramSelection;

public class DiffApplyIgnoreTest extends DiffApplyTestAdapter {

	@Test
	public void testProgramContextIgnore() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		assertNotNull(dialog);
		pressButtonByText(dialog, "OK");
		waitForSwing();
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		ignore(programContextApplyCB);
		AddressSet as = new AddressSet(addr("1002378"), addr("1002383"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testByteIgnore() throws Exception {

		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		assertNotNull(dialog);
		pressButtonByText(dialog, "OK");
		waitForSwing();
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		ignore(byteApplyCB);
		AddressSet as = new AddressSet(addr("1002b45"), addr("1002b45"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testCodeUnitIgnore() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		assertNotNull(dialog);
		pressButtonByText(dialog, "OK");
		waitForSwing();
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		ignore(codeUnitApplyCB);
		AddressSet as = new AddressSet(addr("10024b8"), addr("10024b8"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testReferenceIgnore() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		assertNotNull(dialog);
		pressButtonByText(dialog, "OK");
		waitForSwing();
		showApplySettings();

		memRefIgnore();
		extRefIgnore();
		stackRefIgnore();
	}

	private void memRefIgnore() {
		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		ignore(refApplyCB);
		AddressSet as = new AddressSet(addr("1002a2a"), addr("1002a2a"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
	}

	private void extRefIgnore() {
		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		ignore(refApplyCB);
		AddressSet as = new AddressSet(addr("1001034"), addr("1001037"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
	}

	private void stackRefIgnore() {
		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		ignore(refApplyCB);
		AddressSet as = new AddressSet(addr("10029d1"), addr("10029d1"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testCommentIgnore() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		showApplySettings();

		plateCommentIgnore();
		preCommentIgnore();
		eolCommentIgnore();
		repeatableCommentIgnore();
		postCommentIgnore();
	}

	private void plateCommentIgnore() {
		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		ignore(plateCommentApplyCB);
		AddressSet as = new AddressSet(addr("100415a"), addr("100415a"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
	}

	private void preCommentIgnore() {
		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		ignore(preCommentApplyCB);
		AddressSet as = new AddressSet(addr("1002395"), addr("1002395"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
	}

	private void eolCommentIgnore() {
		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		ignore(eolCommentApplyCB);
		AddressSet as = new AddressSet(addr("100238f"), addr("100238f"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
	}

	private void repeatableCommentIgnore() {
		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		ignore(repeatableCommentApplyCB);
		AddressSet as = new AddressSet(addr("1002336"), addr("1002336"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
	}

	private void postCommentIgnore() {
		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		ignore(postCommentApplyCB);
		AddressSet as = new AddressSet(addr("100239d"), addr("100239d"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testLabelIgnore() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		showApplySettings();
		ignore(labelApplyCB);

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		AddressSet as = new AddressSet(addr("1002a0c"), addr("1002a0c"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
		SymbolTable symtab = program.getSymbolTable();
		Symbol[] symbols = symtab.getSymbols(addr("1002a0c"));
		Comparator<Symbol> c = SymbolUtilities.getSymbolNameComparator();
		Arrays.sort(symbols, c);
		assertEquals(2, symbols.length);
		assertEquals("getResources", symbols[0].getName());
		assertEquals("mySymbol", symbols[1].getName());
		assertTrue(symbols[0].isPrimary());
		assertFalse(symbols[1].isPrimary());
	}

	@Test
	public void testBookmarkIgnore() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		assertNotNull(dialog);
		pressButtonByText(dialog, "OK");
		waitForSwing();
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		ignore(bookmarkApplyCB);
		AddressSet as = new AddressSet(addr("1002318"), addr("1002318"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testPropertyIgnore() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		assertNotNull(dialog);
		pressButtonByText(dialog, "OK");
		waitForSwing();
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		ignore(propertiesApplyCB);
		AddressSet as = new AddressSet(addr("100248c"), addr("100248e"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testFunctionIgnore() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		assertNotNull(dialog);
		pressButtonByText(dialog, "OK");
		waitForSwing();
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		AddressSet as = new AddressSet(addr("100299e"), addr("100299e"));
		assertTrue("Original diff set doesn't contain " + as.toString(), origDiffs.contains(as));
		ignore(functionApplyCB);
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
	}

}
