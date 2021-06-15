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

import java.util.*;

import javax.swing.JDialog;

import org.junit.Test;

import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

public class DiffApplyReplaceTest extends DiffApplyTestAdapter {

	@Test
	public void testProgramContextReplace() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		waitForSwing();
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		replace(programContextApplyCB);
		AddressSet as = new AddressSet(addr("1002378"), addr("1002383"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs.subtract(as), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testByteReplace() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForSwing();
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		replace(byteApplyCB);
		AddressSet as = new AddressSet(addr("1002b45"), addr("1002b45"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs.subtract(as), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testCodeUnitReplace() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForSwing();
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		replace(codeUnitApplyCB);
		AddressSet as = new AddressSet(addr("10024b8"), addr("10024bf"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs.subtract(as), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testReferenceReplace() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForSwing();
		showApplySettings();
		memRefReplace();
		extRefReplace();
		stackRefReplace();
	}

	private void memRefReplace() {
		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		replace(refApplyCB);
		AddressSet as = new AddressSet(addr("1002a2a"), addr("1002a2a"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs.subtract(as), diffPlugin.getDiffHighlightSelection());
	}

	private void extRefReplace() {
		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		replace(refApplyCB);
		AddressSet as = new AddressSet(addr("1001034"), addr("1001037"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs.subtract(as), diffPlugin.getDiffHighlightSelection());
	}

	private void stackRefReplace() {
		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		replace(refApplyCB);
		AddressSet as = new AddressSet(addr("10029d1"), addr("10029d1"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs.subtract(as), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testCommentReplace() {
		openDiff(diffTestP1, diffTestP2);
		showApplySettings();

		plateCommentReplace();
		preCommentReplace();
		eolCommentReplace();
		repeatableCommentReplace();
		postCommentReplace();
	}

	/**
	 * Tests that we can replace tags in one function with tags from another.
	 *
	 * Note: The test programs must be modified a bit to facilitate this test. Specifically
	 *  	 we have to add a function at the same address in both programs, then add tags
	 *  	 to each program, then add those tags to the newly created functions.
	 */
	@Test
	public void testFunctionTagReplace() {

		try {
			loadProgram(diffTestP1);
			loadProgram(diffTestP2);

			FunctionManagerDB funcMgr1 = (FunctionManagerDB) diffTestP1.getFunctionManager();
			FunctionManagerDB funcMgr2 = (FunctionManagerDB) diffTestP2.getFunctionManager();

			// Create a function in Program 1.
			int id = diffTestP1.startTransaction("create1");
			funcMgr1.createFunction("testfunc", addr("1002040"),
				new AddressSet(addr("1002040"), addr("1002048")), SourceType.DEFAULT);
			diffTestP1.endTransaction(id, true);

			// Create a function in Program 2.
			id = diffTestP2.startTransaction("create2");
			funcMgr2.createFunction("testfunc", addr("1002040"),
				new AddressSet(addr("1002040"), addr("1002048")), SourceType.DEFAULT);
			diffTestP2.endTransaction(id, true);

			Function f1 = diffTestP1.getFunctionManager().getFunctionAt(addr("1002040"));
			Function f2 = diffTestP2.getFunctionManager().getFunctionAt(addr("1002040"));

			// Create a tag and add it to Program 1.
			id = diffTestP1.startTransaction("create1");
			funcMgr1.getFunctionTagManager().createFunctionTag("TagA", "tag A comment");
			funcMgr1.getFunctionTagManager().createFunctionTag("TagB", "tag B comment");
			f1.addTag("TagA");
			f1.addTag("TagB");
			diffTestP1.endTransaction(id, true);

			// Create a tag and add it to Program 2.
			id = diffTestP2.startTransaction("create2");
			funcMgr2.getFunctionTagManager().createFunctionTag("TagC", "tag C comment");
			funcMgr2.getFunctionTagManager().createFunctionTag("TagD", "tag D comment");
			funcMgr2.getFunctionTagManager().createFunctionTag("TagE", "tag E comment");
			f2.addTag("TagC");
			f2.addTag("TagD");
			f2.addTag("TagE");
			diffTestP2.endTransaction(id, true);

			// Open the diff display and apply the merge.
			openDiff(diffTestP1, diffTestP2);
			showApplySettings();
			replace(functionTagApplyCB);
			AddressSet as = new AddressSet(addr("1002040"), addr("1002040"));
			setDiffSelection(as);
			apply();

			// Check the results. We should have both tags now in the target program
			// (Program 1), so check the number of tags and make sure the names are
			// correct.
			Iterator<FunctionTag> iter = f1.getTags().iterator();
			List<String> tagNames = new ArrayList<>();
			while (iter.hasNext()) {
				FunctionTag tag = iter.next();
				tagNames.add(tag.getName());
			}
			assertEquals(tagNames.size(), 3);
			assertTrue(tagNames.contains("TagC"));
			assertTrue(tagNames.contains("TagD"));
			assertTrue(tagNames.contains("TagE"));

		}
		catch (InvalidInputException | OverlappingFunctionException e) {
			Msg.error(this, "Error setting up function tag diff test.", e);
		}
	}

	private void plateCommentReplace() {
		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		replace(plateCommentApplyCB);
		AddressSet as = new AddressSet(addr("100415a"), addr("100415a"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs.subtract(as), diffPlugin.getDiffHighlightSelection());
	}

	private void preCommentReplace() {
		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		replace(preCommentApplyCB);
		AddressSet as = new AddressSet(addr("1002395"), addr("1002395"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs.subtract(as), diffPlugin.getDiffHighlightSelection());
	}

	private void eolCommentReplace() {
		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		replace(eolCommentApplyCB);
		AddressSet as = new AddressSet(addr("100238f"), addr("100238f"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs.subtract(as), diffPlugin.getDiffHighlightSelection());
	}

	private void repeatableCommentReplace() {
		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		replace(repeatableCommentApplyCB);
		AddressSet as = new AddressSet(addr("1002336"), addr("1002336"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs.subtract(as), diffPlugin.getDiffHighlightSelection());
	}

	private void postCommentReplace() {
		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		replace(postCommentApplyCB);
		AddressSet as = new AddressSet(addr("100239d"), addr("100239d"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs.subtract(as), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testLabelReplace() {
		openDiff(diffTestP1, diffTestP2);
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		replace(labelApplyCB);
		AddressSet as = new AddressSet(addr("1002a0c"), addr("1002a0c"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs.subtract(as), diffPlugin.getDiffHighlightSelection());
		SymbolTable symtab = program.getSymbolTable();
		Symbol[] symbols = symtab.getSymbols(addr("1002a0c"));
		Comparator<Symbol> c = SymbolUtilities.getSymbolNameComparator();
		Arrays.sort(symbols, c);
		assertEquals(3, symbols.length);
		assertEquals("begin", symbols[0].getName());
		assertEquals("fooBar234", symbols[1].getName());
		assertEquals("sub21001", symbols[2].getName());
	}

	@Test
	public void testBookmarkReplace() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForSwing();
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		replace(bookmarkApplyCB);
		AddressSet as = new AddressSet(addr("1002318"), addr("1002318"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs.subtract(as), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testPropertyReplace() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForSwing();
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		replace(propertiesApplyCB);
		AddressSet as = new AddressSet(addr("100248c"), addr("100248e"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs.subtract(as), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testFunctionReplace() throws Exception {
		openDiff(diffTestP1, diffTestP2);
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForSwing();
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		AddressSet as = new AddressSet(addr("100299e"), addr("100299e"));
		assertTrue("Original diff set doesn't contain " + as.toString(), origDiffs.contains(as));
		replace(functionApplyCB);
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs.subtract(as), diffPlugin.getDiffHighlightSelection());
	}

}
