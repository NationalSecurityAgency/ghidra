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

import org.junit.Test;

import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

public class DiffApplyMergeTest extends DiffApplyTestAdapter {

	@Override
	public void tearDown() {

		closeAllWindows();
		super.tearDown();
	}

	@Test
	public void testPlateCommentMerge() {
		openDiff(diffTestP1, diffTestP2);
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		merge(plateCommentApplyCB);
		AddressSet as = new AddressSet(addr("100415a"), addr("100415a"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs.subtract(as), diffPlugin.getDiffHighlightSelection());
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitAt(addr("100415a"));
		assertEquals("This is my function for testing diff", cu.getComment(CodeUnit.PLATE_COMMENT));
	}

	@Test
	public void testPreCommentMerge() {
		openDiff(diffTestP1, diffTestP2);
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		merge(preCommentApplyCB);
		AddressSet as = new AddressSet(addr("1002395"), addr("1002395"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitAt(addr("1002395"));
		assertEquals("Pre: Program1\nPre: Program2", cu.getComment(CodeUnit.PRE_COMMENT));
	}

	@Test
	public void testEolCommentMerge() {
		openDiff(diffTestP1, diffTestP2);
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		merge(eolCommentApplyCB);
		AddressSet as = new AddressSet(addr("100238f"), addr("100238f"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitAt(addr("100238f"));
		assertEquals("EOL: Program1\nEOL: Program2", cu.getComment(CodeUnit.EOL_COMMENT));
	}

	@Test
	public void testRepeatableCommentMerge() {
		openDiff(diffTestP1, diffTestP2);
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		merge(repeatableCommentApplyCB);
		AddressSet as = new AddressSet(addr("1002336"), addr("1002336"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitAt(addr("1002336"));
		assertEquals("ONE: Repeatable comment.\nTWO: Repeatable comment.",
			cu.getComment(CodeUnit.REPEATABLE_COMMENT));
	}

	@Test
	public void testPostCommentMerge() {
		openDiff(diffTestP1, diffTestP2);
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		merge(postCommentApplyCB);
		AddressSet as = new AddressSet(addr("100239d"), addr("100239d"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitAt(addr("100239d"));
		assertEquals("Post: Program1\nPost: Program2", cu.getComment(CodeUnit.POST_COMMENT));
	}

	/**
	 * Tests that we can merge two different function tags that have been added to the
	 * same function.
	 *
	 * Note: The test programs must be modified a bit to facilitate this test. Specifically
	 *  	 we have to add a function at the same address in both programs, then add tags
	 *  	 to each program, then add those tags to the newly created functions.
	 */
	@Test
	public void testFunctionTagMerge() {

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
			f1.addTag("TagA");
			diffTestP1.endTransaction(id, true);

			// Create a tag and add it to Program 2.
			id = diffTestP2.startTransaction("create2");
			funcMgr2.getFunctionTagManager().createFunctionTag("TagB", "tag B comment");
			f2.addTag("TagB");
			diffTestP2.endTransaction(id, true);

			// Open the diff display and apply the merge.
			openDiff(diffTestP1, diffTestP2);
			showApplySettings();
			merge(functionTagApplyCB);
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
			assertEquals(tagNames.size(), 2);
			assertTrue(tagNames.contains("TagA"));
			assertTrue(tagNames.contains("TagB"));

		}
		catch (InvalidInputException | OverlappingFunctionException e) {
			Msg.error(this, "Error setting up function tag diff test.", e);
		}
	}

	@Test
	public void testLabelMerge() {
		openDiff(diffTestP1, diffTestP2);
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		merge(labelApplyCB);
		AddressSet as = new AddressSet(addr("1002a0c"), addr("1002a0c"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
		SymbolTable symtab = program.getSymbolTable();
		Symbol[] symbols = symtab.getSymbols(addr("1002a0c"));
		Comparator<Symbol> c = SymbolUtilities.getSymbolNameComparator();
		Arrays.sort(symbols, c);
		assertEquals(5, symbols.length);
		assertEquals("begin", symbols[0].getName());
		assertEquals("fooBar234", symbols[1].getName());
		assertEquals("getResources", symbols[2].getName());
		assertEquals("mySymbol", symbols[3].getName());
		assertEquals("sub21001", symbols[4].getName());
		assertFalse(symbols[0].isPrimary());
		assertFalse(symbols[1].isPrimary());
		assertTrue(symbols[2].isPrimary());
		assertFalse(symbols[3].isPrimary());
		assertFalse(symbols[4].isPrimary());
	}

	@Test
	public void testLabelMergeSetPrimary() {
		openDiff(diffTestP1, diffTestP2);
		showApplySettings();

		ProgramSelection origDiffs = diffPlugin.getDiffHighlightSelection();
		mergeSetPrimary(labelApplyCB);
		AddressSet as = new AddressSet(addr("1002a0c"), addr("1002a0c"));
		setDiffSelection(as);
		apply();
		assertEquals(origDiffs, diffPlugin.getDiffHighlightSelection());
		SymbolTable symtab = program.getSymbolTable();
		Symbol[] symbols = symtab.getSymbols(addr("1002a0c"));
		Comparator<Symbol> c = SymbolUtilities.getSymbolNameComparator();
		Arrays.sort(symbols, c);
		assertEquals(5, symbols.length);
		assertEquals("begin", symbols[0].getName());
		assertEquals("fooBar234", symbols[1].getName());
		assertEquals("getResources", symbols[2].getName());
		assertEquals("mySymbol", symbols[3].getName());
		assertEquals("sub21001", symbols[4].getName());
		assertTrue(symbols[0].isPrimary());
		assertFalse(symbols[1].isPrimary());
		assertFalse(symbols[2].isPrimary());
		assertFalse(symbols[3].isPrimary());
		assertFalse(symbols[4].isPrimary());
	}

}
