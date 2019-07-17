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

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import ghidra.program.model.address.AddressSet;
import ghidra.program.util.DiffUtility;

public class DiffApplyTest extends DiffApplyTestAdapter {

	@Test
	public void testShowHideDiffApplySettings() {
		openDiff_CloseWarningDialog(diffTestP1, diffTestP2);
		showApplySettings();

		assertTrue(isProviderShown(tool.getToolFrame(), "Diff Apply Settings"));

		diffPlugin.getDiffApplySettingsProvider().closeComponent();
		waitForPostedSwingRunnables();
		assertTrue(!isProviderShown(tool.getToolFrame(), "Diff Apply Settings"));

		invokeLater(diffApplySettings);
		assertTrue(isProviderShown(tool.getToolFrame(), "Diff Apply Settings"));

		diffPlugin.getDiffApplySettingsProvider().closeComponent();
		waitForPostedSwingRunnables();
		assertTrue(!isProviderShown(tool.getToolFrame(), "Diff Apply Settings"));

		invokeLater(diffApplySettings);
		assertTrue(isProviderShown(tool.getToolFrame(), "Diff Apply Settings"));
	}

	@Test
	public void testInitialDiffApplySettings() {
		openDiff_CloseWarningDialog(diffTestP1, diffTestP2);
		showApplySettings();

		isReplace(programContextApplyCB);
		isReplace(byteApplyCB);
		isReplace(codeUnitApplyCB);
		isReplace(refApplyCB);
		isMerge(plateCommentApplyCB);
		isMerge(preCommentApplyCB);
		isMerge(eolCommentApplyCB);
		isMerge(repeatableCommentApplyCB);
		isMerge(postCommentApplyCB);
		isMergeSetPrimary(labelApplyCB);
		isReplace(functionApplyCB);
		isReplace(bookmarkApplyCB);
		isReplace(propertiesApplyCB);
	}

	@Test
	public void testIgnoreAllDiffsSettings() {
		openDiff_CloseWarningDialog(diffTestP1, diffTestP2);
		showApplySettings();

		invokeLater(ignoreAll);
		isIgnore(programContextApplyCB);
		isIgnore(byteApplyCB);
		isIgnore(codeUnitApplyCB);
		isIgnore(refApplyCB);
		isIgnore(plateCommentApplyCB);
		isIgnore(preCommentApplyCB);
		isIgnore(eolCommentApplyCB);
		isIgnore(repeatableCommentApplyCB);
		isIgnore(postCommentApplyCB);
		isIgnore(labelApplyCB);
		isIgnore(functionApplyCB);
		isIgnore(bookmarkApplyCB);
		isIgnore(propertiesApplyCB);
	}

	@Test
	public void testReplaceAllDiffsSettings() {
		openDiff_CloseWarningDialog(diffTestP1, diffTestP2);
		showApplySettings();

		invokeLater(replaceAll);
		isReplace(programContextApplyCB);
		isReplace(byteApplyCB);
		isReplace(codeUnitApplyCB);
		isReplace(refApplyCB);
		isReplace(plateCommentApplyCB);
		isReplace(preCommentApplyCB);
		isReplace(eolCommentApplyCB);
		isReplace(repeatableCommentApplyCB);
		isReplace(postCommentApplyCB);
		isReplace(labelApplyCB);
		isReplace(functionApplyCB);
		isReplace(bookmarkApplyCB);
		isReplace(propertiesApplyCB);
	}

	@Test
	public void testMergeAllDiffsSettings() {
		openDiff_CloseWarningDialog(diffTestP1, diffTestP2);
		showApplySettings();

		invokeLater(ignoreAll);
		invokeLater(mergeAll);
		isReplace(programContextApplyCB);
		isReplace(byteApplyCB);
		isReplace(codeUnitApplyCB);
		isReplace(refApplyCB);
		isMerge(plateCommentApplyCB);
		isMerge(preCommentApplyCB);
		isMerge(eolCommentApplyCB);
		isMerge(repeatableCommentApplyCB);
		isMerge(postCommentApplyCB);
		isMergeSetPrimary(labelApplyCB);
		isReplace(functionApplyCB);
		isReplace(bookmarkApplyCB);
		isReplace(propertiesApplyCB);
	}

	@Test
	public void testApplyAllDiffsActionWithSimpleLabelMerge() throws Exception {
		openDiff_CloseWarningDialog(diffTestP1, diffTestP2);
		showApplySettings();
		merge(labelApplyCB);

		invokeLater(selectAllDiffs);
		apply();

		// FUTURE: Check that actually applied.

		AddressSet addrSet = new AddressSet();
		// Comment Diffs
		addrSet.addRange(addr("1002040"), addr("1002040"));
		addrSet.addRange(addr("1002304"), addr("1002304"));
		addrSet.addRange(addr("1002306"), addr("1002306"));
		addrSet.addRange(addr("100230b"), addr("100230b"));
		addrSet.addRange(addr("1002312"), addr("1002312"));
		addrSet.addRange(addr("1002336"), addr("1002336"));
		addrSet.addRange(addr("1002346"), addr("1002346"));
		addrSet.addRange(addr("100238f"), addr("100238f"));
		addrSet.addRange(addr("1002395"), addr("1002395"));
		addrSet.addRange(addr("100239d"), addr("100239d"));
		addrSet.addRange(addr("10030d2"), addr("10030d2"));
		addrSet.addRange(addr("100355f"), addr("100355f"));

		// Label Diffs
		addrSet.addRange(addr("1002a01"), addr("1002a01"));
		addrSet.addRange(addr("1002a0c"), addr("1002a0c"));
		addrSet.addRange(addr("1002a0d"), addr("1002a0d"));

		// onlyInProgram1
		addrSet.addRange(addr("00000200"), addr("000002ff"));

		// Conflicting Data Diffs
		addrSet.add(getPgmConflictDataDiffs());

		checkDiffSelection(DiffUtility.getCodeUnitSet(addrSet, program));
	}

	@Test
	public void testApplyAllDiffsAction() throws Exception { // Merges labels and sets primary.
		openDiff_CloseWarningDialog(diffTestP1, diffTestP2);
		showApplySettings();

		invokeLater(selectAllDiffs);
		apply();

		// FUTURE: Check that actually applied.

		AddressSet addrSet = new AddressSet();
		// Comment Diffs
		addrSet.addRange(addr("1002040"), addr("1002040"));
		addrSet.addRange(addr("1002304"), addr("1002304"));
		addrSet.addRange(addr("1002306"), addr("1002306"));
		addrSet.addRange(addr("100230b"), addr("100230b"));
		addrSet.addRange(addr("1002312"), addr("1002312"));
		addrSet.addRange(addr("1002336"), addr("1002336"));
		addrSet.addRange(addr("1002346"), addr("1002346"));
		addrSet.addRange(addr("100238f"), addr("100238f"));
		addrSet.addRange(addr("1002395"), addr("1002395"));
		addrSet.addRange(addr("100239d"), addr("100239d"));
		addrSet.addRange(addr("10030d2"), addr("10030d2"));
		addrSet.addRange(addr("100355f"), addr("100355f"));

		// Label Diffs
		addrSet.addRange(addr("1002a01"), addr("1002a01"));
		addrSet.addRange(addr("1002a0c"), addr("1002a0c"));
		addrSet.addRange(addr("1002a0d"), addr("1002a0d"));

		// onlyInProgram1
		addrSet.addRange(addr("00000200"), addr("000002ff"));

		// Conflicting Data Diffs
		addrSet.add(getPgmConflictDataDiffs());

		checkDiffSelection(DiffUtility.getCodeUnitSet(addrSet, program));
	}

	@Test
	public void testReplaceAllDiffsAction() throws Exception {
		openDiff_CloseWarningDialog(diffTestP1, diffTestP2);

		showApplySettings();

		invokeLater(replaceAll);
		invokeLater(selectAllDiffs);
		apply();

		checkDiffSelection(getPgmConflictDataDiffs());
	}

	@Test
	public void testReplaceAllDiffsLabelConflict() throws Exception {

		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		openDiff(diffTestP1, diffTestP2);
		waitForPostedSwingRunnables();
		showApplySettings();

		invokeLater(replaceAll);
		invokeLater(selectAllDiffs);
		apply();

		checkDiffSelection(getSetupConflictDataDiffs());
	}
}
