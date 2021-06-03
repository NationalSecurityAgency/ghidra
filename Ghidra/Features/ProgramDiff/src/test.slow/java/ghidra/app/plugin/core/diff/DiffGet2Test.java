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

import javax.swing.JDialog;

import org.junit.Test;

public class DiffGet2Test extends DiffTestAdapter {

	@Test
	public void testGetByteDiffsAction() throws Exception {
		getDiffDialog(diffTestP1, diffTestP2);
		setAllTypes(false);
		byteCB.setSelected(true);
		waitForPostedSwingRunnables();
		pressButtonByText(getDiffsDialog, "OK");
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForPostedSwingRunnables();
		waitForDiff();

		assertEquals(getPgmByteDiffs(), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testGetCodeUnitDiffsAction() throws Exception {
		getDiffDialog(diffTestP1, diffTestP2);
		setAllTypes(false);
		codeUnitCB.setSelected(true);
		waitForPostedSwingRunnables();
		pressButtonByText(getDiffsDialog, "OK");
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForPostedSwingRunnables();
		waitForDiff();

		assertEquals(getPgmCodeUnitDiffs(), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testGetProgramContextDiffsAction() throws Exception {
		getDiffDialog(diffTestP1, diffTestP2);
		setAllTypes(false);
		programContextCB.setSelected(true);
		waitForPostedSwingRunnables();
		pressButtonByText(getDiffsDialog, "OK");
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForPostedSwingRunnables();
		waitForDiff();
		assertEquals(getPgmProgramContextDiffs(), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testGetBookmarkDiffsAction() throws Exception {
		getDiffDialog(diffTestP1, diffTestP2);
		setAllTypes(false);
		bookmarkCB.setSelected(true);
		waitForPostedSwingRunnables();
		pressButtonByText(getDiffsDialog, "OK");
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForPostedSwingRunnables();
		waitForDiff();
		assertEquals(getPgmBookmarkDiffs(), diffPlugin.getDiffHighlightSelection());
	}

	@Test
	public void testGetCommentDiffsAction() throws Exception {
		getDiffDialog(diffTestP1, diffTestP2);
		setAllTypes(false);
		commentCB.setSelected(true);
		waitForPostedSwingRunnables();
		pressButtonByText(getDiffsDialog, "OK");
		JDialog dialog = waitForJDialog("Memory Differs");
		pressButtonByText(dialog, "OK");
		waitForPostedSwingRunnables();
		waitForDiff();
		assertEquals(getPgmCommentDiffs(), diffPlugin.getDiffHighlightSelection());
	}
}
