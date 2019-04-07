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
package ghidra.framework.project.tool;

import static org.junit.Assert.*;

import java.awt.*;
import java.io.IOException;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.swing.JDialog;
import javax.swing.JFrame;

import org.junit.Assert;
import org.junit.Test;

import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

/**
 * A test that outlines and tests the expected saving action of tools that are closed.  Normally,
 * a tool will save itself when closed, but sometimes it cannot.  This test class verifies these
 * conditions.
 */
public class ToolSaving1Test extends AbstractToolSavingTest {

	@Test
	public void testAutoSaveOption() {
		// the other tests make sure that auto save works 'out of the box', so we will try to
		// disable it and then reset it
		PluginTool tool = launchTool(DEFAULT_TEST_TOOL_NAME);

		// turn off auto save
		setAutoSaveEnabled(false);

		setBooleanFooOptions(tool, true);
		closeTool(tool); // NOTE: this will now trigger a save prompt
		waitForSwing();

		JDialog dialog = getOldStyleSaveChangesDialog(tool);
		pressDontSave(dialog);

		tool = launchTool(DEFAULT_TEST_TOOL_NAME);
		assertEquals("Tool options not saved", false, getBooleanFooOptions(tool));

		// turn auto save back on
		setAutoSaveEnabled(true);

		setBooleanFooOptions(tool, true);
		closeToolAndWait(tool);
		waitForSwing();

		tool = launchTool(DEFAULT_TEST_TOOL_NAME);
		assertEquals("Tool options not saved", true, getBooleanFooOptions(tool));
	}

	// test that when auto save is disabled, we do not save options
	@Test
	public void testAutoSaveOptionFromExitGhidra_WithToolConfigChange() {
		PluginTool tool = launchTool(DEFAULT_TEST_TOOL_NAME);

		// sanity check
		assertTrue("Test tool did not start out in expected state", !getBooleanFooOptions(tool));

		// turn off auto save
		setAutoSaveEnabled(false);

		setBooleanFooOptions(tool, true);

		// exit
		closeAndReopenGhidra_WithGUI(tool, true, false);

		// re-launch tool to see if the option was saved
		tool = launchTool(DEFAULT_TEST_TOOL_NAME);
		assertEquals("Tool options saved when auto-save is disabled", false,
			getBooleanFooOptions(tool));
	}

	// change various states of the tool and make sure they are persisted automatically
	@Test
	public void testAutoSaveSingleTool() throws IOException {
		PluginTool tool = launchTool(DEFAULT_TEST_TOOL_NAME);

		//
		// position
		//

		Point position = new Point(50, 50);
		setToolPosition(tool, position);
		Point newToolPosition = getToolPosition(tool);
		assertEquals("Tool positioning was not saved", position, newToolPosition);

		closeToolAndWait(tool);
		waitForSwing();

		tool = launchTool(DEFAULT_TEST_TOOL_NAME);
		Point restoredToolPosition = getToolPosition(tool);
		if (!position.equals(restoredToolPosition)) {
			System.err.println("About to fail test.  Did the correct x,y values get saved?: ");
			printToolXmlContainting(DEFAULT_TEST_TOOL_NAME, "X_POS");
			// dumpToolFile(DEFAULT_TEST_TOOL_NAME);
		}

		assertEquals("Tool positioning was not saved", position, restoredToolPosition);

		//
		// layout
		//
		boolean isShowing = isBookmarkProviderShowing(tool);
		setBookmarkProviderShowing(tool, !isShowing);

		closeToolAndWait(tool);
		waitForSwing();

		tool = launchTool(DEFAULT_TEST_TOOL_NAME);
		boolean isNowShowing = isBookmarkProviderShowing(tool);
		assertEquals("Tool layout was not saved", !isShowing, isNowShowing);

		//
		// size
		//
		Dimension size = new Dimension(300, 300);
		setToolSize(tool, size);

		closeToolAndWait(tool);
		waitForSwing();

		tool = launchTool(DEFAULT_TEST_TOOL_NAME);
		Dimension newSize = getToolSize(tool);

		assertEquals("Tool size was not saved", size, newSize);

		//
		// option change
		//
		setBooleanFooOptions(tool, true);
		closeToolAndWait(tool);
		waitForSwing();

		tool = launchTool(DEFAULT_TEST_TOOL_NAME);
		assertEquals("Tool options not saved", true, getBooleanFooOptions(tool));
	}

	// the tool should be auto saved
	@Test
	public void testExitGhidraWithOneTool() {
		PluginTool tool = launchTool(DEFAULT_TEST_TOOL_NAME);
		Dimension size = new Dimension(450, 550);
		setToolSize(tool, size);
		closeAndReopenProject();

		// we expect the *session* tool to be reopened with the project and to be our size
		JFrame window = getOpenedToolWindow(DEFAULT_TEST_TOOL_NAME);
		Dimension sessionToolSize = window.getSize();
		assertEquals("Session tool's size did not get saved with the project on Ghidra exit", size,
			sessionToolSize);

		// we also expect the tool in the tool chest to have the new size
		tool = launchTool(DEFAULT_TEST_TOOL_NAME);
		Dimension newSize = getToolSize(tool);
		assertTrue("Tool size was not saved. Expected: " + size + " and found: " + newSize,
			size.equals(newSize));
	}

	// the only changed tool should be saved
	@Test
	public void testExitGhidraWithTwoTools_OneChange() {
		PluginTool tool = launchTool(DEFAULT_TEST_TOOL_NAME);
		launchTool(DEFAULT_TEST_TOOL_NAME);

		// make a *config* change
		boolean isSet = getBooleanFooOptions(tool);
		setBooleanFooOptions(tool, !isSet);

		closeAndReopenProject();

		tool = launchTool(DEFAULT_TEST_TOOL_NAME);
		assertEquals("Changed tool was not saved", !isSet, getBooleanFooOptions(tool));
	}

	// we should be prompted to save, since we cannot programatically decide which to save
	@Test
	public void testExitGhidraWithTwoTools_TwoChanges() {
		PluginTool tool = launchTool(DEFAULT_TEST_TOOL_NAME);
		PluginTool tool2 = launchTool(DEFAULT_TEST_TOOL_NAME);

		// make a *config* change
		boolean isSet = getBooleanFooOptions(tool);
		setBooleanFooOptions(tool, !isSet);
		setBooleanFooOptions(tool2, !isSet);

		closeAndReopenProject();
		SelectChangedToolDialog dialog = getSaveSessionChangesDialog();
		assertNotNull("Did not get a save dialog with multiple dirty tools", dialog);
		selectAndSaveSessionTool(dialog, tool);

		tool = launchTool(DEFAULT_TEST_TOOL_NAME);
		assertEquals("Changed tool was not saved", !isSet, getBooleanFooOptions(tool));
	}

	@Test
	public void testSaveToolAndNotLoseOptions() {
		PluginTool tool = launchTool(DEFAULT_TEST_TOOL_NAME);

		Map<String, Object> initialMap = getOptionsMap(tool);
		saveTool(tool);

		Map<String, Object> postSaveMap = getOptionsMap(tool);

		if (initialMap.size() != postSaveMap.size()) {
			if (initialMap.size() > postSaveMap.size()) {
				Msg.debug(this, "We have less options than before our save.  Missing options: ");
				initialMap.keySet().removeAll(postSaveMap.keySet());
				Set<Entry<String, Object>> entrySet = initialMap.entrySet();
				for (Entry<String, Object> entry : entrySet) {
					Msg.debug(this, "\tkey: " + entry.getKey() + " - value: " + entry.getValue());
				}
			}
			else {
				Msg.debug(this, "We have more options than before our save");
				postSaveMap.keySet().removeAll(initialMap.keySet());
				Set<Entry<String, Object>> entrySet = postSaveMap.entrySet();
				for (Entry<String, Object> entry : entrySet) {
					Msg.debug(this, "\tkey: " + entry.getKey() + " - value: " + entry.getValue());
				}
			}

			Assert.fail("We lost or gained options after saving the tool");
		}
	}

	// test that with two changed tools they both will prompt to be saved when closed
	@Test
	public void testTwoToolsBothChanged() {
		PluginTool tool1 = launchTool(DEFAULT_TEST_TOOL_NAME);
		PluginTool tool2 = launchTool(DEFAULT_TEST_TOOL_NAME);

		// make a *config* change to tool1
		boolean isSet = getBooleanFooOptions(tool1);
		setBooleanFooOptions(tool1, !isSet);

		// make a *config* change to tool2
		setBooleanFooOptions(tool2, !isSet);

		closeToolAndManuallySave(tool1);

		closeToolAndManuallySave(tool2);

		PluginTool newTool = launchTool(DEFAULT_TEST_TOOL_NAME);

		assertEquals("Changed tool was not saved", !isSet, getBooleanFooOptions(newTool));
	}

	// test that with two tools and one is changed,closed and then the other is closed, that a save
	// is prompted for
	@Test
	public void testTwoToolsChange1_close1_change2_close2() {
		PluginTool tool1 = launchTool(DEFAULT_TEST_TOOL_NAME);
		PluginTool tool2 = launchTool(DEFAULT_TEST_TOOL_NAME);

		boolean isSet = getBooleanFooOptions(tool1);
		setBooleanFooOptions(tool1, !isSet);
		closeToolAndManuallySave(tool1);

		setBooleanFooOptions(tool2, !isSet);
		closeToolAndManuallySave(tool2);

		PluginTool newTool = launchTool(DEFAULT_TEST_TOOL_NAME);

		assertEquals("Changed tool was not saved", !isSet, getBooleanFooOptions(newTool));
	}

	// test that with two tools and one is changed and save, both then close without saving.
	@Test
	public void testTwoToolsOneChanged_save1_closeBoth() {
		PluginTool tool1 = launchTool(DEFAULT_TEST_TOOL_NAME);
		PluginTool tool2 = launchTool(DEFAULT_TEST_TOOL_NAME);

		boolean isSet = getBooleanFooOptions(tool1);
		setBooleanFooOptions(tool1, !isSet);
		saveTool(tool1);

		closeToolAndWait(tool1);
		closeToolAndWait(tool2);

		PluginTool newTool = launchTool(DEFAULT_TEST_TOOL_NAME);
		assertEquals("Changed tool was not saved", !isSet, getBooleanFooOptions(newTool));
	}

	// test that with two tools open, and no *real* changes, that the last closed tool is saved
	@Test
	public void testTwoToolsWithNoChanges() {
		PluginTool tool1 = launchTool(DEFAULT_TEST_TOOL_NAME);
		PluginTool tool2 = launchTool(DEFAULT_TEST_TOOL_NAME);

		setToolPosition(tool1, new Point(11, 11));
		setToolPosition(tool2, new Point(21, 23));

		closeToolAndWait(tool1);
		waitForSwing();
		closeToolAndWait(tool2);
		waitForSwing();

		tool1 = launchTool(DEFAULT_TEST_TOOL_NAME);
		assertEquals("Tool positioning was not saved", new Point(21, 23), getToolPosition(tool1));
	}

	// test that with two tools open and one has changes, that closing the unchanged one does
	// nothing (no prompt) and that the second one closing will *auto* save its changes
	@Test
	public void testTwoToolsWithOneChange_ChangedClosedFirst() {
		PluginTool tool1 = launchTool(DEFAULT_TEST_TOOL_NAME);
		PluginTool tool2 = launchTool(DEFAULT_TEST_TOOL_NAME);

		// make a *config* change
		boolean isSet = getBooleanFooOptions(tool1);
		setBooleanFooOptions(tool1, !isSet);

		closeTool(tool1); // close the changed one (this will trigger a modal dialog)
		waitForSwing();
		Window saveChangesDialog = getSaveChangesDialog(tool1);
		assertNotNull(saveChangesDialog);
		pressSave(saveChangesDialog);
		assertTrue(!saveChangesDialog.isShowing());

		closeTool(tool2);
		waitForSwing();
		String toolTitle = (String) getInstanceField("SAVE_DIALOG_TITLE", tool2);
		Window dialog = getWindowByTitleContaining(tool2.getToolFrame(), toolTitle);
		assertNull(dialog); // no changes, so no dialog

		PluginTool newTool = launchTool(DEFAULT_TEST_TOOL_NAME);
		assertEquals("Changed tool was not saved", !isSet, getBooleanFooOptions(newTool));
	}

	// test that with two tools open and one has changes, that closing the unchanged one does
	// nothing (no prompt) and that the second one closing will *auto* save its changes
	@Test
	public void testTwoToolsWithOneChange_UnchangedClosedFirst() {
		PluginTool tool1 = launchTool(DEFAULT_TEST_TOOL_NAME);
		PluginTool tool2 = launchTool(DEFAULT_TEST_TOOL_NAME);

		Dimension size = new Dimension(450, 550);
		setToolSize(tool1, size);

		closeToolAndWait(tool2); // close the unchanged one
		waitForSwing();

		closeToolAndWait(tool1);
		waitForSwing();

		PluginTool newTool = launchTool(DEFAULT_TEST_TOOL_NAME);
		Dimension newSize = getToolSize(newTool);

		assertEquals("Tool size was not saved", size, newSize);
	}

	// this test is to run last and set the default tool to a good size for all other tests
	@Test
	public void testZFixupTool() {
		PluginTool tool = launchTool(DEFAULT_TEST_TOOL_NAME);
		setToolSize(tool, new Dimension(1000, 800));
		closeToolAndWait(tool);
	}
}
