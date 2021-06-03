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

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import docking.util.image.ToolIconURL;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.framework.main.FrontEndPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.project.tool.GhidraTool;
import ghidra.program.database.ProgramDB;
import ghidra.test.ClassicSampleX86ProgramBuilder;
import ghidra.test.TestEnv;

public class DiffSaveSettingsTest extends DiffApplyTestAdapter {

	@Override
	@Before
	public void setUp() throws Exception {
		fixupGUI();
		env = new TestEnv();
		frontEndTool = env.showFrontEndTool();
		frontEndPlugin = getPlugin(frontEndTool, FrontEndPlugin.class);
	}

	private void launchTool() throws Exception {
		// Launch our own tool for the Diff so that we can close it and handle "Save Tool?".
		runSwing(() -> tool =
			(PluginTool) frontEndTool.getProject().getToolServices().launchTool("MyDiffTestTool",
				null));

		cb = getPlugin(tool, CodeBrowserPlugin.class);
		diffPlugin = getPlugin(tool, ProgramDiffPlugin.class);
		diffListingPanel = diffPlugin.getListingPanel();
		fp1 = cb.getFieldPanel();
		fp2 = diffListingPanel.getFieldPanel();
		openClosePgm2 = (ToggleDockingAction) getAction(diffPlugin, "Open/Close Program View");
	}

	private void showNewTool() throws Exception {
		// Create our own tool for the Diff so that we can close it and handle "Save Tool?".
		runSwing(() -> {
			tool = new GhidraTool(frontEndTool.getProject(), "MyDiffTestTool");
			tool.setIconURL(new ToolIconURL("preferences-system.png"));
			tool.setVisible(true);
		});

		tool.addPlugin(ProgramManagerPlugin.class.getName());
		setUpCodeBrowserTool(tool);

		diffListingPanel = diffPlugin.getListingPanel();
		fp1 = cb.getFieldPanel();
		fp2 = diffListingPanel.getFieldPanel();
		openClosePgm2 = (ToggleDockingAction) getAction(diffPlugin, "Open/Close Program View");
	}

	@Override
	@After
	public void tearDown() {
		Window win = getWindow("Select Other Program");
		if (win != null) {
			//This window should not be up, so cancel it.
			pressButton(win, "Cancel");
		}

		closeOurTool();
		env.dispose();
	}

	void closeOurTool() {
		if (tool == null) {
			return;
		}
		DockingActionIf closeToolAction = getToolAction(tool, "Close Tool");
		if (closeToolAction == null) {
			return;
		}
		performAction(closeToolAction, false);
		try {
			tool.getToolFrame();
		}
		catch (RuntimeException e1) {
			tool = null;
			return; // The tool is closed.
		}

		tool = null;
	}

	@Test
	public void testSaveDiffApplySettings() throws Exception {
//		String p3Name = "notepadSetup1ForDiffTest";
//		String p4Name = "notepadSetup2ForDiffTest";

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		ProgramDB p3 = builder.getProgram();
		ProgramDB p4 = builder.getProgram();

		showNewTool();
		openProgram(p3);
		openDiff(p4);
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

		// Change the apply settings.
		ignore(programContextApplyCB);
		ignore(byteApplyCB);
		ignore(codeUnitApplyCB);
		ignore(refApplyCB);
		replace(plateCommentApplyCB);
		replace(preCommentApplyCB);
		replace(eolCommentApplyCB);
		replace(repeatableCommentApplyCB);
		replace(postCommentApplyCB);
		merge(labelApplyCB);
		ignore(functionApplyCB);
		ignore(bookmarkApplyCB);
		ignore(propertiesApplyCB);

		// Save the settings.
		DockingActionIf saveApplySettingsAction =
			getAction(diffPlugin, "Save Default Diff Apply Settings");
		assertNotNull(saveApplySettingsAction);
		performAction(saveApplySettingsAction, true);

		// Check the settings.
		isIgnore(programContextApplyCB);
		isIgnore(byteApplyCB);
		isIgnore(codeUnitApplyCB);
		isIgnore(refApplyCB);
		isReplace(plateCommentApplyCB);
		isReplace(preCommentApplyCB);
		isReplace(eolCommentApplyCB);
		isReplace(repeatableCommentApplyCB);
		isReplace(postCommentApplyCB);
		isMerge(labelApplyCB);
		isIgnore(functionApplyCB);
		isIgnore(bookmarkApplyCB);
		isIgnore(propertiesApplyCB);

		ProgramManagerPlugin pm = getPlugin(tool, ProgramManagerPlugin.class);
		DockingActionIf closeAllProgramAction = getAction(pm, "Close All");
		assertNotNull(closeAllProgramAction);
		ActionContext defaultContext = tool.getDefaultToolContext();
		performAction(closeAllProgramAction, defaultContext, true);

		openProgram(p3);

		openDiff(p4);
		showApplySettings();

		// Check the settings.
		isIgnore(programContextApplyCB);
		isIgnore(byteApplyCB);
		isIgnore(codeUnitApplyCB);
		isIgnore(refApplyCB);
		isReplace(plateCommentApplyCB);
		isReplace(preCommentApplyCB);
		isReplace(eolCommentApplyCB);
		isReplace(repeatableCommentApplyCB);
		isReplace(postCommentApplyCB);
		isMerge(labelApplyCB);
		isIgnore(functionApplyCB);
		isIgnore(bookmarkApplyCB);
		isIgnore(propertiesApplyCB);

		DockingActionIf closeToolAction = getToolAction(tool, "Close Tool");
		performAction(closeToolAction, false);
		// Save Tool?  (Save)
		Window dialog = waitForWindow("Save Tool?");
		assertNotNull("Couldn't find 'Save Tool?' dialog.", dialog);
		pressButtonByText(dialog, "Save");

		launchTool();

		// Open another Diff.
		openProgram(p3);
		openDiff(p4);
		showApplySettings();

		// Check the settings.
		isIgnore(programContextApplyCB);
		isIgnore(byteApplyCB);
		isIgnore(codeUnitApplyCB);
		isIgnore(refApplyCB);
		isReplace(plateCommentApplyCB);
		isReplace(preCommentApplyCB);
		isReplace(eolCommentApplyCB);
		isReplace(repeatableCommentApplyCB);
		isReplace(postCommentApplyCB);
		isMerge(labelApplyCB);
		isIgnore(functionApplyCB);
		isIgnore(bookmarkApplyCB);
		isIgnore(propertiesApplyCB);

		closeOurTool();
	}
}
