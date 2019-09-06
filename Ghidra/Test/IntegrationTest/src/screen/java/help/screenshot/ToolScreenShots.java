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
package help.screenshot;

import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;

import org.junit.Before;
import org.junit.Test;

import docking.DialogComponentProvider;
import docking.StatusBar;
import docking.action.DockingActionIf;
import docking.actions.KeyEntryDialog;
import docking.actions.ToolActions;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import docking.widgets.table.GTable;
import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.LoggingInitialization;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.main.PickToolDialog;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.dialog.PluginInstallerDialog;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskDialog;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class ToolScreenShots extends GhidraScreenShotGenerator {

	@Override
	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.showFrontEndTool();
	}

	@Test
	public void testConfigTool() {

		tool = env.launchDefaultTool();
		performAction("Configure Tool", ToolConstants.TOOL_OWNER, false);
		captureDialog(600, 500);
	}

	@Test
	public void testConfigurePlugins() {

		tool = env.launchDefaultTool();
		performAction("Configure Tool", ToolConstants.TOOL_OWNER, false);
		performDialogAction("Configure All Plugins", false);
		PluginInstallerDialog installerProvider =
			(PluginInstallerDialog) getDialog(PluginInstallerDialog.class);

		JTable table = findComponent(installerProvider, JTable.class);
		selectRow(table, 0);
		captureDialog(PluginInstallerDialog.class, 800, 600);
	}

	@Test
	public void testSaveTool() {
		tool = env.launchDefaultTool();
		performAction("Save Tool As", ToolConstants.TOOL_OWNER, false);
		captureDialog();
	}

	@Test
	public void testImportDefaultToolsDialog() {
		performFrontEndAction("Import Ghidra Tools", "FrontEndPlugin", false);
		captureDialog("Import Ghidra Tools");
	}

	@Test
	public void testSetToolAssociations() {
		performFrontEndAction("Set Tool Associations", "FrontEndPlugin", false);
		captureDialog("Set Tool Associations");
	}

	@Test
	public void testPickTool() {
		performFrontEndAction("Set Tool Associations", "FrontEndPlugin", false);
		DialogComponentProvider dialogProvider =
			waitForDialogComponent(DialogComponentProvider.class);
		GTable table = (GTable) getInstanceField("table", dialogProvider);
		selectRow(table, 0);
		pressButtonByText(dialogProvider, "Edit", false);

		captureDialog(PickToolDialog.class);
	}

	@Test
	public void testSaveChangesDialog() {
		runSwing(() -> OptionDialog.showOptionDialog(tool.getToolFrame(), "Save Program?",
			"WinHelloCPP.exe" + " has changed. Do you want to save it?", "&Save", "Do&n't Save",
			OptionDialog.QUESTION_MESSAGE), false);
		captureDialog();

	}

	@Test
	public void testProgress() throws Exception {

		tool = env.launchDefaultTool();
		loadProgram();

		int topBottomMargin = 60;
		int leftRightMargin = 50;

		goToListing(0x401008);
		int id = program.startTransaction("Test");
		StatusBar statusBar = findComponent(tool.getToolFrame(), StatusBar.class);
		setWindowSize(tool.getToolFrame(), 1100, 500);
		tool.executeBackgroundCommand(new DummyBackgroundCommand(), program);

		Border inner = BorderFactory.createRaisedBevelBorder();
		Border outer = BorderFactory.createLineBorder(Color.BLACK);
		statusBar.setBorder(BorderFactory.createCompoundBorder(outer, inner));
		captureComponent(statusBar);
		program.endTransaction(id, false);
		padImage(Color.WHITE, topBottomMargin, leftRightMargin, leftRightMargin, topBottomMargin);

		JComponent statusLabel = (JComponent) getInstanceField("statusLabel", statusBar);
		Font font = new Font("Ariel", Font.PLAIN, 12);
		FontMetrics metrics = statusLabel.getFontMetrics(font);
		Rectangle rect = statusLabel.getBounds();
		int statusAreaWidth = rect.width + 10;  // not sure why, but had to add a 10 fudge factor

		labelTop(statusLabel.getName(), rect, font, metrics, topBottomMargin, leftRightMargin, 10);

		int height = image.getHeight(null);
		boolean top = false;

		JComponent statusArea = (JComponent) getInstanceField("statusAreaPanel", statusBar);
		for (Component component : statusArea.getComponents()) {
			String name = component.getName();
			Rectangle bounds = component.getBounds();
			if (name == null) {
				continue;
			}
			if (top) {
				labelTop(name, bounds, font, metrics, topBottomMargin,
					leftRightMargin + statusAreaWidth, 10);
			}
			else {
				labelBottom(name, bounds, font, metrics, topBottomMargin,
					leftRightMargin + statusAreaWidth, 10, height);
			}
			top = !top;
		}
		Rectangle b = statusBar.getBounds();
		int cancelDistanceFromEnd = 60;
		int space = b.width - cancelDistanceFromEnd;
		b.x = b.x + space;
		b.width = cancelDistanceFromEnd;
		labelTop("Cancel Button", b, font, metrics, topBottomMargin, leftRightMargin, 10);
	}

	private void labelBottom(String label, Rectangle bounds, Font font, FontMetrics metrics,
			int topMargin, int leftMargin, int textBottomMargin, int height) {
		int textX = getTextStart(bounds, metrics, label) + leftMargin;
		int textY = height - textBottomMargin;
		int arrowX = bounds.x + bounds.width / 2 + leftMargin;
		int arrowStartY = textY - metrics.getHeight() - 5;
		int arrowEndY = height - topMargin;
		drawText(label, Color.BLACK, new Point(textX, textY), font);
		drawArrow(Color.BLACK, 1, new Point(arrowX, arrowStartY), new Point(arrowX, arrowEndY), 9);
	}

	private void labelTop(String label, Rectangle bounds, Font font, FontMetrics metrics,
			int topMargin, int leftMargin, int textTopMargin) {
		int textX = getTextStart(bounds, metrics, label) + leftMargin;
		int textY = textTopMargin + metrics.getHeight();
		int arrowX = bounds.x + bounds.width / 2 + leftMargin;
		int arrowStartY = textY + 5;
		int arrowEndY = topMargin;
		drawText(label, Color.BLACK, new Point(textX, textY), font);
		drawArrow(Color.BLACK, 1, new Point(arrowX, arrowStartY), new Point(arrowX, arrowEndY), 9);
	}

	private int getTextStart(Rectangle bounds, FontMetrics metrics, String string) {
		int stringWidth = metrics.stringWidth(string);
		return bounds.x + (bounds.width - stringWidth) / 2;
	}

	@Test
	public void testModalTaskDialog() {
		waitForSwing();
		TaskDialog taskDialog = new TaskDialog("Clear with Options", true, false, true);
		taskDialog.initialize(100);
		taskDialog.setProgress(20);
		taskDialog.setMessage("Clearing code at 0040785f");
		tool.showDialog(taskDialog);
		waitForSwing();
		captureDialog(300, 140);
	}

	@Test
	public void testShowLog() throws Exception {

		tool = env.launchDefaultTool();
		loadProgram();

		File file = LoggingInitialization.getApplicationLogFile();
		List<String> lines = FileUtilities.getLines(file);
		List<String> lines2 = new ArrayList<>(lines.size());
		// remove any users names
		for (String string : lines) {
			if (!string.contains("User")) {
				lines2.add(string);
			}
		}
		FileUtilities.writeLinesToFile(file, lines2);

		performFrontEndAction("Show Log", ToolConstants.TOOL_OWNER, false);
		captureDialog("Ghidra User Log");
	}

	@Test
	public void testTip() {
		performFrontEndAction("Tips of the day", "TipOfTheDayPlugin", false);
		captureDialog("Tip of the Day");
	}

	@Test
	public void testRestoreDefaults() {

		tool = env.launchDefaultTool();

		runSwing(() -> {
			OptionsService service = tool.getService(OptionsService.class);
			service.showOptionsDialog("Entropy", "");
		}, false);

		DialogComponentProvider dialog = getDialog();
		Window window = windowForComponent(dialog.getComponent());
		setWindowSize(window, 700, 350);
		waitForSwing();

		captureDialog();

		JButton button = findButtonByText(window, "Restore Defaults");
		drawRectangleWithDropShadowAround(button, Color.GREEN, 2);

		crop(new Rectangle(0, 200, 700, 150));
	}

	@Test
	public void testKeyBindings() {
		tool = env.launchDefaultTool();
		runSwing(() -> {
			OptionsService service = tool.getService(OptionsService.class);
			service.showOptionsDialog("Key Bindings", "");
		}, false);
		DialogComponentProvider dialog = getDialog();
		Window window = windowForComponent(dialog.getComponent());
		setWindowSize(window, 900, 600);
		captureDialog();
	}

	@Test
	public void testSetKeyBindings() {

		tool = env.launchDefaultTool();
		ToolActions toolActions = (ToolActions) getInstanceField("toolActions", tool);

		DockingActionIf action = getAction(tool, "FunctionPlugin", "Delete Function");
		final KeyEntryDialog keyEntryDialog = new KeyEntryDialog(action, toolActions);

		runSwing(() -> tool.showDialog(keyEntryDialog), false);
		captureDialog();
	}

	// Overridden because the ErrorReporting module has the same "Tool" help topic as Base
	// 		make sure we get the right one.
	@Override
	protected List<File> getHelpTopicDirs() {
		List<File> helpTopicDirs = new ArrayList<>();
		Collection<ResourceFile> modules = Application.getModuleRootDirectories();
		for (ResourceFile file : modules) {
			if (file.getName().equals("Base")) {
				helpTopicDirs.add(new File(file.getFile(false), "src/main/help/help/topics"));
				break;
			}
		}
		return helpTopicDirs;
	}

	private class DummyBackgroundCommand extends BackgroundCommand {

		public DummyBackgroundCommand() {
			super("Dummy", true, true, false);
		}

		@Override
		public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
			monitor.initialize(1200);
			monitor.setProgress(350);
			monitor.setMessage("Scalar Operand Reference");
			invokeInstanceMethod("update", monitor);
			sleep(5000);
			return true;
		}

	}
}
