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
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JDialog;
import javax.swing.JFrame;

import org.junit.After;
import org.junit.Before;

import docking.ComponentProvider;
import docking.DockingWindowManager;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.bookmark.BookmarkPlugin;
import ghidra.framework.ToolUtils;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Msg;
import junit.framework.AssertionFailedError;
import utilities.util.FileUtilities;

/**
 * A test that outlines and tests the expected saving action of tools that are closed.  Normally,
 * a tool will save itself when closed, but sometimes it cannot.  This test class verifies these
 * conditions.
 */
public abstract class AbstractToolSavingTest extends AbstractGhidraHeadedIntegrationTest {

	protected static final int SAVE_DIALOG_TIMEOUT = 1000;
	protected Point defaultPosition;
	protected Dimension defaultSize;
	protected TestEnv testEnv;

	@Before
	public void setUp() throws Exception {
		deleteTool(DEFAULT_TEST_TOOL_NAME); // remove the old tool and its saved data

		startGhidra();

		// put the code browser tool in a known position and size
		PluginTool tool = testEnv.createDefaultTool();

		defaultSize = new Dimension(500, 500);
		setToolSize(tool, defaultSize);

		defaultPosition = new Point(30, 30);
		setToolPosition(tool, defaultPosition);

		closeTool(tool);
		waitForPostedSwingRunnables();
	}

	protected void startGhidra() throws IOException {
		testEnv = new TestEnv();
		testEnv.setAutoSaveEnabled(true); // this class relies on auto-saving being enabled
	}

	@After
	public void tearDown() {
		closeAllWindows();
		exitGhidra();
	}

	protected void closeAndReopenGhidra_WithGUI(PluginTool tool, boolean willPrompt,
			boolean saveIfPrompted) {

		closeAndReopenProject();

		// we will get the dialog to save in the middle of the process
		if (willPrompt) {
			JDialog dialog = getOldStyleSaveChangesDialog(tool);
			assertNotNull(dialog);
			if (saveIfPrompted) {
				pressSave(dialog);
			}
			else {
				pressDontSave(dialog);
			}
		}
	}

	protected void closeAndReopenProject() {
		executeOnSwingWithoutBlocking(() -> {
			try {
				// we want to trigger the saving of tools to the toolchest for our tests
				// just closing the project doesn't save anything.
				testEnv.getProject().saveSessionTools();
				testEnv.getProject().save();
				testEnv.closeAndReopenProject();
			}
			catch (IOException e) {
				AssertionFailedError afe = new AssertionFailedError();
				afe.initCause(e);
				throw afe;
			}
		});
		waitForPostedSwingRunnables();
	}

	protected void closeTool(PluginTool tool) {
		testEnv.closeTool(tool, false);
	}

	protected void closeToolAndManuallySave(PluginTool tool) {
		closeTool(tool); // close the changed one (this will trigger a modal dialog)
		waitForPostedSwingRunnables();
		Window saveChangesDialog = getSaveChangesDialog(tool);
		assertNotNull(saveChangesDialog);
		pressSave(saveChangesDialog);
		assertTrue(!saveChangesDialog.isShowing());
	}

//==================================================================================================
// Helper Methods
//==================================================================================================

	protected void closeToolAndWait(PluginTool tool) {
		testEnv.closeTool(tool);

		int maxTimeout = 10000;
		int sleepTime = 250;
		int waitTime = 0;
		while (tool.isVisible() && waitTime < maxTimeout) {
			try {
				Thread.sleep(sleepTime);
			}
			catch (InterruptedException e) {
				// don't care, will try again
			}
			waitTime += sleepTime;
		}

		assertTrue("Unable to close tool for test!", !tool.isVisible());
	}

	protected void closeToolWithNoSaveDialog(PluginTool tool) {
		closeTool(tool);
		Window saveChangesDialog = getSaveChangesDialog(tool);
		assertNull(saveChangesDialog);
	}

	/** A crude counting of available options */
	// the 'name' variable in the inner-loop
	protected int countOptions(PluginTool tool) {
		Msg.debug(this, "\n\nCount Options: ");
		Options[] options = tool.getOptions();
		int count = 0;
		for (Options option : options) {
			List<String> optionNames = option.getOptionNames();
			for (String name : optionNames) {
				Object value = invokeInstanceMethod("getObject", option,
					new Class[] { String.class, Object.class }, new Object[] { name, null });
				Msg.debug(this, "\tname: " + name + " - value: " + value);
				count++;
			}
		}

		return count;
	}

	protected void deleteTool(String toolName) {
		Map<String, ToolTemplate> toolsMap = ToolUtils.loadUserTools();
		ToolTemplate template = toolsMap.get(toolName);
		if (template == null) {
			return; // the tool may not exist at this point
		}
		ToolUtils.deleteTool(template);
	}

	protected void exitGhidra() {
		testEnv.dispose();
	}

	protected List<PluginTool> findOpenTools() {
		ToolManager tm = testEnv.getProject().getToolManager();
		Workspace activeWorkspace = tm.getActiveWorkspace();
		PluginTool[] tools = activeWorkspace.getTools();
		List<PluginTool> pluginToolList = new ArrayList<>(tools.length);
		for (PluginTool tool : tools) {
			pluginToolList.add(tool);
		}
		return pluginToolList;
	}

	protected boolean getBooleanFooOptions(PluginTool tool) {
		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		return options.getBoolean("foo", false);
	}

	protected JDialog getOldStyleSaveChangesDialog(PluginTool tool) {
		String toolTitle = (String) getInstanceField("NON_AUTOSAVE_SAVE_TOOL_TITLE", tool);
		return waitForJDialog(toolTitle);
	}

	protected JFrame getOpenedToolWindow(String toolName) {
		List<DockingWindowManager> windowManagers =
			DockingWindowManager.getAllDockingWindowManagers();
		for (DockingWindowManager manager : windowManagers) {
			JFrame rootFrame = manager.getRootFrame();
			String title = rootFrame.getTitle();
			if (toolName.equals(title)) {
				return rootFrame;
			}
		}
		return null;
	}

	protected Map<String, Object> getOptionsMap(PluginTool tool) {
		Map<String, Object> map = new TreeMap<>();
		Options[] options = tool.getOptions();

		for (Options option : options) {
			String optionsName = option.getName();
			List<String> optionNames = option.getOptionNames();
			for (String name : optionNames) {
				Object value = invokeInstanceMethod("getObject", option,
					new Class[] { String.class, Object.class }, new Object[] { name, null });
				map.put(optionsName + "." + name, value);
			}
		}
		return map;
	}

	protected Window getSaveChangesDialog(PluginTool tool) {
		String toolTitle = (String) getInstanceField("SAVE_DIALOG_TITLE", tool);
		waitForSwing();
		return getWindowByTitleContaining(null, toolTitle);
	}

	protected SelectChangedToolDialog getSaveSessionChangesDialog() {
		return waitForDialogComponent(SelectChangedToolDialog.class);
	}

	protected Point getToolPosition(final PluginTool tool) {
		return runSwing(() -> tool.getToolFrame().getLocation());
	}

	protected Dimension getToolSize(PluginTool tool) {
		JFrame toolFrame = tool.getToolFrame();
		return toolFrame.getSize();
	}

	protected boolean isBookmarkProviderShowing(PluginTool tool) {
		BookmarkPlugin plugin = getPlugin(tool, BookmarkPlugin.class);
		ComponentProvider provider = (ComponentProvider) getInstanceField("provider", plugin);
		return tool.isVisible(provider);
	}

	protected PluginTool launchTool(String toolName) {
		PluginTool tool = testEnv.launchTool(toolName, null);

		// There is some delayed options registration that causes sporadic test failures.  Waiting
		// for swing here seems to fix that.
		waitForSwing();
		return tool;
	}

	protected void dumpToolFile(String name) throws IOException {
		File file = ToolUtils.getToolFile(name);
		List<String> lines = FileUtilities.getLines(file);
		System.err.println("Tool contents '" + name + "': ");
		for (String line : lines) {
			System.err.println(line);
		}
	}

	protected void printToolXmlContainting(String name, String text) throws IOException {
		File file = ToolUtils.getToolFile(name);
		List<String> lines = FileUtilities.getLines(file);
		System.err.println("Tool '" + file + "'\n\t- lines containing '" + text + "': ");
		Pattern p = Pattern.compile(".*" + Pattern.quote(text) + ".*");
		for (String line : lines) {
			Matcher m = p.matcher(line);
			if (m.matches()) {
				System.err.println(line);
			}
		}
	}

	protected void pressDontSave(Window dialog) {
		pressButtonByText(dialog, "Don't Save", true);
	}

	protected void pressSave(Window dialog) {
		pressButtonByText(dialog, "Save", true);
	}

	protected void saveTool(final PluginTool tool) {
		runSwing(() -> tool.saveTool());
	}

	protected void selectAndSaveSessionTool(SelectChangedToolDialog dialog, PluginTool tool) {
		setInstanceField("selectedTool", dialog, tool);
		pressButtonByText(dialog, "OK", true);
	}

	protected void setAutoSaveEnabled(boolean enabled) {
		testEnv.setAutoSaveEnabled(enabled);
	}

	protected void setBookmarkProviderShowing(final PluginTool tool, final boolean visible) {
		BookmarkPlugin plugin = getPlugin(tool, BookmarkPlugin.class);
		final ComponentProvider provider = (ComponentProvider) getInstanceField("provider", plugin);
		runSwing(() -> tool.showComponentProvider(provider, visible));

		boolean newVisibleState = tool.isVisible(provider);
		assertEquals(visible, newVisibleState);
	}

	protected void setBooleanFooOptions(PluginTool tool, boolean value) {
		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		options.setBoolean("foo", value);
	}

	protected void setToolPosition(final PluginTool tool, final Point point) {

		JFrame toolFrame = tool.getToolFrame();
		runSwing(() -> {
			toolFrame.setLocation(point);
		});
		waitForSwing();

		waitForCondition(() -> {
			toolFrame.setLocation(point);
			return point.equals(toolFrame.getLocation());
		});
	}

	protected void setToolSize(PluginTool tool, final Dimension dimension) {
		final JFrame toolFrame = tool.getToolFrame();

		runSwing(() -> toolFrame.setSize(dimension));
	}

}
