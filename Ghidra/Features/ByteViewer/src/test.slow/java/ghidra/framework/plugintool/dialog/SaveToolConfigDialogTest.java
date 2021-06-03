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
package ghidra.framework.plugintool.dialog;

import static org.junit.Assert.*;

import java.awt.event.ActionListener;
import java.io.File;
import java.io.InputStream;
import java.net.URL;

import javax.swing.*;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.tool.ToolConstants;
import docking.util.image.ToolIconURL;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import generic.test.AbstractGTest;
import ghidra.app.plugin.core.byteviewer.ByteViewerPlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.data.DataPlugin;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.equate.EquateTablePlugin;
import ghidra.app.plugin.core.function.FunctionPlugin;
import ghidra.app.plugin.core.memory.MemoryMapPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NavigationHistoryPlugin;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.framework.model.ToolChest;
import ghidra.framework.model.ToolTemplate;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.framework.preferences.Preferences;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.exception.AssertException;
import resources.ResourceManager;
import utilities.util.FileUtilities;

/**
 * Tests for saving the tool config.
 * 
 * 
 */
public class SaveToolConfigDialogTest extends AbstractGhidraHeadedIntegrationTest {

	private PluginTool tool;
	private TestEnv env;
	private SaveToolConfigDialog saveDialog;
	private JTextField toolNameField;
	private JList iconList;
	private JTextField iconNameField;
	private PluginTool newtool;

	public SaveToolConfigDialogTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(NavigationHistoryPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(MemoryMapPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool.addPlugin(DataTypeManagerPlugin.class.getName());
		tool.addPlugin(DataPlugin.class.getName());
		tool.addPlugin(FunctionPlugin.class.getName());
		tool.addPlugin(EquateTablePlugin.class.getName());
		tool.addPlugin(ProgramTreePlugin.class.getName());

		env.showTool();
		showDialogs();
	}

	@After
	public void tearDown() throws Exception {
		ToolChest tc = tool.getProject().getLocalToolChest();
		tc.remove("MyTestTool");
		tc.remove("TestTool");

		waitForSwing();
		tool.setConfigChanged(false);
		runSwing(() -> saveDialog.close());
		env.dispose();
	}

	@Test
	public void testDialog() throws Exception {
		assertEquals("Save Tool to Tool Chest", saveDialog.getTitle());
		assertNotNull(toolNameField);
		assertNotNull(iconNameField);
		assertEquals(tool.getToolName(), toolNameField.getText());

		JButton browseButton = (JButton) findComponentByName(saveDialog, "BrowseButton");
		assertNotNull(browseButton);

		ImageIcon icon = tool.getIcon();
		ToolIconURL selectedIcon = (ToolIconURL) iconList.getSelectedValue();
		assertNotNull(selectedIcon);
		assertEquals(icon.toString(), selectedIcon.getIcon().toString());
	}

	@Test
	public void testSetName() throws Exception {
		setText(toolNameField, "MyTestTool", false);
		pressButtonByText(saveDialog, "Save");

		assertTrue(!tool.hasConfigChanged());
		waitForSwing();
		assertTrue(!saveDialog.isVisible());
		ToolChest tc = tool.getProject().getLocalToolChest();
		ToolTemplate config = tc.getToolTemplate("MyTestTool");
		assertNotNull(config);
		tc.remove("MyTestTool");
	}

	@Test
	public void testInvalidName() throws Exception {
		setText(toolNameField, "My Test Tool", true);
		JLabel statusLabel = (JLabel) findComponentByName(saveDialog, "statusLabel");
		String msg = statusLabel.getText();
		pressButtonByText(saveDialog, "Cancel");
		while (saveDialog.isVisible()) {
			Thread.sleep(5);
		}
		waitForSwing();
		assertEquals("Name cannot have spaces.", msg);
	}

	@Test
	public void testSetIcon() throws Exception {
		ToolIconURL iconUrl = new ToolIconURL("Caution.png");
		iconList.setSelectedValue(iconUrl, true);
		ToolIconURL iconUrl2 = (ToolIconURL) iconList.getSelectedValue();
		assertEquals(iconUrl, iconUrl2);
		setText(toolNameField, "MyTestTool", false);
		pressButtonByText(saveDialog, "Save");

		assertTrue(!tool.hasConfigChanged());
		waitForSwing();
		assertTrue(!saveDialog.isVisible());
		ToolChest tc = tool.getProject().getLocalToolChest();
		ToolTemplate template = tc.getToolTemplate("MyTestTool");
		tc.remove("MyTestTool");

		ImageIcon icon = ResourceManager.getScaledIcon(
			ResourceManager.loadImage("defaultTools/images/Caution.png"),
			ToolIconURL.LARGE_ICON_SIZE, ToolIconURL.LARGE_ICON_SIZE);

		assertEquals(icon.getDescription(), template.getIcon().getDescription());
	}

	@Test
	public void testSelectIcon() throws Exception {
		ToolIconURL iconUrl = new ToolIconURL("Caution.png");
		iconList.setSelectedValue(iconUrl, true);
		ToolIconURL iconUrl2 = (ToolIconURL) iconList.getSelectedValue();
		assertEquals(iconUrl, iconUrl2);

		pressButtonByText(saveDialog, "Cancel");
		while (saveDialog.isVisible()) {
			Thread.sleep(5);
		}
		waitForSwing();
	}

	@Test
	public void testBrowseButton() throws Exception {
		setText(toolNameField, "MyTestTool", false);
		Preferences.setProperty(Preferences.PROJECT_DIRECTORY, null);

		// choose icon from the filesystem

		// put TestIcon.gif in project dir
		String iconName = "core.png"; // an icon that should not go away
		URL url = ResourceManager.getResource("images/" + iconName);

		assertNotNull("Could not find test icon: " + iconName);

		String tempDir = AbstractGTest.getTestDirectoryPath();

		final File destFile = new File(tempDir, iconName);
		destFile.deleteOnExit();

		InputStream in = url.openStream();
		FileUtilities.copyStreamToFile(in, destFile, false, null);
		in.close();

		final JButton browseButton = (JButton) findComponentByName(saveDialog, "BrowseButton");
		pressButton(browseButton, false);

		final GhidraFileChooser chooser = waitForDialogComponent(GhidraFileChooser.class);

		assertNotNull(chooser);
		runSwing(() -> chooser.setSelectedFile(destFile));
		waitForUpdateOnChooser(chooser);

		final JButton openButton = findButtonByText(chooser, "OK");
		pressButton(openButton);
		waitForSwing();

		ToolIconURL selectedIcon = (ToolIconURL) iconList.getSelectedValue();
		assertNotNull(selectedIcon);
		assertTrue(selectedIcon.getIcon().toString().endsWith(destFile.getName().toString()));

		String lastDirPreference =
			Preferences.getProperty(SaveToolConfigDialog.LAST_ICON_DIRECTORY);
		assertEquals(destFile.getParent(), lastDirPreference);

		saveDialog.close();
	}

	@Test
	public void testSaveToExistingName() throws Exception {
		ToolChest tc = tool.getProject().getLocalToolChest();
		// create a tool
		tool.setToolName("MyTestTool");

		SwingUtilities.invokeLater(() -> tool.getToolServices().saveTool(tool));
		while (tc.getToolTemplate("MyTestTool") == null) {
			Thread.sleep(10);
		}
		waitForSwing();

		setText(toolNameField, "MyTestTool", false);

		SwingUtilities.invokeLater(() -> {
			// force a change to the tool config
			try {
				tool.addPlugin(ByteViewerPlugin.class.getName());
				tool.setConfigChanged(true);
			}
			catch (PluginException e) {
				throw new AssertException();
			}
			JButton saveButton = findButtonByText(saveDialog, "Save");
			saveButton.getActionListeners()[0].actionPerformed(null);
		});
		waitForSwing();

		final OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		assertEquals("Overwrite Tool?", d.getTitle());
		pressButtonByText(d.getComponent(), "Overwrite");

		while (d.isVisible()) {
			Thread.sleep(10);
		}
		waitForSwing();

		assertTrue(!tool.hasConfigChanged());
	}

	@Test
	public void testSaveToExistingNameCancel() throws Exception {
		ToolChest tc = tool.getProject().getLocalToolChest();
		// save tool to the tool chest
		tool.setToolName("MyTestTool");

		SwingUtilities.invokeLater(() -> tool.getToolServices().saveTool(tool));
		while (tc.getToolTemplate("MyTestTool") == null) {
			Thread.sleep(10);
		}
		waitForSwing();

		setText(toolNameField, "MyTestTool", false);

		runSwing(() -> {
			// force a change to the tool config
			try {
				tool.addPlugin(ByteViewerPlugin.class.getName());
				tool.setConfigChanged(true);
			}
			catch (PluginException e) {
				throw new AssertException();
			}
		});

		SwingUtilities.invokeLater(() -> {
			JButton saveButton = findButtonByText(saveDialog, "Save");
			saveButton.getActionListeners()[0].actionPerformed(null);
		});
		waitForSwing();

		final OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		assertEquals("Overwrite Tool?", d.getTitle());
		pressButtonByText(d.getComponent(), "Cancel");

		while (d.isVisible()) {
			Thread.sleep(10);
		}
		waitForSwing();

		assertTrue(tool.hasConfigChanged());
	}

	private void showDialogs() throws Exception {

		DockingActionIf action = getAction(tool, ToolConstants.TOOL_OWNER, "Save Tool As");
		performAction(action, false);
		waitForSwing();

		saveDialog = waitForDialogComponent(SaveToolConfigDialog.class);

		assertNotNull(saveDialog);
		toolNameField = (JTextField) findComponentByName(saveDialog, "ToolName");
		iconList = (JList) findComponentByName(saveDialog, "IconList");
		iconNameField = (JTextField) findComponentByName(saveDialog, "IconName");
	}

	private void setText(final JTextField field, final String text, final boolean doAction)
			throws Exception {

		runSwing(() -> {
			field.setText(text);
			if (doAction) {
				ActionListener[] listeners = field.getActionListeners();
				if (listeners != null && listeners.length > 0) {
					listeners[0].actionPerformed(null);
				}
			}
		});
		waitForSwing();
	}
}
