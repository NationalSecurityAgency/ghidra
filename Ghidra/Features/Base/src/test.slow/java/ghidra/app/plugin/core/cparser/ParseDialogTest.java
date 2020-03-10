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
package ghidra.app.plugin.core.cparser;

import static org.junit.Assert.*;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.table.TableModel;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.pathmanager.PathnameTablePanel;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Msg;

public class ParseDialogTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String CLIB_PRF = "clib.prf";
	private TestEnv env;
	private PluginTool tool;
	private CParserPlugin plugin;
	private DockingActionIf parseAction;
	private ParseDialog dialog;
	private JComboBox<?> profilesComboBox;
	private DefaultComboBoxModel<?> profilesComboBoxModel;

	private List<String> paths;

	private String defaultPrfOptions;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(DataTypeManagerPlugin.class.getName());
		tool.addPlugin(CParserPlugin.class.getName());
		plugin = getPlugin(tool, CParserPlugin.class);

		env.showTool();

		String tempPath = createTempFilePath(getClass().getSimpleName());
		plugin.setUserProfileDir(tempPath);
		parseAction = getAction(plugin, CParserPlugin.PARSE_ACTION_NAME);
		readDefaultParseProfileFile();
		removeAllProfiles();

		dialog = showDialog();
		profilesComboBox = findComponent(dialog, JComboBox.class);
		assertNotNull(profilesComboBox);
		profilesComboBoxModel = (DefaultComboBoxModel<?>) profilesComboBox.getModel();

		// sanity checks
		// -ensure a default profile
		selectProfile(CLIB_PRF);

		String parseOptions = runSwing(() -> dialog.getParseOptions());
		assertEquals("Dialog options not correctly loaded", defaultPrfOptions, parseOptions);
	}

	@After
	public void tearDown() throws Exception {
		removeAllProfiles();
		env.dispose();
	}

	@Test
	public void testDialog() throws Exception {

		assertNotNull(parseAction);
		assertTrue(parseAction.isEnabled());

		PathnameTablePanel pathPanel =
			findComponent(dialog.getComponent(), PathnameTablePanel.class);
		assertNotNull(pathPanel);
		JTable table = pathPanel.getTable();
		TableModel tableModel = table.getModel();
		assertEquals(paths.size(), tableModel.getRowCount());

		String path = (String) tableModel.getValueAt(0, 0);
		assertEquals(paths.get(0), path);

		String parseOptions = runSwing(() -> dialog.getParseOptions());
		assertNotNull(parseOptions);

		assertEquals(defaultPrfOptions, parseOptions);

		JButton parseProgramButton = findButtonByText(dialog, "Parse to Program");
		assertNotNull(parseProgramButton);

		JButton parseToFileButton = findButtonByText(dialog, "Parse to File...");
		assertNotNull(parseToFileButton);

		DockingActionIf saveAsAction = getAction(dialog, "Save Profile As");
		assertTrue(saveAsAction.isEnabled());

		DockingActionIf saveAction = getAction(dialog, "Save Profile");
		assertFalse(saveAction.isEnabled());

		DockingActionIf clearAction = getAction(dialog, "Clear Profile");
		assertTrue(clearAction.isEnabled());

		DockingActionIf deleteAction = getAction(dialog, "Delete Profile");
		assertFalse(deleteAction.isEnabled());

		DockingActionIf refreshAction = getAction(dialog, "Refresh User Profiles");
		assertTrue(refreshAction.isEnabled());
	}

	@Test
	public void testEditDefaultProfile() throws Exception {

		addSourceFile("c:\\temp\\fred.h");

		DockingActionIf saveAction = getAction(dialog, "Save Profile");
		assertFalse(saveAction.isEnabled());

		DockingActionIf saveAsAction = getAction(dialog, "Save Profile As");
		assertTrue(saveAsAction.isEnabled());
	}

	@Test
	public void testCreateProfile() throws Exception {

		int startModelSize = getProfileCount();

		addSourceFile("c:\\temp\\fred.h");

		String profileName = "MyProfile";
		saveProfileAs(profileName);
		assertProfileSelected(profileName);

		assertEquals(startModelSize + 1, getProfileCount());

		String parseOptions = runSwing(() -> dialog.getParseOptions());
		if (!defaultPrfOptions.equals(parseOptions)) {
			// debug
			capture(dialog.getComponent(), "parse.dialog.options.png");
		}
		assertEquals(defaultPrfOptions, parseOptions);

		DockingActionIf saveAction = getAction(dialog, "Save Profile");
		assertFalse(saveAction.isEnabled());

		DockingActionIf deleteAction = getAction(dialog, "Delete Profile");
		assertTrue(deleteAction.isEnabled());

		DockingActionIf clearAction = getAction(dialog, "Clear Profile");
		assertTrue(clearAction.isEnabled());
	}

	@Test
	public void testOverwriteExistingFile() throws Exception {

		createProfile("MyProfile_1");
		createProfile("MyProfile_2");
		createProfile("MyProfile_3");

		int startModelSize = getProfileCount();

		String profileName = "MyProfile_2";
		saveProfileAs(profileName);

		OptionDialog optDialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull(optDialog);
		assertEquals("Overwrite Existing File?", optDialog.getTitle());
		pressButtonByText(optDialog, "Yes");
		waitForSwing();

		// we overwrote, so the size shouldn't have changed		
		assertEquals(startModelSize, getProfileCount());
		assertProfileSelected(profileName);
	}

	@Test
	public void testDoNotOverwrite() throws Exception {

		addSourceFile("c:\\temp\\fred.h");

		String profileName = "MyProfile";
		saveProfileAs(profileName);
		assertProfileSelected(profileName);

		selectProfile(CLIB_PRF);
		saveProfileAs(profileName);

		OptionDialog optDialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull(optDialog);
		assertEquals("Overwrite Existing File?", optDialog.getTitle());

		pressButtonByText(optDialog, "No");
	}

	@Test
	public void testChangeSelectionAfterEdits() throws Exception {

		String profileName = "MyProfile";
		createProfile(profileName);
		assertProfileSelected(profileName);

		addSourceFile("c:\\temp\\fred.h");

		// select the default profile
		selectProfile(CLIB_PRF);

		OptionDialog optDialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull(optDialog);
		assertEquals("Save Changes to Profile?", optDialog.getTitle());

		pressButtonByText(optDialog, "Yes");
	}

	@Test
	public void testDeleteProfile() throws Exception {

		String profileName = "MyProfile";
		createProfile(profileName);
		assertProfileSelected(profileName);

		DockingActionIf deleteAction = getAction(dialog, "Delete Profile");
		performAction(deleteAction, false);

		waitForSwing();

		OptionDialog optDialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull(optDialog);
		assertEquals("Delete Profile?", optDialog.getTitle());

		pressButtonByText(optDialog.getComponent(), "Delete");
	}

	@Test
	public void testClearProfile() throws Exception {

		createProfile("MyProfile");

		DockingActionIf clearAction = getAction(dialog, "Clear Profile");
		performAction(clearAction);

		PathnameTablePanel pathPanel =
			findComponent(dialog.getComponent(), PathnameTablePanel.class);
		TableModel tableModel = pathPanel.getTable().getModel();
		assertEquals(0, tableModel.getRowCount());

		String parseOptions = runSwing(() -> dialog.getParseOptions());
		assertTrue(parseOptions.isEmpty());

		DockingActionIf saveAction = getAction(dialog, "Save Profile");
		assertTrue(saveAction.isEnabled());
	}

	@Test
	public void testRefresh() throws Exception {

		createProfile("MyProfile_1");
		createProfile("MyProfile_2");
		createProfile("MyProfile_3");

		int startModelSize = getProfileCount();

		String value = getSelectedProfile();
		assertEquals("MyProfile_3.prf", value);

		deleteProfile("MyProfile_1.prf");

		DockingActionIf refreshAction = getAction(dialog, "Refresh User Profiles");
		performAction(refreshAction, true);

		assertEquals(startModelSize - 1, getProfileCount());// make sure the deleted is removed
		value = getSelectedProfile();
		assertEquals("MyProfile_3.prf", value);
	}

	@Test
	public void testRefreshWithEdits() throws Exception {

		createProfile("MyProfile_1");
		createProfile("MyProfile_2");
		createProfile("MyProfile_3");

		String sourceFile = "c:\\temp\\fred.h";
		addSourceFile(sourceFile);

		DockingActionIf refreshAction = getAction(dialog, "Refresh User Profiles");
		performAction(refreshAction, false);
		waitForSwing();

		OptionDialog optDialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull(optDialog);
		assertEquals("Save Changes to Profile?", optDialog.getTitle());
		pressButtonByText(optDialog, "Yes");

		assertProfileSelected("MyProfile_3.prf");
		assertContainsSourceFile(sourceFile);
	}

	private void assertContainsSourceFile(String expectedPath) {
		PathnameTablePanel pathPanel =
			findComponent(dialog.getComponent(), PathnameTablePanel.class);
		String[] allPaths = pathPanel.getPaths();
		for (String path : allPaths) {
			if (path.equals(expectedPath)) {
				return;
			}
		}

		fail("Source file path not in dialog: " + expectedPath);
	}

	private void addSourceFile(String path) {
		PathnameTablePanel pathPanel =
			findComponent(dialog.getComponent(), PathnameTablePanel.class);
		runSwing(() -> pathPanel.setPaths(new String[] { paths.get(0), path }));
	}

	private ParseDialog showDialog() {
		performAction(parseAction, true);
		return waitForDialogComponent(ParseDialog.class);
	}

	private void readDefaultParseProfileFile() throws Exception {

		StringBuffer buffy = new StringBuffer();
		List<String> pathList = new ArrayList<>();

		ResourceFile profileFile = getPrfFile();
		Msg.debug(this, "Reading parse profile file: " + profileFile.getAbsolutePath());

		BufferedReader br = new BufferedReader(new InputStreamReader(profileFile.getInputStream()));
		String line = null;
		while ((line = br.readLine()) != null) {
			line = line.trim();
			if (line.startsWith("-") || (line.length() == 0 && buffy.length() > 0)) {
				// this is a compiler directive
				buffy.append(line + "\n");
			}
			else if (line.length() > 0) {
				File f = new File(line);
				pathList.add(f.getPath());
			}
		}

		paths = pathList;
		defaultPrfOptions = buffy.toString();

		br.close();
	}

	private ResourceFile getPrfFile() throws IOException {
		ResourceFile parent = Application.getModuleDataSubDirectory(ParseDialog.PROFILE_DIR);
		ResourceFile clib = new ResourceFile(parent, CLIB_PRF);
		assertTrue(clib.exists());
		return clib;
	}

	private void deleteProfile(String name) {
		File profileDir = plugin.getUserProfileDir();
		File[] files = profileDir.listFiles();
		for (File f : files) {
			if (f.getName().equals(name)) {
				f.delete();
				return;
			}
		}
		Assert.fail("Unable to find parser profile to delete: " + name + " in dir: " + profileDir);
	}

	private void removeAllProfiles() {
		File file = plugin.getUserProfileDir();
		File[] files = file.listFiles();
		for (File file2 : files) {
			file2.delete();
		}
	}

	private void selectProfile(String profileName) {

		for (int i = 0; i < profilesComboBoxModel.getSize(); i++) {
			Object item = profilesComboBoxModel.getElementAt(i);
			String text = item.toString();

			// note: we use 'contains()' since the passed-in name does not include all the
			//       text found in the combo box
			if (text.contains(profileName)) {
				int index = i;
				runSwing(() -> profilesComboBox.setSelectedIndex(index), false);
				return;
			}
		}

		waitForSwing();
		assertProfileSelected(profileName);
	}

	private void assertProfileSelected(String expected) {
		// note: we use 'contains()' since the passed-in name does not include all the
		//       text found in the combo box
		String actual = getSelectedProfile();
		assertTrue("Profile is not selected", actual.contains(expected));
	}

	private int getProfileCount() {
		return runSwing(() -> profilesComboBoxModel.getSize());
	}

	private String getSelectedProfile() {
		return runSwing(() -> profilesComboBoxModel.getSelectedItem().toString());
	}

	private void createProfile(String name) throws Exception {

		PathnameTablePanel pathPanel =
			findComponent(dialog.getComponent(), PathnameTablePanel.class);
		JTextArea textArea = findComponent(dialog.getComponent(), JTextArea.class);
		runSwing(() -> {
			pathPanel.setPaths(new String[] { paths.get(0), "c:\\temp\\fred.h" });
			textArea.append("\n-D_MY_DIRECTIVE");
		});

		saveProfileAs(name);
	}

	private void saveProfileAs(String newName) {
		DockingActionIf saveAsAction = getAction(dialog, "Save Profile As");
		performAction(saveAsAction, false);
		waitForSwing();

		InputDialog inputDialog = waitForDialogComponent(InputDialog.class);
		assertNotNull(inputDialog);

		JTextField tf = findComponent(inputDialog.getComponent(), JTextField.class);
		assertNotNull(tf);

		setText(tf, newName);
		pressButtonByText(inputDialog, "OK", true);
		waitForSwing();
	}
}
