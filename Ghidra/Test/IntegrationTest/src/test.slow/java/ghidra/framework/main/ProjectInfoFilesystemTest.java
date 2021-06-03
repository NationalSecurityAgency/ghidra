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
package ghidra.framework.main;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;

import javax.swing.*;

import org.junit.*;

import docking.action.DockingActionIf;
import generic.test.TestUtils;
import ghidra.framework.data.ProjectFileManager;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.framework.store.Version;
import ghidra.framework.store.local.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.InvalidNameException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class ProjectInfoFilesystemTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String TEST_PROJECT_NAME = "TestProject";

	private TestEnv env;

	private ProjectLocator projectLocator;
	private Project project;

	private FrontEndTool frontEndTool;
	private ProjectInfoDialog dialog;

	public ProjectInfoFilesystemTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();

		projectLocator = new ProjectLocator(getTestDirectoryPath(), TEST_PROJECT_NAME);
		projectLocator.getMarkerFile().delete();

		File projectDir = new File(getTestDirectoryPath(),
			TEST_PROJECT_NAME + ProjectLocator.getProjectDirExtension());
		if (projectDir.isDirectory()) {
			if (!FileUtilities.deleteDir(projectDir)) {
				Assert.fail("Cleanup of old test project failed");
			}
		}
	}

	@After
	public void tearDown() throws Exception {
		closeAllWindows();
		env.dispose();

		if (project != null) {
			project.close();
		}
		if (projectLocator != null) {
			projectLocator.getMarkerFile().delete();
			FileUtilities.deleteDir(projectLocator.getProjectDir());
		}
	}

	private void createMangledFilesystems(String... fsNames) throws IOException {
		for (String fsName : fsNames) {
			File rootDir = new File(projectLocator.getProjectDir(), fsName);
			LocalFilesystemTestUtils.createMangledFilesystem(rootDir.getAbsolutePath(), false,
				false, false).dispose();
		}
	}

	private void createIndexV0Filesystems(String... fsNames) throws IOException {
		for (String fsName : fsNames) {
			File rootDir = new File(projectLocator.getProjectDir(), fsName);
			LocalFilesystemTestUtils.createIndexedV0Filesystem(rootDir.getAbsolutePath(), false,
				false, false).dispose();
		}
	}

	private void createIndexV1Filesystems(String... fsNames) throws IOException {
		for (String fsName : fsNames) {
			File rootDir = new File(projectLocator.getProjectDir(), fsName);
			LocalFilesystemTestUtils.createIndexedV1Filesystem(rootDir.getAbsolutePath(), false,
				false, false).dispose();
		}
	}

	private void createProject(int filesystemVersion) throws Exception {

		if (filesystemVersion < 0) {
			createMangledFilesystems("data", "versioned", "user");
		}
		else if (filesystemVersion == 0) {
			createIndexV0Filesystems("idata", "versioned", "user");
		}
		else if (filesystemVersion == 1) {
			createIndexV1Filesystems("idata", "versioned", "user");
		}

		try {
			projectLocator.getMarkerFile().createNewFile();
		}
		catch (Exception e) {
			Assert.fail("Failed to open constructed project: " + projectLocator);
		}

		ProjectManager projectManager = env.getProjectManager();
		Project tesEnvProject = projectManager.getActiveProject();
		tesEnvProject.close();// close TestEnv project

		try {
			project = projectManager.openProject(projectLocator, true, false);
		}
		catch (Exception e) {
			Assert.fail("Failed to open fabricated project: " + projectLocator);
		}

		addVersionedProgram("/a", "testA");
		addVersionedProgram("/a/b", "testB");
	}

	private void verifyPrograms() throws Exception {
		verifyProgram("/a/testA");
		verifyProgram("/a/b/testB");
	}

	private DockingActionIf getAction(PluginTool tool, String actionName) {

		DockingActionIf action = getAction(frontEndTool, "FrontEndPlugin", actionName);
		return action;
	}

	private void openProjectAndInfo(int filesystemVersion) throws Exception {

		frontEndTool = env.getFrontEndTool();

		env.showFrontEndTool();

		runSwing(() -> {

			// TODO: Workaround for front-end failure to notify listeners
			// when closing program via setActiveProject method - only done by FileActionManager
			@SuppressWarnings("unchecked")
			Iterable<ProjectListener> listeners =
				(Iterable<ProjectListener>) TestUtils.invokeInstanceMethod("getListeners",
					frontEndTool);
			for (ProjectListener listener : listeners) {
				listener.projectClosed(project);
			}
			frontEndTool.setActiveProject(null);// remove TestEnv project
		});

		createProject(filesystemVersion);

		runSwing(() -> frontEndTool.setActiveProject(project));

		DockingActionIf action = getAction(frontEndTool, "View Project Info");
		assertNotNull(action);
		performAction(action, true);

		dialog = waitForDialogComponent(ProjectInfoDialog.class);
	}

	private DomainFolder getFolder(String folderPath, boolean create) throws IOException {
		ProjectData projectData = project.getProjectData();
		DomainFolder folder = projectData.getRootFolder();
		for (String folderName : folderPath.split("/")) {
			if (folderName.length() == 0) {
				continue;
			}
			DomainFolder f = folder.getFolder(folderName);
			if (f == null) {
				try {
					f = folder.createFolder(folderName);
				}
				catch (InvalidNameException e) {
					Assert.fail("Unexpected Exception");
				}
			}
			folder = f;
		}
		return folder;
	}

	private DomainFile addVersionedProgram(String folderPath, String name) throws Exception {
		DomainFile df;
		Program p = createDefaultProgram(name, ProgramBuilder._TOY64_LE, this);
		try {
			AddressFactory addressFactory = p.getAddressFactory();
			ProgramUserData programUserData = p.getProgramUserData();
			int txId = programUserData.startTransaction();
			try {
				StringPropertyMap propertyMap =
					programUserData.getStringProperty("TEST", "userProp1", true);
				propertyMap.add(addressFactory.getAddress("0100"), "userValue100");
				propertyMap.add(addressFactory.getAddress("0200"), "userValue200");
			}
			finally {
				programUserData.endTransaction(txId);
			}

			df = getFolder(folderPath, true).createFile(name, p, TaskMonitor.DUMMY);
		}
		finally {
			p.release(this);
		}

		df.addToVersionControl("Initial", true, TaskMonitor.DUMMY);
		return df;
	}

	private void verifyProgram(String path) throws Exception {

		DomainFile df = project.getProjectData().getFile(path);
		assertNotNull("Domain file not found: " + path);

		assertTrue(df.isVersioned());
		assertTrue(df.isCheckedOut());
		assertTrue(df.isCheckedOutExclusive());// non-shared version repo

		ItemCheckoutStatus[] checkouts = df.getCheckouts();
		assertEquals(1, checkouts.length);

		Version[] versionHistory = df.getVersionHistory();
		assertEquals(1, versionHistory.length);
		assertEquals("Initial", versionHistory[0].getComment());

		Program p =
			(Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		try {
			AddressFactory addressFactory = p.getAddressFactory();
			ProgramUserData programUserData = p.getProgramUserData();
			StringPropertyMap propertyMap =
				programUserData.getStringProperty("TEST", "userProp1", false);
			AddressIterator propertyIterator = propertyMap.getPropertyIterator();
			Address addr = addressFactory.getAddress("0100");
			assertEquals(addr, propertyIterator.next());
			assertEquals("userValue100", propertyMap.getString(addr));
			addr = addressFactory.getAddress("0200");
			assertEquals(addr, propertyIterator.next());
			assertEquals("userValue200", propertyMap.getString(addr));
		}
		finally {
			p.release(this);
		}

	}

	private void checkProjectInfo(Class<?> filesystemClass, String storageType) {
		ProjectFileManager projectData = (ProjectFileManager) project.getProjectData();
		String msg = "Expected " + filesystemClass.getSimpleName() + ": ";
		assertTrue(msg + "Local FileSystem", filesystemClass.isInstance(
			TestUtils.invokeInstanceMethod("getLocalFileSystem", projectData)));
		assertTrue(msg + "Versioned FileSystem", filesystemClass.isInstance(
			TestUtils.invokeInstanceMethod("getVersionedFileSystem", projectData)));
		assertTrue(msg + "User FileSystem", filesystemClass.isInstance(
			TestUtils.invokeInstanceMethod("getUserFileSystem", projectData)));

		JLabel storageTypeLabel =
			(JLabel) findComponentByName(dialog.getComponent(), "Project Storage Type");
		assertNotNull(storageTypeLabel);
		assertEquals(storageType, storageTypeLabel.getText());

		JLabel nameLabel = (JLabel) findComponentByName(dialog.getComponent(), "Project Name");
		assertNotNull(nameLabel);
		assertEquals(TEST_PROJECT_NAME, nameLabel.getText());
	}

	private void doStorageConvert(String buttonText) {

		JButton button = findButtonByText(dialog, buttonText);
		assertNotNull("Could not find storage convert button", button);

		pressButton(button, false);

		JDialog confirmDialog =
			waitForJDialog("Confirm Convert/Upgrade Project Storage");
		assertNotNull("Expected convert confirm dialog", confirmDialog);

		JButton confirmButton = findButtonByText(confirmDialog, "Convert");
		pressButton(confirmButton);

		waitForPostedSwingRunnables();

		dialog = waitForDialogComponent(ProjectInfoDialog.class);
		assertNotNull("Expected to find Project Info dialog after conversion completed", dialog);

		ProjectManager projectManager = env.getProjectManager();
		project = projectManager.getActiveProject();
	}

	@Test
	public void testMangledFilesystemConversion() throws Exception {

		openProjectAndInfo(-1);

		checkProjectInfo(MangledLocalFileSystem.class, "Mangled Filesystem");

		doStorageConvert("Convert Project Storage to Indexed...");

		checkProjectInfo(IndexedV1LocalFileSystem.class, "Indexed Filesystem (V1)");

		pressButtonByText(dialog, "Dismiss");

		verifyPrograms();
	}

	@Test
	public void testIndexedV0FilesystemConversion() throws Exception {

		openProjectAndInfo(0);

		checkProjectInfo(IndexedLocalFileSystem.class, "Indexed Filesystem (V0)");

		doStorageConvert("Upgrade Project Storage Index...");

		checkProjectInfo(IndexedV1LocalFileSystem.class, "Indexed Filesystem (V1)");

		pressButtonByText(dialog, "Dismiss");

		verifyPrograms();
	}

	@Test
	public void testIndexedV1FilesystemConversion() throws Exception {

		openProjectAndInfo(1);

		checkProjectInfo(IndexedV1LocalFileSystem.class, "Indexed Filesystem (V1)");

		pressButtonByText(dialog, "Dismiss");

		verifyPrograms();
	}
}
