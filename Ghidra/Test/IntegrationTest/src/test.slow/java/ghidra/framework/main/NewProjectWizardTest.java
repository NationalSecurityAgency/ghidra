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
import java.net.InetAddress;
import java.net.UnknownHostException;

import javax.swing.*;

import org.junit.*;
import org.junit.experimental.categories.Category;

import docking.action.DockingActionIf;
import docking.wizard.WizardManager;
import generic.test.AbstractGenericTest;
import generic.test.category.PortSensitiveCategory;
import ghidra.framework.GenericRunInfo;
import ghidra.framework.client.*;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.preferences.Preferences;
import ghidra.server.remote.ServerTestUtil;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import utilities.util.FileUtilities;

/**
 * Test for the New Project Wizard.
 *
 */
@Category(PortSensitiveCategory.class)
public class NewProjectWizardTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private FrontEndTool frontEndTool;
	private File serverRoot;
	private RepositoryServerAdapter repositoryServer;

	private static final String USER = ClientUtil.getUserName();
	private static final int SERVER_PORT = 14100;
	private static String LOCALHOST = createLocalHostString();

	private static String createLocalHostString() {
		String localHostString = null;
		try {
			localHostString = InetAddress.getLocalHost().getHostName();
		}
		catch (UnknownHostException e) {
			localHostString = "127.0.0.1";
		}
		return localHostString;
	}

	public NewProjectWizardTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		File projectDirectory = new File(GenericRunInfo.getProjectsDirPath());
		deleteProject(projectDirectory.getAbsolutePath(), "ProjectTest");

		// Note: we must call clear() on the preferences, and not delete the file, since
		// the preferences have already been loaded at this point.  Also, even if you deleted the
		// file before the data was loaded, then the preferences would simply load from
		// another directory.
		Preferences.clear();

		frontEndTool = env.getFrontEndTool();
		env.showFrontEndTool();

	}

	@After
	public void tearDown() throws Exception {

		try {

			DockingActionIf saveAction = getAction("Save Project");
			performAction(saveAction, true);
			DockingActionIf action = getAction("Close Project");
			performAction(action, true);

			File projectDirectory = new File(GenericRunInfo.getProjectsDirPath());

			deleteProject(projectDirectory.getAbsolutePath(), "ProjectTest");
		}
		finally {
			cleanupResources();
		}
	}

	private void cleanupResources() throws Exception {
		env.dispose();

		try {
			Preferences.setProperty("ServerInfo", null);
			Preferences.store();
		}
		finally {
			if (serverRoot != null) {
				ServerTestUtil.disposeServer();
				FileUtilities.deleteDir(serverRoot);
			}
		}
	}

	@Test
	public void testCreateNonSharedProject() {
		try {
			DockingActionIf action = getAction("New Project");
			performAction(action, false);
			waitForPostedSwingRunnables();

			WizardManager wm =
				waitForDialogComponent(frontEndTool.getToolFrame(), WizardManager.class, 2000);
			assertNotNull(wm);

			ProjectTypePanel typePanel = findComponent(wm, ProjectTypePanel.class);
			assertNotNull(typePanel);
			JRadioButton rb =
				(JRadioButton) findAbstractButtonByText(typePanel, "Non-Shared Project");
			assertNotNull(rb);
			assertTrue(rb.isSelected());

			JButton nextButton = findButtonByText(wm, "Next >>");
			assertNotNull(nextButton);
			assertTrue(nextButton.isEnabled());
			JButton finishButton = findButtonByText(wm, "Finish");
			assertNotNull(finishButton);
			assertTrue(!finishButton.isEnabled());

			pressButton(nextButton, true);
			assertTrue(!nextButton.isEnabled());

			SelectProjectPanel projPanel = findComponent(wm, SelectProjectPanel.class);
			assertNotNull(projPanel);

			JTextField dirField = (JTextField) findComponentByName(projPanel, "Project Directory");
			assertNotNull(dirField);
			assertTrue(dirField.getText().length() > 0);

			final JTextField projField =
				(JTextField) findComponentByName(projPanel, "Project Name");
			assertNotNull(projField);
			assertEquals("", projField.getText());

			SwingUtilities.invokeAndWait(() -> projField.setText("ProjectTest"));
			waitForPostedSwingRunnables();

			assertTrue(createSelectProjectPanelOutputMessage(wm.getStatusMessage(), projPanel),
				finishButton.isEnabled());

			pressButton(finishButton, true);
			Thread.sleep(500);
			waitForPostedSwingRunnables();

			Project project = frontEndTool.getProject();
			assertNotNull(project);
			ProjectLocator url = project.getProjectLocator();
			assertEquals("ProjectTest", url.getName());
		}
		catch (Exception e) {
			e.printStackTrace();
			org.junit.Assert.fail(e.toString());
		}
	}

	@Test
	public void testCreateNonSharedProject2() {
		try {
			// test entering a directory that does not exist

			DockingActionIf action = getAction("New Project");
			performAction(action, false);
			waitForPostedSwingRunnables();

			WizardManager wm =
				waitForDialogComponent(frontEndTool.getToolFrame(), WizardManager.class, 2000);
			assertNotNull(wm);

			ProjectTypePanel typePanel = findComponent(wm, ProjectTypePanel.class);
			assertNotNull(typePanel);
			JRadioButton rb =
				(JRadioButton) findAbstractButtonByText(typePanel, "Non-Shared Project");
			assertNotNull(rb);
			assertTrue(rb.isSelected());

			JButton nextButton = findButtonByText(wm, "Next >>");
			assertNotNull(nextButton);
			assertTrue(nextButton.isEnabled());
			JButton finishButton = findButtonByText(wm, "Finish");
			assertNotNull(finishButton);
			assertTrue(!finishButton.isEnabled());

			pressButton(nextButton, true);
			assertTrue(!nextButton.isEnabled());

			SelectProjectPanel projPanel = findComponent(wm, SelectProjectPanel.class);
			assertNotNull(projPanel);

			final JTextField dirField =
				(JTextField) findComponentByName(projPanel, "Project Directory");
			assertNotNull(dirField);

			final JTextField projField =
				(JTextField) findComponentByName(projPanel, "Project Name");
			assertNotNull(projField);

			SwingUtilities.invokeAndWait(() -> {
				String dirText = dirField.getText();
				dirText = dirText + File.separator + "new";
				dirField.setText(dirText);
				projField.setText("MyProject");
			});
			waitForPostedSwingRunnables();

			assertTrue(!finishButton.isEnabled());
			assertEquals("Project directory does not exist.", wm.getStatusMessage());
			pressButtonByText(wm, "Cancel");
		}
		catch (Exception e) {
			e.printStackTrace();
			org.junit.Assert.fail(e.toString());
		}
	}

	@Test
	public void testCreateSharedProject() {
		try {
			// start a local server
			startServer();

			DockingActionIf action = getAction("New Project");
			performAction(action, false);
			waitForPostedSwingRunnables();

			WizardManager wm =
				waitForDialogComponent(frontEndTool.getToolFrame(), WizardManager.class, 2000);
			assertNotNull(wm);

			ProjectTypePanel typePanel = findComponent(wm, ProjectTypePanel.class);
			assertNotNull(typePanel);
			final JRadioButton rb =
				(JRadioButton) findAbstractButtonByText(typePanel, "Shared Project");
			assertNotNull(rb);
			assertTrue(!rb.isSelected());

			SwingUtilities.invokeAndWait(() -> rb.setSelected(true));
			waitForPostedSwingRunnables();

			JButton nextButton = findButtonByText(wm, "Next >>");
			assertNotNull(nextButton);
			assertTrue(nextButton.isEnabled());
			JButton finishButton = findButtonByText(wm, "Finish");
			assertNotNull(finishButton);
			assertTrue(!finishButton.isEnabled());

			pressButton(nextButton, true);

			ServerInfoPanel serverPanel = findComponent(wm, ServerInfoPanel.class);
			assertNotNull(serverPanel);

			final JTextField serverField =
				(JTextField) findComponentByName(serverPanel, "Server Name");
			final JTextField portNumberField =
				(JTextField) findComponentByName(serverPanel, "Port Number");
			assertNotNull(serverField);
			assertNotNull(portNumberField);

			SwingUtilities.invokeAndWait(() -> {
				serverField.setText(LOCALHOST);
				portNumberField.setText(Integer.toString(SERVER_PORT));
			});
			waitForPostedSwingRunnables();

			assertTrue(nextButton.isEnabled());
			assertTrue(!finishButton.isEnabled());

			pressButton(nextButton);

			// next panel should be the repository panel
			RepositoryPanel repPanel = findComponent(wm, RepositoryPanel.class);
			assertNotNull(repPanel);

			JRadioButton existingRb =
				(JRadioButton) findAbstractButtonByText(repPanel, "Existing Repository");
			assertNotNull(existingRb);
			assertTrue(existingRb.isSelected());

			// create a new repository
			final JRadioButton createRb =
				(JRadioButton) findAbstractButtonByText(repPanel, "Create Repository");
			assertNotNull(createRb);
			assertTrue(!createRb.isSelected());
			final JTextField repNameField = findComponent(repPanel, JTextField.class);
			assertNotNull(repNameField);
			assertTrue(!repNameField.isEnabled());

			JList repList = findComponent(repPanel, JList.class);
			assertNotNull(repList);
			assertTrue(repList.isEnabled());

			pressButton(createRb, true);
			assertTrue(!existingRb.isSelected());
			assertTrue(repNameField.isEnabled());
			assertTrue(!repList.isEnabled());
			assertTrue(!nextButton.isEnabled());
			assertTrue(!finishButton.isEnabled());

			SwingUtilities.invokeAndWait(() -> repNameField.setText("TestRepository"));
			waitForPostedSwingRunnables();
			assertTrue(nextButton.isEnabled());
			assertTrue(!finishButton.isEnabled());

			pressButton(nextButton, true);
			assertTrue(
				"Next button did not become enabled - status message: " + wm.getStatusMessage(),
				nextButton.isEnabled());

			// next panel should be user access panel
			ProjectAccessPanel accessPanel = findComponent(wm, ProjectAccessPanel.class);
			assertNotNull(accessPanel);

			assertTrue(nextButton.isEnabled());
			assertTrue(
				"Finish button did not become enabled - status message: " + wm.getStatusMessage(),
				finishButton.isEnabled());

			// next panel is project location panel
			pressButton(nextButton, true);
			assertTrue(!nextButton.isEnabled());

			SelectProjectPanel projPanel = findComponent(wm, SelectProjectPanel.class);
			assertNotNull(projPanel);

			JTextField dirField = (JTextField) findComponentByName(projPanel, "Project Directory");
			assertNotNull(dirField);
			assertTrue(dirField.getText().length() > 0);

			final JTextField projField =
				(JTextField) findComponentByName(projPanel, "Project Name");
			assertNotNull(projField);
			assertEquals("TestRepository", projField.getText());

			SwingUtilities.invokeAndWait(() -> projField.setText("ProjectTest"));
			waitForPostedSwingRunnables();
			assertTrue(finishButton.isEnabled());
			assertTrue(!nextButton.isEnabled());

			pressButton(finishButton, true);
			Thread.sleep(500);
			waitForPostedSwingRunnables();

			Project project = frontEndTool.getProject();
			assertNotNull(project);
			ProjectLocator url = project.getProjectLocator();
			assertEquals("ProjectTest", url.getName());
		}
		catch (Exception e) {
			e.printStackTrace();
			org.junit.Assert.fail(e.toString());
		}
	}

	@Test
	public void testCreateSharedProjectExisting() throws Exception {
		// create shared project against existing repository

		try {
			// start a local server
			startServer();

			DockingActionIf action = getAction("New Project");
			performAction(action, false);
			waitForPostedSwingRunnables();

			WizardManager wm =
				waitForDialogComponent(frontEndTool.getToolFrame(), WizardManager.class, 2000);
			assertNotNull(wm);

			ProjectTypePanel typePanel = findComponent(wm, ProjectTypePanel.class);
			assertNotNull(typePanel);
			final JRadioButton rb =
				(JRadioButton) findAbstractButtonByText(typePanel, "Shared Project");
			assertNotNull(rb);
			assertTrue(!rb.isSelected());

			SwingUtilities.invokeAndWait(() -> rb.setSelected(true));
			waitForPostedSwingRunnables();

			JButton nextButton = findButtonByText(wm, "Next >>");
			assertNotNull(nextButton);
			assertTrue(nextButton.isEnabled());
			JButton finishButton = findButtonByText(wm, "Finish");
			assertNotNull(finishButton);
			assertTrue(!finishButton.isEnabled());

			pressButton(nextButton, true);

			ServerInfoPanel serverPanel = findComponent(wm, ServerInfoPanel.class);
			assertNotNull(serverPanel);

			final JTextField serverField =
				(JTextField) findComponentByName(serverPanel, "Server Name");
			final JTextField portNumberField =
				(JTextField) findComponentByName(serverPanel, "Port Number");
			assertNotNull(serverField);
			assertNotNull(portNumberField);

			if (nextButton.isEnabled()) {
				// enabled because we have left over server info from previous test
				assertTrue(serverField.getText().length() > 0);
				assertTrue(portNumberField.getText().length() > 0);
			}

			SwingUtilities.invokeAndWait(() -> {
				serverField.setText(LOCALHOST);
				portNumberField.setText(Integer.toString(SERVER_PORT));
			});
			waitForPostedSwingRunnables();
			assertTrue(nextButton.isEnabled());
			assertTrue(!finishButton.isEnabled());

			pressButton(nextButton);

			// next panel should be the repository panel
			RepositoryPanel repPanel = findComponent(wm, RepositoryPanel.class);
			assertNotNull(repPanel);

			JRadioButton existingRb =
				(JRadioButton) findAbstractButtonByText(repPanel, "Existing Repository");
			assertNotNull(existingRb);
			assertTrue(existingRb.isSelected());

			// create a new repository
			final JRadioButton createRb =
				(JRadioButton) findAbstractButtonByText(repPanel, "Create Repository");
			assertNotNull(createRb);
			assertTrue(!createRb.isSelected());
			final JTextField repNameField = findComponent(repPanel, JTextField.class);
			assertNotNull(repNameField);
			assertTrue(!repNameField.isEnabled());

			final JList repList = findComponent(repPanel, JList.class);
			assertNotNull(repList);
			assertTrue(repList.isEnabled());

			assertTrue(!createRb.isSelected());
			assertTrue(!repNameField.isEnabled());
			assertTrue(repList.isEnabled());
			assertTrue(!nextButton.isEnabled());
			assertTrue(!finishButton.isEnabled());

			// select existing repository
			SwingUtilities.invokeAndWait(() -> repList.setSelectedIndex(0));
			waitForPostedSwingRunnables();
			assertTrue(nextButton.isEnabled());
			assertTrue(!finishButton.isEnabled());

			// next panel is project location panel
			pressButton(nextButton, true);
			assertTrue(!nextButton.isEnabled());

			SelectProjectPanel projPanel = findComponent(wm, SelectProjectPanel.class);
			assertNotNull(projPanel);

			JTextField dirField = (JTextField) findComponentByName(projPanel, "Project Directory");
			assertNotNull(dirField);
			assertTrue(dirField.getText().length() > 0);

			final JTextField projField =
				(JTextField) findComponentByName(projPanel, "Project Name");
			assertNotNull(projField);
			assertEquals("My_Repository", projField.getText());

			SwingUtilities.invokeAndWait(() -> projField.setText("ProjectTest"));
			waitForPostedSwingRunnables();
			assertTrue(createSelectProjectPanelOutputMessage(wm.getStatusMessage(), projPanel),
				finishButton.isEnabled());
			assertTrue(!nextButton.isEnabled());

			pressButton(finishButton, true);
			Thread.sleep(500);
			waitForPostedSwingRunnables();

			Project project = frontEndTool.getProject();
			assertNotNull(project);
			ProjectLocator url = project.getProjectLocator();
			assertEquals("ProjectTest", url.getName());
		}
		catch (Exception e) {
			e.printStackTrace();
			org.junit.Assert.fail(e.toString());
		}

	}

	////////////////////////////////////////////////////////////////////

	private String createSelectProjectPanelOutputMessage(String statusMessage,
			SelectProjectPanel projectPanel) {

		JTextField dirField = (JTextField) findComponentByName(projectPanel, "Project Directory");
		JTextField projectField = (JTextField) findComponentByName(projectPanel, "Project Name");

		String message = "Finish button did not become enabled - status message: " + statusMessage +
			".\n\tDirectory: " + dirField.getText() + "\n\tProject name: " + projectField.getText();
		return message;
	}

	private DockingActionIf getAction(String actionName) {

		DockingActionIf action = getAction(frontEndTool, "FrontEndPlugin", actionName);
		return action;
	}

	private void startServer() throws Exception {
		File parent = new File(AbstractGenericTest.getTestDirectoryPath());

		// Create server instance
		serverRoot = new File(parent, "My_Server");
		FileUtilities.deleteDir(serverRoot);

		repositoryServer = ServerTestUtil.getServerAdapter(serverRoot, new String[] { USER });

		if (repositoryServer == null || !repositoryServer.isConnected()) {
			ServerTestUtil.disposeServer();
			FileUtilities.deleteDir(serverRoot);
			serverRoot = null;
			Assert.fail("Server connect failed");
		}

		RepositoryAdapter repository = repositoryServer.createRepository("My_Repository");
		assertTrue(repository.getUser().isAdmin());
	}
}
