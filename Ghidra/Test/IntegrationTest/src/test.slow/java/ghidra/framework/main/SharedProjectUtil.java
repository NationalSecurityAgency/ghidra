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
/**
 * 
 */
package ghidra.framework.main;

import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import javax.swing.*;

import docking.action.DockingActionIf;
import docking.test.AbstractDockingTest;
import docking.wizard.WizardManager;
import generic.test.AbstractGTest;
import generic.test.AbstractGenericTest;
import ghidra.framework.client.*;
import ghidra.framework.model.*;
import ghidra.server.remote.ServerTestUtil;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.UserAccessException;
import utilities.util.FileUtilities;

/**
 * Static method to create a shared project, and start a server.
 *
 */
public class SharedProjectUtil {

	public static final int SERVER_PORT = ServerTestUtil.GHIDRA_TEST_SERVER_PORT;
	public static String LOCALHOST = createLocalhostString();
	private static final String USER = ClientUtil.getUserName();
	private static File serverRoot;
	private static RepositoryServerAdapter repositoryServer;

	private static String createLocalhostString() {
		try {
			return InetAddress.getLocalHost().getHostName();
		}
		catch (UnknownHostException e) {
			return "127.0.0.1";
		}
	}

	public static boolean createSharedProject(FrontEndTool frontEndTool, final String projectName)
			throws Exception {
		// create shared project against existing repository
		System.err.println("SharedProjectUtil.createSharedProject(): " + projectName);

		UtilProjectListener projectListener = new UtilProjectListener();
		frontEndTool.addProjectListener(projectListener);

		DockingActionIf action = getAction(frontEndTool, "New Project");
		AbstractDockingTest.performAction(action, false);
		AbstractGenericTest.waitForSwing();

		WizardManager wm = AbstractDockingTest.waitForDialogComponent(WizardManager.class);

		ProjectTypePanel typePanel = AbstractDockingTest.findComponent(wm, ProjectTypePanel.class);
		final JRadioButton rb =
			(JRadioButton) AbstractGenericTest.findAbstractButtonByText(typePanel,
				"Shared Project");

		SwingUtilities.invokeAndWait(() -> rb.setSelected(true));

		JButton nextButton = AbstractDockingTest.findButtonByText(wm, "Next >>");
		JButton finishButton = AbstractDockingTest.findButtonByText(wm, "Finish");

		AbstractGenericTest.pressButton(nextButton, true);

		ServerInfoPanel serverPanel = AbstractDockingTest.findComponent(wm, ServerInfoPanel.class);

		final JTextField serverField =
			(JTextField) AbstractGenericTest.findComponentByName(serverPanel, "Server Name");
		final JTextField portNumberField =
			(JTextField) AbstractGenericTest.findComponentByName(serverPanel, "Port Number");

		SwingUtilities.invokeAndWait(() -> {
			serverField.setText(LOCALHOST);
			portNumberField.setText(Integer.toString(SERVER_PORT));
		});

		AbstractGenericTest.pressButton(nextButton);

		// next panel should be the repository panel
		RepositoryPanel repPanel = AbstractDockingTest.findComponent(wm, RepositoryPanel.class);

		final JList<?> repList = AbstractGenericTest.findComponent(repPanel, JList.class);

		// select existing repository
		SwingUtilities.invokeAndWait(() -> repList.setSelectedIndex(0));

		// next panel is project location panel
		AbstractGenericTest.pressButton(nextButton, true);

		final SelectProjectPanel projPanel =
			AbstractDockingTest.findComponent(wm, SelectProjectPanel.class);

		final String testProjectDirectory = AbstractGTest.getTestDirectoryPath();
		final JTextField projDirField =
			(JTextField) AbstractGenericTest.findComponentByName(projPanel, "Project Directory");
		final JTextField projNameField =
			(JTextField) AbstractGenericTest.findComponentByName(projPanel, "Project Name");

		SwingUtilities.invokeAndWait(() -> {
			projDirField.setText(testProjectDirectory);
			projNameField.setText(projectName);
		});

		if (!finishButton.isEnabled()) {
			String statusMessage = projPanel.getStatusMessage();
			System.err.println(
				"Finish button is unexectedly disabled!!\n\t" + "Status message: " + statusMessage);
			return false;
		}

		AbstractGenericTest.pressButton(finishButton, true);
		AbstractGenericTest.waitForSwing();
		boolean didOpen = waitForProjectToOpen(projectName, projectListener);
		System.err.println("\tdid the project get opened?: " + didOpen);
		return didOpen;
	}

	private static boolean waitForProjectToOpen(String desiredProjectName,
			UtilProjectListener projectListener) {
		int waitTime = 100;
		int maxWaits = 150;
		int numWaits = 0;
		String lastOpenedProjectName = projectListener.getLastOpenedProjectName();
		while (!desiredProjectName.equals(lastOpenedProjectName) && numWaits < maxWaits) {
			numWaits++;
			AbstractGTest.sleep(waitTime);
		}

		AbstractGenericTest.waitForSwing();
		boolean success = desiredProjectName.equals(lastOpenedProjectName);
		if (!success) {
			System.err.println("\tOpen windows: " + AbstractDockingTest.getOpenWindowsAsString());
		}

		return success;
	}

	public static boolean deleteTestProject(String projectName) {
		File projectDirectory = new File(AbstractGTest.getTestDirectoryPath());

		File dirFile =
			new File(projectDirectory, projectName + ProjectLocator.getProjectDirExtension());

		int count = 0;
		while (dirFile.exists() && count < 500) {
			++count;
			try {
				Thread.sleep(50);
			}
			catch (InterruptedException e) {
				e.printStackTrace();
			}

			AbstractGhidraHeadlessIntegrationTest.deleteProject(projectDirectory.getAbsolutePath(),
				projectName);
		}
		if (count > 500) {
			System.err.println("Could not delete " + projectName);
			return false;
		}
		return true;
	}

	/**
	 * Note: This should be called with Err's GUI mode disabled.  When you get a FrontEnd
	 * tool from TestEnv, that action turns on the GUI display for showing errors, by default.  
	 * So, you should call this method before accessing any GUI components in the test system. 
	 * If the GUI error display is enabled when this method is invoked, then server 
	 * connection attempts may trigger error dialogs that are considered 'normal' when running
	 * in the test environment.
	 * 
	 * @return the new server adapter 
	 * @throws Exception if there are any exceptions starting the server
	 */
	public static RepositoryAdapter startServer() throws Exception {
		System.err.println("SharedProjectUtil.startServer()...");
		repositoryServer = null;
		File parent = new File(AbstractGTest.getTestDirectoryPath());

		// Create server instance
		serverRoot = new File(parent, "My_Server");
		FileUtilities.deleteDir(serverRoot);

		System.err.println("SharedProjectUtil.startServer()\tgetting server adapter...");
		repositoryServer = ServerTestUtil.getServerAdapter(serverRoot, new String[] { USER });

		System.err.println("SharedProjectUtil.startServer()\tchecking connection...");
		if (repositoryServer == null || !repositoryServer.isConnected()) {
			deleteServerRoot();
			fail("Server connect failed");
		}

		System.err.println("SharedProjectUtil.startServer()\tcreating repository...");
		return repositoryServer.createRepository("My_Repository");
	}

	public static void deleteServerRoot() {
		if (serverRoot != null) {
			ServerTestUtil.disposeServer();
			FileUtilities.deleteDir(serverRoot);
			serverRoot = null;
		}
	}

	public static void createRepository(String repositoryName)
			throws DuplicateNameException, UserAccessException, NotConnectedException, IOException {
		if (repositoryServer == null) {
			throw new IllegalStateException(
				"startServer() method must be called before a " + "repository can be created!");
		}
		repositoryServer.createRepository(repositoryName);
	}

	private static DockingActionIf getAction(FrontEndTool frontEndTool, String actionName) {

		DockingActionIf action =
			AbstractDockingTest.getAction(frontEndTool, "FrontEndPlugin", actionName);
		return action;
	}

	private static class UtilProjectListener implements ProjectListener {

		private String lastOpenedProjectName;

		@Override
		public void projectClosed(Project project) {
			System.err.println(getClass().getSimpleName() + ".projectClosed(): " + project);
		}

		@Override
		public void projectOpened(Project project) {
			System.err.println(getClass().getSimpleName() + ".projectOpened(): " + project);
			lastOpenedProjectName = project.getName();
		}

		String getLastOpenedProjectName() {
			return lastOpenedProjectName;
		}
	}
}
