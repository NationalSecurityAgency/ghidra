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

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;

import org.junit.*;
import org.junit.experimental.categories.Category;

import docking.AbstractErrDialog;
import docking.action.DockingActionIf;
import docking.widgets.OptionDialog;
import docking.wizard.WizardManager;
import generic.test.category.PortSensitiveCategory;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.model.*;
import ghidra.framework.preferences.Preferences;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@Category(PortSensitiveCategory.class)
public class ProjectInfoDialogTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private FrontEndTool frontEndTool;
	private DomainFolder rootFolder;
	private ProjectInfoDialog dialog;

	public ProjectInfoDialogTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		setErrorGUIEnabled(false);
		env = new TestEnv();

		frontEndTool = env.getFrontEndTool();
		env.showFrontEndTool();

		rootFolder = env.getProject().getProjectData().getRootFolder();

		DomainFile df;

		Program p = createDefaultProgram("testA", ProgramBuilder._TOY64_LE, this);
		try {
			df = rootFolder.createFile("testA", p, TaskMonitor.DUMMY);
		}
		finally {
			p.release(this);
		}

		df.addToVersionControl("This is a test", false, TaskMonitor.DUMMY);

		showViewProjectInfoDialog();

		RepositoryAdapter rep = null;
		try {
			// this can throw a NotConnectedException
			System.err.println(getClass().getName() + "\tstarting server...");
			rep = SharedProjectUtil.startServer();
		}
		catch (Exception e) {
			cleanupResources();
			throw e;
		}

		assertNotNull(rep);
		assertTrue(rep.isConnected());

	}

	@After
	public void tearDown() throws Exception {

		try {
			DockingActionIf saveAction = getAction("Save Project");
			System.err.println("\tsaving project");
			performAction(saveAction, true);
			System.err.println("\tclosing project");
			DockingActionIf action = getAction("Close Project");
			performAction(action, true);
		}
		finally {
			cleanupResources();
		}

	}

	private void cleanupResources() throws Exception {
		System.err.println(getClass().getName() + ".cleanupResources()...");
		try {
			System.err.println(getClass().getName() + "\tdisposing...");
			env.dispose();
			System.err.println(getClass().getName() + "\tstoring preferences...");
			Preferences.setProperty("ServerInfo", null);
			Preferences.store();
		}
		finally {
			System.err.println(getClass().getName() + "\tdeleting server root...");
			SharedProjectUtil.deleteServerRoot();
			System.err.println(getClass().getName() + "\tdeleting test project...");
			SharedProjectUtil.deleteTestProject("TestProject");
		}
		System.err.println(getClass().getName() + ".cleanupResources() done!s");
	}

	@Test
	public void testConvertProjectFilesCheckedOut() throws Exception {
		setErrorGUIEnabled(true); // we need the dialog below

		// check-out testA
		rootFolder = getProject().getProjectData().getRootFolder();
		DomainFile df = rootFolder.getFile("testA");
		assertTrue(df.checkout(false, TaskMonitor.DUMMY));

		// make simple change to checked-out file
		Program p = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		try {

			int txId = p.startTransaction("test");
			try {
				p.setName("XYZ");
			}
			finally {
				p.endTransaction(txId, true);
			}
			p.save(null, TaskMonitor.DUMMY);
		}
		finally {
			p.release(this);
		}

		pressButtonByText(dialog, ProjectInfoDialog.CONVERT, false);
		windowForComponent(dialog.getComponent());

		stepThroughWizard(true);

		OptionDialog opt = waitForDialogComponent(OptionDialog.class);
		assertNotNull(opt);
		assertEquals("Confirm Convert Project", opt.getTitle());
		pressButtonByText(opt, "Convert");
	}

	@Test
	public void testOpenFiles() throws CancelledException, IOException {

		// cannot convert project if files are open
		DomainFile df = rootFolder.getFile("testA");
		assertTrue(df.checkout(false, TaskMonitor.DUMMY));

		env.launchTool("CodeBrowser", df);

		setErrorGUIEnabled(true);
		pressButtonByText(dialog, ProjectInfoDialog.CONVERT, false);
		OptionDialog opt = waitForDialogComponent(OptionDialog.class);
		assertNotNull(opt);
		assertEquals("Cannot Convert Project with Open Files", opt.getTitle());

		pressButtonByText(opt, "OK", true);
	}

	@Test
	public void testConvertProjectToShared() throws Exception {

		pressButtonByText(dialog, ProjectInfoDialog.CONVERT, false);
		windowForComponent(dialog.getComponent());
		Project oldProject = getProject();
		stepThroughWizard(true);

		OptionDialog opt = waitForDialogComponent(OptionDialog.class);
		assertNotNull(opt);
		pressButtonByText(opt, "Convert");

		waitForTasks();

		Project newProject = getProject();
		assertNotSame("Converting project failed", oldProject, newProject);
		assertNotNull(newProject.getRepository());

		checkProjectInfo("My_Repository");
	}

	@Test
	public void testConvertProjectCanceled() throws Exception {

		pressButtonByText(dialog, ProjectInfoDialog.CONVERT, false);
		windowForComponent(dialog.getComponent());

		stepThroughWizard(true);
		OptionDialog opt = waitForDialogComponent(OptionDialog.class);
		assertNotNull(opt);
		pressButtonByText(opt, "Cancel");

		assertNull(env.getProject().getRepository());
	}

	@Test
	public void testConvertProjectCanceled2() throws Exception {

		pressButtonByText(dialog, ProjectInfoDialog.CONVERT, false);
		stepThroughWizard(false);
		assertNull(env.getProject().getRepository());
	}

	private Project getProject() {
		AtomicReference<Project> ref = new AtomicReference<>();
		runSwing(() -> ref.set(frontEndTool.getProject()));
		return ref.get();
	}

	@Test
	public void testUpdateSharedProjectInfo() throws Exception {

		pressButtonByText(dialog, ProjectInfoDialog.CONVERT, false);

		stepThroughWizard(true);

		OptionDialog opt = waitForDialogComponent(OptionDialog.class);
		assertNotNull(opt);
		pressButtonByText(opt, "Convert");
		waitForTasks();

		SharedProjectUtil.createRepository("AnotherRepository");

		dialog = waitForDialogComponent(ProjectInfoDialog.class);
		assertNotNull(dialog);

		pressButtonByText(dialog, ProjectInfoDialog.CHANGE, false);
		waitForSwing();

		// change project to use a different repository
		stepThroughWizard(true, "AnotherRepository");

		opt = waitForDialogComponent(OptionDialog.class);
		assertNotNull(opt);
		assertEquals("Update Shared Project Info", opt.getTitle());
		pressButtonByText(opt, "Update");
		waitForTasks();

		checkProjectInfo("AnotherRepository");

	}

	@Test
	public void testUpdateSharedProjectInfoWithCheckouts() throws Exception {

		pressButtonByText(dialog, ProjectInfoDialog.CONVERT, false);

		stepThroughWizard(true);

		OptionDialog opt = waitForDialogComponent(OptionDialog.class);
		assertNotNull(opt);
		pressButtonByText(opt, "Convert");
		waitForTasks();

		// check out file from shared project
		rootFolder = getProject().getProjectData().getRootFolder();
		DomainFile df = rootFolder.getFile("testA");
		df.addToVersionControl("test", true, TaskMonitor.DUMMY);
		assertTrue(df.isCheckedOut());

		setErrorGUIEnabled(true); // we need the dialog below

		SharedProjectUtil.createRepository("AnotherRepository");

		dialog = waitForDialogComponent(ProjectInfoDialog.class);

		pressButtonByText(dialog, ProjectInfoDialog.CHANGE, false);
		waitForSwing();

		// change project to use a different repository
		stepThroughWizard(true, "AnotherRepository");

		opt = waitForDialogComponent(OptionDialog.class);
		assertNotNull(opt);
		assertEquals("Update Shared Project Info", opt.getTitle());
		pressButtonByText(opt, "Update");
		waitForTasks();

		AbstractErrDialog errorDialog = waitForErrorDialog();
		assertEquals("Failed to Update Shared Project Info", errorDialog.getTitle());
		close(errorDialog);
	}

	private void checkProjectInfo(String expectedRepName) {
		dialog = waitForDialogComponent(ProjectInfoDialog.class);

		RepositoryAdapter repository = getProject().getRepository();
		assertEquals(expectedRepName, repository.getName());
		JLabel repLabel = (JLabel) findComponentByName(dialog.getComponent(), "Repository Name");
		assertNotNull(repLabel);
		assertEquals(expectedRepName, repLabel.getText());

		JLabel serverLabel = (JLabel) findComponentByName(dialog.getComponent(), "Server Name");
		assertNotNull(serverLabel);
		ServerInfo info = repository.getServerInfo();
		assertEquals(info.getServerName(), serverLabel.getText());

		JLabel portLabel = (JLabel) findComponentByName(dialog.getComponent(), "Port Number");
		assertNotNull(portLabel);
		assertEquals(Integer.toString(info.getPortNumber()), portLabel.getText());

		JLabel userLabel = (JLabel) findComponentByName(dialog.getComponent(), "User Access Level");
		assertNotNull(userLabel);
		assertEquals("Administrator", userLabel.getText());

		JButton button = (JButton) findComponentByName(dialog.getComponent(), "Connect Button");
		assertNotNull(button);
		assertTrue(button.isEnabled());
		assertEquals(FrontEndPlugin.CONNECTED_ICON, button.getIcon());
	}

	private void showViewProjectInfoDialog() {
		DockingActionIf action = getAction("View Project Info");
		assertNotNull(action);
		performAction(action, true);
		dialog = waitForDialogComponent(ProjectInfoDialog.class);
		assertNotNull(dialog);
	}

	private DockingActionIf getAction(String actionName) {
		DockingActionIf action = getAction(frontEndTool, "FrontEndPlugin", actionName);
		return action;
	}

	private void stepThroughWizard(boolean doFinish) throws Exception {
		stepThroughWizard(doFinish, null);
	}

	private void stepThroughWizard(boolean doFinish, final String repositoryName) throws Exception {
		System.err.println(getClass().getName() + ".stepThroughWizard()...");
		windowForComponent(dialog.getComponent());
		WizardManager wm = waitForDialogComponent(WizardManager.class);
		assertNotNull(wm);

		JButton nextButton = findButtonByText(wm, "Next >>");
		JButton finishButton = findButtonByText(wm, "Finish");
		JButton cancelButton = findButtonByText(wm, "Cancel");

		ServerInfoPanel serverPanel = findComponent(wm, ServerInfoPanel.class);

		final JTextField serverField = (JTextField) findComponentByName(serverPanel, "Server Name");
		final JTextField portNumberField =
			(JTextField) findComponentByName(serverPanel, "Port Number");

		runSwing(() -> {
			serverField.setText(SharedProjectUtil.LOCALHOST);
			portNumberField.setText(Integer.toString(SharedProjectUtil.SERVER_PORT));
		});

		System.err.println(getClass().getName() + ".stepThroughWizard()\tpressing next button...");
		pressButton(nextButton);

		// next panel should be the repository panel
		RepositoryPanel repPanel = findComponent(wm, RepositoryPanel.class);

		System.err.println(
			getClass().getName() + ".stepThroughWizard()\tfound repPanel: " + repPanel);
		final JList<?> repList = findComponent(repPanel, JList.class);
		ListModel<?> model = repList.getModel();
		int index = 0;
		if (repositoryName != null) {
			for (int i = 0; i < model.getSize(); i++) {
				if (repositoryName.equals(model.getElementAt(i))) {
					index = i;
					break;
				}

			}
		}
		final int selIndex = index;
		// select existing repository
		runSwing(() -> repList.setSelectedIndex(selIndex));
		if (doFinish) {
			pressButton(finishButton, true);
		}
		else {
			pressButton(cancelButton, true);
		}

		assertTrue("The wizard panel is not closed for some reason", !wm.isShowing());

		System.err.println(getClass().getName() + ".stepThroughWizard() done!");
	}
}
