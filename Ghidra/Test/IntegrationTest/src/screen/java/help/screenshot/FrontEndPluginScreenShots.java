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
import java.io.IOException;
import java.util.*;
import java.util.List;

import javax.swing.*;

import org.junit.Assert;
import org.junit.Test;

import docking.DialogComponentProvider;
import docking.DockingDialog;
import docking.widgets.*;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.table.GTable;
import docking.wizard.WizardManager;
import docking.wizard.WizardPanel;
import ghidra.app.plugin.core.archive.RestoreDialog;
import ghidra.framework.data.GhidraFileData;
import ghidra.framework.main.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.dialog.*;
import ghidra.framework.preferences.Preferences;
import ghidra.framework.remote.User;
import ghidra.framework.store.LockException;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.lang.Language;
import ghidra.test.ProjectTestUtils;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.MultiIcon;

public class FrontEndPluginScreenShots extends GhidraScreenShotGenerator {
	private static final String OTHER_PROJECT = "Other_Project";
	private final static String TEMP_DIR = System.getProperty("java.io.tmpdir");
	Icon icon = (Icon) getInstanceField("CONVERT_ICON", ProjectInfoDialog.class);

	public FrontEndPluginScreenShots() {
		super();
	}

	@Override
	public void prepareTool() {
		tool = getFrontEndTool();
	}

	@Override
	public void loadProgram() {
		// don't need to load a program
	}

	@Test
	public void testArchiveFileExists() {
		runSwing(() -> OptionDialog.showOptionDialog(null, "Archive File Exists",
			"/Projects/Demo" + " exists.\n " + "Do you want to overwrite existing file?", "Yes"),
			false);
		sleep(500);
		captureDialog();
	}

	@Test
	public void testArchiveProject() {

		performAction("Archive Project", "ArchivePlugin", false);
		waitForSwing();

		DialogComponentProvider dialog = getDialog();
		JTextField textField = (JTextField) getInstanceField("archiveField", dialog);
		setText(textField, "/projects/testPrj.gar");
		paintImmediately(dialog);

		captureDialog();
	}

	@Test
	public void testChangeAccessList() {
		String[] knownUsers = { "user1", "user2", "user3", "user4", "user5", "user6" };
		ArrayList<User> userList = new ArrayList<>();
		userList.add(new User("user4", 2));

		runSwing(() -> {
			WizardPanel panel =
				new ProjectAccessPanel(knownUsers, "Bob", userList, "Demo", false, false, tool);
			TestDummyPanelManager panelMgr =
				new TestDummyPanelManager(panel, true, false, true, 650, 250);
			WizardManager wizard =
				new WizardManager("Change Shared Project Information", false, panelMgr, icon);
			wizard.showWizard();
		});

		waitForSwing();

		captureDialog();
	}

	@Test
	public void testChangePassword() {
		final PasswordChangeDialog pcd =
			new PasswordChangeDialog("Change Password", "Repository Server", "server1", "user-1");
		runSwing(() -> tool.showDialog(pcd), false);

		PasswordChangeDialog dialog = waitForDialogComponent(PasswordChangeDialog.class);
		captureDialog(dialog);

	}

	@Test
	public void testChangeRepositoryPanel() {
		RepositoryPanel panel =
			new RepositoryPanel(null, "MyServer", new String[] { "Demo", "Test", "Sample" }, false);

		TestDummyPanelManager panelMgr =
			new TestDummyPanelManager(panel, false, true, false, 600, 375);
		WizardManager wizard =
			new WizardManager("Change Shared Project Information", false, panelMgr, icon);
		wizard.showWizard();

		waitForSwing();

		captureDialog();
	}

	@Test
	public void testChangeServerInfoPanel() {
		TestDummyPanelManager panelMgr =
			new TestDummyPanelManager(null, false, true, false, 600, 180);
		ServerInfoPanel panel = new ServerInfoPanel(panelMgr);
		panelMgr.setPanel(panel);

		WizardManager wizard =
			new WizardManager("Change Shared Project Information", false, panelMgr, icon);

		panel.setServerInfo(new ServerInfo("server1", 13100));

		wizard.showWizard();

		waitForSwing();

		captureDialog();
	}

	@Test
	public void testCheckedOutNotLatest() {
		MultiIcon multiIcon = new MultiIcon(GhidraFileData.VERSION_ICON);
		multiIcon.addIcon(ProgramContentHandler.PROGRAM_ICON);

		multiIcon.addIcon(GhidraFileData.NOT_LATEST_CHECKED_OUT_ICON);
		captureIconAndText(multiIcon, "Example (2 of 3)*");
	}

	@Test
	public void testConfigureTool() {
		performAction("Configure Tool", "Project Window", false);
		waitForSwing();
		captureDialog();
	}

	@Test
	public void testConfigureExtensions() {
		performAction("Extensions", "Project Window", false);
		waitForSwing();

		ExtensionTableProvider provider =
			(ExtensionTableProvider) getDialog(ExtensionTableProvider.class);
		Object panel = getInstanceField("extensionTablePanel", provider);
		GTable table = (GTable) getInstanceField("table", panel);

		// Create some extensions to put in the table.
		ExtensionDetails ext1 = new ExtensionDetails("extension 1", "This is a sample extension",
			"John B. Author", "09/21/1974", "1.0.0");
		ExtensionDetails ext2 = new ExtensionDetails("extension 2",
			"This is another sample extension", "Gertrude B. Author", "09/22/1974", "1.0.1");
		Set<ExtensionDetails> exts = new HashSet<>();
		exts.add(ext1);
		exts.add(ext2);

		ExtensionTablePanel ePanel = (ExtensionTablePanel) panel;
		ePanel.setExtensions(exts);

		selectRow(table, 1);

		captureDialog();
	}

	@Test
	public void testConfirmChangePassword() {
		runSwing(() -> OptionDialog.showOptionDialog(tool.getToolFrame(), "Confirm Password Change",
			"You are about to change your repository server password for:\n" + "server1:13100" +
				"\n \nThis password is used when connecting to project\n" +
				"repositories associated with this server",
			"Continue", OptionDialog.WARNING_MESSAGE), false);
		sleep(50);
		waitForSwing();
		captureDialog();
	}

	@Test
	public void testConfirmDeleteProject() {
		runSwing(() -> OptionDialog.showOptionDialog(tool.getToolFrame(), "Confirm Delete",
			"Are you sure you want to delete\n" + "Project: /users/user/Sample?\n" +
				"\n \nWARNING: Delete CANNOT be undone!",
			"Delete", OptionDialog.INFORMATION_MESSAGE), false);
		sleep(50);
		waitForSwing();
		captureDialog();
	}

	@Test
	public void testConnectTools() {
		loadDefaultTool();
		loadDefaultTool();

		waitForSwing();
		performAction("Connect Tools", "FrontEndPlugin", false);
		DialogComponentProvider dialog = getDialog();
		Object panel = getInstanceField("panel", dialog);
		final JList<?> consumerList = (JList<?>) getInstanceField("consumerList", panel);
		final JList<?> producerList = (JList<?>) getInstanceField("producerList", panel);
		runSwing(() -> {
			producerList.setSelectedIndices(new int[] { 0 });
			consumerList.setSelectedIndices(new int[] { 1 });
		});

		dialog.toFront();
		waitForSwing();

		captureDialog();
	}

	@Test
	public void testDeleteProject() {
		performAction("Delete Project", "FrontEndPlugin", false);
		captureDialog();
	}

	@Test
	public void testEditPluginPath() {
		Preferences.setPluginPaths(new String[] { "/myJar.jar", "/MyPlugins/classes" });
		performAction("Edit Plugin Path", "FrontEndPlugin", false);
		DialogComponentProvider dialog = getDialog();
		final JList<?> jList = (JList<?>) getInstanceField("pluginPathsList", dialog);
		runSwing(() -> {
			jList.setCellRenderer(new DefaultListCellRenderer());// files don't exist - don't want them in red
			jList.setSelectedIndex(0);
		});
		captureDialog();
	}

	@Test
	public void testEditProjectAccessList() {
		String[] knownUsers = { "user1", "user2", "user3", "user4", "user5", "user6" };
		ArrayList<User> userList = new ArrayList<>();
		userList.add(new User("user2", 2));
		userList.add(new User("user4", 0));
		userList.add(new User("user5", 1));

		runSwing(() -> {
			JPanel panel =
				new ProjectAccessPanel(knownUsers, "Bob", userList, "What", false, false, tool);

			DummyDialogComponentProvider dialog =
				new DummyDialogComponentProvider("Edit Project Access List for Demo", panel);

			tool.showDialog(dialog);
		});

		waitForSwing();

		captureDialog();
	}

	@Test
	public void testhijack_file() {
		MultiIcon multiIcon = new MultiIcon(GhidraFileData.VERSION_ICON);
		multiIcon.addIcon(ProgramContentHandler.PROGRAM_ICON);

		multiIcon.addIcon(GhidraFileData.HIJACKED_ICON);
		captureIconAndText(multiIcon, "Example (Highjacked)");
	}

	@Test
	public void testNonSharedProjectInfo() {
		performAction("View Project Info", "FrontEndPlugin", false);
		captureDialog();
	}

	@Test
	public void testOpenProject() {
		performAction("Open Project", "FrontEndPlugin", false);
		captureDialog();
	}

	@Test
	public void testPrivateFileIcon() {
		Icon programIcon = ProgramContentHandler.PROGRAM_ICON;
		MultiIcon multiIcon = new MultiIcon(programIcon);
		captureIconAndText(multiIcon, "Example");
	}

	@Test
	public void testProjectDataTable()
			throws CancelledException, IOException, InvalidNameException {
		program = env.getProgram("WinHelloCPP.exe");
		Project project = env.getProject();
		ProjectData projectData = project.getProjectData();
		projectData.getRootFolder().createFile("WinHelloCpp.exe", program, TaskMonitor.DUMMY);
		projectData.getRootFolder().createFile("OldWinHelloCpp.exe", program, TaskMonitor.DUMMY);

		FrontEndPlugin plugin = getPlugin(tool, FrontEndPlugin.class);
		JComponent projectDataPanel = (JComponent) getInstanceField("projectDataPanel", plugin);
		JTabbedPane tabbedPane =
			(JTabbedPane) getInstanceField("projectTabPanel", projectDataPanel);
		tabbedPane.setSelectedIndex(1);
		setToolSize(800, 600);
		captureComponent(projectDataPanel);
	}

	@Test
	public void testProjectDataTree() throws InvalidNameException, CancelledException, IOException {
		program = env.getProgram("WinHelloCPP.exe");
		Project project = env.getProject();
		ProjectData projectData = project.getProjectData();
		projectData.getRootFolder().createFile("WinHelloCpp.exe", program, TaskMonitor.DUMMY);
		projectData.getRootFolder().createFile("OldWinHelloCpp.exe", program, TaskMonitor.DUMMY);
		FrontEndPlugin plugin = getPlugin(tool, FrontEndPlugin.class);
		JComponent projectDataPanel = (JComponent) getInstanceField("projectDataPanel", plugin);
		setToolSize(800, 600);
		captureComponent(projectDataPanel);
	}

	@Test
	public void testProjectExists() {
		OkDialog.show("Project Exists",
			"Cannot restore project because project named TestPrj already exists.");
		captureDialog();
	}

	@Test
	public void testProjectWindow() throws InvalidNameException, CancelledException, IOException {
		program = env.getProgram("WinHelloCPP.exe");
		Project project = env.getProject();
		ProjectData projectData = project.getProjectData();
		projectData.getRootFolder().createFile("WinHelloCpp.exe", program, TaskMonitor.DUMMY);
		projectData.getRootFolder().createFile("OldWinHelloCpp.exe", program, TaskMonitor.DUMMY);
		Msg.info(FrontEndService.class, "This is a log message...");// something nice in the status area
		captureToolWindow(800, 600);
	}

	@Test
	public void testReopenProject() {
		FrontEndPlugin plugin = getPlugin(tool, FrontEndPlugin.class);
		ProjectManager pm = (ProjectManager) getInstanceField("projectManager", plugin);
		@SuppressWarnings("unchecked")
		List<ProjectLocator> recentProjects =
			(List<ProjectLocator>) getInstanceField("recentlyOpenedProjectsList", pm);
		recentProjects.add(new ProjectLocator("/projects", "Demo"));
		recentProjects.add(new ProjectLocator("/projects", "Sample"));
		recentProjects.add(new ProjectLocator("/projects", "Test"));

		runSwing(() -> tool.setVisible(true));

		Msg.info(FrontEndService.class, "This is a log message...");// something nice in the status area

		setToolSize(500, 550);
		showMenuBarMenu("File", "Reopen");
		captureComponent(tool.getToolFrame());
	}

	@Test
	public void testRepositoryNamePanel() {
		TestDummyPanelManager panelMgr =
			new TestDummyPanelManager(null, false, true, true, 600, 375);

		final RepositoryPanel panel = new RepositoryPanel(panelMgr, "Server1",
			new String[] { "Demo", "Test", "Sample" }, false);
		panelMgr.setPanel(panel);

		WizardManager wizard =
			new WizardManager("Specify Repository Name on Server1", false, panelMgr, icon);

		wizard.showWizard();

		runSwing(() -> {
			JList<?> jlist = (JList<?>) getInstanceField("nameList", panel);
			jlist.setSelectedIndex(0);
		});

		waitForSwing();

		captureDialog();

	}

	@Test
	public void testRestoreProjectFilledIn() {
		runSwing(() -> {
			RestoreDialog restoreDialog = new RestoreDialog(null);
			JTextField textField = (JTextField) getInstanceField("archiveField", restoreDialog);
			textField.setText("/Projects/Demo.gar");
			textField = (JTextField) getInstanceField("restoreField", restoreDialog);
			textField.setText("/Projects");
			textField = (JTextField) getInstanceField("projectNameField", restoreDialog);
			textField.setText("Demo");
			tool.showDialog(restoreDialog);
		}, false);

		captureDialog();
	}

	@Test
	public void testSaveFiles() throws InvalidNameException, CancelledException, IOException {
		program = env.getProgram("WinHelloCPP.exe");

		Project project = env.getProject();
		ProjectData projectData = project.getProjectData();
		projectData.getRootFolder().createFile("WinHelloCpp.exe", program, TaskMonitor.DUMMY);

		int tx = program.startTransaction("Test");
		program.setName("Bob");
		program.setName("WinHelloCPP.exe");
		program.endTransaction(tx, true);

		runSwing(() -> {
			SaveDataDialog dialog = new SaveDataDialog(tool);

			dialog.showDialog(Arrays.asList(new DomainFile[] { program.getDomainFile() }));
		}, false);

		captureDialog();
	}

	@Test
	public void testSaveReadOnly() {
		program = env.getProgram("WinHelloCPP.exe");
		final StringBuffer sb = new StringBuffer();
		sb.append("The following files are Read-Only and cannot be\n" +
			" saved 'As Is.' You must do a manual 'Save As' for these\n" + " files: \n \n");

		sb.append(program.getDomainFile().getPathname());
		sb.append("\n");
		// note: put the extra space in or else OptionDialog will not show
		// the new line char
		sb.append(" \nChoose 'Cancel' to cancel Close Project, or \n");
		sb.append("'Lose Changes' to continue.");

		runSwing(() -> OptionDialog.showOptionDialog(tool.getToolFrame(), "Read-Only Files",
			sb.toString(), "Lose Changes", OptionDialog.QUESTION_MESSAGE), false);

		captureDialog();
	}

	@Test
	public void testSelectProjectLocation() {
		performAction("New Project", "FrontEndPlugin", false);
		DialogComponentProvider dialog = getDialog();
		final WizardManager wm = (WizardManager) dialog;
		runSwing(() -> {
			wm.next();
			WizardPanel panel = wm.getCurrentWizardPanel();
			JTextField textField = (JTextField) getInstanceField("directoryField", panel);
			textField.setText("/Projects");
			wm.setStatusText("");
		});

		captureDialog(700, 350);
	}

	@Test
	public void testSelectProjectType() {
		performAction("New Project", "FrontEndPlugin", false);
		captureDialog(700, 350);
	}

	@Test
	public void testSelectSharedProjectLocation() {
		performAction("New Project", "FrontEndPlugin", false);
		DialogComponentProvider dialog = getDialog();
		final WizardManager wm = (WizardManager) dialog;
		runSwing(() -> {
			wm.next();
			WizardPanel panel = wm.getCurrentWizardPanel();
			JTextField textField = (JTextField) getInstanceField("directoryField", panel);
			textField.setText("/Projects");
			textField = (JTextField) getInstanceField("projectNameField", panel);
			textField.setText("Demo");
			wm.setStatusText("");
			JLabel label = (JLabel) getInstanceField("titleLabel", wm);
			label.setText("Select Local Project Location for Repository Demo");
			JButton button = (JButton) getInstanceField("finishButton", wm);
			button.setEnabled(true);
		});

		captureDialog(700, 300);
	}

	@Test
	public void testSelectSharedProjectType() {
		performAction("New Project", "FrontEndPlugin", false);
		DialogComponentProvider dialog = getDialog();
		final WizardManager wm = (WizardManager) dialog;
		runSwing(() -> {
			WizardPanel panel = wm.getCurrentWizardPanel();
			JRadioButton sharedRB = (JRadioButton) getInstanceField("sharedRB", panel);
			sharedRB.setSelected(true);
			wm.setStatusText("");
		});
		captureDialog(700, 350);
	}

	@Test
	public void testServerInfo() {
		performAction("New Project", "FrontEndPlugin", false);
		DialogComponentProvider dialog = getDialog();
		final WizardManager wm = (WizardManager) dialog;
		runSwing(() -> {
			WizardPanel panel = wm.getCurrentWizardPanel();
			JRadioButton sharedRB = (JRadioButton) getInstanceField("sharedRB", panel);
			sharedRB.setSelected(true);
			wm.next();
			panel = wm.getCurrentWizardPanel();
			Component comp = (Component) getInstanceField("serverInfoComponent", panel);

			JTextField textField = (JTextField) getInstanceField("nameField", comp);
			textField.setText("Server1");
		});
		captureDialog(700, 300);
	}

	@Test
	public void testSharedProjectInfo() {
		performAction("View Project Info", "FrontEndPlugin", true);
		final DialogComponentProvider dialog = getDialog();
		runSwing(() -> {
			JLabel label = (JLabel) getInstanceField("projectDirLabel", dialog);
			label.setText("/Projects/TestPrj.rep");
			label = (JLabel) getInstanceField("serverLabel", dialog);
			label.setText("Server1");
			label = (JLabel) getInstanceField("portLabel", dialog);
			label.setText("13100");
			label = (JLabel) getInstanceField("repNameLabel", dialog);
			label.setText("Demo");

			JButton button = (JButton) getInstanceField("connectionButton", dialog);
			button.setEnabled(true);

			button = (JButton) getInstanceField("changeConvertButton", dialog);
			button.setText(ProjectInfoDialog.CHANGE);

		});
		captureDialog(400, 500);
	}

	@Test
	public void testEditProjectAccessPanel() {
		String[] knownUsers = { "user1", "user2", "user3", "user4", "user5", "user6" };
		ArrayList<User> userList = new ArrayList<>();
		userList.add(new User("user2", 2));
		userList.add(new User("user4", 0));
		userList.add(new User("user5", 1));

		runSwing(() -> {
			WizardPanel panel =
				new ProjectAccessPanel(knownUsers, "user2", userList, "Demo", false, false, tool);

			TestDummyPanelManager panelMgr =
				new TestDummyPanelManager(panel, true, false, true, 650, 250);
			WizardManager wizard = new WizardManager("New Project", false, panelMgr, icon);
			wizard.showWizard();
		});

		waitForSwing();
		captureDialog();
	}

	@Test
	public void testViewProjectAccessPanel() {
		String[] knownUsers = { "user1", "user2", "user3", "user4", "user5", "user6" };
		ArrayList<User> userList = new ArrayList<>();
		userList.add(new User("user2", 2));
		userList.add(new User("user4", 0));
		userList.add(new User("user5", 1));

		runSwing(() -> {
			JPanel panel = new ViewProjectAccessPanel(knownUsers, "user2", userList, "Demo", false,
				false, tool);

			DummyDialogComponentProvider dialog =
				new DummyDialogComponentProvider("View Project Access List for Demo", panel);

			tool.showDialog(dialog);
		});

		waitForSwing();
		captureDialog();
	}

	@Test
	public void testVersionedFileCOnoServer() {
		MultiIcon multiIcon = new MultiIcon(GhidraFileData.VERSION_ICON);
		multiIcon.addIcon(ProgramContentHandler.PROGRAM_ICON);

		multiIcon.addIcon(GhidraFileData.CHECKED_OUT_ICON);
		captureIconAndText(multiIcon, "Example (1 of 1)");
	}

	@Test
	public void testVersionedFileCOwithServer() {
		MultiIcon multiIcon = new MultiIcon(GhidraFileData.VERSION_ICON);
		multiIcon.addIcon(ProgramContentHandler.PROGRAM_ICON);

		multiIcon.addIcon(GhidraFileData.CHECKED_OUT_ICON);
		captureIconAndText(multiIcon, "Example (3 of 3)*");
	}

	@Test
	public void testVersionedFileIcon() {
		MultiIcon multiIcon = new MultiIcon(GhidraFileData.VERSION_ICON);
		multiIcon.addIcon(ProgramContentHandler.PROGRAM_ICON);

		captureIconAndText(multiIcon, "Example (1)");
	}

	@Test
	public void testMemoryUsage() {
		performFrontEndAction("Show VM memory", "MemoryUsagePlugin", false);
		waitForVMMemoryInitialilzed();// this is asynchronous and takes a while
		captureDialog();
	}

	@Test
	public void testViewOtherProjects()
			throws IOException, LockException, InvalidNameException, CancelledException {
		ProjectTestUtils.deleteProject(TEMP_DIR, OTHER_PROJECT);
		Project project = env.getProject();
		program = env.getProgram("WinHelloCPP.exe");
		ProjectData projectData = project.getProjectData();
		projectData.getRootFolder().createFile("HelloCpp.exe", program, TaskMonitor.DUMMY);

		project.close();

		Project otherProject = ProjectTestUtils.getProject(TEMP_DIR, OTHER_PROJECT);

		Language language = getZ80_LANGUAGE();
		ProjectTestUtils.createProgramFile(otherProject, "Program1", language,
			language.getDefaultCompilerSpec(), null);
		ProjectTestUtils.createProgramFile(otherProject, "Program2", language,
			language.getDefaultCompilerSpec(), null);

		otherProject.close();
		waitForSwing();
		project = ProjectTestUtils.getProject(TEMP_DIR, PROJECT_NAME);

		performAction("View Project", "FrontEndPlugin", false);
		final GhidraFileChooser fileChooser = (GhidraFileChooser) getDialog();
		runSwing(() -> fileChooser.setSelectedFile(new File(TEMP_DIR, OTHER_PROJECT)));
		pressButtonOnDialog("Select Project");
		setToolSize(500, 600);
		captureToolWindow(700, 600);

		ProjectTestUtils.deleteProject(TEMP_DIR, OTHER_PROJECT);
		ProjectTestUtils.deleteProject(TEMP_DIR, OTHER_PROJECT);

	}

	private void waitForVMMemoryInitialilzed() {
		Window w = waitForWindow("VM Memory Usage");
		DialogComponentProvider dc = ((DockingDialog) w).getDialogComponent();
		Boolean initialized = (Boolean) invokeInstanceMethod("isInitialized", dc);

		int sleepyTime = 10;
		int totalTime = 0;
		while (!initialized && totalTime < 3000) {
			sleep(sleepyTime);
			initialized = (Boolean) invokeInstanceMethod("isInitialized", dc);
			totalTime += sleepyTime;
		}

		initialized = (Boolean) invokeInstanceMethod("isInitialized", dc);
		if (!initialized) {
			Assert.fail("VM Memory window did not show its real values.");
		}
	}

	private void paintImmediately(final DialogComponentProvider dialog) {
		runSwing(() -> {
			Rectangle bounds = dialog.getComponent().getBounds();
			dialog.getComponent().paintImmediately(bounds);
		});
		waitForSwing();
		sleep(40);
	}

	private void captureIconAndText(Icon labelImage, String text) {
		final JLabel label = new JLabel(text);
		label.setBackground(Color.WHITE);
		label.setOpaque(true);
		label.setIcon(labelImage);
		label.setHorizontalAlignment(SwingConstants.CENTER);

		runSwing(() -> {
			JDialog dialog = new JDialog();
			Container contentPane = dialog.getContentPane();
			contentPane.setLayout(new BorderLayout());
			JPanel panel = new JPanel(new BorderLayout());
			panel.setBorder(BorderFactory.createEmptyBorder(50, 50, 50, 50));
			contentPane.add(panel, BorderLayout.CENTER);
			panel.add(label, BorderLayout.CENTER);
			dialog.pack();
			Dimension size = dialog.getSize();
			size.width += 6;
			size.height += 6;
			dialog.setSize(size);
			dialog.setVisible(true);
		});
		waitForSwing();
		label.paintImmediately(label.getBounds());
		captureComponent(label);

	}

	class DummyDialogComponentProvider extends DialogComponentProvider {
		DummyDialogComponentProvider(String title, JPanel mainPanel) {
			super(title, false);
			addWorkPanel(mainPanel);
			addOKButton();
			addCancelButton();
		}

	}

}
