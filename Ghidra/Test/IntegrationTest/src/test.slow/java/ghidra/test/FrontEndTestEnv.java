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
package ghidra.test;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.*;

import javax.swing.*;
import javax.swing.tree.TreePath;

import docking.*;
import docking.action.DockingActionIf;
import docking.test.AbstractDockingTest;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import generic.test.AbstractGTest;
import generic.test.AbstractGuiTest;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.main.SharedProjectUtil;
import ghidra.framework.main.datatree.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.server.remote.ServerTestUtil;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This is a helper to setup an environment that has a Front End, a project, and optionally a 
 * server running.   This class provides some convenience methods for creating and 
 * manipulating versioned files. 
 */
public class FrontEndTestEnv {

	private static final String TEST_PROJECT_NAME = "TestProject";

	public static final String PROGRAM_A = "Program_A";

	// TODO make private
	protected TestEnv env;
	protected FrontEndTool frontEndTool;
	protected DomainFolder rootFolder; // active project root
	protected DataTreeHelper projectTreeHelper;

	public FrontEndTestEnv() throws Exception {
		this(false);
	}

	public FrontEndTestEnv(boolean isRemote) throws Exception {

		env = new TestEnv();
		frontEndTool = env.getFrontEndTool();
		env.showFrontEndTool();

		if (isRemote) {
			startServer();
		}

		// assume read-only project views are not active and only active 
		// project tree is present
		DataTree tree =
			AbstractGuiTest.findComponent(frontEndTool.getToolFrame(), DataTree.class);
		projectTreeHelper = new DataTreeHelper(tree, true);

		Project project = frontEndTool.getProject();
		rootFolder = project.getProjectData().getRootFolder();

		Program p = buildProgram(this);
		rootFolder.createFile(PROGRAM_A, p, TaskMonitor.DUMMY);
		p.release(this);

		waitForTree();
	}

	public Program buildProgram(Object consumer) throws Exception {
		ProgramBuilder builder =
			new ClassicSampleX86ProgramBuilder("SampleProgram", true, consumer);
		ProgramDB p = builder.getProgram();
		return p;
	}

	private void startServer() throws Exception {

		SharedProjectUtil.deleteTestProject(TEST_PROJECT_NAME);

		// TODO not sure why this is here; please doc
		Preferences.setProperty(Preferences.LAST_NEW_PROJECT_DIRECTORY,
			AbstractGTest.getTestDirectoryPath());

		try {
			SharedProjectUtil.startServer();

			if (!SharedProjectUtil.createSharedProject(frontEndTool, TEST_PROJECT_NAME)) {
				ServerTestUtil.disposeServer();
				fail("Failed to create shared TestProject in setup");
			}
		}
		catch (Exception e) {
			SharedProjectUtil.deleteServerRoot();
			SharedProjectUtil.deleteTestProject(TEST_PROJECT_NAME);
			throw e;
		}
	}

	public void waitForTree() {
		projectTreeHelper.waitForTree();
	}

	public DomainFolder getRootFolder() {
		return rootFolder;
	}

	public GTree getTree() {
		return projectTreeHelper.getTree();
	}

	public GTreeNode getRootNode() {
		return projectTreeHelper.getRootNode();
	}

	/** 
	 * Returns the default program node named {@link #PROGRAM_A}
	 * @return the default program node named {@link #PROGRAM_A}
	 */
	public DomainFileNode getProgramNode() {
		return waitForFileNode(PROGRAM_A);
	}

	public DomainFileNode getTreeNode(String name) {
		return projectTreeHelper.waitForFileNode(name);
	}

	public GTreeNode waitForTreeNode(String name) {
		return projectTreeHelper.waitForTreeNode(name);
	}

	public DomainFileNode waitForFileNode(String name) {
		return projectTreeHelper.waitForFileNode(name);
	}

	public DomainFolderNode waitForFolderNode(String name) {
		return projectTreeHelper.waitForFolderNode(name);
	}

	public void clearTreeSelection() {
		projectTreeHelper.clearTreeSelection();
	}

	public void waitForSwing() {
		AbstractGuiTest.waitForSwing();
	}

	private void runSwing(Runnable r) {
		AbstractGuiTest.runSwing(r);
	}

	private void runSwing(Runnable r, boolean wait) {
		AbstractGuiTest.runSwing(r, wait);
	}

	private void waitForTasks() {
		AbstractGuiTest.waitForTasks();
	}

	public void setTreeSelection(final TreePath[] paths) throws Exception {
		projectTreeHelper.setTreeSelection(paths);
	}

	public void selectNodes(GTreeNode... nodes) {
		projectTreeHelper.selectNodes(nodes);
	}

	public void expandNode(GTreeNode node) {
		projectTreeHelper.expandNode(node);
	}

	public void dispose() {

		try {
			cleanupProject();
			AbstractDockingTest.closeAllWindows();
			env.dispose();
		}
		finally {

			// note: the client may not have started a server; try to shutdown anyway
			ServerTestUtil.disposeServer();
			SharedProjectUtil.deleteServerRoot();
			SharedProjectUtil.deleteTestProject(TEST_PROJECT_NAME);
		}
	}

	private void cleanupProject() {
		if (frontEndTool == null) {
			return;
		}

		Project project = frontEndTool.getProject();

		if (project == null) {
			return;
		}

		runSwing(() -> {
			project.releaseFiles(this);
			project.close();
		});
	}

	public void createMultipleCheckins() throws Exception {

		// create 3 versions of program

		DomainFileNode node = getTreeNode(PROGRAM_A);
		addToVersionControl(node, true);

		assertTrue(node.getDomainFile().isCheckedOut());

		AbstractGuiTest.waitForSwing();
		AbstractGuiTest.waitForTasks();

		Program program =
			(Program) node.getDomainFile().getDomainObject(this, true, false, TaskMonitor.DUMMY);
		editProgram(program, (p) -> {
			SymbolTable symTable = program.getSymbolTable();
			symTable.createLabel(program.getMinAddress().getNewAddress(0x010001000), "fred",
				SourceType.USER_DEFINED);
		});

		// TODO no need to select
		selectNodes(node);
		checkIn(node, "This is checkin 1");

		// make another change
		editProgram(program, (p) -> {
			SymbolTable symTable = program.getSymbolTable();
			symTable.createLabel(program.getMinAddress().getNewAddress(0x010001000), "bob",
				SourceType.USER_DEFINED);
		});

		selectNodes(node);
		checkIn(node, "This is checkin 2");

		// make one more change
		editProgram(program, (p) -> {
			SymbolTable symTable = program.getSymbolTable();
			symTable.createLabel(program.getMinAddress().getNewAddress(0x010001000), "joe",
				SourceType.USER_DEFINED);
		});

		selectNodes(node);
		checkIn(node, "This is checkin 3");

		program.release(this);
	}

	public void addToVersionControl(final GTreeNode node, final boolean keepCheckedOut)
			throws Exception {

		// TODO should not be needed
		selectNodes(node);

		DockingActionIf action = getAction("Add to Version Control");
		AbstractDockingTest.performAction(action, getDomainFileActionContext(node), false);

		VersionControlDialog dialog =
			AbstractDockingTest.waitForDialogComponent(VersionControlDialog.class);
		JTextArea textArea = AbstractDockingTest.findComponent(dialog, JTextArea.class);
		JCheckBox cb = AbstractDockingTest.findComponent(dialog, JCheckBox.class);
		runSwing(() -> {
			textArea.setText("This is a test");
			cb.setSelected(keepCheckedOut);
		});
		AbstractDockingTest.pressButtonByText(dialog, "OK");
		waitForTasks();
		DomainFile df = ((DomainFileNode) node).getDomainFile();
		assertTrue(df.isVersioned());
	}

	public void terminateCheckout(DialogComponentProvider provider) {

		DockingActionIf terminateCheckoutAction =
			AbstractDockingTest.getAction(provider, "Terminate Checkout");
		ActionContext context = provider.getActionContext(null);
		AbstractDockingTest.performAction(terminateCheckoutAction, context, false);
		OptionDialog optDialog = AbstractDockingTest.waitForDialogComponent(OptionDialog.class);
		AbstractGuiTest.pressButtonByText(optDialog.getComponent(), "Yes", true);
		waitForTasks();
		waitForSwing();
	}

	public ActionContext getDomainFileActionContext(GTreeNode... nodes) {
		return projectTreeHelper.getDomainFileActionContext(nodes);
	}

	public FrontEndTool getFrontEndTool() {
		return frontEndTool;
	}

	public PluginTool showTool() {
		return env.showTool();
	}

	public List<PluginTool> getTools() {
		PluginTool[] tools =
			frontEndTool.getProject().getToolManager().getActiveWorkspace().getTools();
		return new ArrayList<>(Arrays.asList(tools));
	}

	public Set<DockingActionIf> getFrontEndActions() {
		return AbstractDockingTest.getActionsByOwner(frontEndTool, "FrontEndPlugin");
	}

	public DockingActionIf getAction(String actionName) {
		DockingActionIf action =
			AbstractDockingTest.getAction(frontEndTool, "FrontEndPlugin", actionName);
		return action;
	}

	public void performFrontEndAction(DockingActionIf action) {
		ComponentProvider provider = env.getFrontEndProvider();
		runSwing(() -> {
			ActionContext context = provider.getActionContext(null);
			action.actionPerformed(context);
		}, false);
		waitForSwing();
	}

	public void checkout(DomainFileNode node) throws Exception {
		checkout(node, false);
	}

	public void checkout(DomainFileNode node, boolean exclusive) throws Exception {

		// TODO should not need this
		selectNodes(node);
		final DockingActionIf action = getAction("CheckOut");
		AbstractDockingTest.performAction(action, getDomainFileActionContext(node), false);
		waitForSwing();

		CheckoutDialog dialog = AbstractDockingTest.getDialogComponent(CheckoutDialog.class);
		if (dialog == null) {
			return; // a single checkout does not trigger a dialog
		}

		if (exclusive) {
			JCheckBox cb = AbstractDockingTest.findComponent(dialog, JCheckBox.class);
			assertNotNull(cb);
			assertEquals("Request exclusive checkout", cb.getText());
			runSwing(() -> cb.setSelected(true));
		}

		JButton okButton =
			(JButton) AbstractGuiTest.findAbstractButtonByText(dialog.getComponent(), "OK");
		assertNotNull(okButton);
		AbstractGuiTest.pressButton(okButton);
		waitForTasks();
		DomainFile df = node.getDomainFile();

		AbstractGTest.waitForCondition(() -> df.isCheckedOut());
		waitForTasks();
		waitForTree();
	}

	public void checkIn(GTreeNode node, final String text) throws Exception {
		DockingActionIf checkInAction = getAction("CheckIn");
		AbstractDockingTest.performAction(checkInAction, getDomainFileActionContext(node), false);

		VersionControlDialog dialog =
			AbstractDockingTest.waitForDialogComponent(VersionControlDialog.class);
		assertNotNull(dialog);
		JTextArea textArea = AbstractDockingTest.findComponent(dialog, JTextArea.class);
		assertNotNull(textArea);
		JCheckBox cb = AbstractDockingTest.findComponent(dialog, JCheckBox.class);
		assertNotNull(cb);
		runSwing(() -> {
			textArea.setText(text);
			cb.setSelected(true);
		});
		AbstractDockingTest.pressButtonByText(dialog, "OK");
		waitForTasks();
	}

	public void editProgram(Program program, ModifyProgramCallback modifyProgramCallback)
			throws CancelledException, IOException {
		int transactionID = program.startTransaction("test");
		try {
			modifyProgramCallback.call(program);
		}
		catch (Exception e) {
			AbstractGTest.failWithException("Unexpected exception", e);
		}
		finally {
			program.endTransaction(transactionID, true);
			program.save(null, TaskMonitor.DUMMY);
		}
	}

	public void editProgram(DomainFile df, Object consumer, ModifyProgramCallback edit)
			throws Exception {

		Program program = (Program) df.getDomainObject(this, true, false, TaskMonitor.DUMMY);

		try {
			editProgram(program, edit);
			df.save(TaskMonitor.DUMMY);
		}
		finally {
			program.release(this);
		}
	}

	public interface ModifyProgramCallback {
		public void call(Program p) throws Exception;
	}

	/**
	 * Get the named READ-ONLY project view tree helper
	 * @param tabName project view name (should match tab name)
	 * @return named READ-ONLY project view tree helper or null if view tree not found
	 */
	public DataTreeHelper getReadOnlyProjectTreeHelper(String tabName) {
		String dataTreeName = "Data Tree: " + tabName;
		DataTree tree = (DataTree) AbstractGuiTest
				.findComponentByName(frontEndTool.getToolFrame(), dataTreeName);
		return tree != null ? new DataTreeHelper(tree, true) : null;
	}

	/**
	 * Get the READ-ONLY project view tree helper for first view found
	 * @return READ-ONLY project view tree helper for first view found or null if none displayed
	 */
	public DataTreeHelper getFirstReadOnlyProjectTreeHelper() {
		for (DataTree tree : AbstractGuiTest.findComponents(frontEndTool.getToolFrame(),
			DataTree.class)) {
			if (tree.getName().startsWith("Data Tree:")) {
				return new DataTreeHelper(tree, true);
			}
		}
		return null;
	}
}
