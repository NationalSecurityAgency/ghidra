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

import static org.junit.Assert.*;

import java.awt.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.*;

import org.junit.Assert;
import org.junit.Test;

import docking.DialogComponentProvider;
import docking.options.editor.DateEditor;
import docking.options.editor.OptionsDialog;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.app.plugin.core.progmgr.MultiTabPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.dialog.CheckoutDialog;
import ghidra.framework.data.CheckinHandler;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.main.OpenVersionedFileDialog;
import ghidra.framework.model.*;
import ghidra.framework.remote.User;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitorAdapter;

public class ProgramManagerPluginScreenShots extends GhidraScreenShotGenerator
		implements CheckinHandler {
	private String checkinComment;
	private boolean keepCheckedOut = true;

	public ProgramManagerPluginScreenShots() {
		super();
	}

	@Test
	public void testClosedTab() throws Exception {
		createAndOpenPrograms(2, 1);
		closeProvider(DataTypesProvider.class);
		captureToolWindow(900, 400);
		drawOval(new Color(108, 0, 0), new Rectangle(280, 92, 190, 60), 8);

	}

	@Test
	public void testEditDate() {
		DateEditor dateEditor = new DateEditor();
		Component datePanel = dateEditor.getCustomEditor();
		final JButton button = (JButton) getInstanceField("browseButton", datePanel);

		runSwing(() -> pressButton(button), false);

		captureDialog(-1, -1);// Let is keep its size, lest we get a bunch of "..."
	}

	@Test
	public void testFileNotCheckedOut() {
		User user = new User("User 1", User.WRITE);
		CheckoutDialog checkoutDialog = new CheckoutDialog(program.getDomainFile(), user);
		showDialogWithoutBlocking(tool, checkoutDialog);
		captureDialog();
	}

	@Test
	public void testFrontEnd3() throws Exception {
		createAndOpenPrograms(3, 1);
		tool.setConfigChanged(false);
		env.closeTool(tool);

		FrontEndTool frontEndTool = getFrontEndTool();
		captureWindow(frontEndTool.getActiveWindow(), 500, 500);
	}

	@Test
	public void testFrontEndWithProgram() throws Exception {
		createAndOpenPrograms(3, 1);
		tool.setConfigChanged(false);

		FrontEndTool frontEndTool = getFrontEndTool();
		captureWindow(frontEndTool.getActiveWindow(), 500, 500);
	}

	@Test
	public void testOpenHistory() throws Exception {
		Project project = env.getProject();
		ProjectData projectData = project.getProjectData();
		projectData.getRootFolder()
				.createFile("WinHelloCpp.exe", program,
					TaskMonitorAdapter.DUMMY_MONITOR);

		DomainFile df = program.getDomainFile();

		addItemToVersionControl(df, "Added to Version Control", true);

		// Make change
		Program p = (Program) df.getDomainObject(this, false, false, null);
		changeProgram(p, "aaa");
		checkinComment = "Version 2";
		keepCheckedOut = true;
		assertTrue(df.canCheckin());
		df.checkin(this, false, null);

		changeProgram(p, "bbb");
		checkinComment = "Version 3";
		keepCheckedOut = true;
		assertTrue(df.canCheckin());
		df.checkin(this, false, null);

		p.release(this);
		performAction("Open File", "ProgramManagerPlugin", false);
		final OpenVersionedFileDialog dialog = (OpenVersionedFileDialog) getDialog();
		waitForSwing();
		Object treePanel = getInstanceField("treePanel", dialog);
		final GTree tree = (GTree) getInstanceField("tree", treePanel);
		GTreeNode rootNode = tree.getViewRoot();
		GTreeNode child = rootNode.getChild(0);
		tree.setSelectedNode(child);
		assertNotNull(dialog);
		runSwing(() -> invokeInstanceMethod("advancedButtonCallback", dialog));

		captureDialog(850, 400);
		closeAllWindowsAndFrames();
	}

	@Test
	public void testOpenProgram() throws Exception {
		createAndOpenPrograms(3, 1);

		performAction("Open File", "ProgramManagerPlugin", false);

		captureDialog(500, 400);
		closeAllWindowsAndFrames();

	}

	@Test
	public void testOpenProgramMenu() throws Exception {
		createAndOpenPrograms(3, 1);
		performAction("Open File", "ProgramManagerPlugin", false);

		waitForSwing();
		DialogComponentProvider dialog = getDialog();
		Object treePanel = getInstanceField("treePanel", dialog);
		GTree tree = (GTree) getInstanceField("tree", treePanel);
		JTree jTree = (JTree) getInstanceField("tree", tree);
		Rectangle rowBounds = jTree.getRowBounds(1);
		waitForTree(tree);

		rightClick(jTree, rowBounds.x + 25, rowBounds.y + 10);
		waitForSwing();
		captureDialog();
		closeAllWindowsAndFrames();
	}

	@Test
	public void testProgramOptionsDialog() {
		performAction("Program Options", "ProgramManagerPlugin", false);
		OptionsDialog dialog = (OptionsDialog) getDialog();
		Object optionsPanel = getInstanceField("panel", dialog);
		GTree tree = (GTree) getInstanceField("gTree", optionsPanel);
		GTreeNode rootNode = tree.getViewRoot();
		GTreeNode child = rootNode.getChild("Program Information");
		tree.setSelectedNode(child);
		waitForTree(tree);
		waitForSwing();
		captureDialog();
	}

	@Test
	public void testProgramTabs_No_Hidden() throws Exception {

		createAndOpenPrograms(4, 2);

		setToolSize(800, 400);
		goToListing(0x04002ba);

		captureIsolatedProvider(CodeViewerProvider.class, 600, 350);
	}

	@Test
	public void testProgramTabs_With_Hidden_Go_to_Program() throws Exception {

		CodeViewerProvider provider = getProvider(CodeViewerProvider.class);
		moveProviderToItsOwnWindow(provider);

		createAndOpenPrograms(6, 2);

		goToListing(0x04002ba);

		Window window = windowForComponent(provider.getComponent());
		setWindowSize(window, 600, 350);
		waitForSwing();

		performAction("Go To Program", "MultiTabPlugin", true);
		captureProviderWithScreenShot(provider);
	}

	@Test
	public void testProgramTabs_With_Hidden_More_Button() throws Exception {
		CodeViewerProvider provider = getProvider(CodeViewerProvider.class);
		moveProviderToItsOwnWindow(provider);
		Window window = windowForComponent(provider.getComponent());
		setWindowSize(window, 600, 350);
		waitForSwing();
		createAndOpenPrograms(6, 3);
		captureProvider(CodeViewerProvider.class);
		drawOval(new Color(108, 0, 0), new Rectangle(440, 16, 70, 50), 8);
	}

	@Test
	public void testProgramTabs_With_Hidden_Popup_Window() throws Exception {
		CodeViewerProvider provider = getProvider(CodeViewerProvider.class);
		moveProviderToItsOwnWindow(provider);

		createAndOpenPrograms(6, 2);

		goToListing(0x04002ba);
		Window window = windowForComponent(provider.getComponent());
		setWindowSize(window, 600, 350);
		waitForSwing();

		MultiTabPlugin plugin = getPlugin(tool, MultiTabPlugin.class);
		Object tabPanel = getInstanceField("tabPanel", plugin);
		JLabel label = (JLabel) getInstanceField("showHiddenListLabel", tabPanel);
		leftClick(label, 5, 5);
		waitForSwing();
		Component popupDialog = (Component) getInstanceField("listWindow", tabPanel);

		Component dockableComponent = getDockableComponent(provider.getComponent());
		captureComponents(Arrays.asList(dockableComponent, popupDialog));
	}

	@Test
	public void testProgramTabs_With_Highlighted_Tab() throws Exception {
		CodeViewerProvider provider = getProvider(CodeViewerProvider.class);
		moveProviderToItsOwnWindow(provider);
		Window window = windowForComponent(provider.getComponent());
		setWindowSize(window, 600, 350);
		waitForSwing();

		createAndOpenPrograms(6, 1);
		runSwing(() -> {
			MultiTabPlugin plugin = getPlugin(tool, MultiTabPlugin.class);
			invokeInstanceMethod("highlightNextProgram", plugin, new Class<?>[] { boolean.class },
				new Object[] { true });
		});

		captureProvider(CodeViewerProvider.class);
		drawOval(new Color(108, 0, 0), new Rectangle(221, 16, 140, 50), 8);
	}

	@Test
	public void testSaveProgram() {
		runSwing(() -> OptionDialog.showOptionDialog(tool.getToolFrame(), "Save Program?",
			"program1 has changed. Do you want to save it?", "&Save", "Do&n't Save",
			OptionDialog.QUESTION_MESSAGE), false);
		captureDialog();
	}

	@Test
	public void testSaveProgramAs() throws Exception {
		Program p = createAndOpenPrograms(4, 0);
		changeProgram(p, "Hey");
		performAction("Save As File", "ProgramManagerPlugin", false);
		captureDialog(300, 300);
		pressButtonOnDialog("Cancel");
	}

	@Test
	public void testTabs() throws Exception {
		createAndOpenPrograms(2, 1);
		goToListing(0x04002ba);
		captureIsolatedProvider(CodeViewerProvider.class, 600, 230);
	}

	private Program createAndOpenPrograms(int count, int currentProgramIndex) throws Exception {
		program = env.getProgram("WinHelloCPP.exe");
		CodeViewerProvider provider = getProvider(CodeViewerProvider.class);
		Project project = env.getProject();
		ProjectData projectData = project.getProjectData();
		List<DomainFile> list = new ArrayList<>();
		for (int i = 0; i < count; i++) {
			String programName = "Program" + (i + 1) + ".exe";
			list.add(projectData.getRootFolder()
					.createFile(programName, program,
						TaskMonitorAdapter.DUMMY_MONITOR));

		}
		program.flushEvents();

		ProgramManager service = tool.getService(ProgramManager.class);
		service.closeAllPrograms(true);
		List<Program> programs = new ArrayList<>();
		for (DomainFile domainFile : list) {
			programs.add(service.openProgram(domainFile));
		}
		service.setCurrentProgram(programs.get(currentProgramIndex));
		return programs.get(currentProgramIndex);
	}

	private void changeProgram(Program p, String labelName) {
		int txId = p.startTransaction("create symbol");
		try {
			p.getSymbolTable().createLabel(getAddr(p, 0), labelName, SourceType.USER_DEFINED);
		}
		catch (Exception e) {
			Assert.fail("Unexpected Exception creating symbol");
		}
		finally {
			p.endTransaction(txId, true);
		}
		try {
			p.save(null, null);
		}
		catch (Exception e) {
			Assert.fail("Unexpected Exception saving Exception");
		}

	}

	private void addItemToVersionControl(DomainFile domainFile, String comment,
			boolean keepItCheckedOut) throws Exception {
		TaskLauncher.launchModal(comment, () -> {
			try {
				domainFile.addToVersionControl(comment, keepItCheckedOut,
					TaskMonitorAdapter.DUMMY_MONITOR);
			}
			catch (CancelledException | IOException e) {
				throw new RuntimeException(e);
			}
		});
		waitForSwing();
	}

	private Address getAddr(Program p, long offset) {
		AddressFactory addrMap = p.getAddressFactory();
		AddressSpace space = addrMap.getDefaultAddressSpace();
		return space.getAddress(offset);
	}

	/*
	 * @see ghidra.framework.data.CheckinHandler#getComment()
	 */
	@Override
	public String getComment() {
		return checkinComment;
	}

	/*
	 * @see ghidra.framework.data.CheckinHandler#keepCheckedOut()
	 */
	@Override
	public boolean keepCheckedOut() {
		return keepCheckedOut;
	}

	@Override
	public boolean createKeepFile() throws CancelledException {
		return false;
	}

}
