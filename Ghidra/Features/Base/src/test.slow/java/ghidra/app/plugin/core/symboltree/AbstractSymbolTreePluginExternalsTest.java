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
package ghidra.app.plugin.core.symboltree;

import static org.junit.Assert.*;

import java.awt.Component;

import javax.swing.*;

import org.junit.After;
import org.junit.Before;

import docking.AbstractErrDialog;
import docking.action.DockingActionIf;
import docking.test.AbstractDockingTest;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.marker.MarkerManagerPlugin;
import ghidra.app.plugin.core.memory.MemoryMapPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.AddressInput;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.main.datatree.DataTree;
import ghidra.framework.main.datatree.ProjectDataTreePanel;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.LockException;
import ghidra.program.database.symbol.LibrarySymbol;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for the symbol tree plugin.
 */
public abstract class AbstractSymbolTreePluginExternalsTest
		extends AbstractGhidraHeadedIntegrationTest {

	protected static String GZF_NAME = "WinHelloCPP.exe";
	protected static String PROGRAM_NAME = "WinHelloCPP";
	protected static String EXTERNAL_PROGRAM_PATHNAME = "/" + PROGRAM_NAME;

	protected TestEnv env;
	protected PluginTool tool;
	protected Program program;
	protected SymbolTreePlugin plugin;
	protected GTreeNode rootNode;
	protected GTree tree;
	protected DockingActionIf renameAction;
	protected DockingActionIf cutAction;
	protected DockingActionIf pasteAction;
	protected DockingActionIf deleteAction;
	protected DockingActionIf selectionAction;
	protected DockingActionIf createNamespaceAction;
	protected DockingActionIf createClassAction;
	protected DockingActionIf goToToggleAction;
	protected DockingActionIf goToExtLocAction;
	protected DockingActionIf createLibraryAction;
	protected DockingActionIf setExternalProgramAction;
	protected DockingActionIf createExternalLocationAction;
	protected DockingActionIf editExternalLocationAction;
	protected SymbolTreeTestUtils util;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(ProgramTreePlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(MarkerManagerPlugin.class.getName());
		tool.addPlugin(SymbolTreePlugin.class.getName());
		tool.addPlugin(MemoryMapPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		plugin = env.getPlugin(SymbolTreePlugin.class);

		util = new SymbolTreeTestUtils(plugin);
		program = util.getProgram();

		getActions();
		env.showTool();
	}

	@After
	public void tearDown() throws Exception {
		closeProgram();
		env.dispose();
	}

	protected EditExternalLocationDialog showExternalEditDialog(String libraryName, String name)
			throws Exception {
		selectExternalLocation(libraryName, name);
		performAction(editExternalLocationAction, util.getProvider(), false);
		waitForSwing();

		EditExternalLocationDialog createDialog =
			AbstractDockingTest.waitForDialogComponent(EditExternalLocationDialog.class);
		waitForBusyTool(tool);
		return createDialog;
	}

	protected void pressRestoreButton(EditExternalLocationDialog dialog) {
		EditExternalLocationPanel extLocPanel =
			findComponent(dialog.getComponent().getRootPane(), EditExternalLocationPanel.class);
		JButton restoreButton = (JButton) getInstanceField("restoreButton", extLocPanel);
		pressButton(restoreButton);
	}

	protected void assertOriginalField(EditExternalLocationDialog createDialog,
			String expectedText) {

		EditExternalLocationPanel extLocPanel = findComponent(
			createDialog.getComponent().getRootPane(), EditExternalLocationPanel.class);
		JTextField extOriginalNameTextField =
			(JTextField) getInstanceField("extOriginalLabelTextField", extLocPanel);
		if (expectedText == null || expectedText.length() == 0) {
			assertNull(extOriginalNameTextField); // not shown
		}
		else {
			String text = extOriginalNameTextField.getText();
			assertEquals(expectedText, text);
		}
	}

	protected void changeToFunction(EditExternalLocationDialog createDialog, boolean isFunction) {
		EditExternalLocationPanel extLocPanel = findComponent(
			createDialog.getComponent().getRootPane(), EditExternalLocationPanel.class);
		JCheckBox functionCheckBox = (JCheckBox) getInstanceField("functionCheckBox", extLocPanel);
		functionCheckBox.setSelected(isFunction);
	}

	protected ExternalLocation setupExternalLocation(String library, String label, Address address,
			SourceType sourceType, boolean isFunction)
			throws InvalidInputException, DuplicateNameException {
		boolean success = false;
		int transactionID =
			program.startTransaction("Setting Up External Location " + library + "::" + label);
		try {
			ExternalManager externalManager = program.getExternalManager();
			Namespace libraryScope = getLibraryScope("ADVAPI32.dll");
			ExternalLocation extLocation =
				externalManager.addExtLocation(libraryScope, label, address, sourceType);
			assertNotNull(extLocation);
			if (isFunction) {
				Function function = extLocation.createFunction();
				assertNotNull(function);
			}
			success = true;
			return extLocation;
		}
		finally {
			program.endTransaction(transactionID, success);
		}
	}

	protected ExternalLocation setupExternalLocation(String library, String label, Address address,
			SourceType sourceType) throws InvalidInputException, DuplicateNameException {
		return setupExternalLocation(library, label, address, sourceType, false);
	}

	protected ExternalLocation setupExternalFunction(String library, String label, Address address,
			SourceType sourceType) throws InvalidInputException, DuplicateNameException {
		return setupExternalLocation(library, label, address, sourceType, true);
	}

	protected Namespace addNamespace(String libraryName, String namespace)
			throws InvalidInputException {
		boolean success = false;
		int transactionID = program.startTransaction(
			"Added namespace " + namespace + " to library " + libraryName + ".");
		try {
			Namespace libraryScope = getLibraryScope(libraryName);
			Namespace namespaceInLibrary = NamespaceUtils.createNamespaceHierarchy(namespace,
				libraryScope, program, SourceType.USER_DEFINED);
			assertNotNull(namespaceInLibrary);
			success = true;
			return namespaceInLibrary;
		}
		finally {
			program.endTransaction(transactionID, success);
		}
	}

	protected Namespace getLibraryScope(String libraryName) {
		Symbol s = program.getSymbolTable().getLibrarySymbol(libraryName);
		if (s instanceof LibrarySymbol) {
			return (Namespace) s.getObject();
		}
		return null;
	}

	protected void closeExternalLocation(EditExternalLocationDialog createDialog,
			String buttonText) {
		pressButtonByText(createDialog.getComponent(), buttonText);
		assertFalse(createDialog.isShowing());
		waitForSwing();
	}

	protected GTreeNode selectLibraryNode(String libraryName) throws Exception {

		flushAndWaitForTree();

		GTreeNode importsNode = rootNode.getChild("Imports");
		assertNotNull(importsNode);
		util.expandNode(importsNode);
		waitForSwing();
		flushAndWaitForTree();
		GTreeNode advapiNode = importsNode.getChild(libraryName);
		assertNotNull(advapiNode);
		tree.expandPath(advapiNode);
		tree.setSelectedNode(advapiNode);
		waitForSwing();
		flushAndWaitForTree();
		GTreeNode selectedNode = util.getSelectedNode();
		assertEquals(advapiNode, selectedNode);
		assertEquals("[Global, Imports, " + libraryName + "]",
			selectedNode.getTreePath().toString());
		return advapiNode;
	}

	protected GTreeNode selectExternalLocation(String libraryName, String externalLocation)
			throws Exception {
		flushAndWaitForTree();

		GTreeNode importsNode = rootNode.getChild("Imports");
		assertNotNull(importsNode);
		util.expandNode(importsNode);
		waitForSwing();
		flushAndWaitForTree();

		GTreeNode advapiNode = importsNode.getChild(libraryName);
		assertNotNull(advapiNode);
		util.expandNode(advapiNode);
		waitForSwing();
		flushAndWaitForTree();

		GTreeNode locationNode = advapiNode.getChild(externalLocation);
		assertNotNull(locationNode);
		tree.setSelectedNode(locationNode);
		waitForSwing();
		flushAndWaitForTree();
		GTreeNode selectedNode = util.getSelectedNode();
		assertEquals(locationNode, selectedNode);
		assertEquals("[Global, Imports, ADVAPI32.dll, " + externalLocation + "]",
			selectedNode.getTreePath().toString());
		return locationNode;
	}

	protected void checkExternalLocationPath(EditExternalLocationDialog createDialog,
			String externalProgramPath) {
		SystemUtilities.runSwingNow(() -> {
			EditExternalLocationPanel panel = findComponent(
				createDialog.getComponent().getRootPane(), EditExternalLocationPanel.class);
			Object pathTextObj = getInstanceField("extLibPathTextField", panel);
			JTextField pathTextField = (JTextField) pathTextObj;
			String text = pathTextField.getText();
			assertEquals(externalProgramPath, text);
		});
	}

	protected void checkExternalLibraryName(EditExternalLocationDialog createDialog,
			String expectedName) {
		SystemUtilities.runSwingNow(() -> {
			EditExternalLocationPanel panel = findComponent(
				createDialog.getComponent().getRootPane(), EditExternalLocationPanel.class);
			Object libNameObj = getInstanceField("extLibNameComboBox", panel);
			GhidraComboBox<?> nameComboBox = (GhidraComboBox<?>) libNameObj;
			String libName = nameComboBox.getText();
			assertEquals(expectedName, libName);
		});
	}

	protected void chooseExternalLibraryName(EditExternalLocationDialog createDialog,
			String libraryName) {
		SystemUtilities.runSwingNow(() -> {
			EditExternalLocationPanel panel = findComponent(
				createDialog.getComponent().getRootPane(), EditExternalLocationPanel.class);
			Object libNameObj = getInstanceField("extLibNameComboBox", panel);
			GhidraComboBox<?> nameComboBox = (GhidraComboBox<?>) libNameObj;
			nameComboBox.setSelectedItem(libraryName);
		});
	}

	protected void typeExternalLibraryName(EditExternalLocationDialog createDialog,
			String libraryName) {

		runSwing(() -> {
			EditExternalLocationPanel panel = findComponent(
				createDialog.getComponent().getRootPane(), EditExternalLocationPanel.class);
			Object libNameObj = getInstanceField("extLibNameComboBox", panel);
			GhidraComboBox<?> nameComboBox = (GhidraComboBox<?>) libNameObj;
			nameComboBox.requestFocusInWindow();
			Component editorComponent = nameComboBox.getEditor().getEditorComponent();
			assertTrue(editorComponent instanceof JTextField);
			if (editorComponent instanceof JTextField) {
				JTextField textField = (JTextField) editorComponent;
				textField.setText(libraryName);
			}
		});
	}

	protected void checkExternalLocationPathEndsWith(EditExternalLocationDialog createDialog,
			String externalProgramPathEndsWith) {
		EditExternalLocationPanel panel = findComponent(createDialog.getComponent().getRootPane(),
			EditExternalLocationPanel.class);
		Object pathTextObj = getInstanceField("extLibPathTextField", panel);
		JTextField pathTextField = (JTextField) pathTextObj;
		String text = pathTextField.getText();
		assertTrue(
			"Program path '" + text + "' doesn't end with '" + externalProgramPathEndsWith + "'",
			text.endsWith(externalProgramPathEndsWith));
	}

	protected void chooseProgram(Project project, String programName) {

		DataTreeDialog chooseDialog =
			AbstractDockingTest.waitForDialogComponent(DataTreeDialog.class);

		ProjectData projectData = project.getProjectData();
		DomainFolder folder = projectData.getFolder("/");
		assertNotNull(folder);

		DomainFile file = folder.getFile(programName);
		assertNotNull(file);

		setFileInDataTreeDialog(chooseDialog, file);

		pressDataTreeDialogOK(chooseDialog);

		waitForBusyTool(tool);

		flushAndWaitForTree();
	}

	protected void chooseProgramButCancel(Project project, String programName) {

		DataTreeDialog chooseDialog =
			AbstractDockingTest.waitForDialogComponent(DataTreeDialog.class);

		ProjectData projectData = project.getProjectData();
		DomainFolder folder = projectData.getFolder("/");
		assertNotNull(folder);
		DomainFile file = folder.getFile(programName);
		assertNotNull(file);

		setFileInDataTreeDialog(chooseDialog, file);

		pressDataTreeDialogCancel(chooseDialog);

		waitForBusyTool(tool);

		flushAndWaitForTree();
	}

	protected void closeErrorDialog(String expectedTitle) {

		AbstractErrDialog d = waitForErrorDialog();
		String actualTitle = d.getTitle();
		close(d);
		assertEquals(expectedTitle, actualTitle);

		waitForBusyTool(tool);

		flushAndWaitForTree();
	}

	protected void checkExternalLocationLabel(EditExternalLocationDialog createDialog,
			String label) {
		EditExternalLocationPanel extLocPanel = findComponent(
			createDialog.getComponent().getRootPane(), EditExternalLocationPanel.class);
		JTextField extLabelTextField =
			(JTextField) getInstanceField("extLabelTextField", extLocPanel);
		String text = extLabelTextField.getText();
		assertEquals(label, text);
	}

	protected void setExternalLocationLabel(EditExternalLocationDialog createDialog, String label) {
		runSwing(() -> {
			EditExternalLocationPanel extLocPanel = findComponent(
				createDialog.getComponent().getRootPane(), EditExternalLocationPanel.class);
			JTextField extLabelTextField =
				(JTextField) getInstanceField("extLabelTextField", extLocPanel);
			extLabelTextField.setText(label);
		});
	}

	protected void checkExternalLocationAddressInput(EditExternalLocationDialog createDialog,
			String space, String address) {
		EditExternalLocationPanel extLocPanel = findComponent(
			createDialog.getComponent().getRootPane(), EditExternalLocationPanel.class);
		AddressInput extAddressInputWidget =
			(AddressInput) getInstanceField("extAddressInputWidget", extLocPanel);

		Address inputAddress = extAddressInputWidget.getAddress();
		if (extAddressInputWidget.containsAddressSpaces()) {
			JComboBox<?> combo = (JComboBox<?>) getInstanceField("combo", extAddressInputWidget);
			AddressSpace addressSpace = (AddressSpace) combo.getSelectedItem();
			String currentAddressSpace = (addressSpace != null) ? addressSpace.getName() : "";
			assertEquals(space, currentAddressSpace);
		}
		String currentAddress = (inputAddress != null) ? inputAddress.toString(false) : "";
		assertEquals(address, currentAddress);
	}

	protected void setExternalLocationAddressInput(EditExternalLocationDialog createDialog,
			AddressSpace addressSpace, String address) {
		runSwing(() -> {
			EditExternalLocationPanel extLocPanel = findComponent(
				createDialog.getComponent().getRootPane(), EditExternalLocationPanel.class);
			AddressInput extAddressInputWidget =
				(AddressInput) getInstanceField("extAddressInputWidget", extLocPanel);
			if (extAddressInputWidget.containsAddressSpaces()) {
				JComboBox<?> addressSpaceWidget =
					(JComboBox<?>) getInstanceField("combo", extAddressInputWidget);
				addressSpaceWidget.setSelectedItem(addressSpace);
			}
			JTextField addressWidget =
				(JTextField) getInstanceField("textField", extAddressInputWidget);
			addressWidget.setText(address);
		});
	}

	protected void addOverlayBlock(String name, String startAddress, long length)
			throws LockException, DuplicateNameException, MemoryConflictException,
			AddressOverflowException, CancelledException {
		int transactionID = program.startTransaction("Add Overlay Block to test");
		Address address = program.getAddressFactory().getAddress(startAddress);
		Memory memory = program.getMemory();
		memory.createInitializedBlock(name, address, length, (byte) 0, TaskMonitor.DUMMY, true);
		program.endTransaction(transactionID, true);
	}

	protected void closeProgram() throws Exception {
		ProgramManager pm = tool.getService(ProgramManager.class);
		runSwing(() -> pm.closeProgram());
	}

	protected void showSymbolTree() throws Exception {
		util.showSymbolTree();
		rootNode = util.getRootNode();
		tree = util.getTree();
	}

	protected void getActions() throws Exception {
		renameAction = getAction(plugin, "Rename Symbol");
		assertNotNull(renameAction);
		cutAction = getAction(plugin, "Cut SymbolTree Node");
		assertNotNull(cutAction);
		pasteAction = getAction(plugin, "Paste Symbols");
		assertNotNull(pasteAction);
		deleteAction = getAction(plugin, "Delete Symbols");
		assertNotNull(deleteAction);
		selectionAction = getAction(plugin, "Make Selection");
		assertNotNull(selectionAction);
		createClassAction = getAction(plugin, "Create Class");
		assertNotNull(createClassAction);
		createNamespaceAction = getAction(plugin, "Create Namespace");
		assertNotNull(createNamespaceAction);
		createLibraryAction = getAction(plugin, "Create Library");
		assertNotNull(createLibraryAction);
		setExternalProgramAction = getAction(plugin, "Set External Program");
		assertNotNull(setExternalProgramAction);
		createExternalLocationAction = getAction(plugin, "Create External Location");
		assertNotNull(createExternalLocationAction);
		editExternalLocationAction = getAction(plugin, "Edit External Location");
		assertNotNull(editExternalLocationAction);

		goToToggleAction = getAction(plugin, "Navigation");
		assertNotNull(goToToggleAction);

		goToExtLocAction = getAction(plugin, "Go To External Location");
		assertNotNull(goToExtLocAction);
	}

	protected void pressDataTreeDialogOK(DataTreeDialog dialog) {
		pressButtonByText(dialog.getComponent(), "OK");
		assertFalse(dialog.isShowing());
		waitForSwing();
	}

	protected void pressDataTreeDialogCancel(DataTreeDialog dialog) {
		pressButtonByText(dialog.getComponent(), "Cancel");
		assertFalse(dialog.isShowing());
		waitForSwing();
	}

	protected void setFileInDataTreeDialog(DataTreeDialog dialog, DomainFile file) {
		runSwing(() -> dialog.selectDomainFile(file), true);

		waitForDialogTree(dialog);
	}

	protected void waitForDialogTree(DataTreeDialog dialog) {
		waitForSwing();
		ProjectDataTreePanel treePanel =
			(ProjectDataTreePanel) getInstanceField("treePanel", dialog);
		DataTree dataTree = treePanel.getDataTree();
		waitForTree(dataTree);
	}

	protected void flushAndWaitForTree() {
		program.flushEvents();
		waitForSwing();
		util.waitForTree();
	}
}
