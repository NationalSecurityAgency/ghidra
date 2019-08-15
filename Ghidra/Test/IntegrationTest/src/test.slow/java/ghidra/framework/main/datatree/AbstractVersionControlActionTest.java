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
package ghidra.framework.main.datatree;

import static org.junit.Assert.*;

import java.awt.Window;
import java.io.IOException;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;

import org.junit.After;
import org.junit.Before;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.ThreadedTableModel;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.store.Version;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.FrontEndTestEnv;
import ghidra.test.FrontEndTestEnv.ModifyProgramCallback;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class AbstractVersionControlActionTest extends AbstractGhidraHeadedIntegrationTest {

	protected static final String PROGRAM_A = FrontEndTestEnv.PROGRAM_A;
	protected static final String PROGRAM_B = "Program_B";
	protected static final String PROGRAM_C = "Program_C";
	protected FrontEndTestEnv frontEnd;

	@Before
	public void setUp() throws Exception {

		frontEnd = new FrontEndTestEnv();

		Program p1 = frontEnd.buildProgram(this);
		DomainFolder rootFolder = frontEnd.getRootFolder();

		// Program A created by the FrontEndTestEnv
		rootFolder.createFile(PROGRAM_B, p1, TaskMonitor.DUMMY);

		Program p2 = frontEnd.buildProgram(this);
		rootFolder.createFile(PROGRAM_C, p2, TaskMonitor.DUMMY);

		p1.release(this);
		p2.release(this);

		waitForTree();
		frontEnd.waitForTreeNode(PROGRAM_C);
	}

	@After
	public void tearDown() throws Exception {
		frontEnd.dispose();
	}

	protected void addToVersionControl(GTreeNode node, boolean keepCheckedOut) throws Exception {
		frontEnd.addToVersionControl(node, keepCheckedOut);
	}

	protected void assertVersionAtRow(final VersionHistoryTableModel model, final int row,
			int expectedVersion, String comment) {

		final AtomicReference<Version> ref = new AtomicReference<>();
		runSwing(() -> {
			Version version = model.getVersionAt(row);
			ref.set(version);
		});

		Version version = ref.get();
		assertEquals("Version number is wrong for row " + row, expectedVersion,
			version.getVersion());
		assertEquals("Version comment is wrong: ", comment, version.getComment());
	}

	protected void checkout(final GTreeNode node) throws Exception {
		frontEnd.checkout((DomainFileNode) node);
	}

	protected void clearSelectionPaths() throws Exception {
		frontEnd.clearTreeSelection();
	}

	protected void createHistoryEntry(Program program, String symbolName)
			throws InvalidInputException, IOException, CancelledException {
		int transactionID = program.startTransaction("test");
		try {
			SymbolTable symTable = program.getSymbolTable();
			symTable.createLabel(program.getMinAddress().getNewAddress(0x010001000), symbolName,
				SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(transactionID, true);
			program.save(null, TaskMonitor.DUMMY);
		}
	}

	protected void doCreateVersions() throws Exception {

		frontEnd.createMultipleCheckins();
	}

	protected void editProgram(Program program, ModifyProgramCallback modifyProgramCallback)
			throws CancelledException, IOException {
		frontEnd.editProgram(program, modifyProgramCallback);
	}

	// TODO delete this--do we need 'apply to all'?
	protected void fillOutCheckInDialog() {

		VersionControlDialog dialog = waitForDialogComponent(VersionControlDialog.class);
		assertNotNull(dialog);
		JTextArea textArea = findComponent(dialog, JTextArea.class);
		assertNotNull(textArea);
		JCheckBox cb = findComponent(dialog, JCheckBox.class);
		assertNotNull(cb);
		runSwing(() -> {
			textArea.setText("This is a test");
			cb.setSelected(false);
		});
		pressButtonByText(dialog, "Apply to All");
	}

	protected DockingActionIf getAction(String actionName) {
		return frontEnd.getAction(actionName);
	}

	protected DockingActionIf getDeleteAction(VersionHistoryDialog dialog) {
		waitForSwing();
		Set<DockingActionIf> dialogActions = dialog.getActions();
		for (DockingActionIf action : dialogActions) {
			if (action.getName().equals("Delete Version")) {
				return action;
			}
		}
		fail("Unable to find 'Delete Version' action");
		return null; // can't get here
	}

	protected ActionContext getDomainFileActionContext(GTreeNode... nodes) {
		return frontEnd.getDomainFileActionContext(nodes);
	}

	protected JPopupMenu getPopupMenu() {
		Set<Window> allWindows = getAllWindows();
		for (Window window : allWindows) {
			JPopupMenu popup = findComponent(window, JPopupMenu.class);
			if (popup != null) {
				return popup;
			}
		}
		return null;
	}

	protected void performFrontEndAction(DockingActionIf action) {
		frontEnd.performFrontEndAction(action);
	}

	protected void showHistory(final GTreeNode node) {
		final DockingActionIf historyAction = getAction("Show History");
		runSwing(() -> historyAction.actionPerformed(getDomainFileActionContext(node)));
	}

	////////////////////////////////////////////////////////////////////
	protected void waitForBusyTable(GTable table) {
		ThreadedTableModel<?, ?> model = (ThreadedTableModel<?, ?>) table.getModel();
		waitForTableModel(model);
	}

	protected void waitForTree() {
		frontEnd.waitForTree();
	}

	protected DomainFileNode getNode(String name) {
		return frontEnd.getTreeNode(name);
	}

	protected DomainFolderNode getFolderNode(String name) {
		return frontEnd.waitForFolderNode(name);
	}

	protected void selectNode(GTreeNode node) {
		selectNodes(node);
	}

	protected void selectNodes(GTreeNode... nodes) {
		frontEnd.selectNodes(nodes);
	}

	protected void expandNode(GTreeNode node) {
		frontEnd.expandNode(node);
	}

	protected void selectInTable(GTable table, GTreeNode node) {

		// assume name is column 0
		String name = node.getName();
		int nameCol = 0;
		int n = table.getRowCount();
		for (int i = 0; i < n; i++) {
			int row = i;
			Object value = runSwing(() -> table.getValueAt(row, nameCol));
			if (value == null) {
				continue;
			}

			if (name.equals(value.toString())) {
				table.changeSelection(row, 0, false, false);
				return;
			}
		}

	}
}
