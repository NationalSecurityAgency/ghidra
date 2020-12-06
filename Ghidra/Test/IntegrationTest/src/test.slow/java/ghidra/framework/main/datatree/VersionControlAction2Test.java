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

import java.util.Set;

import javax.swing.*;

import org.junit.Assert;
import org.junit.Test;

import docking.AbstractErrDialog;
import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.OptionDialog;
import docking.widgets.table.GTable;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.main.projectdata.actions.VersionControlAction;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import resources.MultiIcon;
import resources.ResourceManager;

/**
 * Tests for version control (not multi user).
 */
public class VersionControlAction2Test extends AbstractVersionControlActionTest {

	@Test
	public void testActionsEnabledForFile() throws Exception {

		GTreeNode node = getNode(PROGRAM_C);
		selectNode(node);

		Set<DockingActionIf> actions = frontEnd.getFrontEndActions();
		for (DockingActionIf action : actions) {

			if (!(action instanceof VersionControlAction)) {
				continue;
			}
			String actionName = action.getName();
			ActionContext context = getDomainFileActionContext(node);
			if (actionName.equals("Add to Version Control")) {
				assertTrue(action.isEnabledForContext(context));
			}
			else {
				assertTrue(!action.isEnabledForContext(context));
			}
			if (actionName.equals("Find Checkouts")) {
				assertTrue(!action.isAddToPopup(context));
			}
			else {
				assertTrue(action.isAddToPopup(context));
			}
		}
	}

	@Test
	public void testActionsEnabledForFolder() throws Exception {

		DomainFolder rootFolder = frontEnd.getRootFolder();
		DomainFolder f = rootFolder.createFolder("myFolder");
		waitForSwing();

		Program p = frontEnd.buildProgram(this);
		f.createFile("Sample", p, TaskMonitor.DUMMY);
		p.release(this);

		waitForSwing();
		GTreeNode node = getFolderNode("myFolder");
		assertNotNull(node);

		expandNode(node);
		selectNode(node);

		Set<DockingActionIf> actions = frontEnd.getFrontEndActions();
		for (DockingActionIf action : actions) {
			if (!(action instanceof VersionControlAction)) {
				continue;
			}
			if (action.getName().equals("Find Checkouts")) {
				assertTrue(action.isEnabledForContext(getDomainFileActionContext(node)));
			}
			else {
				assertTrue(!action.isEnabledForContext(getDomainFileActionContext(node)));
			}
		}
	}

	@Test
	public void testAddToVersionControlKeepCheckedOut() throws Exception {
		GTreeNode node = getNode(PROGRAM_C);
		selectNode(node);

		DockingActionIf action = getAction("Add to Version Control");

		performAction(action, getDomainFileActionContext(node), false);

		VersionControlDialog dialog = waitForDialogComponent(VersionControlDialog.class);
		assertNotNull(dialog);
		JTextArea textArea = findComponent(dialog, JTextArea.class);
		assertNotNull(textArea);
		runSwing(() -> textArea.setText("This is a test"));
		pressButtonByText(dialog, "OK");
		waitForTasks();
		DomainFile df = ((DomainFileNode) node).getDomainFile();
		assertTrue(df.isVersioned());
		assertTrue(df.isCheckedOut());
		assertEquals(1, df.getLatestVersion());
	}

	@Test
	public void testAddToVersionControl() throws Exception {
		GTreeNode node = getNode(PROGRAM_C);

		frontEnd.addToVersionControl(node, false);

		DomainFile df = ((DomainFileNode) node).getDomainFile();
		assertTrue(!df.isCheckedOut());
		assertEquals(1, df.getLatestVersion());
	}

	@Test
	public void testAddMultipleToVersionControl() throws Exception {
		GTreeNode nodeA = getNode(PROGRAM_A);
		GTreeNode nodeC = getNode(PROGRAM_C);
		selectNodes(nodeA, nodeC);

		DockingActionIf action = getAction("Add to Version Control");
		SwingUtilities.invokeLater(
			() -> action.actionPerformed(getDomainFileActionContext(nodeA, nodeC)));
		waitForSwing();
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
		waitForTasks();
		DomainFile df = ((DomainFileNode) nodeC).getDomainFile();
		assertTrue(df.isVersioned());
		assertTrue(!df.isCheckedOut());
		assertEquals(1, df.getLatestVersion());

		df = ((DomainFileNode) nodeA).getDomainFile();
		assertTrue(df.isVersioned());
		assertTrue(!df.isCheckedOut());
		assertEquals(1, df.getLatestVersion());
	}

	@Test
	public void testCheckOut() throws Exception {
		// add program to version control
		GTreeNode node = getNode(PROGRAM_A);
		addToVersionControl(node, false);

		selectNode(node);
		DockingActionIf action = getAction("CheckOut");
		SwingUtilities.invokeLater(() -> action.actionPerformed(getDomainFileActionContext(node)));
		waitForSwing();
		waitForTasks();
		DomainFile df = ((DomainFileNode) node).getDomainFile();
		assertTrue(df.isCheckedOut());
		Icon icon = df.getIcon(false);
		assertTrue(icon instanceof MultiIcon);
		Icon[] icons = ((MultiIcon) icon).getIcons();
		Icon checkOutIcon = ResourceManager.loadImage("images/checkex.png");
		boolean found = false;
		for (Icon element : icons) {
			if (checkOutIcon.equals(element)) {
				found = true;
				break;
			}
		}
		if (!found) {
			Assert.fail("Did not find checkout icon!");
		}
	}

	@Test
	public void testCheckIn() throws Exception {
		GTreeNode node = getNode(PROGRAM_A);
		addToVersionControl(node, false);

		selectNode(node);
		DockingActionIf action = getAction("CheckOut");
		runSwing(() -> action.actionPerformed(getDomainFileActionContext(node)), false);
		waitForSwing();
		waitForTasks();

		Program program = (Program) ((DomainFileNode) node).getDomainFile()
				.getDomainObject(this,
					true, false, TaskMonitor.DUMMY);
		int transactionID = program.startTransaction("test");
		try {
			SymbolTable symTable = program.getSymbolTable();
			symTable.createLabel(program.getMinAddress().getNewAddress(0x010001000), "fred",
				SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(transactionID, true);
			program.save(null, TaskMonitor.DUMMY);
		}
		program.release(this);

		DockingActionIf checkInAction = getAction("CheckIn");
		runSwing(() -> checkInAction.actionPerformed(getDomainFileActionContext(node)), false);
		waitForSwing();
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
		pressButtonByText(dialog, "OK");
		waitForTasks();
		DomainFile df = ((DomainFileNode) node).getDomainFile();
		assertTrue(!df.isCheckedOut());

	}

	@Test
	public void testDeleteVersionCheckedOut() throws Exception {
		// cannot delete a version that is checked out
		setErrorGUIEnabled(true);// expect an error dialog
		// create 3 versions of the program
		doCreateVersions();
		GTreeNode node = getNode(PROGRAM_A);

		selectNode(node);
		DockingActionIf historyAction = getAction("Show History");
		runSwing(() -> historyAction.actionPerformed(getDomainFileActionContext(node)));

		VersionHistoryDialog dialog = waitForDialogComponent(VersionHistoryDialog.class);
		DockingActionIf deleteAction = getDeleteAction(dialog);

		GTable table = findComponent(dialog, GTable.class);
		runSwing(() -> table.selectRow(0));
		performAction(deleteAction, false);

		// cannot delete a file that is checked out
		AbstractErrDialog d = waitForErrorDialog();
		assertEquals("File version has one or more checkouts.", d.getMessage());
		close(d);
	}

	@Test
	public void testDeleteVersionNotFirstOrLast() throws Exception {
		//	can delete only the first or last version of the file
		setErrorGUIEnabled(true);// expect an error dialog

		doCreateVersions();
		GTreeNode node = getNode(PROGRAM_A);
		selectNode(node);

		DockingActionIf historyAction = getAction("Show History");
		runSwing(() -> historyAction.actionPerformed(getDomainFileActionContext(node)));

		VersionHistoryDialog dialog = waitForDialogComponent(VersionHistoryDialog.class);
		DockingActionIf deleteAction = getDeleteAction(dialog);

		GTable table = findComponent(dialog, GTable.class);
		runSwing(() -> table.selectRow(1));
		performAction(deleteAction, false);

		//	can delete only the first or last version of the file
		AbstractErrDialog d = waitForErrorDialog();
		assertEquals("Only first and last version may be deleted.", d.getMessage());
		close(d);
		close(dialog);
	}

	@Test
	public void testDeleteVersion() throws Exception {
		doCreateVersions();

		GTreeNode node = getNode(PROGRAM_A);
		selectNode(node);

		DockingActionIf undoAction = getAction("UndoCheckOut");
		performAction(undoAction, getDomainFileActionContext(node), true);

		selectNode(node);
		DockingActionIf historyAction = getAction("Show History");
		performAction(historyAction, getDomainFileActionContext(node), true);

		VersionHistoryDialog dialog = waitForDialogComponent(VersionHistoryDialog.class);
		DockingActionIf deleteAction = getDeleteAction(dialog);

		GTable table = findComponent(dialog, GTable.class);
		runSwing(() -> table.selectRow(0));
		int rowCount = table.getRowCount();

		performAction(deleteAction, false);

		OptionDialog confirmDialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull(confirmDialog);
		pressButtonByText(confirmDialog, "Delete");

		waitForTasks();

		assertEquals(rowCount - 1, table.getRowCount());

		close(dialog);
	}

	@Test
	public void testFindCheckoutsInSubFolder() throws Exception {

		DomainFolder rootFolder = frontEnd.getRootFolder();
		DomainFolder folder = rootFolder.createFolder("myFolder_1");
		folder = folder.createFolder("myFolder_2");

		Program p = frontEnd.buildProgram(this);
		folder.createFile("My_Program", p, TaskMonitor.DUMMY);
		p.release(this);
		waitForSwing();

		GTreeNode node = getFolderNode("myFolder_1");
		assertNotNull(node);
		node = node.getChild("myFolder_2");
		assertNotNull(node);
		node = node.getChild("My_Program");
		assertNotNull(node);
		addToVersionControl(node, true);

		selectNode(getFolderNode("myFolder_1"));
		DockingActionIf action = getAction("Find Checkouts");
		performFrontEndAction(action);

		FindCheckoutsDialog dialog = waitForDialogComponent(FindCheckoutsDialog.class);
		assertNotNull(dialog);

		GTable table = findComponent(dialog.getComponent(), GTable.class);
		assertNotNull(table);
		waitForBusyTable(table);

		FindCheckoutsTableModel model = (FindCheckoutsTableModel) table.getModel();

		assertEquals(1, model.getRowCount());
		CheckoutInfo checkoutInfo = model.getRowObject(0);
		DomainFile file = checkoutInfo.getFile();
		DomainFolder parent = file.getParent();
		assertEquals("/myFolder_1/myFolder_2", parent.getPathname());
		pressButtonByText(dialog, "Dismiss");
	}

	@Test
	public void testCheckInFromFindDialog() throws Exception {
		// verify that you get the Check In dialog to popup
		GTreeNode node = getNode(PROGRAM_B);
		addToVersionControl(node, true);
		node = getNode(PROGRAM_C);
		addToVersionControl(node, true);

		DomainFile df = ((DomainFileNode) node).getDomainFile();
		Program p = (Program) df.getDomainObject(this, true, false, TaskMonitor.DUMMY);
		editProgram(p, program -> {
			CodeUnit cu = program.getListing().getCodeUnitAt(program.getMinAddress());
			cu.setComment(CodeUnit.PLATE_COMMENT, "my Plate Comment");
		});
		p.release(this);

		GTreeNode rootNode = frontEnd.getRootNode();
		selectNode(rootNode);

		DockingActionIf action = getAction("Find Checkouts");
		performFrontEndAction(action);

		FindCheckoutsDialog dialog = waitForDialogComponent(FindCheckoutsDialog.class);

		assertNotNull(dialog);

		GTable table = findComponent(dialog.getComponent(), GTable.class);
		assertNotNull(table);
		waitForBusyTable(table);

		FindCheckoutsTableModel model = (FindCheckoutsTableModel) table.getModel();
		assertEquals(2, model.getRowCount());

		selectInTable(table, node);

		DockingActionIf checkInAction = getAction("CheckIn");
		ActionContext context = dialog.getActionContext(null);
		assertTrue(checkInAction.isEnabledForContext(context));
		performAction(checkInAction, context, false);
		VersionControlDialog d = waitForDialogComponent(VersionControlDialog.class);

		pressButtonByText(d, "Cancel");

		pressButtonByText(dialog, "Dismiss");
		waitForTasks();
	}
}
