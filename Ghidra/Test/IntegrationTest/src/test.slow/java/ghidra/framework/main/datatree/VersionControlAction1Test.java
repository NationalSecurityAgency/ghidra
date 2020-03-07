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

import java.awt.Component;
import java.awt.Rectangle;
import java.awt.event.*;
import java.util.List;

import javax.swing.*;

import org.junit.Assert;
import org.junit.Test;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingActionIf;
import docking.widgets.table.*;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.framework.store.Version;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import resources.MultiIcon;
import resources.ResourceManager;

/**
 * Tests for version control (not multi user).
 */
public class VersionControlAction1Test extends AbstractVersionControlActionTest {

	@Test
	public void testUndoCheckout() throws Exception {
		// add program to version control
		GTreeNode node = getNode(PROGRAM_A);
		addToVersionControl(node, false);

		selectNode(node);
		final DockingActionIf action = getAction("CheckOut");
		runSwing(() -> action.actionPerformed(getDomainFileActionContext(node)), false);
		waitForSwing();

		waitForTasks();
		final DockingActionIf undoAction = getAction("UndoCheckOut");
		runSwing(() -> undoAction.actionPerformed(getDomainFileActionContext(node)));

		waitForSwing();
		waitForTasks();

		DomainFile df = ((DomainFileNode) node).getDomainFile();
		assertTrue(!df.isCheckedOut());
		Icon icon = df.getIcon(false);
		Icon[] icons = ((MultiIcon) icon).getIcons();
		Icon checkOutIcon = ResourceManager.loadImage("images/checkex.png");
		for (Icon element : icons) {
			if (checkOutIcon.equals(element)) {
				Assert.fail("Found unexpected check out icon!");
			}
		}
	}

	@Test
	public void testUndoCheckOutModified() throws Exception {
		GTreeNode node = getNode(PROGRAM_A);
		addToVersionControl(node, false);

		selectNode(node);
		DockingActionIf action = getAction("CheckOut");
		performAction(action, getDomainFileActionContext(node), false);

		waitForTasks();

		// make a change to the program
		DomainFile df = ((DomainFileNode) node).getDomainFile();
		Program program = (Program) df.getDomainObject(this, true, false, TaskMonitor.DUMMY);
		int transactionID = program.startTransaction("test");
		try {
			program.getSymbolTable().createNameSpace(null, "myNamespace", SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(transactionID, true);
			program.save(null, TaskMonitor.DUMMY);
		}
		program.release(this);
		program.flushEvents();

		DockingActionIf undoAction = getAction("UndoCheckOut");
		performAction(undoAction, getDomainFileActionContext(node), false);
		UndoActionDialog dialog = waitForDialogComponent(UndoActionDialog.class);
		assertNotNull(dialog);

		JCheckBox cb = (JCheckBox) findAbstractButtonByText(dialog.getComponent(),
			"Save copy of the file with a .keep extension");
		assertNotNull(cb);
		assertTrue(cb.isSelected());

		pressButtonByText(dialog, "OK");
		waitForTasks();

		df = ((DomainFileNode) node).getDomainFile();
		assertTrue(!df.isCheckedOut());
		Icon icon = df.getIcon(false);
		Icon[] icons = ((MultiIcon) icon).getIcons();
		Icon checkOutIcon = ResourceManager.loadImage("images/checkex.png");
		for (Icon element : icons) {
			if (checkOutIcon.equals(element)) {
				Assert.fail("Found unexpected check out icon!");
			}
		}

		DomainFileNode keepNode = getNode(PROGRAM_A + ".keep");
		assertNotNull(keepNode);
	}

	@Test
	public void testUndoHijack() throws Exception {

		// check out a file
		GTreeNode node = getNode(PROGRAM_A);
		addToVersionControl(node, false);

		selectNode(node);
		final DockingActionIf action = getAction("CheckOut");
		SwingUtilities.invokeLater(() -> action.actionPerformed(getDomainFileActionContext(node)));
		waitForSwing();

		waitForTasks();

		DockingActionIf undoHijackAction = getAction("Undo Hijack");
		assertTrue(!undoHijackAction.isEnabledForContext(getDomainFileActionContext(node)));

		// make a change to the program
		DomainFile df = ((DomainFileNode) node).getDomainFile();
		Program program = (Program) df.getDomainObject(this, true, false, TaskMonitor.DUMMY);
		int transactionID = program.startTransaction("test");
		try {
			program.getSymbolTable().createNameSpace(null, "myNamespace", SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(transactionID, true);
			program.save(null, TaskMonitor.DUMMY);
		}
		program.release(this);
		program.flushEvents();

		// terminate the checkout to get a hijacked file
		ItemCheckoutStatus[] items = df.getCheckouts();
		assertEquals(1, items.length);
		df.terminateCheckout(items[0].getCheckoutId());
		waitForSwing();

		clearSelectionPaths();

		selectNode(node);
		assertTrue(undoHijackAction.isEnabledForContext(getDomainFileActionContext(node)));
		waitForSwing();

		// undo the hijack		
		performFrontEndAction(undoHijackAction);
		UndoActionDialog dialog = waitForDialogComponent(UndoActionDialog.class);
		assertNotNull(dialog);

		DomainFilesPanel panel = findComponent(dialog.getComponent(), DomainFilesPanel.class);
		assertNotNull(panel);

		DomainFile[] files = panel.getSelectedDomainFiles();
		assertEquals(1, files.length);
		assertEquals(df, files[0]);

		assertTrue(dialog.saveCopy());
		pressButtonByText(dialog.getComponent(), "OK");

		waitForSwing();
		waitForTasks();

		assertNotNull(getNode(PROGRAM_A + ".keep"));
		assertTrue(!undoHijackAction.isEnabledForContext(getDomainFileActionContext(node)));
	}

	@Test
	public void testMultipleCheckIns() throws Exception {
		GTreeNode node = getNode(PROGRAM_A);
		addToVersionControl(node, false);
		GTreeNode xnode = getNode(PROGRAM_B);
		addToVersionControl(xnode, false);

		selectNodes(node, xnode);

		DockingActionIf action = getAction("CheckOut");
		performAction(action, getDomainFileActionContext(node, xnode), false);

		DialogComponentProvider dialog = waitForDialogComponent("Confirm Bulk Checkout");
		pressButtonByText(dialog, "Yes");

		waitForTasks();

		// make some changes to check in
		Program program = (Program) ((DomainFileNode) node).getDomainFile()
				.getDomainObject(this,
					true, false, TaskMonitor.DUMMY);
		editProgram(program, (p) -> {
			SymbolTable symTable = p.getSymbolTable();
			symTable.createLabel(p.getMinAddress().getNewAddress(0x010001000), "fred",
				SourceType.USER_DEFINED);
		});

		program = (Program) ((DomainFileNode) xnode).getDomainFile()
				.getDomainObject(this, true,
					false, TaskMonitor.DUMMY);
		editProgram(program, (p) -> {
			SymbolTable symTable = p.getSymbolTable();
			symTable.createLabel(p.getMinAddress(), "bob", SourceType.USER_DEFINED);
		});

		DockingActionIf checkInAction = getAction("CheckIn");
		performAction(checkInAction, getDomainFileActionContext(node, xnode), false);

		fillOutCheckInDialog();

		waitForTasks();

		DomainFile df = ((DomainFileNode) node).getDomainFile();
		assertTrue(!df.isCheckedOut());
		df = ((DomainFileNode) xnode).getDomainFile();
		assertTrue(!df.isCheckedOut());
	}

	@Test
	public void testShowHistory() throws Exception {
		// create 3 versions of the program

		GTreeNode programNode = getNode(PROGRAM_A);
		addToVersionControl(programNode, false);

		checkout(programNode);

		Program program =
			(Program) ((DomainFileNode) programNode).getDomainFile()
					.getDomainObject(this, true,
						false, TaskMonitor.DUMMY);

		createHistoryEntry(program, "Symbol1");
		frontEnd.checkIn(programNode, "This is checkin 1");

		// make another change
		createHistoryEntry(program, "Symbol2");
		frontEnd.checkIn(programNode, "This is checkin 2");

		// make one more change
		createHistoryEntry(program, "Symbol3");
		frontEnd.checkIn(programNode, "This is checkin 3");

		program.release(this);

		showHistory(programNode);

		VersionHistoryDialog dialog = waitForDialogComponent(VersionHistoryDialog.class);
		assertNotNull(dialog);

		VersionHistoryPanel panel = findComponent(dialog, VersionHistoryPanel.class);
		assertNotNull(panel);
		VersionHistoryTableModel model = panel.getVersionHistoryTableModel();
		assertEquals(4, model.getRowCount());

		JTable table = findComponent(dialog, JTable.class);
		AbstractSortedTableModel<?> m = (AbstractSortedTableModel<?>) table.getModel();
		assertEquals(VersionHistoryTableModel.VERSION_COL, m.getPrimarySortColumnIndex());

		TableSortState sortState = m.getTableSortState();
		assertEquals("More columns sorted than expected", 1, sortState.getSortedColumnCount());
		List<ColumnSortState> sortStates = sortState.getAllSortStates();
		ColumnSortState columnSortState = sortStates.get(0);
		int index = columnSortState.getColumnModelIndex();
		assertEquals("Model not sorted on correct column", VersionHistoryTableModel.VERSION_COL,
			index);
		assertFalse("Column not sorted descending", columnSortState.isAscending());

		// sorted descending, so row 0 is version 4, row 1 is version 3, etc
		assertVersionAtRow(model, 1, 3, "This is checkin 2");
		assertVersionAtRow(model, 2, 2, "This is checkin 1");

		runSwing(() -> dialog.close());
	}

	@Test
	public void testOpenVersionDoubleClick() throws Exception {

		// create 3 versions of the program
		doCreateVersions();

		DomainFileNode node = getNode(PROGRAM_A);
		selectNode(node);
		final DockingActionIf historyAction = getAction("Show History");
		runSwing(() -> historyAction.actionPerformed(getDomainFileActionContext(node)));

		VersionHistoryDialog dialog = waitForDialogComponent(VersionHistoryDialog.class);

		GTable table = findComponent(dialog, GTable.class);
		runSwing(() -> table.selectRow(0));

		VersionHistoryPanel panel = findComponent(dialog, VersionHistoryPanel.class);

		VersionHistoryTableModel tm = panel.getVersionHistoryTableModel();
		Version version = runSwing(() -> tm.getVersionAt(0));

		Rectangle rect = table.getCellRect(0, 0, true);
		final MouseEvent event = new MouseEvent(table, MouseEvent.MOUSE_CLICKED,
			System.currentTimeMillis(), 0, rect.x, rect.y, 2, false, MouseEvent.BUTTON1);

		runSwing(() -> {
			MouseListener[] mls = table.getMouseListeners();
			for (final MouseListener ml : mls) {
				ml.mouseClicked(event);
				if (event.isConsumed()) {
					break;
				}
			}
		});

		waitForSwing();

		List<PluginTool> tools = frontEnd.getTools();
		assertEquals(1, tools.size());

		DomainFile[] dfs = tools.get(0).getDomainFiles();
		assertEquals(1, dfs.length);

		assertTrue(dfs[0].isReadOnly());
		assertEquals(version.getVersion(), dfs[0].getVersion());

		runSwing(() -> dialog.close());

	}

	@Test
	public void testOpenVersion() throws Exception {

		// create 3 versions of the program
		doCreateVersions();
		GTreeNode node = getNode(PROGRAM_A);

		selectNode(node);
		DockingActionIf historyAction = getAction("Show History");
		performAction(historyAction, getDomainFileActionContext(node), true);

		VersionHistoryDialog dialog = waitForDialogComponent(VersionHistoryDialog.class);

		VersionHistoryPanel panel = findComponent(dialog, VersionHistoryPanel.class);

		JTable table = findComponent(dialog, JTable.class);
		VersionHistoryTableModel tm = panel.getVersionHistoryTableModel();
		Version version = runSwing(() -> tm.getVersionAt(0));

		runSwing(() -> table.setRowSelectionInterval(0, 0));

		Rectangle rect = table.getCellRect(0, 0, true);

		final MouseEvent event = new MouseEvent(table, MouseEvent.MOUSE_PRESSED,
			System.currentTimeMillis(), 0, rect.x, rect.y, 1, true);

		runSwing(() -> {
			MouseListener[] mls = table.getMouseListeners();
			for (final MouseListener ml : mls) {
				ml.mousePressed(event);
				if (event.isConsumed()) {
					break;
				}
			}
		});

		JPopupMenu popup = getPopupMenu();
		assertNotNull(popup);

		int n = popup.getComponentCount();
		for (int i = 0; i < n; i++) {
			Component comp = popup.getComponent(i);
			if (comp instanceof JMenuItem) {
				if (((JMenuItem) comp).getText().equals("Open in Default Tool")) {
					final ActionListener al = ((JMenuItem) comp).getActionListeners()[0];
					runSwing(new Runnable() {
						@Override
						public void run() {
							al.actionPerformed(new ActionEvent(this, 0, null));
						}
					});
					break;
				}
			}
		}

		waitForSwing();

		List<PluginTool> tools = frontEnd.getTools();
		assertEquals(1, tools.size());

		DomainFile[] dfs = tools.get(0).getDomainFiles();
		assertEquals(1, dfs.length);

		assertTrue(dfs[0].isReadOnly());
		assertEquals(version.getVersion(), dfs[0].getVersion());

		runSwing(() -> dialog.close());

	}

	@Test
	public void testOpenVersionWith() throws Exception {

		// create 3 versions of the program
		doCreateVersions();

		GTreeNode node = getNode(PROGRAM_A);
		selectNode(node);

		DockingActionIf historyAction = getAction("Show History");
		performAction(historyAction, getDomainFileActionContext(node), true);

		VersionHistoryDialog dialog = waitForDialogComponent(VersionHistoryDialog.class);

		GTable table = findComponent(dialog, GTable.class);
		runSwing(() -> table.selectRow(0));

		VersionHistoryPanel panel = findComponent(dialog, VersionHistoryPanel.class);
		VersionHistoryTableModel tm = panel.getVersionHistoryTableModel();
		Version version = runSwing(() -> tm.getVersionAt(0));

		Rectangle rect = table.getCellRect(0, 0, true);
		final MouseEvent event = new MouseEvent(table, MouseEvent.MOUSE_PRESSED,
			System.currentTimeMillis(), 0, rect.x, rect.y, 1, true);

		runSwing(() -> {
			MouseListener[] mls = table.getMouseListeners();
			for (final MouseListener ml : mls) {
				ml.mousePressed(event);
				if (event.isConsumed()) {
					break;
				}
			}
		});

		JPopupMenu popup = getPopupMenu();
		assertNotNull(popup);

		int n = popup.getComponentCount();
		for (int i = 0; i < n; i++) {
			Component comp = popup.getComponent(i);
			if (comp instanceof JMenu) {
				JMenu menu = (JMenu) comp;
				int nItems = menu.getItemCount();
				for (int j = 0; j < nItems; j++) {
					Component item = menu.getMenuComponent(j);
					if (item instanceof JMenuItem) {
						if (((JMenuItem) item).getText().equals("CodeBrowser")) {
							final ActionListener al = ((JMenuItem) item).getActionListeners()[0];
							runSwing(new Runnable() {
								@Override
								public void run() {
									al.actionPerformed(new ActionEvent(this, 0, null));
								}
							});
							break;
						}
					}
				}
			}
		}

		waitForSwing();

		List<PluginTool> tools = frontEnd.getTools();
		assertEquals(1, tools.size());

		DomainFile[] dfs = tools.get(0).getDomainFiles();
		assertEquals(1, dfs.length);

		assertTrue(dfs[0].isReadOnly());
		assertEquals(version.getVersion(), dfs[0].getVersion());

		runSwing(() -> dialog.close());

	}

	@Test
	public void testRefreshFolder() throws Exception {

		doCreateVersions();

		DomainFolder rootFolder = frontEnd.getRootFolder();
		DomainFolder folder = rootFolder.createFolder("myFolder");

		Program p = frontEnd.buildProgram(this);
		folder.createFile("My_Program", p, TaskMonitor.DUMMY);
		p.release(this);

		waitForSwing();

		GTreeNode node = getNode(PROGRAM_A);
		DomainFile df = ((DomainFileNode) node).getDomainFile();
		df.copyTo(folder, TaskMonitor.DUMMY);

		waitForSwing();

		final GTreeNode fnode = getFolderNode("myFolder");
		assertNotNull(fnode);
		expandNode(fnode);
		assertEquals(2, fnode.getChildCount());
		selectNode(fnode);

		DockingActionIf action = getAction("Refresh");
		performFrontEndAction(action);
		assertEquals(2, fnode.getChildCount());
	}

	@Test
	public void testFindMyCheckouts() throws Exception {
		doCreateVersions();

		DomainFolder rootFolder = frontEnd.getRootFolder();
		DomainFolder folder = rootFolder.createFolder("myFolder_1");
		folder = folder.createFolder("myFolder_2");
		Program p = frontEnd.buildProgram(this);
		folder.createFile("My_Program", p, TaskMonitor.DUMMY);
		p.release(this);

		GTreeNode node = getFolderNode("myFolder_1");
		assertNotNull(node);
		node = node.getChild("myFolder_2");
		assertNotNull(node);
		node = node.getChild("My_Program");
		assertNotNull(node);
		addToVersionControl(node, true);

		GTreeNode rootNode = frontEnd.getRootNode();
		selectNode(rootNode);
		DockingActionIf action = getAction("Find Checkouts");
		performFrontEndAction(action);

		FindCheckoutsDialog dialog = waitForDialogComponent(FindCheckoutsDialog.class);
		assertNotNull(dialog);

		final GTable table = findComponent(dialog.getComponent(), GTable.class);
		assertNotNull(table);
		waitForBusyTable(table);

		FindCheckoutsTableModel model = (FindCheckoutsTableModel) table.getModel();

		assertEquals(2, model.getRowCount());
		assertEquals(4, model.getColumnCount());

		DockingActionIf undoCheckoutAction = getAction("UndoCheckOut");
		DockingActionIf checkInAction = getAction("CheckIn");
		assertFalse(checkInAction.isEnabledForContext(dialog.getActionContext(null)));
		assertFalse(undoCheckoutAction.isEnabledForContext(dialog.getActionContext(null)));

		// make a selection in the table
		selectInTable(table, node);
		assertFalse(checkInAction.isEnabledForContext(dialog.getActionContext(null)));
		assertTrue(undoCheckoutAction.isEnabledForContext(dialog.getActionContext(null)));

		CheckoutInfo checkoutInfo = model.getRowObject(0);
		DomainFile file = checkoutInfo.getFile();
		DomainFolder parent = file.getParent();
		assertEquals("/myFolder_1/myFolder_2", parent.getPathname());
		pressButtonByText(dialog, "Dismiss");
	}

	@Test
	public void testUndoCheckoutFromFindDialog() throws Exception {
		GTreeNode node = getNode(PROGRAM_B);
		addToVersionControl(node, true);
		node = getNode(PROGRAM_C);
		addToVersionControl(node, true);

		GTreeNode rootNode = frontEnd.getRootNode();
		selectNode(rootNode);

		DockingActionIf action = getAction("Find Checkouts");
		performFrontEndAction(action);

		FindCheckoutsDialog dialog = waitForDialogComponent(FindCheckoutsDialog.class);
		assertNotNull(dialog);

		final GTable table = findComponent(dialog.getComponent(), GTable.class);
		assertNotNull(table);
		waitForBusyTable(table);

		FindCheckoutsTableModel model = (FindCheckoutsTableModel) table.getModel();
		assertEquals(2, model.getRowCount());

		selectInTable(table, node);

		DockingActionIf undoCheckoutAction = getAction("UndoCheckOut");
		ActionContext actionContext = dialog.getActionContext(null);
		assertTrue(undoCheckoutAction.isEnabledForContext(actionContext));
		performAction(undoCheckoutAction, actionContext, true);

		waitForBusyTable(table);
		assertEquals(1, model.getRowCount());
		runSwing(() -> dialog.close());
	}

	@Test
	public void testUndoCheckoutFromFindDialogMultiSelection() throws Exception {
		GTreeNode node = getNode(PROGRAM_B);
		addToVersionControl(node, true);
		node = getNode(PROGRAM_C);
		addToVersionControl(node, true);

		GTreeNode rootNode = frontEnd.getRootNode();
		selectNode(rootNode);

		DockingActionIf action = getAction("Find Checkouts");
		performFrontEndAction(action);

		FindCheckoutsDialog dialog = waitForDialogComponent(FindCheckoutsDialog.class);

		assertNotNull(dialog);

		final GTable table = findComponent(dialog.getComponent(), GTable.class);
		assertNotNull(table);
		waitForBusyTable(table);

		FindCheckoutsTableModel model = (FindCheckoutsTableModel) table.getModel();
		assertEquals(2, model.getRowCount());

		runSwing(() -> {
			ListSelectionModel selectionModel = table.getSelectionModel();
			selectionModel.setSelectionInterval(0, 1); // both rows
		});

		DockingActionIf undoCheckoutAction = getAction("UndoCheckOut");
		ActionContext context = dialog.getActionContext(null);
		assertTrue(undoCheckoutAction.isEnabledForContext(context));
		performAction(undoCheckoutAction, context, true);

		waitForBusyTable(table);
		assertEquals(0, model.getRowCount());
		runSwing(() -> dialog.close());
	}
}
