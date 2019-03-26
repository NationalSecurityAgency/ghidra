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
package ghidra.app.plugin.core.programtree;

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.util.ArrayList;

import javax.swing.*;
import javax.swing.tree.DefaultTreeCellEditor;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import ghidra.app.services.GoToService;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.GroupPath;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitorAdapter;
import resources.ResourceManager;

public class ProgramTreePlugin1Test extends AbstractProgramTreePluginTest {

	private JTextField textField;// text field for cell editor

	@Override
	protected ProgramDB buildProgram() throws Exception {
		//Default Tree
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		builder.createMemory("test1", "0x1001000", 0x2000);

		//Main Tree
		builder.createProgramTree("Main Tree");
		builder.createFragment("Main Tree", "", ".text", "0x1001000", "0x10011ff");
		builder.createFragment("Main Tree", "", ".data", "0x1001200", "0x10013ff");
		builder.createFragment("Main Tree", "", ".rsrc", "0x1001400", "0x10015ff");
		builder.createFragment("Main Tree", "", ".imports", "0x1001600", "0x10017ff");
		builder.createFragment("Main Tree", "", ".debug_data", "0x1001800", "0x10019ff");
		builder.createFragment("Main Tree", "DLLs", "ADVAPI32.DLL", "0x1001a00", "0x1001bff");
		builder.createFragment("Main Tree", "Functions", "doStuff", "0x1001c00", "0x1001cff");
		builder.createFragment("Main Tree", "Functions", "ghidra", "0x1001d00", "0x1001dff");
		builder.createFragment("Main Tree", "Functions", "sscanf", "0x1001e00", "0x1001eff");
		builder.createFragment("Main Tree", "Not Real Blocks", "stuff", "0x1002000", "0x10020ff");

		//Tree Three
		builder.createProgramTree("Tree Three");
		builder.createFragment("Tree Three", "", ".text", "0x1001000", "0x10011ff");
		builder.createFragment("Tree Three", "", ".data", "0x1001200", "0x10013ff");
		builder.createFragment("Tree Three", "", ".rsrc", "0x1001400", "0x10015ff");
		builder.createFragment("Tree Three", "", ".imports", "0x1001600", "0x10017ff");
		builder.createFragment("Tree Three", "", ".debug_data", "0x1001800", "0x10019ff");
		builder.createFragment("Tree Three", "A.B.C.D", "test", "0x1001a00", "0x1001bff");
		builder.createFragment("Tree Three", "A.B", "testb", "0x1001d00", "0x1001dff");

		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testProgramOpened() {
		Memory mem = program.getMemory();

		AddressSetView set = getView();
		assertTrue(mem.hasSameAddresses(set));
		assertTrue(mem.hasSameAddresses(cbPlugin.getView()));
	}

	@Test
	public void testCreateFragmentFromCodeUnits() throws Exception {
		Address start = getAddr(0x0100101c);
		Address end = getAddr(0x0100101f);
		AddressSet set = new AddressSet();
		set.addRange(start, end);

		int childCount = root.getChildCount();
		addCodeUnits(root, set);
		// wait for events to get processed
		program.flushEvents();

		assertEquals(childCount + 1, root.getChildCount());
		ProgramNode node = (ProgramNode) root.getChildAt(childCount);
		assertEquals("0100101c", node.getName());

		undo();
		assertEquals(childCount, root.getChildCount());
		redo();
		assertEquals(childCount + 1, root.getChildCount());
		node = (ProgramNode) root.getChildAt(childCount);
		assertEquals("0100101c", node.getName());
	}

	@Test
	public void testCreateFragFromCUwithLabel() throws Exception {
		SymbolTable symbolTable = program.getSymbolTable();

		Address start = getAddr(0x0100101c);
		Address end = getAddr(0x0100101f);

		AddressSet set = new AddressSet();
		set.addRange(start, end);

		int transactionID = program.startTransaction("Test");
		symbolTable.createLabel(start, "MyLabel", SourceType.USER_DEFINED);
		program.endTransaction(transactionID, true);

		set.addRange(getAddr(0x01001190), getAddr(0x01001193));

		int childCount = root.getChildCount();

		addCodeUnits(root, set);

		program.flushEvents();

		assertEquals(childCount + 1, root.getChildCount());
		ProgramNode node = (ProgramNode) root.getChildAt(childCount);
		assertEquals("MyLabel", node.getName());

		ProgramFragment f = node.getFragment();
		assertTrue(f.hasSameAddresses(set));

		undo();
		assertEquals(childCount, root.getChildCount());
		redo();
		assertEquals(childCount + 1, root.getChildCount());
		node = (ProgramNode) root.getChildAt(childCount);
		assertEquals("MyLabel", node.getName());
	}

	@Test
	public void testCreateFolder() throws Exception {

		int childCount = root.getChildCount();
		setSelectionPath(root.getTreePath());

		final DockingActionIf createFolderAction = getAction("Create Folder");

		String newFolderName = tree.getNewFolderName();
		runSwing(() -> {
			createFolderAction.actionPerformed(new ActionContext());
			tree.stopEditing();
		});

		// wait for events to get processed
		program.flushEvents();

		assertEquals(childCount + 1, root.getChildCount());
		ProgramNode node = (ProgramNode) root.getChildAt(childCount);
		assertEquals(newFolderName, node.getName());

		// test undo/redo
		undo();
		assertEquals(childCount, root.getChildCount());
		redo();
		assertEquals(childCount + 1, root.getChildCount());

	}

	@Test
	public void testCreateFragment() throws Exception {
		int childCount = root.getChildCount();
		setSelectionPath(root.getTreePath());

		final DockingActionIf createFragmentAction = getAction("Create Fragment");

		String newFragName = tree.getNewFragmentName();
		runSwing(() -> {
			createFragmentAction.actionPerformed(new ActionContext());
			tree.stopEditing();
		});

		// wait for events to get processed
		program.flushEvents();

		assertEquals(childCount + 1, root.getChildCount());
		ProgramNode node = (ProgramNode) root.getChildAt(childCount);
		assertEquals(newFragName, node.getName());

		undo();
		assertEquals(childCount, root.getChildCount());
		redo();
		assertEquals(childCount + 1, root.getChildCount());
	}

	@Test
	public void testCreateFolder2() throws Exception {
		setSelectionPath(root.getTreePath());

		String newFolderName = tree.getNewFolderName();
		int transactionID = program.startTransaction("Test");
		createModule(root, newFolderName);
		program.endTransaction(transactionID, true);

		program.flushEvents();

		int childCount = root.getChildCount();

		final DockingActionIf createFolderAction = getAction("Create Folder");

		runSwing(() -> {
			createFolderAction.actionPerformed(new ActionContext());
			tree.stopEditing();
		});
		// wait for events to get processed
		program.flushEvents();

		assertEquals(childCount + 1, root.getChildCount());
		ProgramNode node = (ProgramNode) root.getChildAt(childCount);
		assertEquals(newFolderName + " (2)", node.getName());
	}

	@Test
	public void testCreateFolderDuplicate() throws Exception {
		setSelectionPath(root.getTreePath());
		final String newName = tree.getNewFolderName();

		final DockingActionIf createFolderAction = getAction("Create Folder");

		final JTextField[] newFolderTextField = new JTextField[1];
		runSwing(() -> {
			createFolderAction.actionPerformed(new ActionContext());
			program.flushEvents();
			int row = tree.getRowForPath(tree.getEditingPath());
			DefaultTreeCellEditor cellEditor = (DefaultTreeCellEditor) tree.getCellEditor();
			Container container = (Container) cellEditor.getTreeCellEditorComponent(tree,
				tree.getEditingPath().getLastPathComponent(), true, true, true, row);
			newFolderTextField[0] = (JTextField) container.getComponent(0);
			newFolderTextField[0].setText("test1");
			tree.stopEditing();
		});

		final String[] text = new String[1];
		runSwing(() -> text[0] = newFolderTextField[0].getText());

		assertEquals(newName, text[0]);
	}

	@Test
	public void testCreateFragment2() throws Exception {
		setSelectionPath(root.getTreePath());

		int transactionID = program.startTransaction("Test");
		String newFragName = tree.getNewFragmentName();
		createModule(root, newFragName);
		program.endTransaction(transactionID, true);
		program.flushEvents();

		int childCount = root.getChildCount();

		final DockingActionIf createFragmentAction = getAction("Create Fragment");

		runSwing(() -> {
			createFragmentAction.actionPerformed(new ActionContext());
			tree.stopEditing();
		});
		program.flushEvents();

		assertEquals(childCount + 1, root.getChildCount());
		ProgramNode node = (ProgramNode) root.getChildAt(childCount);
		assertEquals(newFragName + " (2)", node.getName());
	}

	@Test
	public void testCreateFragmentDuplicate() throws Exception {

		setSelectionPath(root.getTreePath());
		final String newName = tree.getNewFragmentName();

		final DockingActionIf createFragmentAction = getAction("Create Fragment");

		final JTextField[] newFragmentTextField = new JTextField[1];
		runSwing(() -> {
			createFragmentAction.actionPerformed(new ActionContext());
			program.flushEvents();
			int row = tree.getRowForPath(tree.getEditingPath());
			DefaultTreeCellEditor cellEditor = (DefaultTreeCellEditor) tree.getCellEditor();
			Container container = (Container) cellEditor.getTreeCellEditorComponent(tree,
				tree.getEditingPath().getLastPathComponent(), true, true, true, row);
			newFragmentTextField[0] = (JTextField) container.getComponent(0);
			newFragmentTextField[0].setText("test1");
			tree.stopEditing();
		});

		final String[] text = new String[1];
		runSwing(() -> text[0] = newFragmentTextField[0].getText());
		assertEquals(newName, text[0]);
	}

	@Test
	public void testDeleteFolder() throws Exception {
		setSelectionPath(root.getTreePath());

		String newFolderName = tree.getNewFolderName();
		int transactionID = program.startTransaction("Test");
		createModule(root, newFolderName);
		program.endTransaction(transactionID, true);
		// wait for events to get processed

		program.flushEvents();

		int childCount = root.getChildCount();
		ProgramNode node = (ProgramNode) root.getChildAt(childCount - 1);
		setSelectionPath(node.getTreePath());

		final DockingActionIf deleteAction = getAction("Delete");

		runSwing(() -> deleteAction.actionPerformed(new ActionContext()));

		// wait for events to get processed

		program.flushEvents();
		runSwing(() -> root.getChildCount());

		assertEquals(childCount - 1, root.getChildCount());
		undo();
		assertEquals(childCount, root.getChildCount());
		redo();
		assertEquals(childCount - 1, root.getChildCount());
	}

	@Test
	public void testDeleteNotEmpty() throws Exception {
		setSelectionPath(root.getTreePath());
		Address start = getAddr(0x0100101c);
		Address end = getAddr(0x0100101f);
		AddressSet set = new AddressSet();
		set.addRange(start, end);

		int childCount = root.getChildCount();
		addCodeUnits(root, set);
		// wait for events to get processed
		program.flushEvents();

		ProgramNode node = (ProgramNode) root.getChildAt(childCount);
		setSelectionPath(node.getTreePath());

		DockingActionIf deleteAction = getAction("Delete");
		assertTrue(!deleteAction.isEnabled());

	}

	@Test
	public void testDeleteDuplicate() throws Exception {

		final ProgramNode node = (ProgramNode) root.getChildAt(0);

		int transactionID = program.startTransaction("Test");
		ProgramModule m = createModule(root, "MyModule");
		m.add(node.getFragment());
		program.endTransaction(transactionID, true);
		program.flushEvents();
		waitForPostedSwingRunnables();
		final ProgramNode mNode = root.getChild("MyModule");
		runSwing(() -> {
			setSelectionPath(mNode.getTreePath());
			setSelectionPath(node.getTreePath());
		});

		DockingActionIf deleteAction = getAction("Delete");
		assertTrue(deleteAction.isEnabled());
	}

	@Test
	public void testRenameFragment() throws Exception {
		ProgramNode node = (ProgramNode) root.getChildAt(0);
		ProgramFragment f = node.getFragment();

		int transactionID = program.startTransaction("Test");
		ProgramModule m = createModule(root, "Module-1");
		m.add(f);
		m = m.createModule("Module-2");
		m.add(f);
		m = m.createModule("Module-3");
		m.add(f);

		program.endTransaction(transactionID, true);
		waitForPostedSwingRunnables();

		// wait for events to get processed
		program.flushEvents();

		expandRoot();

		buildNodeList();
		ProgramNode[] nodes = findNodes(f.getName());
		assertEquals(4, nodes.length);

		transactionID = program.startTransaction("Test");
		f.setName("MyFragment");
		program.endTransaction(transactionID, true);
		program.flushEvents();

		buildNodeList();
		nodes = findNodes(f.getName());
		assertEquals(4, nodes.length);
	}

	@Test
	public void testRenameFolder() throws Exception {

		int transactionID = program.startTransaction("Test");
		ProgramModule m = createModule(root, "Module-1");
		ProgramModule m2 = createModule(root, "submodule");
		m.add(m2);

		m = m.createModule("Module-2");
		m.add(m2);
		m = m.createModule("Module-3");
		m.add(m2);
		m = m.createModule("Module-4");
		m.add(m2);
		program.endTransaction(transactionID, true);
		program.flushEvents();

		expandRoot();
		buildNodeList();
		ProgramNode[] nodes = findNodes(m2.getName());
		assertEquals(5, nodes.length);

		transactionID = program.startTransaction("Test");
		m2.setName("MyModule");
		program.endTransaction(transactionID, true);

		// wait for events to get processed
		program.flushEvents();

		buildNodeList();
		nodes = findNodes(m2.getName());
		assertEquals(5, nodes.length);

		undo();
		nodes = findNodes("submodule");
		assertEquals(5, nodes.length);
		assertEquals(0, findNodes("MyModule").length);
		redo();
		assertEquals(0, findNodes("submodule").length);
		assertEquals(5, findNodes("MyModule").length);
	}

	@Test
	public void testRenameDuplicateFolder() throws Exception {
		int transactionID = program.startTransaction("Test");
		createModule(root, "printf");
		createModule(root, "submodule");
		program.endTransaction(transactionID, true);
		program.flushEvents();

		expandRoot();
		buildNodeList();

		final ProgramNode[] nodes = findNodes("submodule");
		setSelectionPath(nodes[0].getTreePath());

		final DockingActionIf action = getAction(plugin, "Rename folder/fragment");
		assertTrue(action.isEnabled());

		runSwing(() -> {
			action.actionPerformed(new ActionContext());
			int row = tree.getRowForPath(nodes[0].getTreePath());
			DefaultTreeCellEditor cellEditor = (DefaultTreeCellEditor) tree.getCellEditor();
			Container container = (Container) cellEditor.getTreeCellEditorComponent(tree, nodes[0],
				true, true, false, row);
			textField = (JTextField) container.getComponent(0);

			textField.setText("printf");
			tree.stopEditing();
		});
		waitForPostedSwingRunnables();
		assertEquals("submodule", textField.getText());
	}

	@Test
	public void testRenameDuplicateFragment() throws Exception {

		int transactionID = program.startTransaction("Test");
		ProgramModule m = createModule(root, "Module-1");
		ProgramFragment f = m.createFragment("strcpy");
		program.endTransaction(transactionID, true);
		program.flushEvents();

		expandRoot();

		buildNodeList();
		final ProgramNode[] nodes = findNodes("strcpy");
		setSelectionPath(nodes[0].getTreePath());
		final DockingActionIf action = getAction(plugin, "Rename folder/fragment");
		assertTrue(action.isEnabled());

		runSwing(() -> {
			action.actionPerformed(new ActionContext());
			int row = tree.getRowForPath(nodes[0].getTreePath());
			DefaultTreeCellEditor cellEditor = (DefaultTreeCellEditor) tree.getCellEditor();
			Container container = (Container) cellEditor.getTreeCellEditorComponent(tree, nodes[0],
				true, true, true, row);
			textField = (JTextField) container.getComponent(0);
			textField.setText(".data");
			tree.stopEditing();
		});
		waitForPostedSwingRunnables();
		assertEquals(f.getName(), textField.getText());
	}

	@Test
	public void testRenameWithCellEditor() throws Exception {
		int transactionID = program.startTransaction("Test");
		createModule(root, "Module-1");
		createModule(root, "submodule");
		program.endTransaction(transactionID, true);
		program.flushEvents();

		expandRoot();
		buildNodeList();

		final ProgramNode[] nodes = findNodes("Module-1");
		setSelectionPath(nodes[0].getTreePath());
		final DockingActionIf action = getAction(plugin, "Rename folder/fragment");
		assertTrue(action.isEnabled());

		runSwing(() -> {
			action.actionPerformed(new ActionContext());
			int row = tree.getRowForPath(nodes[0].getTreePath());
			DefaultTreeCellEditor cellEditor = (DefaultTreeCellEditor) tree.getCellEditor();
			Container container = (Container) cellEditor.getTreeCellEditorComponent(tree, nodes[0],
				true, true, false, row);
			textField = (JTextField) container.getComponent(0);

			textField.setText("My Module-1");
			tree.stopEditing();
		});

		assertEquals("My Module-1", textField.getText());
		program.flushEvents();
		assertEquals("My Module-1", nodes[0].getModule().getName());
	}

	@Test
	public void testExpandAll() throws Exception {

		ProgramNode node = (ProgramNode) root.getChildAt(0);

		final ProgramFragment f = node.getFragment();
		runSwing(() -> {
			int transactionID = program.startTransaction("Test");
			try {
				ProgramModule m = root.getModule().createModule("Module-1");

				ProgramModule m2 = root.getModule().createModule("submodule");
				m.add(m2);
				m.add(f);

				m = m.createModule("Module-2");
				m.add(m2);
				m.add(f);

				m = m.createModule("Module-3");
				m.add(m2);
				m.add(f);

				m = m.createModule("Module-4");
				m.add(m2);
				m.add(f);
				program.endTransaction(transactionID, true);
				// wait for events to get processed
			}
			catch (Exception e) {
				Assert.fail("Error modifying program: " + e);
			}
		});

		program.flushEvents();
		waitForBusyTool(tool);

		runSwing(() -> root = (ProgramNode) tree.getModel().getRoot());

		int childCount = root.getChildCount();
		assertEquals(3, childCount);

		ProgramModule m2 = program.getListing().getModule(plugin.getViewedTreeName(), "submodule");
		buildNodeList();
		ProgramNode[] nodes = findNodes(m2.getName());
		assertEquals(1, nodes.length);

		expandRoot();
		buildNodeList();
		nodes = findNodes(m2.getName());
		assertEquals(5, nodes.length);
		ArrayList<?> nodeList = tree.getNodeList();
		for (int i = 0; i < nodeList.size(); i++) {
			node = (ProgramNode) nodeList.get(i);
			if (node.getAllowsChildren() && !node.isLeaf()) {
				assertTrue(tree.isExpanded(node.getTreePath()));
			}
		}
	}

	@Test
	public void testCollapseAll() throws Exception {

		ProgramNode node = (ProgramNode) root.getChildAt(0);

		final ProgramFragment f = node.getFragment();
		runSwing(() -> {
			int transactionID = program.startTransaction("Test");
			try {
				ProgramModule m = root.getModule().createModule("Module-1");

				ProgramModule m2 = root.getModule().createModule("submodule");
				m.add(m2);
				m.add(f);

				m = m.createModule("Module-2");
				m.add(m2);
				m.add(f);

				m = m.createModule("Module-3");
				m.add(m2);
				m.add(f);

				m = m.createModule("Module-4");
				m.add(m2);
				m.add(f);
				program.endTransaction(transactionID, true);
				// wait for events to get processed
			}
			catch (Exception e) {
				Assert.fail("Error modifying program: " + e);
			}
		});

		runSwing(() -> root = (ProgramNode) tree.getModel().getRoot());
		collapseNode(root);
		buildNodeList();
		ArrayList<?> nodeList = tree.getNodeList();
		for (int i = 0; i < nodeList.size(); i++) {
			node = (ProgramNode) nodeList.get(i);
			if (node.getAllowsChildren() && !node.isLeaf()) {
				assertTrue(!tree.isExpanded(node.getTreePath()));
			}
		}
	}

	@Test
	public void testChangeViews() {
		setTreeView("Main Tree");
		ProgramNode debugNode = root.getChild(".debug_data");
		ProgramNode nrbNode = root.getChild("Not Real Blocks");
		setViewPaths(new TreePath[] { debugNode.getTreePath(), nrbNode.getTreePath() });
		AddressSet set1 = new AddressSet();
		set1.add(debugNode.getFragment());
		set1.add(nrbNode.getModule().getAddressSet());
		AddressSet view = getView();
		assertTrue(set1.hasSameAddresses(view));
		assertTrue(view.hasSameAddresses(cbPlugin.getView()));
		assertTrue(view.hasSameAddresses(viewMgrService.getCurrentView()));

		setTreeView("Tree Three");
		ProgramNode textNode = root.getChild(".text");
		ProgramNode aNode = root.getChild("A");
		visitNode(aNode);
		ProgramNode bNode = aNode.getChild("B");
		visitNode(bNode);
		ProgramNode cNode = bNode.getChild("C");
		setViewPaths(new TreePath[] { cNode.getTreePath(), textNode.getTreePath() });
		AddressSet set2 = new AddressSet();
		set2.add(textNode.getFragment());
		set2.add(cNode.getModule().getAddressSet());
		view = getView();
		assertTrue(set2.hasSameAddresses(view));
		assertTrue(view.hasSameAddresses(cbPlugin.getView()));
		assertTrue(view.hasSameAddresses(viewMgrService.getCurrentView()));

		setTreeView("Main Tree");
		view = getView();
		assertTrue(set1.hasSameAddresses(view));
		assertPluginViewAppliedToTool();
		waitForSwing();
	}

	@Test
	public void testGoToUsingViewManager() {
		setTreeView("Main Tree");

		//clears the view
		clearView();

		ProgramNode dllsNode = root.getChild("DLLs");
		expandNode(dllsNode);
		ProgramNode advNode = dllsNode.getChild("ADVAPI32.DLL");

		viewMgrService.addToView(new ProgramLocation(program, getAddr(0x01001a00)));

		assertTrue(getView().hasSameAddresses(advNode.getFragment()));
		assertPluginViewAppliedToTool();

		assertTrue(advNode.isInView());
	}

	@Test
	public void testGoToUsingGoToService() {
		setTreeView("Main Tree");
		ProgramNode funcNode = root.getChild("Functions");
		visitNode(funcNode);
		ProgramNode sscanfNode = funcNode.getChild("sscanf");
		setViewPaths(new TreePath[] { sscanfNode.getTreePath() });

		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(new ProgramLocation(program, sscanfNode.getFragment().getMinAddress()));
		assertPluginViewAppliedToTool();
	}

	@Test
	public void testGoToViewIcon() {
		setTreeView("Main Tree");

		actionMgr.setProgramTreeView("Main Tree", tree);

		clearView();

		runSwing(() -> viewMgrService.addToView(new ProgramLocation(program, getAddr(0x01001000))));

		ProgramFragment f = program.getListing().getFragment("Main Tree", getAddr(0x01001000));
		ProgramNode[] nodes = findNodes(f.getName());
		assertTrue(nodes.length > 0);

		int row = getRowForPath(nodes[0].getTreePath());
		Component comp = getCellRendererComponentForLeaf(nodes[0], row);
		assertEquals(ResourceManager.loadImage(DnDTreeCellRenderer.VIEWED_FRAGMENT),
			((JLabel) comp).getIcon());
	}

	@Test
	public void testRemoveView() {
		setTreeView("Main Tree");

		ProgramNode node = (ProgramNode) root.getChildAt(0);
		ProgramNode n2 = (ProgramNode) root.getChildAt(1);
		setSelectionPaths(new TreePath[] { node.getTreePath() });
		// replace view so we can remove each node
		setViewPaths(getSelectionPaths());

		DockingActionIf removeAction = getAction("Remove");
		assertTrue(removeAction.isEnabled());

		performAction(removeAction, true);

		AddressSet set = new AddressSet();
		set.add(node.getFragment());
		assertTrue(!getView().contains(set));

		setSelectionPaths(new TreePath[] { n2.getTreePath() });

		set = new AddressSet();
		set.add(n2.getFragment());
		assertTrue(!getView().contains(set));

		assertPluginViewAppliedToTool();
	}

	@Test
	public void testRemoveViewIcon() {
		setTreeView("Main Tree");

		ProgramNode node = (ProgramNode) root.getChildAt(0);
		ProgramNode n2 = (ProgramNode) root.getChildAt(1);
		setSelectionPaths(new TreePath[] { node.getTreePath(), n2.getTreePath() });

		setViewPaths(getSelectionPaths());

		int row = getRowForPath(node.getTreePath());
		Component comp = getCellRendererComponentForLeaf(node, row);
		assertEquals(ResourceManager.loadImage(DnDTreeCellRenderer.VIEWED_FRAGMENT),
			((JLabel) comp).getIcon());

		row = getRowForPath(n2.getTreePath());
		comp = getCellRendererComponentForLeaf(n2, row);
		assertEquals(ResourceManager.loadImage(DnDTreeCellRenderer.VIEWED_FRAGMENT),
			((JLabel) comp).getIcon());

		setSelectionPaths(new TreePath[] { n2.getTreePath() });
		setViewPaths(getSelectionPaths());

		row = getRowForPath(n2.getTreePath());
		comp = getCellRendererComponentForLeaf(n2, row);
		assertEquals(ResourceManager.loadImage(DnDTreeCellRenderer.VIEWED_FRAGMENT),
			((JLabel) comp).getIcon());

		row = getRowForPath(node.getTreePath());
		getCellRendererComponentForLeaf(node, row);
		assertEquals(ResourceManager.loadImage(DnDTreeCellRenderer.FRAGMENT),
			((JLabel) comp).getIcon());

	}

	@Test
	public void testRemoveFolderView() {
		setTreeView("Main Tree");

		ProgramNode node = root.getChild("Functions");

		if (node == null) {
			Assert.fail("Expected a Functions module!");
		}
		setSelectionPaths(new TreePath[] { node.getTreePath() });

		DockingActionIf replaceAction = getAction("Replace");
		performAction(replaceAction, true);

		assertTrue(getView().hasSameAddresses(node.getModule().getAddressSet()));

		DockingActionIf removeAction = getAction("Remove");
		performAction(removeAction, true);

		assertTrue(getView().isEmpty());
		assertTrue(cbPlugin.getView().isEmpty());
	}

	@Test
	public void testRemoveFolderViewIcon() {
		setTreeView("Main Tree");

		ProgramNode node = root.getChild("Functions");

		if (node == null) {
			Assert.fail("Expected a Functions module!");
		}

		tree.addSelectionPaths(new TreePath[] { node.getTreePath() });
		setViewPaths(getSelectionPaths());

		final ProgramNode finalNode = node;
		runSwing(() -> tree.removeFromView(finalNode.getTreePath()));

		int row = getRowForPath(node.getTreePath());
		Component comp = tree.getCellRenderer().getTreeCellRendererComponent(tree, node, true,
			false, true, row, false);
		assertEquals(ResourceManager.loadImage(DnDTreeCellRenderer.CLOSED_FOLDER),
			((JLabel) comp).getIcon());
	}

	@Test
	public void testRemoveMultiSelection() {
		setTreeView("Main Tree");

		ProgramNode node0 = (ProgramNode) root.getChildAt(0);
		ProgramNode node1 = (ProgramNode) root.getChildAt(1);
		ProgramNode node2 = (ProgramNode) root.getChildAt(2);

		setSelectionPaths(
			new TreePath[] { node0.getTreePath(), node1.getTreePath(), node2.getTreePath() });
		setViewPaths(getSelectionPaths());

		// now remove two of these from the view
		setSelectionPaths(new TreePath[] { node0.getTreePath(), node2.getTreePath() });

		DockingActionIf removeAction = getAction("Remove");
		performAction(removeAction, true);

		AddressSet set = new AddressSet();
		set.add(node0.getFragment());
		set.add(node2.getFragment());
		assertTrue(!getView().contains(set));
		assertTrue(getView().contains(node1.getFragment()));
		assertTrue(getView().hasSameAddresses(cbPlugin.getView()));

	}

	@Test
	public void testRemoveDescendantsInView() throws Exception {
		setTreeView("Main Tree");

		// clear the view
		clearView();

		// select two of the fragments and add them to the view
		ProgramNode[] nodes = findNodes("Functions");
		assertEquals(1, nodes.length);

		visitNode(nodes[0]);
		ProgramNode child1 = (ProgramNode) nodes[0].getChildAt(0);
		ProgramNode child3 = (ProgramNode) nodes[0].getChildAt(2);

		ProgramNode dllNode = (ProgramNode) root.getChildAt(6);
		visitNode(dllNode);
		buildNodeList();

		//select a fragment in another folder and add to view
		ProgramNode[] othernodes = findNodes("Not Real Blocks");
		assertEquals(1, othernodes.length);
		visitNode(othernodes[0]);
		ProgramNode otherchild1 = (ProgramNode) othernodes[0].getFirstChild();

		setViewPaths(new TreePath[] { child1.getTreePath(), child3.getTreePath(),
			otherchild1.getTreePath() });
		AddressSet set = new AddressSet();
		set.add(child1.getFragment());
		set.add(child3.getFragment());
		set.add(otherchild1.getFragment());

		assertTrue(getView().hasSameAddresses(set));

		// collapse the test folder and remove the view
		collapseNode(nodes[0]);
		setSelectionPath(nodes[0].getTreePath());

		DockingActionIf removeAction = getAction("Remove");
		performAction(removeAction, true);

		// verify that all the descendants of the folder are removed from the view
		assertTrue(!getView().contains(child1.getFragment()));
		assertTrue(!getView().contains(child3.getFragment()));

		assertTrue(getView().contains(otherchild1.getFragment()));
		assertPluginViewAppliedToTool();
	}

	@Test
	public void testReplaceViewFragment() {

		setTreeView("Main Tree");

		ProgramNode node = (ProgramNode) root.getChildAt(6);
		visitNode(node);
		ProgramNode child = (ProgramNode) node.getChildAt(0);
		setSelectionPath(child.getTreePath());

		DockingActionIf replaceAction = getAction("Replace");
		performAction(replaceAction, true);

		assertTrue(getView().hasSameAddresses(child.getFragment()));
		assertTrue(getView().hasSameAddresses(cbPlugin.getView()));
		assertTrue(getView().hasSameAddresses(viewMgrService.getCurrentView()));

		int row = getRowForPath(child.getTreePath());
		Component comp = tree.getCellRenderer().getTreeCellRendererComponent(tree, child, true,
			false, true, row, false);
		assertEquals(ResourceManager.loadImage(DnDTreeCellRenderer.VIEWED_FRAGMENT),
			((JLabel) comp).getIcon());

	}

	@Test
	public void testReplaceViewFolder() {
		setTreeView("Main Tree");

		ProgramNode node = (ProgramNode) root.getChildAt(6);
		setSelectionPath(node.getTreePath());

		DockingActionIf replaceAction = getAction("Replace");
		assertTrue(replaceAction.isEnabled());

		performAction(replaceAction, new ActionContext(), true);

		assertTrue(plugin.getView().hasSameAddresses(node.getModule().getAddressSet()));
		assertPluginViewAppliedToTool();
	}

	@Test
	public void testReplaceViewMultiSelection() {
		setTreeView("Main Tree");

		ProgramNode textNode = (ProgramNode) root.getChildAt(1);
		ProgramNode dataNode = (ProgramNode) root.getChildAt(2);
		setViewPaths(new TreePath[] { textNode.getTreePath(), dataNode.getTreePath() });

		// select DLLs folder
		ProgramNode dllsNode = (ProgramNode) root.getChildAt(6);
		visitNode(dllsNode);

		ProgramNode functionsNode = (ProgramNode) root.getChildAt(7);
		visitNode(functionsNode);
		ProgramNode sscanfNode = (ProgramNode) functionsNode.getChildAt(2);

		// set a folder not in the view and a fragment that is not a
		// descendant of that folder, and not in the view
		setSelectionPaths(new TreePath[] { dllsNode.getTreePath(), sscanfNode.getTreePath() });

		DockingActionIf replaceAction = getAction("Replace");
		performAction(replaceAction, true);

		AddressSet set = new AddressSet();
		set.add(dllsNode.getModule().getAddressSet());
		set.add(sscanfNode.getFragment());
		assertTrue(plugin.getView().hasSameAddresses(set));
		assertPluginViewAppliedToTool();
	}

	@Test
	public void testDoubleClickOnFragment() {

		setTreeView("Main Tree");
		Rectangle rect = tree.getRowBounds(2);
		clickMouse(tree, MouseEvent.BUTTON1, rect.x, rect.y, 2, 0);

		ProgramNode node = (ProgramNode) tree.getPathForRow(2).getLastPathComponent();
		ProgramFragment fragment = node.getFragment();
		Address address = fragment.getMinAddress();
		assertEquals(address, cbPlugin.getCurrentAddress());
	}

	@Test
	public void testDoubleClick2() {
		setTreeView("Main Tree");
		ProgramNode node = root.getChild(".data");
		TreePath[] paths = new TreePath[] { node.getTreePath() };
		setViewPaths(paths);

		int row = getRowForPath(paths[0]);

		Rectangle rect = tree.getRowBounds(row);
		clickMouse(tree, MouseEvent.BUTTON1, rect.x, rect.y, 2, 0);
		node = (ProgramNode) tree.getPathForRow(3).getLastPathComponent();
		ProgramFragment fragment = node.getFragment();
		Address address = fragment.getMinAddress();
		assertEquals(address, cbPlugin.getCurrentAddress());
	}

	@Test
	public void testMergeWithParent() throws Exception {
		setTreeView("Main Tree");
		expandRoot();

		ProgramNode[] nodes = findNodes("Test");
		int origEvCount = nodes[0].getChildCount();
		ProgramNode dllsNode = (ProgramNode) nodes[0].getChildAt(6);
		int dllsCount = dllsNode.getChildCount();

		setSelectionPath(dllsNode.getTreePath());

		DockingActionIf mergeAction = getAction("Merge");
		performAction(mergeAction, true);

		program.flushEvents();

		int count = nodes[0].getChildCount();
		assertEquals(origEvCount - 1 + dllsCount, count);

		for (int i = 0; i < count; i++) {
			assertTrue(!((ProgramNode) nodes[0].getChildAt(i)).getName().equals("DLLs"));
		}
		assertNull(program.getListing().getModule("Main Tree", "DLLs"));

		undo();
		nodes = findNodes("Test");
		assertEquals(origEvCount, nodes[0].getChildCount());
		assertNotNull(program.getListing().getModule("Main Tree", "DLLs"));
		redo();
		nodes = findNodes("Test");
		assertEquals(origEvCount - 1 + dllsCount, nodes[0].getChildCount());

	}

	//tests merging more than one selected folder with their parents
	@Test
	public void testMergeMultiSelection() throws Exception {
		setTreeView("Tree Three");
		expandRoot();

		ProgramNode[] bNodes = findNodes("B");
		ProgramNode[] dNodes = findNodes("D");

		setSelectionPaths(new TreePath[] { dNodes[0].getTreePath(), bNodes[0].getTreePath() });

		final DockingActionIf mergeAction = getAction("Merge");

		runSwing(() -> mergeAction.actionPerformed(new ActionContext()));

		program.flushEvents();

		assertEquals(7, root.getChildCount());

	}

	@Test
	public void testMergeEnabled() {

		setTreeView("Main Tree");
		expandRoot();

		ProgramNode node = (ProgramNode) root.getChildAt(2);
		setSelectionPath(node.getTreePath());

		DockingActionIf mergeAction = getAction("Merge");
		assertTrue(!mergeAction.isEnabled());

		ProgramNode fnode = (ProgramNode) root.getChildAt(6);
		setSelectionPaths(new TreePath[] { node.getTreePath(), fnode.getTreePath() });

		DockingActionIf mergeAction2 = getAction("Merge");
		assertTrue(mergeAction2.isEnabled());
	}

	@Test
	public void testSaveState() {

		setTreeView("Main Tree");
		expandRoot();
		final ProgramNode node = (ProgramNode) root.getChildAt(2);
		final ProgramNode fnode = (ProgramNode) root.getChildAt(6);
		setViewPaths(new TreePath[] { node.getTreePath(), fnode.getTreePath() });

		runSwing(() -> env.saveRestoreToolState());

		AddressSet set = new AddressSet();
		set.add(node.getFragment());
		set.add(fnode.getModule().getAddressSet());
		assertTrue(getView().hasSameAddresses(set));
		assertPluginViewAppliedToTool();
	}

	@Test
	public void testSetGroupSelection() {
		setTreeView("Main Tree");
		expandRoot();
		GroupPath[] gps = new GroupPath[1];
		gps[0] = new GroupPath(new String[] { root.getName(), "DLLs" });
		plugin.setGroupSelection(gps);

		TreePath[] paths = getSelectionPaths();
		assertNotNull(paths);
		assertEquals(1, paths.length);
		assertEquals("DLLs", ((ProgramNode) paths[0].getLastPathComponent()).getName());
	}

	@Test
	public void testTreeProviderCount() {

		assertEquals(3, plugin.getNumberOfViews());

		String[] treeNames = program.getListing().getTreeNames();
		for (String treeName : treeNames) {
			assertNotNull(plugin.getTree(treeName));
		}
	}

	@Test
	public void testGetChild() {
		setTreeView("Main Tree");
		ProgramNode node = root.getChild("Functions");
		assertNotNull(node);
		assertEquals("Functions", node.getName());
	}

	@Test
	public void testMemoryBlocksAddedRemoved() throws Exception {
		int transactionID = program.startTransaction("Test");
		Memory mem = program.getMemory();
		mem.createInitializedBlock(".test", getAddr(0x30), 0x12, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		program.endTransaction(transactionID, true);
		program.flushEvents();

		setTreeView("Main Tree");
		expandRoot();

		ProgramNode[] nodes = findNodes(".test");
		assertEquals(1, nodes.length);

		transactionID = program.startTransaction("test");
		mem.createInitializedBlock(".test.exp", getAddr(0x42), 4, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		program.endTransaction(transactionID, true);
		program.flushEvents();

		nodes = findNodes(".test.exp");
		assertEquals(1, nodes.length);

		undo();
		nodes = findNodes(".test.exp");
		assertEquals(0, nodes.length);
		redo();
		nodes = findNodes(".test.exp");
		assertEquals(1, nodes.length);

		transactionID = program.startTransaction("test");
		MemoryBlock block = mem.getBlock(getAddr(0x30));
		mem.removeBlock(block, TaskMonitorAdapter.DUMMY_MONITOR);
		block = mem.getBlock(getAddr(0x42));
		mem.removeBlock(block, TaskMonitorAdapter.DUMMY_MONITOR);

		program.endTransaction(transactionID, true);
		program.flushEvents();

		nodes = findNodes(".test");
		assertEquals(0, nodes.length);

		nodes = findNodes(".test.exp");
		assertEquals(0, nodes.length);

		// test undo/redo
		undo();
		nodes = findNodes(".test");
		assertEquals(1, nodes.length);
		nodes = findNodes(".test.exp");
		assertEquals(1, nodes.length);

		redo();

		nodes = findNodes(".test");
		assertEquals(0, nodes.length);
		nodes = findNodes(".test.exp");
		assertEquals(0, nodes.length);

	}

	@Test
	public void testToolTip() throws Exception {
		setTreeView("Main Tree");
		ProgramNode node = root.getChild(".data");
		ProgramFragment f = node.getFragment();
		AddressRange range = f.getFirstRange();
		assertEquals(range.toString(), tree.getToolTipText(node));
	}

	@Test
	public void testShowTreeList() throws Exception {
		final DockingActionIf showAction = getAction(plugin, "Open Tree View");
		assertTrue(showAction.isEnabled());
		String[] treeNames = program.getListing().getTreeNames();

		performAction(showAction, true);

		JPopupMenu menu = plugin.getPopupMenu();
		assertNotNull(menu);
		Component[] comps = menu.getComponents();

		final ArrayList<Component> list = new ArrayList<>();
		for (Component comp : comps) {
			if (comp instanceof JMenuItem) {
				list.add(comp);
			}
		}

		assertEquals(treeNames.length, list.size());
		for (int i = 0; i < treeNames.length; i++) {
			JMenuItem item = (JMenuItem) list.get(i);
			assertEquals(treeNames[i], item.getText());
		}
		for (int i = 0; i < list.size(); i++) {
			JMenuItem item = (JMenuItem) list.get(i);
			final ActionListener[] listeners = item.getActionListeners();
			runSwing(() -> listeners[0].actionPerformed(null));
			ViewProviderService vps = plugin.getCurrentProvider();
			assertEquals(treeNames[i], vps.getViewName());
			assertEquals(vps, viewMgrService.getCurrentViewProvider());
		}
	}

//==================================================================================================
// Private Methods
//==================================================================================================
	private void assertPluginViewAppliedToTool() {
		AddressSet pluginAddrs = plugin.getView();
		assertTrue(pluginAddrs.hasSameAddresses(cbPlugin.getView()));
		assertTrue(pluginAddrs.hasSameAddresses(viewMgrService.getCurrentView()));
	}

	private DockingActionIf getAction(String name) {
		for (DockingActionIf action : actions) {
			if (action.getName().startsWith(name)) {
				return action;
			}
		}
		Assert.fail("Could not find action: " + name);
		return null;// cannot get here
	}

	private void clearView() {
		setViewPaths(new TreePath[0]);
	}
}
