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
import java.util.List;

import javax.swing.*;
import javax.swing.tree.DefaultTreeCellEditor;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.action.DockingActionIf;
import generic.theme.GIcon;
import ghidra.app.services.GoToService;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.GroupPath;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

public class ProgramTreePlugin1Test extends AbstractProgramTreePluginTest {

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

		tx(program, () -> {
			symbolTable.createLabel(start, "MyLabel", SourceType.USER_DEFINED);
		});

		set.addRange(getAddr(0x01001190), getAddr(0x01001193));

		int childCount = root.getChildCount();
		addCodeUnits(root, set);
		waitFor(() -> root.getChildCount() == childCount + 1);

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
		setSelectionPath(root);

		DockingActionIf createFolderAction = getAction("Create Folder");

		String newFolderName = tree.getNewFolderName();
		performAction(createFolderAction);
		commitEdit();
		waitForProgram(program);

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
		setSelectionPath(root);

		DockingActionIf createFragmentAction = getAction("Create Fragment");

		String newFragName = tree.getNewFragmentName();
		performAction(createFragmentAction);
		commitEdit();
		waitForProgram(program);

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
		setSelectionPath(root);

		String newFolderName = tree.getNewFolderName();
		tx(program, () -> {
			createModule(root, newFolderName);
		});

		int childCount = root.getChildCount();
		DockingActionIf createFolderAction = getAction("Create Folder");
		performAction(createFolderAction);
		commitEdit();
		waitForProgram(program);

		assertEquals(childCount + 1, root.getChildCount());
		ProgramNode node = (ProgramNode) root.getChildAt(childCount);
		assertEquals(newFolderName + " (2)", node.getName());
	}

	@Test
	public void testCreateFolderDuplicate() throws Exception {
		setSelectionPath(root);
		String newName = tree.getNewFolderName();

		DockingActionIf createFolderAction = getAction("Create Folder");
		performAction(createFolderAction, getActionContext(), true);
		waitForProgram(program);

		setEditorText("test1");

		String currentText = setEditorText("test1");
		assertEquals(newName, currentText);
	}

	@Test
	public void testCreateFragment2() throws Exception {
		setSelectionPath(root);

		String newFragName = tree.getNewFragmentName();
		tx(program, () -> {
			createModule(root, newFragName);
		});

		int childCount = root.getChildCount();

		DockingActionIf createFragmentAction = getAction("Create Fragment");
		performAction(createFragmentAction, getActionContext(), true);
		commitEdit();

		waitFor(() -> root.getChildCount() == childCount + 1);
		ProgramNode node = (ProgramNode) root.getChildAt(childCount);
		assertEquals(newFragName + " (2)", node.getName());
	}

	@Test
	public void testCreateFragmentDuplicate() throws Exception {

		setSelectionPath(root);
		String newName = tree.getNewFragmentName();

		DockingActionIf createFragmentAction = getAction("Create Fragment");
		performAction(createFragmentAction, getActionContext(), true);
		waitForProgram(program);

		String currentText = setEditorText("test1");
		assertEquals(newName, currentText);
	}

	@Test
	public void testDeleteFolder() throws Exception {
		setSelectionPath(root);

		String newFolderName = tree.getNewFolderName();
		tx(program, () -> {
			createModule(root, newFolderName);
		});

		int childCount = root.getChildCount();
		ProgramNode node = (ProgramNode) root.getChildAt(childCount - 1);
		setSelectionPath(node);

		DockingActionIf deleteAction = getAction("Delete");
		performAction(deleteAction, getActionContext(), true);
		waitForProgram(program);

		assertEquals(childCount - 1, root.getChildCount());
		undo();
		assertEquals(childCount, root.getChildCount());
		redo();
		assertEquals(childCount - 1, root.getChildCount());
	}

	@Test
	public void testDeleteNotEmpty() throws Exception {
		setSelectionPath(root);
		Address start = getAddr(0x0100101c);
		Address end = getAddr(0x0100101f);
		AddressSet set = new AddressSet();
		set.addRange(start, end);

		int childCount = root.getChildCount();
		addCodeUnits(root, set);
		waitFor(() -> root.getChildCount() == childCount + 1);

		ProgramNode node = (ProgramNode) root.getChildAt(childCount);
		setSelectionPath(node);

		DockingActionIf deleteAction = getAction("Delete");
		assertFalse(deleteAction.isEnabledForContext(getActionContext()));
	}

	@Test
	public void testDeleteDuplicate() throws Exception {

		ProgramNode node = (ProgramNode) root.getChildAt(0);

		tx(program, () -> {
			ProgramModule m = createModule(root, "MyModule");
			m.add(node.getFragment());
		});

		ProgramNode mNode = root.getChild("MyModule");
		setSelectionPaths(mNode, node);

		DockingActionIf deleteAction = getAction("Delete");
		assertTrue(deleteAction.isEnabledForContext(getActionContext()));
	}

	@Test
	public void testRenameFragment() throws Exception {
		ProgramNode node = (ProgramNode) root.getChildAt(0);
		ProgramFragment f = node.getFragment();

		tx(program, () -> {
			ProgramModule m = createModule(root, "Module-1");
			m.add(f);
			m = m.createModule("Module-2");
			m.add(f);
			m = m.createModule("Module-3");
			m.add(f);

		});

		expandRoot();

		buildNodeList();
		ProgramNode[] nodes = findNodes(f.getName());
		assertEquals(4, nodes.length);

		tx(program, () -> {
			f.setName("MyFragment");
		});

		buildNodeList();
		nodes = findNodes(f.getName());
		assertEquals(4, nodes.length);
	}

	@Test
	public void testRenameFolder() throws Exception {

		tx(program, () -> {
			ProgramModule m1 = createModule(root, "Module-1");
			ProgramModule submodule = createModule(root, "submodule");
			m1.add(submodule);

			ProgramModule m2 = m1.createModule("Module-2");
			m2.add(submodule);
			ProgramModule m3 = m2.createModule("Module-3");
			m3.add(submodule);
			ProgramModule m4 = m3.createModule("Module-4");
			m4.add(submodule);
		});

		expandRoot();
		buildNodeList();
		ProgramNode[] nodes = findNodes("submodule");
		assertEquals(5, nodes.length);

		String newName = "MyModule";
		tx(program, () -> {
			ProgramModule m = getModule(root, "submodule");
			m.setName("MyModule");
		});

		buildNodeList();
		nodes = findNodes(newName);
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
		tx(program, () -> {
			createModule(root, "printf");
			createModule(root, "submodule");
		});

		expandRoot();
		buildNodeList();

		ProgramNode[] nodes = findNodes("submodule");
		setSelectionPath(nodes[0]);

		DockingActionIf action = getAction(plugin, "Rename folder/fragment");
		assertTrue(action.isEnabledForContext(getActionContext()));
		performAction(action);
		String currentText = setEditorText("printf");
		assertEquals("submodule", currentText);
	}

	@Test
	public void testRenameDuplicateFragment() throws Exception {

		tx(program, () -> {
			ProgramModule m = createModule(root, "Module-1");
			m.createFragment("strcpy");
		});

		expandRoot();

		buildNodeList();
		ProgramNode[] nodes = findNodes("strcpy");
		setSelectionPath(nodes[0]);
		DockingActionIf action = getAction(plugin, "Rename folder/fragment");
		assertTrue(action.isEnabledForContext(getActionContext()));
		performAction(action);
		String currentText = setEditorText(".data");

		ProgramModule module = getModule(root, "Module-1");
		ProgramFragment f = getFragment(module, ".data");
		assertEquals(f.getName(), currentText);
	}

	@Test
	public void testRenameWithCellEditor() throws Exception {
		tx(program, () -> {
			createModule(root, "Module-1");
			createModule(root, "submodule");
		});

		expandRoot();
		buildNodeList();

		ProgramNode[] nodes = findNodes("Module-1");
		setSelectionPath(nodes[0]);
		DockingActionIf action = getAction(plugin, "Rename folder/fragment");
		assertTrue(action.isEnabledForContext(getActionContext()));
		performAction(action);
		String currentText = setEditorText("My Module-1");
		assertEquals("My Module-1", currentText);
		waitForProgram(program);
		assertEquals("My Module-1", nodes[0].getModule().getName());
	}

	@Test
	public void testExpandAll() throws Exception {

		ProgramNode node = (ProgramNode) root.getChildAt(0);

		ProgramFragment f = node.getFragment();

		tx(program, () -> {
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
		});

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
		List<?> nodeList = tree.getNodeList();
		for (Object element : nodeList) {
			node = (ProgramNode) element;
			if (node.getAllowsChildren() && !node.isLeaf()) {
				assertTrue(tree.isExpanded(node.getTreePath()));
			}
		}
	}

	@Test
	public void testCollapseAll() throws Exception {

		ProgramNode node = (ProgramNode) root.getChildAt(0);

		ProgramFragment f = node.getFragment();
		tx(program, () -> {
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
		});

		runSwing(() -> root = (ProgramNode) tree.getModel().getRoot());
		collapseNode(root);
		buildNodeList();
		List<?> nodeList = tree.getNodeList();
		for (Object element : nodeList) {
			node = (ProgramNode) element;
			if (node.getAllowsChildren() && !node.isLeaf()) {
				assertFalse(tree.isExpanded(node.getTreePath()));
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
		setViewPaths(cNode, textNode);
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
		setViewPaths(sscanfNode);

		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(new ProgramLocation(program, sscanfNode.getFragment().getMinAddress()));
		assertPluginViewAppliedToTool();
	}

	@Test
	public void testGoToViewIcon() {
		setTreeView("Main Tree");

		runSwing(() -> actionMgr.setProgramTreeView("Main Tree", tree));

		clearView();

		runSwing(() -> viewMgrService.addToView(new ProgramLocation(program, getAddr(0x01001000))));

		ProgramFragment f = program.getListing().getFragment("Main Tree", getAddr(0x01001000));
		ProgramNode[] nodes = findNodes(f.getName());
		assertTrue(nodes.length > 0);

		int row = getRowForPath(nodes[0].getTreePath());
		Component comp = getCellRendererComponentForLeaf(nodes[0], row);
		assertEquals(new GIcon(DnDTreeCellRenderer.VIEWED_FRAGMENT),
			((JLabel) comp).getIcon());
	}

	@Test
	public void testRemoveView() {
		setTreeView("Main Tree");

		ProgramNode node = (ProgramNode) root.getChildAt(0);
		ProgramNode n2 = (ProgramNode) root.getChildAt(1);
		setSelectionPaths(node);
		// replace view so we can remove each node
		setViewPaths(getSelectionPaths());

		DockingActionIf removeAction = getAction("Remove");
		assertTrue(removeAction.isEnabledForContext(getActionContext()));
		performAction(removeAction, getActionContext(), true);

		AddressSet set = new AddressSet();
		set.add(node.getFragment());
		assertFalse(getView().contains(set));

		setSelectionPaths(new TreePath[] { n2.getTreePath() });

		set = new AddressSet();
		set.add(n2.getFragment());
		assertFalse(getView().contains(set));

		assertPluginViewAppliedToTool();
	}

	@Test
	public void testRemoveViewIcon() {
		setTreeView("Main Tree");

		ProgramNode node = (ProgramNode) root.getChildAt(0);
		ProgramNode n2 = (ProgramNode) root.getChildAt(1);
		setSelectionPaths(node, n2);

		setViewPaths(getSelectionPaths());

		int row = getRowForPath(node.getTreePath());
		Component comp = getCellRendererComponentForLeaf(node, row);
		assertEquals(new GIcon(DnDTreeCellRenderer.VIEWED_FRAGMENT),
			((JLabel) comp).getIcon());

		row = getRowForPath(n2.getTreePath());
		comp = getCellRendererComponentForLeaf(n2, row);
		assertEquals(new GIcon(DnDTreeCellRenderer.VIEWED_FRAGMENT),
			((JLabel) comp).getIcon());

		setSelectionPaths(new TreePath[] { n2.getTreePath() });
		setViewPaths(getSelectionPaths());

		row = getRowForPath(n2.getTreePath());
		comp = getCellRendererComponentForLeaf(n2, row);
		assertEquals(new GIcon(DnDTreeCellRenderer.VIEWED_FRAGMENT),
			((JLabel) comp).getIcon());

		row = getRowForPath(node.getTreePath());
		getCellRendererComponentForLeaf(node, row);
		assertEquals(new GIcon(DnDTreeCellRenderer.FRAGMENT),
			((JLabel) comp).getIcon());

	}

	@Test
	public void testRemoveFolderView() {
		setTreeView("Main Tree");

		ProgramNode node = root.getChild("Functions");

		if (node == null) {
			Assert.fail("Expected a Functions module!");
		}
		setSelectionPaths(node);

		DockingActionIf replaceAction = getAction("Replace");
		performAction(replaceAction);

		assertTrue(getView().hasSameAddresses(node.getModule().getAddressSet()));

		DockingActionIf removeAction = getAction("Remove");
		performAction(removeAction);

		assertTrue(getView().isEmpty());
		assertTrue(cbPlugin.getView().isEmpty());
	}

	@Test
	public void testRemoveFolderViewIcon() {
		setTreeView("Main Tree");

		ProgramNode node = root.getChild("Functions");
		assertNotNull("Expected a Functions module!", node);
		setSelectionPath(node);
		setViewPaths(getSelectionPaths());

		ProgramNode finalNode = node;
		runSwing(() -> tree.removeFromView(finalNode.getTreePath()));

		int row = getRowForPath(node.getTreePath());
		Component comp = tree.getCellRenderer()
				.getTreeCellRendererComponent(tree, node, true, false, true, row, false);
		assertEquals(new GIcon(DnDTreeCellRenderer.CLOSED_FOLDER),
			((JLabel) comp).getIcon());
	}

	@Test
	public void testRemoveMultiSelection() {
		setTreeView("Main Tree");

		ProgramNode node0 = (ProgramNode) root.getChildAt(0);
		ProgramNode node1 = (ProgramNode) root.getChildAt(1);
		ProgramNode node2 = (ProgramNode) root.getChildAt(2);

		setSelectionPaths(node0, node1, node2);
		setViewPaths(getSelectionPaths());

		// now remove two of these from the view
		setSelectionPaths(node0, node2);

		DockingActionIf removeAction = getAction("Remove");
		performAction(removeAction);

		AddressSet set = new AddressSet();
		set.add(node0.getFragment());
		set.add(node2.getFragment());
		assertFalse(getView().contains(set));
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

		setViewPaths(child1, child3, otherchild1);
		AddressSet set = new AddressSet();
		set.add(child1.getFragment());
		set.add(child3.getFragment());
		set.add(otherchild1.getFragment());

		assertTrue(getView().hasSameAddresses(set));

		// collapse the test folder and remove the view
		collapseNode(nodes[0]);
		setSelectionPath(nodes[0]);

		DockingActionIf removeAction = getAction("Remove");
		performAction(removeAction);

		// verify that all the descendants of the folder are removed from the view
		assertFalse(getView().contains(child1.getFragment()));
		assertFalse(getView().contains(child3.getFragment()));

		assertTrue(getView().contains(otherchild1.getFragment()));
		assertPluginViewAppliedToTool();
	}

	@Test
	public void testReplaceViewFragment() {

		setTreeView("Main Tree");

		ProgramNode node = (ProgramNode) root.getChildAt(6);
		visitNode(node);
		ProgramNode child = (ProgramNode) node.getChildAt(0);
		setSelectionPath(child);

		DockingActionIf replaceAction = getAction("Replace");
		performAction(replaceAction);

		assertTrue(getView().hasSameAddresses(child.getFragment()));
		assertTrue(getView().hasSameAddresses(cbPlugin.getView()));
		assertTrue(getView().hasSameAddresses(viewMgrService.getCurrentView()));

		int row = getRowForPath(child.getTreePath());
		Component comp = tree.getCellRenderer()
				.getTreeCellRendererComponent(tree, child, true, false, true, row, false);
		assertEquals(new GIcon(DnDTreeCellRenderer.VIEWED_FRAGMENT),

			((JLabel) comp).getIcon());
	}

	@Test
	public void testReplaceViewFolder() {
		setTreeView("Main Tree");

		ProgramNode node = (ProgramNode) root.getChildAt(6);
		setSelectionPath(node);

		DockingActionIf replaceAction = getAction("Replace");
		assertTrue(replaceAction.isEnabledForContext(getActionContext()));
		performAction(replaceAction, getActionContext(), true);

		assertTrue(plugin.getView().hasSameAddresses(node.getModule().getAddressSet()));
		assertPluginViewAppliedToTool();
	}

	@Test
	public void testReplaceViewMultiSelection() {
		setTreeView("Main Tree");

		ProgramNode textNode = (ProgramNode) root.getChildAt(1);
		ProgramNode dataNode = (ProgramNode) root.getChildAt(2);
		setViewPaths(textNode, dataNode);

		// select DLLs folder
		ProgramNode dllsNode = (ProgramNode) root.getChildAt(6);
		visitNode(dllsNode);

		ProgramNode functionsNode = (ProgramNode) root.getChildAt(7);
		visitNode(functionsNode);
		ProgramNode sscanfNode = (ProgramNode) functionsNode.getChildAt(2);

		// set a folder not in the view and a fragment that is not a
		// descendant of that folder, and not in the view
		setSelectionPaths(dllsNode, sscanfNode);

		DockingActionIf replaceAction = getAction("Replace");
		performAction(replaceAction);

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
		setViewPaths(node);

		int row = getRowForPath(node.getTreePath());

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

		setSelectionPath(dllsNode);

		DockingActionIf mergeAction = getAction("Merge");
		performAction(mergeAction);
		waitForProgram(program);

		int count = nodes[0].getChildCount();
		assertEquals(origEvCount - 1 + dllsCount, count);

		for (int i = 0; i < count; i++) {
			assertFalse(((ProgramNode) nodes[0].getChildAt(i)).getName().equals("DLLs"));
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

		setSelectionPaths(dNodes[0], bNodes[0]);

		DockingActionIf mergeAction = getAction("Merge");
		performAction(mergeAction, getActionContext(), true);
		waitForProgram(program);

		assertEquals(7, root.getChildCount());
	}

	@Test
	public void testMergeEnabled() {

		setTreeView("Main Tree");
		expandRoot();

		ProgramNode node = (ProgramNode) root.getChildAt(2);
		setSelectionPath(node);

		DockingActionIf mergeAction = getAction("Merge");
		assertFalse(mergeAction.isEnabledForContext(getActionContext()));

		ProgramNode fnode = (ProgramNode) root.getChildAt(6);
		setSelectionPaths(node, fnode);

		DockingActionIf mergeAction2 = getAction("Merge");
		assertTrue(mergeAction2.isEnabledForContext(getActionContext()));
	}

	@Test
	public void testSaveState() {

		setTreeView("Main Tree");
		expandRoot();
		ProgramNode node = (ProgramNode) root.getChildAt(2);
		ProgramNode fnode = (ProgramNode) root.getChildAt(6);
		setViewPaths(node, fnode);

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

		Memory mem = program.getMemory();
		tx(program, () -> {
			mem.createInitializedBlock(".test", getAddr(0x30), 0x12, (byte) 0, TaskMonitor.DUMMY,
				false);
		});

		setTreeView("Main Tree");
		expandRoot();

		ProgramNode[] nodes = findNodes(".test");
		assertEquals(1, nodes.length);

		tx(program, () -> {
			mem.createInitializedBlock(".test.exp", getAddr(0x42), 4, (byte) 0, TaskMonitor.DUMMY,
				false);
		});

		nodes = findNodes(".test.exp");
		assertEquals(1, nodes.length);

		undo();
		nodes = findNodes(".test.exp");
		assertEquals(0, nodes.length);
		redo();
		nodes = findNodes(".test.exp");
		assertEquals(1, nodes.length);

		tx(program, () -> {
			MemoryBlock block = mem.getBlock(getAddr(0x30));
			mem.removeBlock(block, TaskMonitor.DUMMY);
			block = mem.getBlock(getAddr(0x42));
			mem.removeBlock(block, TaskMonitor.DUMMY);
		});

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
		DockingActionIf showAction = getAction(plugin, "Open Tree View");
		assertTrue(showAction.isEnabledForContext(getActionContext()));
		String[] treeNames = program.getListing().getTreeNames();

		performAction(showAction);

		JPopupMenu menu = plugin.getPopupMenu();
		assertNotNull(menu);
		Component[] comps = menu.getComponents();

		List<Component> list = new ArrayList<>();
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
			ActionListener[] listeners = item.getActionListeners();
			runSwing(() -> listeners[0].actionPerformed(null));
			ViewProviderService vps = plugin.getCurrentProvider();
			assertEquals(treeNames[i], vps.getViewName());
			assertEquals(vps, viewMgrService.getCurrentViewProvider());
		}
	}

	private String setEditorText(String text) {

		JTextField editorTextField = runSwing(() -> {
			int row = tree.getRowForPath(tree.getEditingPath());
			DefaultTreeCellEditor cellEditor = (DefaultTreeCellEditor) tree.getCellEditor();
			Container container = (Container) cellEditor.getTreeCellEditorComponent(tree,
				tree.getEditingPath().getLastPathComponent(), true, true, true, row);
			JTextField textField = (JTextField) container.getComponent(0);
			textField.setText(text);
			commitEdit();
			return textField;
		});
		waitForProgram(program);
		return runSwing(() -> editorTextField.getText());
	}

	private void commitEdit() {
		runSwing(() -> tree.stopEditing());
		if (!Swing.isSwingThread()) {
			waitForProgram(program);
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

	private ProgramModule getModule(ProgramNode node, String name) {
		ProgramModule nodeModule = node.getModule();
		Group[] children = nodeModule.getChildren();
		for (Group group : children) {
			if (!(group instanceof ProgramModule)) {
				continue;
			}

			ProgramModule module = (ProgramModule) group;
			if (module.getName().equals(name)) {
				return module;
			}
		}
		return null;
	}

	private ProgramFragment getFragment(ProgramModule module, String name) {
		Group[] children = module.getChildren();
		for (Group group : children) {
			if (!(group instanceof ProgramFragment)) {
				continue;
			}

			ProgramFragment fragment = (ProgramFragment) group;
			if (fragment.getName().equals(name)) {
				return fragment;
			}
		}
		return null;
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
