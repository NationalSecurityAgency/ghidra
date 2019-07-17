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

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.services.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.GroupPath;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.RunManager;
import resources.ResourceManager;

public class ProgramTreePluginShowInViewTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private ProgramDB program;
	private ProgramTreePlugin plugin;
	private AddressFactory addrFactory;
	private ProgramDnDTree tree;
	private ProgramTreeActionManager actionMgr;
	private ProgramNode root;
	private DockingActionIf[] actions;
	private DockingActionIf cutAction;
	private DockingActionIf copyAction;
	private DockingActionIf pasteAction;
	private ViewManagerService viewMgrService;
	private CodeBrowserPlugin cb;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(ProgramTreePlugin.class.getName());
		ProgramTreeService service = tool.getService(ProgramTreeService.class);
		plugin = (ProgramTreePlugin) service;
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());

		cb = env.getPlugin(CodeBrowserPlugin.class);

		program = (ProgramDB) buildProgram();

		addrFactory = program.getAddressFactory();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		String treeName = plugin.getViewedTreeName();
		tree = plugin.getTree(treeName);

		actionMgr = plugin.getActionManager();
		actions = actionMgr.getActions();

		copyAction = getAction("Copy");
		pasteAction = getAction("Paste");
		cutAction = getAction("Cut");

		assertNotNull(copyAction);
		assertNotNull(pasteAction);
		assertNotNull(cutAction);

		root = (ProgramNode) tree.getModel().getRoot();
		viewMgrService = tool.getService(ViewManagerService.class);

		setTreeView("Main Tree");

		env.showTool();
	}

	@After
	public void tearDown() throws Exception {
		waitForBusyTool(tool);
		env.dispose();
	}

	@Test
	public void testShowDescendantInViewIcon() {

		setTreeView("Main Tree");

		ProgramNode stringsNode = getNode(root, "Strings");

		visitNode(stringsNode);

		ProgramNode lNode = getNode(stringsNode, "L");

		setViewPaths(new TreePath[0]);

		setSelectionPaths(new TreePath[] { lNode.getTreePath() });
		goToStartFragment();

		assertIcon(stringsNode, DnDTreeCellRenderer.VIEWED_CLOSED_FOLDER_WITH_DESC, false, false);
	}

	@Test
	public void testShowFolderFragmentsInViewIcon() {
		env.showTool();
		setTreeView("Main Tree");

		ProgramNode stringsNode = getNode(root, "Strings");
		ProgramNode firstChild = (ProgramNode) root.getChildAt(0);

		visitNode(stringsNode);

		ProgramNode gNode = getNode(stringsNode, "G");

		addSelectionPaths(new TreePath[] { firstChild.getTreePath(), stringsNode.getTreePath(),
			gNode.getTreePath() });

		setViewPaths(getSelectionPaths());

		assertIcon(firstChild, DnDTreeCellRenderer.VIEWED_FRAGMENT);
		assertIcon(stringsNode, DnDTreeCellRenderer.VIEWED_CLOSED_FOLDER);
		assertIcon(gNode, DnDTreeCellRenderer.VIEWED_CLOSED_FOLDER);

		// make sure address set is correct
		AddressSet set = new AddressSet();
		set.add(firstChild.getFragment());
		set.add(stringsNode.getModule().getAddressSet());
		set.add(gNode.getModule().getAddressSet());
		assertTrue(set.hasSameAddresses(plugin.getView()));
		assertTrue(plugin.getView().hasSameAddresses(cb.getView()));
	}

	@Test
	public void testClearView() {

		setTreeView("Main Tree");

		setViewPaths(new TreePath[0]);
		assertTrue(plugin.getView().isEmpty());
		assertTrue(cb.getView().isEmpty());
	}

	@Test
	public void testShowFolderInView() throws Exception {

		setTreeView("Main Tree");

		ProgramNode stringsNode = getNode(root, "Strings");

		visitNode(stringsNode);
		setViewPaths(new TreePath[0]);

		setSelectionPaths(new TreePath[] { stringsNode.getTreePath() });
		goToStartFragment();

		AddressSetView set = stringsNode.getModule().getAddressSet();
		assertTrue(plugin.getView().hasSameAddresses(set));
		assertTrue(plugin.getView().hasSameAddresses(cb.getView()));

		assertIcon(stringsNode, DnDTreeCellRenderer.VIEWED_CLOSED_FOLDER);
	}

	@Test
	public void testShowFolderInViewIcon() {

		setTreeView("Main Tree");

		ProgramNode stringsNode = getNode(root, "Strings");

		setViewPaths(new TreePath[0]);

		addSelectionPaths(new TreePath[] { stringsNode.getTreePath() });
		goToStartFragment();

		expandPath(stringsNode.getTreePath());

		assertIcon(stringsNode, DnDTreeCellRenderer.VIEWED_OPEN_FOLDER, true);
	}

	@Test
	public void testShowInView() throws Exception {
		ProgramNode node = (ProgramNode) root.getChildAt(0);
		setSelectionPaths(new TreePath[] { node.getTreePath() });
		setViewPaths(getSelectionPaths());

		assertTrue(node.getFragment().hasSameAddresses(plugin.getView()));
		assertTrue(plugin.getView().hasSameAddresses(cb.getView()));
		assertIcon(node, DnDTreeCellRenderer.VIEWED_FRAGMENT);

		DockingActionIf action = getAction(plugin, "Go To start of folder/fragment in View");
		assertTrue(action.isEnabled());
	}

	@Test
	public void testShowInView2() {
		ProgramNode dataNode = root.getChild(".data");
		ProgramNode debugNode = root.getChild(".debug_data");
		setViewPaths(new TreePath[] { dataNode.getTreePath(), debugNode.getTreePath() });

		goTo(0x01001800);

		setSelectionPath(dataNode.getTreePath());
		goToStartFragment();

		assertEquals(getAddr(0x01001200), cb.getCurrentAddress());
	}

	@Test
	public void testShowInView3() {
		setTreeView("Main Tree");
		ProgramNode dataNode = root.getChild(".data");
		ProgramNode dllsNode = root.getChild("DLLs");
		visitNode(dllsNode);
		setViewPaths(new TreePath[] { dataNode.getTreePath(), dllsNode.getTreePath() });

		goTo(0x1001b00);

		setSelectionPath(dllsNode.getTreePath());
		goToStartFragment();

		// verify that the browser is at min address of DLLs
		assertEquals(dllsNode.getModule().getMinAddress(), cb.getCurrentAddress());
	}

	@Test
	public void testShowMultiSelectionInView() throws Exception {
		ProgramNode node0 = (ProgramNode) root.getChildAt(0);
		ProgramNode node1 = (ProgramNode) root.getChildAt(1);
		ProgramNode node3 = (ProgramNode) root.getChildAt(3);
		addSelectionPaths(
			new TreePath[] { node0.getTreePath(), node1.getTreePath(), node3.getTreePath() });

		setViewPaths(getSelectionPaths());

		AddressSet set = new AddressSet();
		set.add(node0.getFragment());
		set.add(node1.getFragment());
		set.add(node3.getFragment());

		assertTrue(plugin.getView().hasSameAddresses(set));
		assertTrue(plugin.getView().hasSameAddresses(cb.getView()));

		assertIcon(node0, DnDTreeCellRenderer.VIEWED_FRAGMENT);
		assertIcon(node1, DnDTreeCellRenderer.VIEWED_FRAGMENT);
		assertIcon(node3, DnDTreeCellRenderer.VIEWED_FRAGMENT);
	}

	@Test
	public void testShowInViewHotKey() throws Exception {
		env.showTool();

		ProgramNode textNode = root.getChild(".text");
		setSelectionPath(textNode.getTreePath());
		DockingActionIf replaceAction = getAction(plugin, "Replace View");

		ActionContext context = getActionContext();
		performAction(replaceAction, context, true);

		ProgramNode rsrcNode = root.getChild(".rsrc");
		setSelectionPath(rsrcNode.getTreePath());

		goToStartFragment();

		AddressSet set = new AddressSet();
		set.add(textNode.getFragment());
		set.add(rsrcNode.getFragment());
		assertTrue(set.hasSameAddresses(plugin.getView()));
		assertTrue(plugin.getView().hasSameAddresses(cb.getView()));
		assertIcon(rsrcNode, DnDTreeCellRenderer.VIEWED_FRAGMENT);
	}

	private ActionContext getActionContext() {

		ViewManagerComponentProvider provider = (ViewManagerComponentProvider) viewMgrService;
		ActionContext context = runSwing(() -> provider.getActionContext(null));
		return context;
	}

	@Test
	public void testRemoveFromView() throws Exception {
		env.showTool();

		ProgramNode textNode = root.getChild(".text");
		setSelectionPath(textNode.getTreePath());

		ProgramNode rsrcNode = root.getChild(".rsrc");

		addSelectionPath(rsrcNode.getTreePath());
		DockingActionIf replaceAction = getAction(plugin, "Replace View");
		ActionContext context = getActionContext();
		performAction(replaceAction, context, true);

		AddressSet set = new AddressSet();
		set.add(textNode.getFragment());
		set.add(rsrcNode.getFragment());

		assertTrue(set.hasSameAddresses(plugin.getView()));
		assertTrue(plugin.getView().hasSameAddresses(cb.getView()));

		setSelectionPath(textNode.getTreePath());

		DockingActionIf removeAction = getAction(plugin, "Remove folder/fragment from View");
		assertTrue(removeAction.isEnabled());
		performAction(removeAction, getActionContext(), true);

		assertTrue(rsrcNode.getFragment().hasSameAddresses(plugin.getView()));
		assertTrue(plugin.getView().hasSameAddresses(cb.getView()));
		assertIcon(rsrcNode, DnDTreeCellRenderer.VIEWED_FRAGMENT);
	}

	@Test
	public void testLocationChange() throws Exception {

		env.showTool();

		setTreeView("Main Tree");

		enableNavigation();

		Listing listing = program.getListing();
		int transactionID = program.startTransaction("test");
		ProgramFragment frag = listing.getFragment("Main Tree", getAddr(0x1002320)); //tests fragment in S folder
		try {
			frag.setName("ShowWindow");
			// copy fragment to other parents
			ProgramModule module = listing.getModule("Main Tree", "L");
			module.add(frag); // ==>  L, ShowWindow

			ProgramModule m2 = listing.getModule("Main Tree", "Fragments");
			m2.add(module); // ==> Fragments, L, ShowWindow 

			ProgramModule m3 = listing.getModule("Main Tree", "Functions");
			m3.add(module); // ==> Functions, L, ShowWindow

		}
		finally {
			program.endTransaction(transactionID, true);
		}

		program.flushEvents();
		waitForBusyTool(tool);

		goTo(0x1002320);

		waitForRunManager();

		TreePath[] selPaths = getSelectionPaths();
		assertEquals(4, selPaths.length);
		List<GroupPath> pathList = new ArrayList<>();

		pathList.add(new GroupPath(
			new String[] { "TestProgram", "Everything", "Fragments", "L", "ShowWindow" }));

		pathList.add(new GroupPath(new String[] { "TestProgram", "Strings", "S", "ShowWindow" }));
		pathList.add(new GroupPath(new String[] { "TestProgram", "Strings", "L", "ShowWindow" }));
		pathList.add(new GroupPath(new String[] { "TestProgram", "Functions", "L", "ShowWindow" }));

		waitForRunManager();

		for (TreePath element : selPaths) {
			ProgramNode node = (ProgramNode) element.getLastPathComponent();
			assertEquals("ShowWindow", node.getName());
			GroupPath gp = node.getGroupPath();
			assertTrue(pathList.contains(gp));

		}

		setTreeView("Program Tree");

		goTo(0x100232e);

		waitForRunManager();

		selPaths = getSelectionPaths();
		assertEquals(1, selPaths.length);
		ProgramNode node = (ProgramNode) selPaths[0].getLastPathComponent();
		assertEquals(new GroupPath(new String[] { "TestProgram", ".text" }), node.getGroupPath());
	}

	private void goTo(long address) {
		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(getAddr(address));
	}

	@Test
	public void testSelectToggleButton() throws Exception {
		setTreeView("Main Tree");

		//setup scenario of fragment C being in two folders
		copyFolderOrFragment(".data", "Not Real Blocks");

		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(getAddr(0x1001200));

		waitForSwing();
		assertEquals(getAddr(0x1001200), cb.getCurrentAddress());

		enableNavigation();

		waitForRunManager();

		TreePath[] selPaths = getSelectionPaths();
		assertEquals(2, selPaths.length);

		List<GroupPath> pathList = new ArrayList<>();
		pathList.add(new GroupPath(new String[] { "TestProgram", ".data" }));
		pathList.add(new GroupPath(new String[] { "TestProgram", "Not Real Blocks", ".data" }));

		for (TreePath element : selPaths) {
			ProgramNode node = (ProgramNode) element.getLastPathComponent();
			assertEquals(".data", node.getName());
			GroupPath gp = node.getGroupPath();
			assertTrue(pathList.contains(gp));
		}
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void enableNavigation() {
		ToggleDockingAction action = (ToggleDockingAction) getAction(plugin, "Navigation");
		if (!action.isSelected()) {
			performAction(action, getActionContext(), true);
		}

	}

	private Program buildProgram() throws Exception {
		//Default Tree
		ProgramBuilder builder = new ProgramBuilder("TestProgram", ProgramBuilder._TOY);
		builder.createMemory(".text", "0x1001000", 0x4000);

		//Main Tree
		builder.createProgramTree("Main Tree");
		builder.createFragment("Main Tree", "", ".data", "0x1001200", "0x10013ff");
		builder.createFragment("Main Tree", "", ".rsrc", "0x1001400", "0x10015ff");
		builder.createFragment("Main Tree", "", ".imports", "0x1001600", "0x10017ff");
		builder.createFragment("Main Tree", "", ".debug_data", "0x1001800", "0x10019ff");
		builder.createFragment("Main Tree", "DLLs", "ADVAPI32.DLL", "0x1001a00", "0x1001aff");
		builder.createFragment("Main Tree", "DLLs", "USER32.DLL", "0x1001b00", "0x1001bff");
		builder.createFragment("Main Tree", "Functions", "doStuff", "0x1001c00", "0x1001cff");
		builder.createFragment("Main Tree", "Functions", "ghidra", "0x1001d00", "0x1001dff");
		builder.createFragment("Main Tree", "Functions", "sscanf", "0x1001e00", "0x1001eff");
		builder.createFragment("Main Tree", "Not Real Blocks", "stuff", "0x1002000", "0x10020ff");
		builder.createFragment("Main Tree", "Subroutines", "01002a91", "0x1002a91", "0x1002aff");
		builder.createFragment("Main Tree", "Subroutines", "01004a15", "0x1004a15", "0x1004aff");
		builder.createFragment("Main Tree", "Subroutines", "010030d8", "0x10030d8", "0x10030ff");
		builder.createFragment("Main Tree", "Everything.C", "testc", "0x1002200", "0x10022ff");
		builder.createFragment("Main Tree", "Everything.Fragments", "text", "0x1002400",
			"0x10024ff");
		builder.createFragment("Main Tree", "Everything.Fragments", "rsrc", "0x1002500",
			"0x10025ff");
		builder.createFragment("Main Tree", "Strings.CC", "testcc", "0x1002300", "0x100230f");
		builder.createFragment("Main Tree", "Strings.G", "testg", "0x1002310", "0x100231f");
		builder.createFragment("Main Tree", "Strings.S", "tests", "0x1002320", "0x100232f");
		builder.createFragment("Main Tree", "Strings.L", "testl", "0x1002330", "0x100233f");

		return builder.getProgram();
	}

	private ProgramNode getNode(ProgramNode parent, String name) {
		ProgramNode node = null;
		int n = parent.getChildCount();
		for (int i = 0; i < n; i++) {
			ProgramNode pn = (ProgramNode) parent.getChildAt(i);
			if (pn.getName().equals(name)) {
				node = pn;
				break;
			}
		}

		assertNotNull("Expected Program Tree module '" + name + "' in " + parent.getName(), node);
		return node;
	}

	private void assertIcon(ProgramNode node, String iconName) {
		assertIcon(node, iconName, false);
	}

	private void assertIcon(ProgramNode node, String iconName, boolean isExpanded) {

		boolean isLeaf = !isExpanded;
		assertIcon(node, iconName, isExpanded, isLeaf);
	}

	private void assertIcon(ProgramNode node, String iconName, boolean isExpanded, boolean isLeaf) {

		int row = getRow(node.getTreePath());
		JLabel comp = render(tree, node, true, isExpanded, isLeaf, row, false);
		assertEquals(ResourceManager.loadImage(iconName), getIcon(comp));
	}

	private void waitForRunManager() {
		waitForSwing();
		RunManager runMgr = plugin.getRunManager();
		waitForCondition(() -> !runMgr.isInProgress());
		waitForSwing();
	}

	private void goToStartFragment() {
		DockingActionIf action = getAction(plugin, "Go To start of folder/fragment in View");
		performAction(action, getActionContext(), true);
	}

	private Icon getIcon(JLabel comp) {
		return runSwing(() -> comp.getIcon());
	}

	private JLabel render(JTree jtree, Object node, boolean selected, boolean expanded,
			boolean leaf, int row, boolean hasFocus) {

		final AtomicReference<Component> ref = new AtomicReference<>();
		runSwing(() -> {
			DnDTreeCellRenderer cellRenderer = (DnDTreeCellRenderer) jtree.getCellRenderer();
			Component comp = cellRenderer.getTreeCellRendererComponent(jtree, node, selected,
				expanded, leaf, row, hasFocus);
			ref.set(comp);
		});

		return (JLabel) ref.get();
	}

	private Address getAddr(long offset) {
		return addrFactory.getDefaultAddressSpace().getAddress(offset);
	}

	private void setTreeView(final String viewName) {
		tree = plugin.getTree(viewName);
		root = (ProgramNode) tree.getModel().getRoot();

		runSwing(() -> viewMgrService.setCurrentViewProvider(viewName));
	}

	private TreePath[] getSelectionPaths() {
		return runSwing(() -> tree.getSelectionPaths());
	}

	private void setViewPaths(final TreePath[] paths) {
		runSwing(() -> tree.setViewPaths(paths));
	}

	private void setSelectionPaths(final TreePath[] treePaths) {
		runSwing(() -> tree.setSelectionPaths(treePaths));
	}

	private void visitNode(final ProgramNode node) {
		runSwing(() -> tree.visitNode(node));
	}

	private void expandPath(final TreePath treePath) {
		runSwing(() -> tree.expandPath(treePath));
	}

	private void setSelectionPath(final TreePath treePath) {
		runSwing(() -> tree.setSelectionPath(treePath));
	}

	private void addSelectionPaths(final TreePath[] treePaths) {
		runSwing(() -> tree.addSelectionPaths(treePaths));
	}

	private void addSelectionPath(final TreePath treePath) {
		runSwing(() -> tree.addSelectionPath(treePath));
	}

	private int getRow(final TreePath path) {
		final AtomicReference<Integer> ref = new AtomicReference<>();
		runSwing(() -> ref.set(tree.getRowForPath(path)));
		return ref.get();
	}

	private DockingActionIf getAction(String name) {
		for (DockingActionIf action : actions) {
			if (action.getName().startsWith(name)) {
				return action;
			}
		}
		Assert.fail("Could not find action: " + name);
		return null; // cannot get here
	}

	private void copyFolderOrFragment(String src, String dst) {

		ProgramNode node = root.getChild(src);

		runSwing(() -> {
			tree.setSelectionPath(node.getTreePath());
			tree.setViewPaths(new TreePath[] { node.getTreePath() });
		});

		performAction(copyAction, getActionContext(), true);

		runSwing(() -> {
			ProgramNode everythingNode = root.getChild(dst);
			tree.setSelectionPath(everythingNode.getTreePath());
		});

		assertTrue(pasteAction.isEnabled());
		performAction(pasteAction, getActionContext(), true);
	}
}
