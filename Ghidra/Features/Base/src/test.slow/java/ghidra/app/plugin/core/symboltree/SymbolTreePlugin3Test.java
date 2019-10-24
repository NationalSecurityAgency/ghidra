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

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.DnDConstants;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.SwingUtilities;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeDragNDropHandler;
import docking.widgets.tree.support.GTreeNodeTransferable;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.marker.MarkerManagerPlugin;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.plugin.core.symboltree.nodes.*;
import ghidra.app.util.viewer.field.LabelFieldFactory;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * More tests for the SymbolTreePlugin.
 *
 *
 *
 */
public class SymbolTreePlugin3Test extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private SymbolTreePlugin plugin;
	private GTreeNode rootNode;
	private DockingActionIf createNamespaceAction;
	private DockingActionIf createClassAction;
	private SymbolTreeTestUtils util;
	private CodeBrowserPlugin cbPlugin;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();

		tool.addPlugin(ProgramTreePlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(MarkerManagerPlugin.class.getName());
		tool.addPlugin(SymbolTreePlugin.class.getName());
		plugin = env.getPlugin(SymbolTreePlugin.class);

		cbPlugin = env.getPlugin(CodeBrowserPlugin.class);

		util = new SymbolTreeTestUtils(plugin);
		program = util.getProgram();

		env.showTool();

		util.showSymbolTree();

		rootNode = util.getRootNode();
		createNamespaceAction = getAction(plugin, "Create Namespace");
		createClassAction = getAction(plugin, "Create Class");
	}

	@After
	public void tearDown() throws Exception {
		util.closeProgram();
		env.dispose();
	}

	@Test
	public void testDropSiteOK() throws Exception {
		// verify that a function is not a valid drop site
		GTreeNode nsNode = rootNode.getChild(5);
		util.createObject(nsNode, "MyNamespace", createNamespaceAction);
		GTreeNode fNode = rootNode.getChild(2);
		util.expandNode(fNode);

		GTreeNode dNode = fNode.getChild(0);
		GTreeNode gNode = fNode.getChild(1);
		GTreeNode sNode = fNode.getChild(2);
		util.selectNodes(new GTreeNode[] { gNode, sNode });

		DataFlavor flavor = ((SymbolTreeNode) gNode).getNodeDataFlavor();

		GTreeDragNDropHandler dnd = util.getTree().getDragNDropHandler();
		assertTrue(!dnd.isDropSiteOk(dNode, new DataFlavor[] { flavor }, DnDConstants.ACTION_MOVE));
	}

	@Test
	public void testDropSiteOK2() throws Exception {
		// verify that a SymbolCategory is not a valid drop site
		GTreeNode nsNode = rootNode.getChild(5);
		util.createObject(nsNode, "MyNamespace", createNamespaceAction);
		GTreeNode fNode = rootNode.getChild(2);
		util.expandNode(fNode);

		GTreeNode gNode = fNode.getChild(1);
		GTreeNode sNode = fNode.getChild(2);
		util.selectNodes(new GTreeNode[] { gNode, sNode });

		GTreeNode extNode = rootNode.getChild(0);
		DataFlavor flavor = ((SymbolTreeNode) gNode).getNodeDataFlavor();

		GTreeDragNDropHandler dnd = util.getTree().getDragNDropHandler();
		assertTrue(
			!dnd.isDropSiteOk(extNode, new DataFlavor[] { flavor }, DnDConstants.ACTION_MOVE));
		assertTrue(
			!dnd.isDropSiteOk(extNode, new DataFlavor[] { flavor }, DnDConstants.ACTION_COPY));

	}

	@Test
	public void testStartDragOK() throws Exception {
		GTreeNode fNode = rootNode.getChild(2);
		util.expandNode(fNode);
		GTreeNode gNode = fNode.getChild(1);
		util.expandNode(gNode);
		GTreeNode pNode = gNode.getChild(0);
		List<GTreeNode> list = new ArrayList<>();
		list.add(pNode);
		GTreeNode p2Node = gNode.getChild(1);
		list.add(p2Node);

		GTreeDragNDropHandler dnd = util.getTree().getDragNDropHandler();
		assertTrue(!dnd.isStartDragOk(list, DnDConstants.ACTION_MOVE));
	}

	@Test
	public void testDragDrop() throws Exception {
		GTreeNode nsParentNode = rootNode.getChild(5);
		assertTrue(nsParentNode instanceof SymbolCategoryNode);

		SymbolCategory namespaceCategory = ((SymbolCategoryNode) nsParentNode).getSymbolCategory();
		assertEquals("Namespaces", namespaceCategory.getName());

		GTreeNode nsNode = util.createObject(nsParentNode, "MyNamespace", createNamespaceAction);
		assertNotNull(nsNode);
		assertEquals("MyNamespace", nsNode.getName());

		int index = nsNode.getIndexInParent();
		GTreeNode fNode = rootNode.getChild(2);
		util.expandNode(fNode);

		GTreeNode gNode = fNode.getChild(1);
		GTreeNode sNode = fNode.getChild(2);
		String gNodeName = gNode.getName();
		String sNodeName = sNode.getName();
		util.selectNodes(new GTreeNode[] { gNode, sNode });
		doDrag(nsNode, DnDConstants.ACTION_MOVE, gNode, sNode);

		util.waitForTree();
		nsParentNode = rootNode.getChild(5);
		nsNode = nsParentNode.getChild(index);
		util.expandNode(nsNode);
		assertEquals(2, nsNode.getChildCount());
		gNode = nsNode.getChild(0);
		assertEquals(gNodeName, gNode.getName());
		sNode = nsNode.getChild(1);
		assertEquals(sNodeName, sNode.getName());
	}

	private void doDrag(final GTreeNode destinationNode, final int dragAction,
			GTreeNode... dragNode) {
		final GTreeDragNDropHandler dragNDropHandler = util.getTree().getDragNDropHandler();
		List<GTreeNode> dropList = new ArrayList<>();
		for (GTreeNode gTreeNode : dragNode) {
			dropList.add(gTreeNode);
		}

		final Transferable transferable = new GTreeNodeTransferable(dragNDropHandler, dropList);

		executeOnSwingWithoutBlocking(
			() -> dragNDropHandler.drop(destinationNode, transferable, dragAction));
		util.waitForTree();
		waitForPostedSwingRunnables();
	}

	@Test
	public void testDragDropLabelOnClass() throws Exception {
		final ToggleDockingAction goToToggleAction =
			(ToggleDockingAction) getAction(plugin, "Navigation");

		SwingUtilities.invokeAndWait(() -> goToToggleAction.setSelected(true));
		GTreeNode cNode = rootNode.getChild(4);
		GTreeNode nsNode = util.createObject(cNode, "MyClass", createClassAction);
		assertNotNull(nsNode);
		int index = nsNode.getIndexInParent();
		GTreeNode fNode = rootNode.getChild(2);
		util.expandNode(fNode);

		GTreeNode gNode = fNode.getChild(1);
		GTreeNode sNode = fNode.getChild(2);
		String gNodeName = gNode.getName();
		String sNodeName = sNode.getName();
		util.selectNodes(new GTreeNode[] { gNode, sNode });
		doDrag(nsNode, DnDConstants.ACTION_MOVE, gNode, sNode);

		util.waitForTree();
		cNode = rootNode.getChild(4);
		nsNode = cNode.getChild(index);
		Symbol classSymbol = ((SymbolNode) nsNode).getSymbol();

		util.expandNode(nsNode);
		assertEquals(2, nsNode.getChildCount());
		gNode = nsNode.getChild(0);
		assertEquals(gNodeName, gNode.getName());
		sNode = nsNode.getChild(1);
		assertEquals(sNodeName, sNode.getName());

		Symbol symbol = getUniqueSymbol(program, "entry");
		assertTrue(cbPlugin.goToField(symbol.getAddress(), LabelFieldFactory.FIELD_NAME, 0, 0));

		Thread.sleep(1000);
		cbPlugin.updateNow();

		GTree tree = util.getTree();
		TreePath path = tree.getSelectionPath();
		assertNotNull(path);
		GTreeNode eNode = (GTreeNode) path.getLastPathComponent();
		util.selectNodes(new GTreeNode[] { eNode });

		doDrag(nsNode, DnDConstants.ACTION_MOVE, eNode);

		Symbol s = ((SymbolNode) eNode).getSymbol();

		// parent namespace should be MyClass.
		assertEquals(classSymbol.getObject(), s.getParentNamespace());
	}

	@Test
	public void testSortNamespaces() throws Exception {
		SymbolTable symTable = program.getSymbolTable();
		String[] names =
			new String[] { "aNamespace", "MYnamespace", "Bnamespace", "AaNamespace", "Cnamespace" };
		List<Symbol> list = new ArrayList<>();
		int transactionID = program.startTransaction("test");

		try {
			for (String element : names) {
				Namespace ns = symTable.createNameSpace(program.getGlobalNamespace(), element,
					SourceType.USER_DEFINED);
				list.add(ns.getSymbol());
			}
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		Collections.sort(list, util.getSymbolComparator());

		program.flushEvents();
		waitForPostedSwingRunnables();
		util.waitForTree();

		List<Symbol> symbolList = new ArrayList<>();

		GTreeNode nsParentNode = rootNode.getChild(5);
		util.expandNode(nsParentNode);
		for (int i = 0; i < nsParentNode.getChildCount(); i++) {
			GTreeNode node = nsParentNode.getChild(i);
			if (node instanceof SymbolNode) {
				Symbol symbol = ((SymbolNode) node).getSymbol();
				if (symbol.getSymbolType() == SymbolType.NAMESPACE) {
					symbolList.add(symbol);
				}
			}
		}

		List<GTreeNode> children = nsParentNode.getChildren();

		//@formatter:off
		List<String> symbolNames = 
			children.stream()
					.map(node -> ((SymbolNode) node).getSymbol())
			        .filter(symbol -> symbol.getSymbolType() == SymbolType.NAMESPACE)
			        .map(symbol -> symbol.getName())
			        .collect(Collectors.toList());
		//@formatter:off

		//
		// This is the way we currently sort, documented here for posterity.
		//
		List<String>  expectedOrder =
			Arrays.asList( "AaNamespace", "aNamespace", "Bnamespace", "Cnamespace", "MYnamespace" );

		assertEquals(expectedOrder.size(), symbolNames.size());
		assertEquals(expectedOrder, symbolNames);
	}

	@Test
	public void testSortClasses() throws Exception {
		SymbolTable symTable = program.getSymbolTable();
		String[] names =
			new String[] { "BClass", "MYclass", "bBClass", "Aaclass", "Cclass", "_anotherClass" };
		List<Symbol> list = new ArrayList<>();
		int transactionID = program.startTransaction("test");

		try {
			for (String element : names) {
				GhidraClass gc = symTable.createClass(program.getGlobalNamespace(), element,
					SourceType.USER_DEFINED);
				list.add(gc.getSymbol());
			}
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		program.flushEvents();
		waitForPostedSwingRunnables();
		util.waitForTree();

		GTreeNode cnode = rootNode.getChild(4);
		List<GTreeNode> children = cnode.getChildren();

		//@formatter:off
		List<String> symbolNames = 
			children.stream()
					.map(node -> ((SymbolNode) node).getSymbol())
			        .filter(symbol -> symbol.getSymbolType() == SymbolType.CLASS)
			        .map(symbol -> symbol.getName())
			        .collect(Collectors.toList());
		//@formatter:off

		//
		// This is the way we currently sort, documented here for posterity.
		//
		List<String>  expectedOrder =
			Arrays.asList("_anotherClass", "Aaclass", "bBClass", "BClass", "Cclass", "MYclass");

		assertEquals(expectedOrder.size(), symbolNames.size());
		assertEquals(expectedOrder, symbolNames);
	}

	@Test
	public void testSaveState() throws Exception {
		final ToggleDockingAction goToToggleAction =
			(ToggleDockingAction) getAction(plugin, "Navigation");
		assertNotNull(goToToggleAction);
		SwingUtilities.invokeAndWait(() -> goToToggleAction.setSelected(true));

		SaveState saveState = new SaveState("Test");
		plugin.writeConfigState(saveState);

		assertTrue(saveState.getBoolean("GO_TO_TOGGLE_STATE", false));

		SwingUtilities.invokeAndWait(() -> {
			tool.removePlugins(new Plugin[] { plugin });
			try {
				tool.addPlugin(SymbolTreePlugin.class.getName());
			}
			catch (PluginException e) {
				e.printStackTrace();
			}
		});
		plugin = getPlugin(tool, SymbolTreePlugin.class);
		assertNotNull(plugin);
		util.setPlugin(plugin);

		ToggleDockingAction goToToggleAction2 =
			(ToggleDockingAction) getAction(plugin, "Navigation");
		assertNotNull(goToToggleAction2);
		assertTrue(!goToToggleAction2.isSelected());
		plugin.readConfigState(saveState);

		assertTrue(goToToggleAction2.isSelected());
	}

	@Test
	public void testCreateNamespaceAtNamespacesNode() throws Exception {
		GTreeNode namespacesRoot = rootNode.getChild("Namespaces");
		util.selectNode(namespacesRoot);
		assertTrue(createNamespaceAction.isEnabledForContext(util.getSymbolTreeContext()));
		performAction(createNamespaceAction, util.getSymbolTreeContext(), true);
		program.flushEvents();
		util.waitForTree();

		SwingUtilities.invokeAndWait(() -> util.getTree().stopEditing());

		GTreeNode nsParentNode = rootNode.getChild(5);
		util.expandNode(nsParentNode);
		assertEquals(1, nsParentNode.getChildCount());
	}

	@Test
	public void testCreateClassAtClassesNode() throws Exception {
		GTreeNode classesRoot = rootNode.getChild("Classes");
		util.selectNode(classesRoot);
		assertTrue(createClassAction.isEnabledForContext(util.getSymbolTreeContext()));
		performAction(createClassAction,util.getSymbolTreeContext(),  true);
		program.flushEvents();
		util.waitForTree();

		SwingUtilities.invokeAndWait(() -> util.getTree().stopEditing());
		GTreeNode cParentNode = rootNode.getChild(4);
		util.expandNode(cParentNode);
		assertEquals(1, cParentNode.getChildCount());
	}

	@Test
	public void testActionsEnabledOnClassNode() throws Exception {
		GTreeNode cNode = rootNode.getChild(4);
		util.selectNode(cNode);
		assertTrue(createClassAction.isEnabledForContext(util.getSymbolTreeContext()));
		assertTrue(!createNamespaceAction.isEnabledForContext(util.getSymbolTreeContext()));
	}

	@Test
	public void testActionsEnabledOnNamespaceNode() throws Exception {
		GTreeNode nsParentNode = rootNode.getChild(5);
		util.selectNode(nsParentNode);
		assertTrue(!createClassAction.isEnabledForContext(util.getSymbolTreeContext()));
		assertTrue(createNamespaceAction.isEnabledForContext(util.getSymbolTreeContext()));
	}
}
