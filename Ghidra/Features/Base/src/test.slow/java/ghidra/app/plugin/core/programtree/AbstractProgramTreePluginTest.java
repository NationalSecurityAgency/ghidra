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

import java.awt.Component;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.tree.TreePath;

import org.junit.Assert;
import org.junit.Before;

import docking.action.DockingActionIf;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.services.ProgramTreeService;
import ghidra.app.services.ViewManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.ProgramModule;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.exception.DuplicateNameException;

public abstract class AbstractProgramTreePluginTest extends AbstractGhidraHeadedIntegrationTest {

	protected TestEnv env;
	protected PluginTool tool;
	protected ProgramDB program;
	protected ProgramTreePlugin plugin;
	protected AddressFactory addrFactory;
	protected ProgramDnDTree tree;
	protected ProgramTreeActionManager actionMgr;
	protected ProgramNode root;
	protected DockingActionIf[] actions;
	protected ViewManagerService viewMgrService;
	protected CodeBrowserPlugin cbPlugin;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		setErrorGUIEnabled(false);
		tool = env.getTool();

		program = buildProgram();

		env.showTool(program);

		tool.addPlugin(ProgramTreePlugin.class.getName());
		ProgramTreeService service = tool.getService(ProgramTreeService.class);
		plugin = (ProgramTreePlugin) service;
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		cbPlugin = env.getPlugin(CodeBrowserPlugin.class);

		addrFactory = program.getAddressFactory();

		String treeName = plugin.getViewedTreeName();
		tree = plugin.getTree(treeName);

		actionMgr = plugin.getActionManager();
		actions = actionMgr.getActions();
		root = (ProgramNode) tree.getModel().getRoot();
		viewMgrService = tool.getService(ViewManagerService.class);
	}

	protected abstract ProgramDB buildProgram() throws Exception;

	protected void setTreeView(final String viewName) {
		tree = plugin.getTree(viewName);
		root = (ProgramNode) tree.getModel().getRoot();
		runSwing(() -> viewMgrService.setCurrentViewProvider(viewName));
	}

	protected void setViewPaths(TreePath[] paths) {
		runSwing(() -> tree.setViewPaths(paths));
	}

	protected TreePath[] getSelectionPaths() {
		AtomicReference<TreePath[]> ref = new AtomicReference<>();
		runSwing(() -> ref.set(tree.getSelectionPaths()));
		return ref.get();
	}

	protected void setSelectionPaths(TreePath[] paths) {
		runSwing(() -> tree.setSelectionPaths(paths));
	}

	protected void setSelectionPath(TreePath path) {
		runSwing(() -> tree.setSelectionPath(path));
	}

	protected void addSelectionPath(TreePath path) {
		runSwing(() -> tree.addSelectionPath(path));
	}

	protected void visitNode(ProgramNode node) {
		runSwing(() -> tree.visitNode(node));
	}

	protected void collapseNode(ProgramNode node) {
		runSwing(() -> tree.collapseNode(node));
	}

	protected void collapsePath(TreePath path) {
		runSwing(() -> tree.collapsePath(path));
	}

	protected void expandPath(TreePath path) {
		runSwing(() -> tree.expandPath(path));
	}

	protected void expandNode(ProgramNode node) {
		runSwing(() -> tree.expandNode(node));
	}

	protected void expandRoot() {
		runSwing(() -> tree.expandNode(root));
	}

	protected Address getAddr(long offset) {
		return addrFactory.getDefaultAddressSpace().getAddress(offset);
	}

	protected Component getCellRendererComponentForLeaf(ProgramNode node, int row) {
		AtomicReference<Component> ref = new AtomicReference<>();

		runSwing(() -> {
			DnDTreeCellRenderer cellRenderer = (DnDTreeCellRenderer) tree.getCellRenderer();
			Component component = cellRenderer.getTreeCellRendererComponent(tree, node, true, false,
				true, row, false);
			ref.set(component);
		});
		return ref.get();
	}

	protected Component getCellRendererComponentForNonLeaf(ProgramNode node, int row) {
		AtomicReference<Component> ref = new AtomicReference<>();

		runSwing(() -> {
			DnDTreeCellRenderer cellRenderer = (DnDTreeCellRenderer) tree.getCellRenderer();
			Component component = cellRenderer.getTreeCellRendererComponent(tree, node, true, false,
				false, row, false);
			ref.set(component);
		});
		return ref.get();
	}

	protected int getRowForPath(TreePath path) {
		AtomicInteger ref = new AtomicInteger();
		runSwing(() -> ref.set(tree.getRowForPath(path)));
		return ref.get();
	}

	protected void undo() throws Exception {
		runSwing(() -> {
			try {
				program.undo();
				program.flushEvents();
				root = (ProgramNode) tree.getModel().getRoot();
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		});

		waitForSwing();
	}

	protected void redo() throws Exception {
		runSwing(() -> {
			try {
				program.redo();
				program.flushEvents();
				root = (ProgramNode) tree.getModel().getRoot();
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		});

		waitForSwing();
	}

	protected void addCodeUnits(ProgramNode node, AddressSetView addrs) {
		runSwing(() -> tree.addCodeUnits(node, addrs));
	}

	protected void buildNodeList() {
		runSwing(() -> tree.buildNodeList());
	}

	protected AddressSet getView() {
		AtomicReference<AddressSet> ref = new AtomicReference<>();
		runSwing(() -> ref.set(plugin.getView()));
		return ref.get();
	}

	protected ProgramNode[] findNodes(String groupName) {
		AtomicReference<ProgramNode[]> ref = new AtomicReference<>();
		runSwing(() -> ref.set(tree.findNodes(groupName)));
		return ref.get();
	}

	protected ProgramModule createModule(ProgramNode node, String name)
			throws DuplicateNameException {
		AtomicReference<Object> ref = new AtomicReference<>();
		runSwing(() -> {
			try {
				ProgramModule module = node.getModule().createModule(name);
				ref.set(module);
			}
			catch (DuplicateNameException e) {
				ref.set(e);
			}
		});

		Object o = ref.get();
		if (o instanceof DuplicateNameException) {
			throw (DuplicateNameException) o;
		}
		return (ProgramModule) o;
	}
}
